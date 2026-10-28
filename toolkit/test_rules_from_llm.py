"""rules_from_llm.py without a network: digest, answer parsing, mechanical validation of proposed rules, rendering, and one rule executed by

logic_engine (including the new `save_from` of a setup step).



  python toolkit/test_rules_from_llm.py        (also collectable by pytest)

"""

import json

import sys

from pathlib import Path

from types import SimpleNamespace



HERE = Path(__file__).resolve().parent

sys.path.insert(0, str(HERE))

sys.path.insert(0, str(HERE / "engine"))

import api as api_mod  # noqa: E402

import logic_engine  # noqa: E402

import rules_from_llm as R  # noqa: E402



OK = {"200": {"description": "ok"}}





def obj(**props):

    return {"type": "object", "properties": {k: ({"type": v} if isinstance(v, str) else v) for k, v in props.items()}}





def body(schema):

    return {"requestBody": {"content": {"application/json": {"schema": schema}}}}





def resp(schema):

    return {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": schema}}}}}





SPEC = {"openapi": "3.0.0", "paths": {

    "/subs": {"post": {**body({**obj(plan={"type": "string", "enum": ["basic", "pro"]}, seats="integer"), "required": ["plan"]}),

                       **resp(obj(id="integer", invoice_id="integer", plan="string"))}},

    "/subs/{sid}/pay": {"post": {**body(obj(amount="integer")), **resp(obj(ok="boolean"))}},

    "/invoices/{iid}": {"get": resp(obj(id="integer", amount="integer", paid="integer", refunded="integer"))},

    "/invoices/{iid}/refund": {"post": {**body(obj(amount="integer")), **resp(obj(ok="boolean"))}},

    "/me": {"get": resp(obj(id="integer", credit="integer"))},

}}





def good_rule(**over):

    r = {"name": "refund cap", "kind": "bounded_by", "field": "refunded", "bound_field": "paid",

         "setup": [{"call": "POST /subs", "body": {"plan": "basic", "seats": 1}, "save": "inv", "save_from": "invoice_id"}],

         "acts": [{"call": "POST /invoices/{inv}/refund", "body": {"amount": 10}}], "repeat": 2, "read": "/invoices/{inv}"}

    r.update(over)

    return r





def test_digest_lists_operations_with_required_marks_enums_and_response_fields_and_respects_the_budget():

    text, shown, total = R.digest(SPEC)

    assert shown == total == 5

    assert "POST /subs body{plan:string=basic|pro*,seats:integer} ->{id,invoice_id,plan}" in text, text

    small, shown2, total2 = R.digest(SPEC, budget=120)

    assert 0 < shown2 < total2 and len(small) <= 120





def test_prompt_fits_the_skycodein_context_for_a_realistic_document():

    system, user, shown, total = R.build_prompt(SPEC)

    assert len(system) + len(user) < 7500

    big = {"paths": {f"/r{i}/{{id}}/act": {"post": {**body(obj(**{f"field{j}": "integer" for j in range(12)}))}} for i in range(120)}}

    s2, u2, shown2, total2 = R.build_prompt(big)

    assert len(s2) + len(u2) < 7500 and shown2 < total2 and "only" in u2          # cut, and it says so





def test_parse_json_ignores_fences_and_prose():

    assert R.parse_json('Here you go:\n```json\n{"rules": [{"name": "a"}]}\n```\nbye') == {"rules": [{"name": "a"}]}

    assert R.parse_json('{"rules": [], "note": "has } brace in \\"string\\" }"}')["rules"] == []

    for bad in ("no json at all", '{"rules": ['):

        try:

            R.parse_json(bad)

        except ValueError:

            continue

        raise AssertionError(bad)





def test_a_well_formed_rule_is_kept():

    assert R.validate_rule(good_rule(), SPEC) is None





def test_invented_paths_fields_enum_values_and_placeholders_are_dropped_with_a_reason():

    cases = {

        "unknown kind": good_rule(kind="magic"),

        "is not in the OpenAPI document": good_rule(acts=[{"call": "POST /invoices/{inv}/chargeback", "body": {}}]),

        "is not in the request schema": good_rule(acts=[{"call": "POST /invoices/{inv}/refund", "body": {"cents": 10}}]),

        "is not one of": good_rule(setup=[{"call": "POST /subs", "body": {"plan": "gold"}, "save": "inv"}]),

        "which no earlier setup step saves": good_rule(acts=[{"call": "POST /invoices/{zzz}/refund", "body": {"amount": 1}}]),

        "is not a field of the GET": good_rule(field="refunded_cents"),

        "no acts": good_rule(acts=[]),

        "needs 'field'": {k: v for k, v in good_rule().items() if k != "field"},

        "bounded_by needs": {k: v for k, v in good_rule().items() if k != "bound_field"},

        "read path GET": good_rule(read="/nothing/{inv}"),

    }

    for expect, rule in cases.items():

        why = R.validate_rule(rule, SPEC)

        assert why and expect in why, (expect, why)





def test_validate_splits_kept_and_dropped():

    kept, dropped = R.validate([good_rule(), good_rule(name="bad", kind="magic"), "junk"], SPEC)

    assert [k["name"] for k in kept] == ["refund cap"] and len(dropped) == 2





def test_render_appends_rules_that_load_back_unchanged_and_merges_with_the_base_spec():

    out = R.render('LOGIC_RULES = [{"name": "mine"}]\nOWNER = {}\n', [good_rule()], {"model": "m", "dropped": 3})

    ns = {}

    exec(compile(out, "qa-spec.llm.py", "exec"), ns)

    assert [r["name"] for r in ns["LOGIC_RULES"]] == ["mine", "refund cap"] and "3 dropped" in out





def test_propose_with_a_fake_llm_keeps_valid_rules_and_reports_drops():

    answer = json.dumps({"rules": [good_rule(), good_rule(name="x", field="nope")]})

    res = R.propose(SPEC, caller=lambda s, u: (answer, {"total_tokens": 1}))

    assert [r["name"] for r in res["kept"]] == ["refund cap"] and len(res["dropped"]) == 1

    res = R.propose(SPEC, caller=lambda s, u: ("sorry, I cannot", {}))

    assert res["kept"] == [] and "unparseable" in res["dropped"][0][1]





class BillingApi:

    """A tiny in-memory service for ONE rule: POST /subs makes an invoice (id differs from the sub id); refunds are capped by `cap`."""



    def __init__(self, cap_bug):

        self.roles, self.log, self.cap_bug = {"anon": {}, "user_a": {"t": "a"}}, [], cap_bug

        self.inv = {77: {"id": 77, "amount": 100, "paid": 100, "refunded": 0}}



    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):

        if method == "POST" and path == "/subs":

            return api_mod.Resp(201, json.dumps({"id": 1, "invoice_id": 77, "plan": "basic"}))

        if method == "POST" and path == "/invoices/77/refund":

            inv = self.inv[77]

            amt = body["amount"]

            limit = inv["amount"] if self.cap_bug else inv["paid"] - inv["refunded"]

            if amt > limit:

                return api_mod.Resp(422, "{}")

            inv["refunded"] += amt

            return api_mod.Resp(200, '{"ok": true}')

        if method == "GET" and path == "/invoices/77":

            return api_mod.Resp(200, json.dumps(self.inv[77]))

        return api_mod.Resp(404, "{}")





def run_rule(cap_bug):

    rule = good_rule(acts=[{"call": "POST /invoices/{inv}/refund", "body": {"amount": 60}}], repeat=2)

    return logic_engine.run(BillingApi(cap_bug), SPEC, SimpleNamespace(LOGIC_RULES=[rule], LOGIC_HEURISTICS=False))





def test_proposed_rule_with_save_from_finds_the_refund_cap_bug_and_is_quiet_on_the_fixed_service():

    bug = run_rule(cap_bug=True)

    assert [f["kind"] for f in bug["findings"]] == ["LOGIC-BOUND-VIOLATION"], (bug["findings"], bug["notes"])

    assert run_rule(cap_bug=False)["findings"] == []





def test_hostile_rule_text_can_never_become_code_of_the_rendered_spec():

    """The finding of the security review: a string with a triple quote must stay data. The attack rule tries to end the literal and run code."""

    import os

    import tempfile

    marker = os.path.join(tempfile.gettempdir(), "qa_injection_marker.txt")

    if os.path.exists(marker):

        os.remove(marker)

    q3 = chr(39) * 3

    evil_name = q3 + " + open(" + repr(marker) + ", " + repr("w") + ").write(" + repr("pwned") + ") + r" + q3     # runs as an operand BEFORE the TypeError

    evil = good_rule(name=evil_name)

    out = R.render("OWNER = {}" + chr(10), [evil], {"model": "m", "dropped": 0})

    ns = {}

    exec(compile(out, "qa-spec.llm.py", "exec"), ns)

    assert not os.path.exists(marker), "rendered spec executed text that came from the LLM"

    assert ns["LOGIC_RULES"][0]["name"] == evil_name                         # the hostile text survived as plain data

    for hostile in ("a" + chr(10) + "b", "a" + chr(0) + "b", "a" * 400):     # and validation refuses control characters / absurd strings

        why = R.validate_rule(good_rule(name=hostile), SPEC)

        assert why and "contains" in why, (hostile[:10], why)





def _sse_server(script):
    """Local server: each POST pops the next entry of `script`: an int = answer with that HTTP status, a list of strings = SSE chunks."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    seen = []
    nl = chr(10)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            seen.append(json.loads(self.rfile.read(n)))
            step = script.pop(0)
            if isinstance(step, int):
                self.send_response(step)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for piece in step:
                self.wfile.write(("data: " + piece + nl + nl).encode())
                self.wfile.flush()
            self.wfile.write(("data: [DONE]" + nl + nl).encode())

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


CFG = {"model": "m", "max_tokens": 100, "json_mode": True}


def _no_proxy_for_loopback():
    """call_llm uses the default opener on purpose (a company may need its proxy for the real service); the local test server must not
    be sent through one, whatever an earlier test or the machine configured."""
    import os
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        os.environ.pop(k, None)
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"


def _chunk(content=None, finish=None, usage=None):
    d = {"choices": [{"delta": ({"content": content} if content is not None else {}), "finish_reason": finish}]}
    if usage:
        d["usage"] = usage
    return json.dumps(d)


def test_streamed_answer_is_assembled_with_usage_and_finish_reason():
    _no_proxy_for_loopback()
    srv, seen = _sse_server([[_chunk("{" + chr(34) + "rules" + chr(34)), _chunk(": []}"), _chunk(None, "stop", {"total_tokens": 9})]])
    try:
        cfg = dict(CFG, api_url=f"http://127.0.0.1:{srv.server_address[1]}/v1/chat/completions")
        text, usage, finish = R.call_llm("sys", "user", cfg, "key", sleep=lambda s: None)
    finally:
        srv.shutdown()
    assert text == "{" + chr(34) + "rules" + chr(34) + ": []}" and usage == {"total_tokens": 9} and finish == "stop"
    assert seen[0]["stream"] is True and seen[0]["response_format"] == {"type": "json_object"} and seen[0]["max_tokens"] == 100


def test_gateway_timeout_524_and_502_are_retried_with_a_growing_pause_then_succeed():
    _no_proxy_for_loopback()
    srv, seen = _sse_server([524, 502, [_chunk("ok", "stop")]])
    pauses = []
    try:
        cfg = dict(CFG, api_url=f"http://127.0.0.1:{srv.server_address[1]}/v1/chat/completions")
        text, _, _ = R.call_llm("s", "u", cfg, "k", tries=3, sleep=pauses.append)
    finally:
        srv.shutdown()
    assert text == "ok" and len(seen) == 3 and pauses == [30, 60]


def test_persistent_failure_ends_with_a_clear_message_and_a_client_error_is_not_retried():
    _no_proxy_for_loopback()
    srv, seen = _sse_server([524, 524, 401])
    pauses = []
    try:
        cfg = dict(CFG, api_url=f"http://127.0.0.1:{srv.server_address[1]}/v1/chat/completions")
        try:
            R.call_llm("s", "u", cfg, "k", tries=2, sleep=pauses.append)
            raise AssertionError("expected SystemExit")
        except SystemExit as e:
            assert "after 2 tries" in str(e) and "nothing was written" in str(e)
        try:
            R.call_llm("s", "u", cfg, "k", tries=3, sleep=pauses.append)
            raise AssertionError("expected SystemExit")
        except SystemExit as e:
            assert "HTTP 401" in str(e)
    finally:
        srv.shutdown()
    assert len(seen) == 3                                        # 524, 524, then one 401 that was not retried


def test_answer_cut_at_the_token_limit_is_reported_as_such():
    cut = json.dumps({"rules": []})[:-1]
    res = R.propose(SPEC, caller=lambda s, u: (cut, {}, "length"))
    assert res["kept"] == [] and "token limit" in res["dropped"][0][1]


if __name__ == "__main__":

    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]

    for name, fn in tests:

        fn()

        print("ok  ", name)

    print(f"RULES FROM LLM OK: {len(tests)} tests")

