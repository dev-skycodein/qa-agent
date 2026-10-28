"""workflow_chains.py on a small billing API with one switch per bug.

  python toolkit/engine/test_workflow_chains.py        (also collectable by pytest)

bugs: neg = pay subtracts the full invoice from the credit (balance goes below zero); cross = pay skips the ownership check;
state = change-plan works on a cancelled subscription; cap = refund cap compares with the invoice total, not what is left;
idem = a reused Idempotency-Key with another body returns the stored response.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import trust  # noqa: E402
import workflow_chains  # noqa: E402

TOKENS = {"Bearer t-alice": 1, "Bearer t-bob": 2, "Bearer t-admin": 3}
ROLE = {1: "customer", 2: "customer", 3: "admin"}
PRICE = {"basic": 1000, "pro": 3000}


def make_doc():
    ok = {"200": {"description": "ok"}}
    return {"openapi": "3.0.0", "paths": {
        "/me": {"get": {"security": [{"b": []}], "responses": ok}},
        "/subs": {"post": {"security": [{"b": []}],
                           "parameters": [{"name": "Idempotency-Key", "in": "header", "schema": {"type": "string"}}],
                           "requestBody": {"content": {"application/json": {"schema": {
                               "type": "object", "required": ["plan", "seats"],
                               "properties": {"plan": {"type": "string", "enum": ["basic", "pro"]},
                                              "seats": {"type": "integer", "minimum": 1, "maximum": 5}}}}}},
                           "responses": {"201": {"description": "c"}}}},
        "/subs/{subscription_id}/cancel": {"post": {"security": [{"b": []}], "responses": ok}},
        "/subs/{subscription_id}/change-plan": {"post": {"security": [{"b": []}], "requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "required": ["plan"], "properties": {"plan": {"type": "string", "enum": ["basic", "pro"]}}}}}}, "responses": ok}},
        "/invoices/{invoice_id}": {"get": {"security": [{"b": []}], "responses": ok}},
        "/invoices/{invoice_id}/pay": {"post": {"security": [{"b": []}], "responses": ok}},
        "/invoices/{invoice_id}/refund": {"post": {"security": [{"b": []}], "requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"amount_cents": {"type": "integer", "minimum": 1}}}}}}, "responses": ok}},
    }}


def start(bugs, start_credit=2500):
    credit = {1: start_credit, 2: start_credit, 3: 0}
    subs, invoices, keys = {}, {}, {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}") if n else {}

        def do_GET(self):
            uid = TOKENS.get(self.headers.get("Authorization", ""))
            if uid is None:
                return self._send(401, {"error": "auth"})
            path = urlparse(self.path).path.strip("/").split("/")
            if path == ["me"]:
                return self._send(200, {"id": uid, "credit_cents": credit[uid], "overdraft": False, "role": ROLE[uid]})
            if path[0] == "invoices" and len(path) == 2 and int(path[1]) in invoices:
                return self._send(200, invoices[int(path[1])])
            return self._send(404, {"error": "nf"})

        def do_POST(self):
            uid = TOKENS.get(self.headers.get("Authorization", ""))
            if uid is None:
                return self._send(401, {"error": "auth"})
            path = urlparse(self.path).path.strip("/").split("/")
            body = self._body()
            if path == ["subs"]:
                k = self.headers.get("Idempotency-Key")
                if k and k in keys:
                    if "idem" in bugs or keys[k][0] == body:
                        return self._send(201, keys[k][1])
                    return self._send(422, {"error": "key reused"})
                sid, iid = len(subs) + 1, len(invoices) + 1
                amount = PRICE[body["plan"]] * body["seats"]
                invoices[iid] = {"id": iid, "customer_id": uid, "amount_cents": amount, "paid_cents": 0, "refunded_cents": 0, "status": "open"}
                subs[sid] = {"id": sid, "customer_id": uid, "plan": body["plan"], "status": "active", "invoice_id": iid}
                if k:
                    keys[k] = (body, subs[sid])
                return self._send(201, subs[sid])
            if path[0] == "subs" and len(path) == 3 and int(path[1]) in subs:
                s = subs[int(path[1])]
                if s["customer_id"] != uid:
                    return self._send(404, {"error": "nf"})
                if path[2] == "cancel":
                    s["status"] = "cancelled"
                    return self._send(200, s)
                if path[2] == "change-plan":
                    if s["status"] == "cancelled" and "state" not in bugs:
                        return self._send(409, {"error": "cancelled"})
                    if body.get("plan") == s["plan"]:
                        return self._send(422, {"error": "same plan"})
                    s["plan"] = body["plan"]
                    return self._send(200, s)
            if path[0] == "invoices" and len(path) == 3 and int(path[1]) in invoices:
                inv = invoices[int(path[1])]
                if path[2] == "pay":
                    if inv["customer_id"] != uid and "cross" not in bugs:
                        return self._send(404, {"error": "nf"})
                    if inv["status"] != "open":
                        return self._send(409, {"error": "not open"})
                    owner = inv["customer_id"]
                    applied = min(max(credit[owner], 0), inv["amount_cents"])
                    credit[owner] -= inv["amount_cents"] if "neg" in bugs else applied
                    inv["paid_cents"], inv["status"] = inv["amount_cents"], "paid"
                    return self._send(200, {"credit_applied_cents": applied, "card_charged_cents": inv["amount_cents"] - applied, "invoice": inv})
                if path[2] == "refund":
                    if ROLE[uid] != "admin":
                        return self._send(403, {"error": "staff only"})
                    if inv["status"] != "paid":
                        return self._send(409, {"error": "unpaid"})
                    amt = body.get("amount_cents", inv["paid_cents"] - inv["refunded_cents"])
                    cap = inv["amount_cents"] if "cap" in bugs else inv["paid_cents"] - inv["refunded_cents"]
                    if amt <= 0 or amt > cap:
                        return self._send(422, {"error": "cap"})
                    inv["refunded_cents"] += amt
                    credit[inv["customer_id"]] += amt
                    return self._send(200, inv)
            return self._send(404, {"error": "nf"})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(bugs=(), start_credit=2500):
    srv = start(set(bugs), start_credit)
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}",
                          {"user_a": {"Authorization": "Bearer t-alice"}, "user_b": {"Authorization": "Bearer t-bob"},
                           "admin": {"Authorization": "Bearer t-admin"}})
        return workflow_chains.run(api, make_doc(), SimpleNamespace())
    finally:
        srv.shutdown()


def kinds(res):
    return {f["kind"] for f in res["findings"]}


def test_clean_billing_has_zero_findings_and_every_chain_oracle_ran():
    res = run()
    assert res["findings"] == [], [(f["kind"], f["endpoint"], f["detail"][:120]) for f in res["findings"]]
    assert trust.resolve(res)[0] == trust.RAN_OK, (trust.resolve(res), res["notes"])
    assert set(res["chains"]) == {"subscription", "invoice"}


def test_balance_below_zero_after_spend_down_is_found():
    assert "LOGIC-NEGATIVE-BALANCE" in kinds(run(["neg"]))


def test_response_amount_that_does_not_match_the_balance_change_is_found():
    assert "LOGIC-CONSERVATION" in kinds(run(["neg"]))


def test_paying_someone_elses_invoice_is_found_as_cross_owner_action():
    res = run(["cross"], start_credit=10 ** 6)                   # plenty of credit left when the attacker pays: it visibly falls
    hits = [f for f in res["findings"] if f["kind"] == "LOGIC-CROSS-OWNER-ACTION"]
    assert hits and hits[0]["severity"] == "high", res["findings"]
    assert "balance changed" in hits[0]["detail"]
    low = [f for f in run(["cross"])["findings"] if f["kind"] == "LOGIC-CROSS-OWNER-ACTION"]     # spent-down owner: nothing visibly moved
    assert low and low[0]["severity"] == "medium"


def test_action_accepted_after_cancel_is_found_even_when_the_default_body_is_the_same_plan():
    assert "LOGIC-STATE-REGRESSION" in kinds(run(["state"]))


def test_refund_cap_against_the_total_instead_of_what_is_left_is_found():
    assert "LOGIC-BOUND-VIOLATION" in kinds(run(["cap"]))


def test_reused_idempotency_key_with_another_body_is_found():
    assert "LOGIC-IDEMPOTENCY" in kinds(run(["idem"]))


def test_each_bug_yields_only_its_own_finding_kinds():
    assert kinds(run(["state"])) == {"LOGIC-STATE-REGRESSION"}
    assert kinds(run(["cap"])) == {"LOGIC-BOUND-VIOLATION"}
    assert kinds(run(["idem"])) == {"LOGIC-IDEMPOTENCY"}


def test_money_returning_followups_after_a_terminal_action_are_not_regressions():
    for verb in ("refund", "reimburse", "credit-back", "return", "chargeback", "notify", "resend-receipt"):
        assert workflow_chains.FOLLOWUP_OK.search(verb), verb
    for verb in ("change-plan", "update", "upgrade", "pay", "add-seat"):
        assert not workflow_chains.FOLLOWUP_OK.search(verb), verb


def test_api_without_a_chain_is_skipped_not_clean():
    doc = {"openapi": "3.0.0", "paths": {"/ping": {"get": {"responses": {"200": {"description": "ok"}}}}}}

    class Idle:
        roles = {"anon": {}, "user_a": {}}
        log = []

        def call(self, *a, **k):
            return api_mod.Resp(200, "{}")
    assert trust.resolve(workflow_chains.run(Idle(), doc, SimpleNamespace()))[0] == trust.SKIPPED


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"WORKFLOW OK: {len(tests)} tests")
