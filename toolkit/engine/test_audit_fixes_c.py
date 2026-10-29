"""Tests for the section C audit fixes: B-H6 (static_checks UNIQUE-FROM-RANDOM), C-H4 (logic_engine conservation float
tolerance), C-H2 (schema_fuzz rejected qa.BODIES entry), C-H3 (differential with no authenticated step).

  python -m uv run --no-project --python 3.12 --with hypothesis --with pytest python -m pytest toolkit/engine/test_audit_fixes_c.py -q

Stdlib servers on 127.0.0.1 with ephemeral ports only. No engine runs against any real app.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import differential as d  # noqa: E402
import logic_engine  # noqa: E402
import static_checks as sc  # noqa: E402
import test_schema_fuzz as tsf  # noqa: E402
import trust  # noqa: E402
from api import Api  # noqa: E402

PRISMA = "model Ticket {\n  id   Int    @id\n  code String @unique\n}\n"
SAVE = "function save(order) {\n  return prisma.ticket.create({ data: { code: %s(order) } });\n}\n"


def _js_project(tmp_path, js):
    (tmp_path / "schema.prisma").write_text(PRISMA, encoding="utf-8")
    (tmp_path / "ticket.js").write_text(js, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------- B-H6: static_checks UNIQUE-FROM-RANDOM

def test_unrelated_random_function_within_900_chars_is_not_blamed(tmp_path):
    js = ("function stableCode(order) {\n  return 'T-' + order.id + '-' + order.seq;\n}\n"
          + "// filler line one, nothing random here\n" * 10
          + "function unrelatedRandom() {\n  return Math.floor(Math.random() * 9000);\n}\n"
          + SAVE % "stableCode")
    assert sc.check_unique_random(_js_project(tmp_path, js)) == []


def test_random_function_really_used_is_still_high(tmp_path):
    js = "function badCode() {\n  return Math.floor(Math.random() * 9000);\n}\n" + SAVE % "badCode"
    found = sc.check_unique_random(_js_project(tmp_path, js))
    assert len(found) == 1 and found[0]["severity"] == "high", found
    assert "~9,000" in found[0]["detail"], found[0]["detail"]


def test_product_of_two_random_terms_uses_the_product_not_the_minimum(tmp_path):
    js = ("function genCode() {\n  return Math.floor(Math.random() * 1000) + Math.floor(Math.random() * 1000000000);\n}\n"
          + SAVE % "genCode")
    found = sc.check_unique_random(_js_project(tmp_path, js))
    assert len(found) == 1, found
    assert found[0]["severity"] == "low", found[0]            # ~1e12 values: not a high
    assert "1,000,000,000,000" in found[0]["detail"], found[0]["detail"]


def test_unknown_size_pattern_is_low_not_high(tmp_path):
    js = "function genHex() {\n  return Math.random().toString(16).slice(2);\n}\n" + SAVE % "genHex"
    found = sc.check_unique_random(_js_project(tmp_path, js))
    assert len(found) == 1, found
    assert found[0]["severity"] == "low" and "unknown size" in found[0]["detail"], found[0]


def test_arrow_expression_generator_is_read(tmp_path):
    js = "const genCode = () => Math.floor(Math.random() * 9000);\n" + SAVE % "genCode"
    found = sc.check_unique_random(_js_project(tmp_path, js))
    assert len(found) == 1 and found[0]["severity"] == "high", found


def test_python_def_body_is_bounded_by_indentation(tmp_path):
    py = ("import random\nfrom django.db import models\n\n"
          "class Ticket(models.Model):\n    code = models.CharField(max_length=8, unique=True)\n\n"
          "def stable_code(order):\n    return f'T-{order.id}-{order.seq}'\n\n"
          "def other():\n    return random.randint(1000, 9999)\n\n"
          "def save(order):\n    code = stable_code(order)\n    return Ticket(code=code)\n")
    (tmp_path / "models.py").write_text(py, encoding="utf-8")
    assert sc.check_unique_random(tmp_path) == []


def test_undetermined_body_reports_nothing(tmp_path):
    js = "function genCode() {\n  return Math.floor(Math.random() * 9000);\n" + SAVE % "genCode"   # braces never close
    root = _js_project(tmp_path, js)
    assert sc.function_bodies(root)["genCode"][0] is None
    assert sc.check_unique_random(root) == []


def test_random_space_unit_cases():
    assert sc.random_space("return 1;") is None
    assert sc.random_space(None) is None
    assert sc.random_space("return Math.random().toString(16);")[0] is None          # random, size unknown
    assert sc.random_space("return Math.floor(Math.random()*9000);")[0] == 9000.0
    space, _ = sc.random_space("return Math.floor(Math.random() * 1000) + Math.floor(Math.random() * 1000000000);")
    assert space == 1e12, space


# ---------------------------------------------------------------- C-H4: logic_engine conservation tolerance

SPEC_BANK = {"paths": {
    "/accounts/1": {"get": {"summary": "read account"}},
    "/accounts/1/withdraw": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"amount": {"type": "number"}}}}}}}},
}}
RULE_BANK = {"name": "withdraw keeps the books", "kind": "conservation", "read": "/accounts/1",
             "act": {"call": "POST /accounts/1/withdraw", "body": {"amount": None}},
             "field": "balance", "delta_field": "amount", "direction": "decrease"}


class Bank:
    def __init__(self, balance, wrong=False):
        self.balance, self.wrong = balance, wrong
        self.roles = {"anon": {}, "user_a": {"t": "a"}}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        if method == "GET" and path == "/accounts/1":
            return api_mod.Resp(200, json.dumps({"id": 1, "balance": self.balance}))
        if method == "POST" and path == "/accounts/1/withdraw":
            amt = body["amount"]
            if amt <= self.balance:
                self.balance = self.balance - (2 * amt if self.wrong else amt)
                return api_mod.Resp(200, json.dumps({"id": 1, "balance": self.balance}))
            return api_mod.Resp(409, "{}")
        return api_mod.Resp(404, "{}")


def _run_bank(start, amount, wrong=False):
    rule = dict(RULE_BANK, act={"call": "POST /accounts/1/withdraw", "body": {"amount": amount}})
    qa = SimpleNamespace(LOGIC_RULES=[rule], LOGIC_HEURISTICS=False, BODIES={}, SKIP=set(), LOGIC_SKIP=set())
    return logic_engine.run(Bank(start, wrong), SPEC_BANK, qa)


def test_float_rounding_is_not_a_conservation_mismatch():
    res = _run_bank(100.1, 0.1)                      # 100.1 - 0.1 == 100.0 in the app, but not in binary floats
    assert res["findings"] == [], res["findings"]
    assert res["status"] == trust.RAN_OK, res


def test_exact_binary_values_control_has_no_finding():
    res = _run_bank(100.0, 0.5)
    assert res["findings"] == [] and res["status"] == trust.RAN_OK, res


def test_real_conservation_error_is_still_a_high_finding():
    res = _run_bank(100.0, 0.5, wrong=True)          # the app takes 1.0 instead of 0.5
    kinds = [(f["kind"], f["severity"]) for f in res["findings"]]
    assert kinds == [("LOGIC-SUM-MISMATCH", "high")], res["findings"]


# ---------------------------------------------------------------- C-H2: schema_fuzz rejected qa.BODIES entry

ITEM_SPEC = {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
    "/items": {"post": {"requestBody": tsf._json_body(tsf.ITEM),
                        "responses": {"201": {"description": "ok", **tsf._json_body(
                            {"type": "object", "properties": {"id": {"type": "integer"}}})}}}}}}


def _items_routes():
    def items(b, q):
        if b.get("quantity", 0) >= 9:          # schema-valid input (maximum is 10) that crashes
            raise RuntimeError("quantity >= 9 crashes")
        return 201, {"id": 7}
    return {"POST /items": items}


def test_rejected_bodies_entry_degrades_only_its_operation_and_keeps_the_5xx_finding():
    qa = SimpleNamespace(BODIES={"POST /items": {"note": "x"}})            # quantity missing: our validator rejects it
    res, _ = tsf.run_engine(_items_routes(), spec=ITEM_SPEC, qa=qa, seed=1)
    kinds = {(f["kind"], f["endpoint"]) for f in res["findings"]}
    assert ("SCHEMA-VALID-5XX", "POST /items") in kinds, res["findings"]
    assert res["status"] == trust.DEGRADED, res["status"]
    assert any("BODIES" in n and "POST /items" in n for n in res["notes"]), res["notes"]
    assert not any("comes from a BODIES entry" in n for n in res["notes"]), res["notes"]


def test_valid_bodies_entry_control_is_ran_ok_with_the_finding():
    qa = SimpleNamespace(BODIES={"POST /items": {"quantity": 1}})
    res, _ = tsf.run_engine(_items_routes(), spec=ITEM_SPEC, qa=qa, seed=1)
    assert ("SCHEMA-VALID-5XX", "POST /items") in {(f["kind"], f["endpoint"]) for f in res["findings"]}, res["findings"]
    assert res["status"] == trust.RAN_OK, res["status"]


# ---------------------------------------------------------------- C-H3: differential with no authenticated step

DOC_ITEMS = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
    "/items": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
        "type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}}}}}}}}}}}}


def _server(need_auth):
    body = json.dumps([{"id": 1}]).encode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            ok = (not need_auth) or bool(self.headers.get("Authorization"))
            self.send_response(200 if ok else 401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body) if ok else 2))
            self.end_headers()
            self.wfile.write(body if ok else b"{}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _diff_run(roles):
    a, b = _server(True), _server(True)
    try:
        qa = SimpleNamespace(DIFF_BASE_URL=f"http://127.0.0.1:{b.server_address[1]}", BODIES={}, SEED=1, DIFF_NOISE_RUNS=1)
        return d.run(Api(f"http://127.0.0.1:{a.server_address[1]}", roles), DOC_ITEMS, qa)
    finally:
        for s in (a, b):
            s.shutdown()
            s.server_close()


def test_two_anon_401s_are_degraded_not_no_regression():
    res = _diff_run({})                              # only the anon role: no login ever happens
    assert res["status"] == trust.DEGRADED, (res["status"], res.get("status_reason"))
    assert any("no step authenticated" in n for n in res["notes"]), res["notes"]
    assert res["findings"] == []


def test_authenticated_pair_is_not_degraded_by_this_rule():
    res = _diff_run({"user_a": {"Authorization": "Bearer t-a"}})   # the plan runs as user_a on both sides
    assert res["status"] == trust.RAN_OK, (res["status"], res.get("status_reason"), res["notes"])
    assert not any("no step authenticated" in n for n in res["notes"]), res["notes"]
