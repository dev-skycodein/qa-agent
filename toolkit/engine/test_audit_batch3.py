"""Repro tests for audit batch 3 (B-M1, B-M3..B-M9, B-M11, B-M12): authz_matrix, negative_engine, shrink, stateful.

  python -m pytest toolkit/engine/test_audit_batch3.py -q

Each test is a repro of one audit item: it fails on the code as it was, and passes once the item is fixed.
Fakes only: in-process API objects and stdlib HTTP servers on 127.0.0.1 with ephemeral ports. No app, no Docker, no port 8765.
"""
import json
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import authz_matrix  # noqa: E402
import negative_engine  # noqa: E402
import shrink  # noqa: E402
import stateful  # noqa: E402

Resp = api_mod.Resp


class Fake:
    """Stands in for api.Api: .roles and .call(role, method, path, body, query, raw=..., headers=...) -> Resp."""

    def __init__(self, handler, roles=("user_a", "user_b")):
        self.roles = {"anon": {}, **{r: {} for r in roles}}
        self.handler = handler
        self.log = []

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        return self.handler(role, method, path, body, query, raw)


def _body(props, required=()):
    return {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": props,
                                                                       "required": list(required)}}}},
            "responses": {"200": {"description": "ok"}, "201": {"description": "ok"}}}


STR = {"type": "string"}


# ---------------------------------------------------------------- B-M1: attacker == owner is not BOLA

def test_b_m1_owner_is_not_its_own_attacker():
    spec = {"paths": {
        "/orders": {"post": _body({"qty": {"type": "integer"}}, ["qty"])},
        "/orders/{order_id}": {"get": {"summary": "read"}},
    }}
    store = {}

    def handler(role, method, path, body, query, raw):
        if method == "POST" and path == "/orders":
            if role == "anon":
                return Resp(401, "{}")
            oid = len(store) + 1
            store[oid] = {"id": oid, "owner": role, "qty": (body or {}).get("qty", 1)}
            return Resp(201, json.dumps(store[oid]))
        m = re.fullmatch(r"/orders/(\d+)", path)
        if method == "GET" and m:                     # everybody reads everything (a BOLA on the read)
            return Resp(200, json.dumps(store[int(m.group(1))]))
        return Resp(404, "{}")

    qa = SimpleNamespace(OWNER={"POST /orders": "user_b"})
    res = authz_matrix.run(Fake(handler), spec, qa)
    own_bola = [f for f in res["findings"] if f["kind"] == "BOLA/IDOR" and f["role"] == "user_b"]
    assert own_bola == [], f"user_b is the owner of the order, yet reported as BOLA: {own_bola}"


# ---------------------------------------------------------------- B-M3: optional auth ([{}, {...}]) is public

def test_b_m3_optional_auth_is_not_missing_auth():
    spec = {"paths": {
        "/products": {"get": {"summary": "list", "security": [{}, {"bearer": []}]}},
        "/private": {"get": {"summary": "private", "security": [{"bearer": []}]}},
    }}

    def handler(role, method, path, body, query, raw):
        return Resp(200, "[]")

    res = authz_matrix.run(Fake(handler), spec, SimpleNamespace())
    missing = {f["endpoint"] for f in res["findings"] if f["kind"] == "MISSING-AUTH"}
    assert "GET /products" not in missing, "security [{}, {...}] allows anonymous access: not a MISSING-AUTH"
    assert "GET /private" in missing, "control: a required-auth endpoint that answers 2xx to anon must still be reported"


# ---------------------------------------------------------------- B-M4: a baseline 5xx is not repeated per mutation

def test_b_m4_baseline_5xx_is_reported_once_not_per_mutation():
    spec = {"paths": {"/notes": {"post": _body({"text": STR, "tag": STR}, ["text"])}}}
    qa = SimpleNamespace(BODIES={"POST /notes": {"text": "hello", "tag": "x"}})
    res = negative_engine.run(Fake(lambda *a: Resp(500, "boom")), spec, qa)
    groups = [f for f in res["findings"] if f["kind"] == "NEG-5XX"]
    assert len(groups) == 1, groups
    examples = groups[0].get("examples", [])
    assert len(examples) == 1 and "baseline" in examples[0]["detail"], \
        f"expected only the baseline 5xx, got {len(examples)} examples: {[e['detail'] for e in examples][:4]}"


# ---------------------------------------------------------------- B-M5: NEG-LEAK on normal 2xx content

def test_b_m5_normal_2xx_content_is_not_a_leak():
    ok = lambda text: negative_engine._leaks(text, ok=True)            # noqa: E731
    assert ok('{"avatar": "https://storage.googleapis.com/bucket/a.png"}') == []
    assert ok('{"logo": "https://cdn.example.com/app/abc123/logo.png"}') == []
    assert ok('{"id": "task-' + "a1" * 16 + '"}') == []
    # the real things stay findings
    assert "secret/key" in ok('{"k": "sk-abcdefghijklmnopqrstuvwx"}')
    assert "secret/key" in ok('{"k": "AIza' + "A" * 35 + '"}')
    assert "third-party error" in negative_engine._leaks("API key not valid. Please pass a valid key", ok=False)
    assert "absolute path" in negative_engine._leaks('{"trace": "failed in /home/alice/app/x/main.py"}', ok=False)


# ---------------------------------------------------------------- B-M6: XREF-IDOR with no proven effect is medium

def test_b_m6_xref_without_proven_effect_is_medium():
    spec = {"paths": {
        "/orders": {"post": _body({"qty": {"type": "integer"}}, ["qty"])},
        "/shipments": {"post": _body({"order_id": STR}, ["order_id"])},
    }}
    seq = iter(range(1, 10_000))

    def handler(role, method, path, body, query, raw):
        if method == "POST" and path in ("/orders", "/shipments"):
            return Resp(201, json.dumps({"id": next(seq)}))
        return Resp(404, "{}")

    qa = SimpleNamespace(BODIES={"POST /orders": {"qty": 1}, "POST /shipments": {"order_id": "1"}})
    res = negative_engine.run(Fake(handler), spec, qa)
    xref = [f for f in res["findings"] if f["kind"] == "XREF-IDOR"]
    assert xref, "control: the accepted cross-user reference must still be reported"
    assert all(f["severity"] == "medium" for f in xref), [(f["severity"], f["detail"]) for f in xref]


# ---------------------------------------------------------------- B-M7: _unique keeps code / sku / handle / slug / login values

def test_b_m7_unique_does_not_change_code_like_values():
    body = {"country_code": "US", "sku": "ABC-1", "slug": "spring-sale", "handle": "shop", "login": "alice"}
    out = negative_engine._unique(body)
    assert out["country_code"] == "US" and out["sku"] == "ABC-1" and out["slug"] == "spring-sale", out
    assert out["handle"] == "shop" and out["login"] == "alice", out
    email = negative_engine._unique({"email": "a@b.test"})["email"]
    assert email.endswith("@b.test") and email != "a@b.test", email          # unique identity values still change


# ---------------------------------------------------------------- B-M8: a state-changing baseline is noted

def test_b_m8_delete_baseline_is_noted():
    spec = {"paths": {
        "/orders": {"post": _body({"qty": {"type": "integer"}}, ["qty"])},
        "/orders/{order_id}": {"delete": {"summary": "delete"}},
    }}
    items = {}

    def handler(role, method, path, body, query, raw):
        if method == "POST" and path == "/orders":
            oid = len(items) + 1
            items[oid] = True
            return Resp(201, json.dumps({"id": oid}))
        m = re.fullmatch(r"/orders/(\d+)", path)
        if method == "DELETE" and m:
            return Resp(204, "") if items.pop(int(m.group(1)), None) else Resp(404, "{}")
        return Resp(404, "{}")

    qa = SimpleNamespace(BODIES={"POST /orders": {"qty": 1}})
    res = negative_engine.run(Fake(handler), spec, qa)
    notes = [n for n in res["notes"] if "DELETE /orders/{order_id}" in n and "baseline" in n]
    assert notes, f"no note that the DELETE baseline consumed the resource: {res['notes']}"


# ---------------------------------------------------------------- B-M9: no NoSQL claim without a NoSQL payload

def test_b_m9_injection_text_makes_no_nosql_claim():
    spec = {"paths": {"/auth/login": {"post": _body({"email": STR, "password": STR}, ["email", "password"])}}}
    qa = SimpleNamespace(BODIES={"POST /auth/login": {"email": "alice@x.test", "password": "pw"}})

    def handler(role, method, path, body, query, raw):
        if isinstance(body, dict) and "'" in str(body.get("email", "")):
            return Resp(500, "You have an error in your SQL syntax near ''")
        return Resp(200, '{"token": "t"}')

    res = negative_engine.run(Fake(handler), spec, qa)
    inj = [f for f in res["findings"] if f["kind"] == "NEG-INJECTION"]
    assert inj, "control: the SQL-shaped payload must still be reported as an injection candidate"
    text = " ".join(f["detail"] for f in inj)
    assert "SQL/NoSQL" not in text and "NoSQL injection" not in text, text     # the claim; the disclaimer "no NoSQL payloads" is fine


# ---------------------------------------------------------------- B-M11: the PoC replays fresh_state seeds and follows local redirects

def _serve(routes):
    """routes(method, path, raw) -> (status, headers dict, text). A stdlib server on 127.0.0.1, ephemeral port."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _do(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            status, headers, text = routes(self.command, self.path, raw)
            data = text.encode()
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _run_poc(poc_path, base):
    return subprocess.run([sys.executable, poc_path, base], capture_output=True, text=True, timeout=120)


def test_b_m11_poc_replays_fresh_state_seed(tmp_path):
    items = {}

    def routes(method, path, raw):
        if method == "POST" and path == "/items":
            nid = len(items) + 1
            items[nid] = {}
            return 201, {}, json.dumps({"id": nid})
        m = re.fullmatch(r"/items/(\d+)", path)
        if method == "GET" and m:
            return (500, {}, "boom") if int(m.group(1)) in items else (404, {}, "{}")
        return 404, {}, "{}"

    srv, base = _serve(routes)
    try:
        steps = [{"idx": 0, "role": "user_a", "method": "GET", "path": "/items/1", "body": None, "query": None}]
        seed = lambda api: (api.call("user_a", "POST", "/items", {"n": 1}), {})[1]        # noqa: E731
        res = shrink.shrink_finding(steps, base, shrink.five_xx, reset=items.clear, roles=None, ctx_factory=seed,
                                    runs=3, max_trials=50, out_dir=str(tmp_path))
        assert res["repro"]["k"] == 3, res
        assert res["poc_path"], res
        items.clear()                                              # the PoC runs on fresh state and does not seed
        p = _run_poc(res["poc_path"], base)
        assert p.returncode == 1, f"PoC exit {p.returncode} (1 = bug reproduced expected): {p.stdout[-300:]} {p.stderr[-200:]}"
    finally:
        srv.shutdown()


def test_b_m11_poc_follows_local_redirect_like_the_replayer(tmp_path):
    def routes(method, path, raw):
        if path == "/go":
            return 302, {"Location": "/boom"}, ""
        if path == "/boom":
            return 500, {}, "boom"
        return 404, {}, "{}"

    srv, base = _serve(routes)
    try:
        steps = [{"idx": 0, "role": "user_a", "method": "GET", "path": "/go", "body": None, "query": None}]
        res = shrink.shrink_finding(steps, base, shrink.five_xx, runs=2, max_trials=20, out_dir=str(tmp_path))
        assert res["repro"]["k"] == 2 and res["poc_path"], res
        p = _run_poc(res["poc_path"], base)
        assert p.returncode == 1, f"PoC exit {p.returncode}: the replayer followed /go -> /boom (500); the PoC must too. {p.stdout[-200:]}"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- B-M12: a stateful finding keeps whole step lines

def test_b_m12_failure_sequence_keeps_whole_step_lines():
    tail = [f"user_a POST /orders -> 201 {{'qty': {i}, 'note': '{'x' * 150}'}}" for i in range(40)]
    tail.append("r_a GET /orders/1 -> 500 None")
    text = stateful.failure_sequence("note: falsifying example", tail)
    assert len(text) <= stateful.SEQUENCE_CAP + 200, len(text)
    step_lines = [ln for ln in text.splitlines() if re.match(r"^\S+ (GET|POST|PUT|PATCH|DELETE) ", ln)]
    assert step_lines, text[:200]
    assert all(ln.startswith(("user_a ", "r_a ")) for ln in step_lines), [ln[:30] for ln in step_lines[:3]]
    assert step_lines[-1].startswith("r_a GET /orders/1 -> 500"), "the failing step must be kept, with its role"
    parsed_steps, _ = shrink.parse_sequence_text(text)
    assert parsed_steps[-1]["role"] == "r_a", parsed_steps[-1]
