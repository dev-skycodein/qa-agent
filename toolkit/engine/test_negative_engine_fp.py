"""Tests for negative_engine.py's NEG-INJECTION oracle, against our own stdlib servers (ephemeral loopback ports).

  python toolkit/engine/test_negative_engine_fp.py        (also collectable by pytest)

Must be FOUND: a boolean-blind SQL login (TRUE answer 200, FALSE and benign 401), a login that answers 5xx only when the
payload has an unbalanced quote, and a login whose 5xx carries a database error text.
Must NOT be found: a safe (parameterised) login, a free-form text field (accepts any text, with or without echo), and an
exact-match lookup on a code the engine itself created (the trap that produced the old false positive).
"""
import json
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import negative_engine  # noqa: E402
from api import Api  # noqa: E402

STR = {"type": "string"}


def _body(props, required):
    return {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": props, "required": required}}}},
            "responses": {"200": {"description": "ok"}, "201": {"description": "ok"}}}


DOC = {"openapi": "3.0.0", "info": {"title": "neg", "version": "1"}, "paths": {
    "/auth/login": {"post": _body({"email": STR, "password": STR}, ["email", "password"])},
    "/notes": {"post": _body({"text": STR}, ["text"])},
    "/promo-codes": {"post": _body({"code": STR}, ["code"])},
    "/redeem": {"post": _body({"code": STR}, ["code"])},
}}
BODIES = {"POST /auth/login": {"email": "alice@x.test", "password": "pw"},
          "POST /notes": {"text": "hello"},
          "POST /promo-codes": {"code": "promo2"},
          "POST /redeem": {"code": "promo1"}}


def serve(login="safe", notes="free"):
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (email TEXT, password TEXT)")
    db.execute("INSERT INTO users VALUES ('alice@x.test', 'pw')")
    promos = {"promo1": True}
    lock = threading.Lock()
    counter = [0]

    def answer_login(body):
        email, pw = body.get("email"), body.get("password")
        if not isinstance(email, str) or not isinstance(pw, str):
            return 422, {"detail": "email and password are required"}
        if login == "safe":
            row = db.execute("SELECT email FROM users WHERE email = ? AND password = ?", (email, pw)).fetchone()
        elif login == "bool":                     # string-built SQL: a tautology after a comment logs in
            try:
                row = db.execute(f"SELECT email FROM users WHERE email = '{email}' AND password = '{pw}'").fetchone()
            except sqlite3.Error:
                row = None
        elif login == "err5xx":                   # an unbalanced quote breaks the server's SQL: a bare 5xx, no DB text
            if email.count("'") % 2:
                return 500, {"detail": "internal server error"}
            row = db.execute("SELECT email FROM users WHERE email = ? AND password = ?", (email, pw)).fetchone()
        elif login == "errtext":                  # same break, but the 5xx leaks the driver's error text
            if email.count("'") % 2:
                return 500, {"detail": "sqlite3.OperationalError: unrecognized token: \"'\""}
            row = db.execute("SELECT email FROM users WHERE email = ? AND password = ?", (email, pw)).fetchone()
        else:
            raise ValueError(login)
        if not row:
            return 401, {"detail": "bad credentials"}
        return 200, {"token": "tok-" + email.replace("'", "")}

    def answer(path, body):
        with lock:
            if path == "/auth/login":
                return answer_login(body)
            text_key = {"/notes": "text", "/promo-codes": "code", "/redeem": "code"}.get(path)
            if text_key is None:
                return 404, {"detail": "not found"}
            value = body.get(text_key)
            if not isinstance(value, str):
                return 422, {"detail": f"{text_key} must be a string"}
            if path == "/notes":
                counter[0] += 1
                return 201, ({"id": counter[0], "text": value} if notes == "echo" else {"id": counter[0]})
            if path == "/promo-codes":
                promos[value] = True          # exact-match store: the engine's own create is what the trap relies on
                return 201, {"code": value}
            return (201, {"ok": True}) if value in promos else (422, {"detail": "unknown code"})

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}
            status, payload = answer(self.path.rstrip("/"), body)
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def run_mock(login="safe", notes="free"):
    srv, base = serve(login, notes)
    try:
        res = negative_engine.run(Api(base), DOC, SimpleNamespace(BODIES=BODIES))
        assert res["requests"] > 0, "the engine must send real traffic"
        return res
    finally:
        srv.shutdown()
        srv.server_close()


def injections(res, endpoint=None):
    return [f for f in res["findings"] if f["kind"] == "NEG-INJECTION" and (endpoint is None or f["endpoint"] == endpoint)]


def test_boolean_blind_login_is_found_high():
    hits = injections(run_mock(login="bool"), "POST /auth/login")
    assert hits, "boolean-blind login must be found"
    assert any(h["severity"] == "high" and "boolean-blind" in h["detail"] for h in hits), [(h["severity"], h["detail"]) for h in hits]


def test_quote_5xx_login_is_found():
    hits = injections(run_mock(login="err5xx"), "POST /auth/login")
    assert hits, "a 5xx only on the payload must be a NEG-INJECTION candidate"
    assert all(h["severity"] == "medium" for h in hits), [(h["severity"], h["detail"]) for h in hits]
    assert any("5xx" in h["detail"] for h in hits)


def test_database_error_text_is_high():
    hits = injections(run_mock(login="errtext"), "POST /auth/login")
    assert any(h["severity"] == "high" and "database error" in h["detail"] for h in hits), [(h["severity"], h["detail"]) for h in hits]


def test_safe_login_has_no_injection():
    assert injections(run_mock(login="safe")) == [], "a parameterised login must not be flagged"


def test_free_form_text_is_not_injection_with_or_without_echo():
    for notes in ("free", "echo"):
        res = run_mock(login="safe", notes=notes)
        assert injections(res, "POST /notes") == [], f"free-form text ({notes}) must not be NEG-INJECTION"
        for f in res["findings"]:
            if f["kind"] == "NEG-ACCEPTED" and "SQL-shaped" in f["detail"]:
                assert f["severity"] == "low", f"acceptance-only must be low: {f}"


def test_exact_match_lookup_on_engine_created_code_is_not_injection():
    # the engine's own POST /promo-codes stores the payload; the lookup then matches it exactly (the old false positive)
    res = run_mock(login="safe")
    assert injections(res, "POST /redeem") == [], "an exact-match hit on a value we stored is not interpretation"


def test_tagged_payload_is_never_a_stored_value():
    a, b = negative_engine.tagged("' OR 1=1--"), negative_engine.tagged("' OR 1=1--")
    assert a != b and a.startswith("' OR 1=1--qa"), (a, b)
    assert negative_engine.false_of("' OR '1'='1' --") == "' AND '1'='2' --"
    assert negative_engine.false_of("plain text") is None


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
