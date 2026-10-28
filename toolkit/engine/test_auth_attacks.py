"""Tests for auth_attacks against a local stdlib auth server with one switch per bug.

Run only this file:  python toolkit/engine/test_auth_attacks.py      (or: python -m pytest toolkit/engine/test_auth_attacks.py)
Each buggy variant must produce its finding kind; the FIXED variant (all switches off) must produce zero findings.
The server and its JWT code are written independently of the engine (own base64 / hmac), so they cannot share a bug.
"""
import base64
import hashlib
import hmac
import json
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.stdout.reconfigure(encoding="utf-8") if hasattr(sys.stdout, "reconfigure") else None
import api as api_mod  # noqa: E402
import auth_attacks  # noqa: E402
import trust  # noqa: E402

PROTECTED_ROUTES = ("/api/profile", "/api/items")
DEFAULTS = dict(alg_none=False, nosig=False, no_sig_check=False, secret=None, no_exp=False, logout_revoke=True,
                rotate_session=True, verbose_login=False, refresh_single_use=True, reset_single_use=True,
                reset_predictable=False, xff=False, xfh=False, xourl=False, method_override=False, path_bypass=False,
                catchall=False, ttl=3600, trust_role_claim=False)

SPEC = {"openapi": "3.0.0", "paths": {
    "/": {"get": {"summary": "qa"}}, "/public": {"get": {"summary": "qa"}}, "/api/profile": {"get": {"summary": "qa"}},
    "/api/items": {"get": {"summary": "qa"}}, "/api/admin": {"get": {"summary": "qa"}},
    "/login": {"post": {"summary": "qa"}}, "/logout": {"post": {"summary": "qa"}}, "/refresh": {"post": {"summary": "qa"}},
    "/reset/request": {"post": {"summary": "qa"}}, "/reset/confirm": {"post": {"summary": "qa"}},
}}
# same API without any logout or refresh endpoint documented: those flows cannot be discovered
SPEC_NO_FLOWS = {"openapi": "3.0.0", "paths": {p: v for p, v in SPEC["paths"].items() if p not in ("/logout", "/refresh")}}


def _b64d(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _norm(raw):
    p = urllib.parse.unquote(raw).split(";")[0].lower()
    while "//" in p:
        p = p.replace("//", "/")
    p = p.replace("/./", "/")
    if p.endswith(".json"):
        p = p[:-5]
    return p.rstrip("/") or "/"


def _unverified(headers):
    """Payload of the Bearer token WITHOUT checking its signature (the defect under test)."""
    auth = headers.get("Authorization") or ""
    parts = auth[7:].split(".") if auth.startswith("Bearer ") else []
    try:
        data = json.loads(_b64d(parts[1])) if len(parts) == 3 else None
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _cookie(headers, name):
    for pair in (headers.get("Cookie") or "").split(";"):
        k, _, v = pair.strip().partition("=")
        if k == name:
            return v
    return None


class AuthServer:
    """Stdlib HTTP server. Flags in DEFAULTS; default = FIXED (every switch off, random HS256 secret)."""

    def __init__(self, **flags):
        self.cfg = {**DEFAULTS, **flags}
        if self.cfg["secret"] is None:
            self.cfg["secret"] = secrets.token_hex(32)
        self.lock = threading.Lock()
        self.users = {"alice@x": {"password": "pw123", "role": "user"}}
        self.revoked, self.sessions, self.refresh = set(), {}, {}
        self.reset_tokens, self.reset_counter = {}, 0
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(self))
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"

    def __enter__(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ----- token issuing / verifying (own implementation) -----
    def _issue(self, email):
        now = int(time.time())
        h = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
        p = _b64e(json.dumps({"sub": "1", "email": email, "role": "user", "iat": now, "exp": now + self.cfg["ttl"]},
                             separators=(",", ":")).encode())
        sig = _b64e(hmac.new(self.cfg["secret"].encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        return f"{h}.{p}.{sig}"

    def _verify(self, token):
        cfg = self.cfg
        if token in self.revoked:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            header = json.loads(_b64d(parts[0]))
            payload = json.loads(_b64d(parts[1]))
        except ValueError:
            return None
        alg = header.get("alg")
        if alg in ("none", "None", "NONE"):
            ok = cfg["alg_none"]
        elif cfg["no_sig_check"]:
            ok = True
        elif not parts[2]:
            ok = cfg["nosig"] and alg == "HS256"
        elif alg != "HS256":
            ok = False
        else:
            want = _b64e(hmac.new(cfg["secret"].encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest())
            ok = hmac.compare_digest(want, parts[2])
        if ok and not cfg["no_exp"] and payload.get("exp", 0) < time.time():
            ok = False
        return payload.get("email") if ok else None

    def _who(self, headers):
        cfg = self.cfg
        if cfg["xff"] and (headers.get("X-Forwarded-For") or "").startswith("127.0.0.1"):
            return "alice@x"
        if cfg["xfh"] and headers.get("X-Forwarded-Host") in ("localhost", "127.0.0.1"):
            return "alice@x"
        auth = headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            email = self._verify(auth[7:])
            if email:
                return email
        sid = _cookie(headers, "sid")
        if sid and self.sessions.get(sid):
            return self.sessions[sid]
        return None

    # ----- routes -----
    def route(self, method, raw, headers, body):
        """-> (status, payload str|dict|list, Set-Cookie value or None)"""
        cfg = self.cfg
        with self.lock:
            if method == "GET" and raw == "/":
                target = headers.get("X-Original-URL")
                if cfg["xourl"] and target in PROTECTED_ROUTES:
                    return self._serve(target, "alice@x")
                return 200, "home", None
            if method == "GET" and raw == "/public":
                sid = _cookie(headers, "sid")
                if sid and sid in self.sessions:
                    return 200, "public", None
                new = secrets.token_hex(16)
                self.sessions[new] = None
                return 200, "public", f"sid={new}; Path=/; HttpOnly"
            if method == "POST" and raw == "/login":
                return self._login(headers, body)
            if method == "POST" and raw == "/logout":
                email = self._who(headers)
                if email is None:
                    return 401, {"error": "login required"}, None
                if cfg["logout_revoke"]:
                    auth = headers.get("Authorization") or ""
                    if auth.startswith("Bearer "):
                        self.revoked.add(auth[7:])
                    self.sessions.pop(_cookie(headers, "sid"), None)
                return 200, {"ok": True}, None
            if method == "POST" and raw == "/refresh":
                return self._refresh(body)
            if method == "POST" and raw == "/reset/request":
                email = body.get("email")
                if email in self.users:
                    self.reset_counter += 1
                    tok = str(1000 + self.reset_counter) if cfg["reset_predictable"] else secrets.token_urlsafe(32)
                    self.reset_tokens[email] = tok
                return 200, {"ok": True}, None
            if method == "POST" and raw == "/reset/confirm":
                tok = body.get("token")
                for email, t in list(self.reset_tokens.items()):
                    if tok is not None and t == tok:
                        self.users[email]["password"] = body.get("password")
                        if cfg["reset_single_use"]:
                            self.reset_tokens.pop(email, None)
                        return 200, {"ok": True}, None
                return 400, {"error": "invalid or expired token"}, None
            if method == "GET" and raw == "/api/admin":       # admin area; its gate can trust the unsigned role claim
                if cfg["trust_role_claim"]:
                    claims = _unverified(headers)
                    if claims and claims.get("role") == "admin":
                        return 200, {"admin": True}, None
                email = self._who(headers)
                if email is None:
                    return 401, {"error": "login required"}, None
                if self.users[email]["role"] != "admin":
                    return 403, {"error": "admin only"}, None
                return 200, {"admin": True}, None
            route = _norm(raw) if cfg["path_bypass"] else raw
            if route in PROTECTED_ROUTES:
                if method == "GET":
                    if raw in PROTECTED_ROUTES:                    # the access gate looks at the raw string
                        email = self._who(headers)
                        if email is None:
                            return 401, {"error": "login required"}, None
                        return self._serve(route, email)
                    return self._serve(route, None)                # gate skipped: bypass
                if method == "POST" and cfg["method_override"] and headers.get("X-HTTP-Method-Override") == "GET":
                    return self._serve(route, None)
                return 405, {"error": "method not allowed"}, None
            if method == "GET" and cfg["catchall"]:
                return 200, "home", None
            return 404, {"error": "not found"}, None

    def _serve(self, route, email):
        if route == "/api/profile":
            return 200, {"email": email or "alice@x"}, None
        return 200, ["widget"], None

    def _login(self, headers, body):
        cfg = self.cfg
        email, pw = body.get("email"), body.get("password")
        if not cfg["verbose_login"]:
            time.sleep(0.02)                                       # fixed: same latency for every answer
        user = self.users.get(email)
        if user is None:
            msg = f"no such user {email}" if cfg["verbose_login"] else "invalid credentials"
            return 401, {"error": msg}, None
        if cfg["verbose_login"]:
            time.sleep(0.02)                                       # verbose build: the hash only runs for existing users
        if user["password"] != pw:
            msg = f"wrong password for {email}" if cfg["verbose_login"] else "invalid credentials"
            return 401, {"error": msg}, None
        token = self._issue(email)
        refresh = secrets.token_urlsafe(16)
        self.refresh[refresh] = email
        old = _cookie(headers, "sid")
        if cfg["rotate_session"]:
            self.sessions.pop(old, None)
            new = secrets.token_hex(16)
            self.sessions[new] = email
            return 200, {"token": token, "refresh_token": refresh}, f"sid={new}; Path=/; HttpOnly"
        if old:
            self.sessions[old] = email                             # buggy: the pre-login id now authenticates, not rotated
            return 200, {"token": token, "refresh_token": refresh}, None
        new = secrets.token_hex(16)
        self.sessions[new] = email
        return 200, {"token": token, "refresh_token": refresh}, f"sid={new}; Path=/; HttpOnly"

    def _refresh(self, body):
        tok = body.get("refresh_token")
        email = self.refresh.get(tok)
        if not email:
            return 401, {"error": "invalid refresh token"}, None
        if self.cfg["refresh_single_use"]:
            self.refresh.pop(tok, None)
            new = secrets.token_urlsafe(16)
            self.refresh[new] = email
            return 200, {"token": self._issue(email), "refresh_token": new}, None
        return 200, {"token": self._issue(email), "refresh_token": tok}, None


def _make_handler(srv):
    class Handler(BaseHTTPRequestHandler):
        def _go(self, method):
            raw = self.path.split("?", 1)[0]
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}
            status, payload, cookie = srv.route(method, raw, self.headers, body)
            if isinstance(payload, str):
                data, ctype = payload.encode(), "text/plain; charset=utf-8"
            else:
                data, ctype = json.dumps(payload).encode(), "application/json"
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

        def log_message(self, *args):
            pass

    return Handler


# ---------- harness ----------

def make_qa(srv, **overrides):
    qa = SimpleNamespace(
        PUBLIC={"GET /", "GET /public"},
        LOGIN={"path": "/login", "user_key": "email", "pass_key": "password", "user": "alice@x", "password": "pw123",
               "token_key": "token", "refresh_key": "refresh_token"},
        LOGOUT={"path": "/logout", "method": "POST"},
        REFRESH={"path": "/refresh", "body_key": "refresh_token"},
        RESET={"request": lambda api: api.call("anon", "POST", "/reset/request", {"email": "alice@x"}),
               "get_token": lambda api: srv.reset_tokens.get("alice@x"),
               "use": lambda api, t: api.call("anon", "POST", "/reset/confirm", {"token": t, "password": "pw123"})},
        ENUM_SAMPLES=10,
    )
    for k, v in overrides.items():
        setattr(qa, k, v)
    return qa


def make_api(srv, cred="bearer"):
    """bearer: role user_a = JWT from /login. cookie: the anonymous sid is logged in, and the role carries the id the
    server hands back after login (a rotated id if the server rotates, the same id if it does not)."""
    api = api_mod.Api(srv.base)
    if cred == "bearer":
        body = api.call("anon", "POST", "/login", {"email": "alice@x", "password": "pw123"}).json
        api.roles["user_a"] = {"Authorization": f"Bearer {body['token']}"}
    else:
        sid = _cookie_value(api.call("anon", "GET", "/public"))
        resp = api.call("anon", "POST", "/login", {"email": "alice@x", "password": "pw123"}, None, None,
                        {"Cookie": f"sid={sid}"})
        api.roles["user_a"] = {"Cookie": f"sid={_cookie_value(resp) or sid}"}
    return api


def _cookie_value(resp):
    """Value of the sid Set-Cookie in a response, or None."""
    for name, value in resp.headers.items():
        if name.lower() == "set-cookie":
            return value.split(";", 1)[0].split("=", 1)[1]
    return None


def run_engine(srv, qa=None, cred="bearer", spec=SPEC):
    api = make_api(srv, cred)
    return auth_attacks.run(api, spec, qa or make_qa(srv))


def kinds(result):
    return sorted({f["kind"] for f in result["findings"]})


def check_buggy(name, expected, result, extra_check=None):
    got = kinds(result)
    for k in expected:
        assert k in got, f"[{name}] expected {k}, got {got}; notes={result.get('notes')} blocked={result.get('not_testable')}"
    if extra_check:
        extra_check(result)


# ---------- tests ----------

def test_fixed_server_zero_findings():
    with AuthServer() as srv:
        res = run_engine(srv)
        assert res["findings"] == [], f"fixed server must have no findings, got {kinds(res)}: {res['findings']}"
        assert res["engine"] == "auth"
        assert res["probes"] > 0
        # the only thing a fixed server cannot give us is an expired token (no signing key, strong secret): honest DEGRADED
        assert res["status"] == trust.DEGRADED, res["status"]
        assert "AUTH-JWT-EXPIRED" in res["status_reason"], res["status_reason"]


def test_alg_none_detected():
    with AuthServer(alg_none=True) as srv:
        check_buggy("alg_none", ["AUTH-JWT-ALG-NONE"], run_engine(srv))


def test_nosig_detected():
    with AuthServer(nosig=True) as srv:
        check_buggy("nosig", ["AUTH-JWT-NOSIG"], run_engine(srv))


def test_tamper_detected_when_signature_not_verified():
    with AuthServer(no_sig_check=True) as srv:
        check_buggy("no_sig_check", ["AUTH-JWT-TAMPER"], run_engine(srv))


def test_weak_secret_detected_without_printing_secret():
    with AuthServer(secret="secret") as srv:
        res = run_engine(srv)
        check_buggy("weak", ["AUTH-JWT-WEAK-SECRET"], res)
        for f in res["findings"]:
            text = json.dumps(f)
            assert '"secret"' not in text and "'secret'" not in text, "the recovered secret value must not be printed"
            assert "Bearer " not in text, "no forged token may appear in a finding"


def test_expired_detected_when_key_recovered():
    with AuthServer(secret="secret", no_exp=True) as srv:
        check_buggy("no_exp", ["AUTH-JWT-WEAK-SECRET", "AUTH-JWT-EXPIRED"], run_engine(srv))


def test_expired_not_testable_without_key():
    with AuthServer() as srv:
        res = run_engine(srv)
        assert any(b["check"] == "AUTH-JWT-EXPIRED" for b in res["not_testable"]), res["not_testable"]


def test_logout_token_reuse_detected():
    with AuthServer(logout_revoke=False) as srv:
        check_buggy("logout", ["AUTH-TOKEN-AFTER-LOGOUT"], run_engine(srv))


def test_session_fixation_detected():
    with AuthServer(rotate_session=False) as srv:
        res = run_engine(srv, cred="cookie")
        check_buggy("fixation", ["AUTH-SESSION-FIXATION"], res)


def test_enumeration_detected_by_message():
    with AuthServer(verbose_login=True) as srv:
        check_buggy("enum", ["AUTH-ENUM"], run_engine(srv))


def test_refresh_reuse_detected():
    with AuthServer(refresh_single_use=False) as srv:
        check_buggy("refresh", ["AUTH-REFRESH-REUSE"], run_engine(srv))


def test_reset_token_reuse_detected():
    with AuthServer(reset_single_use=False) as srv:
        check_buggy("reset_reuse", ["AUTH-RESET-REUSE"], run_engine(srv))


def test_reset_token_predictable_detected():
    with AuthServer(reset_predictable=True) as srv:
        check_buggy("reset_predictable", ["AUTH-RESET-REUSE"], run_engine(srv))


def test_header_bypass_each_variant_detected():
    with AuthServer(xff=True, xfh=True, xourl=True, method_override=True) as srv:
        res = run_engine(srv)
        check_buggy("headers", ["AUTH-HEADER-BYPASS"], res)
        details = " ".join(f["detail"] for f in res["findings"])
        for header in ("X-Forwarded-For", "X-Forwarded-Host", "X-Original-URL", "X-HTTP-Method-Override"):
            assert header in details, f"{header} bypass not reported: {details}"


def test_path_bypass_detected():
    with AuthServer(path_bypass=True) as srv:
        check_buggy("path", ["AUTH-PATH-BYPASS"], run_engine(srv))


def test_catch_all_spa_gives_no_bypass_findings():
    with AuthServer(catchall=True) as srv:
        res = run_engine(srv)
        assert res["findings"] == [], f"SPA catch-all must not look like a bypass: {res['findings']}"


def test_public_endpoint_never_reported():
    with AuthServer() as srv:
        qa = make_qa(srv, PROTECTED={"GET /api/profile", "GET /public"}, PUBLIC={"GET /", "GET /public"})
        res = run_engine(srv, qa)
        assert not [f for f in res["findings"] if f["endpoint"].endswith("/public")], res["findings"]
        assert res["findings"] == [], res["findings"]


def test_no_auth_is_skipped_not_clean():
    with AuthServer(xff=True) as srv:
        api = api_mod.Api(srv.base)                       # no roles, and no qa.LOGIN to log in with
        res = auth_attacks.run(api, SPEC, SimpleNamespace(PUBLIC={"GET /"}))
        assert res["status"] == trust.SKIPPED, res["status"]
        assert res["findings"] == []


def test_missing_knobs_degrade_with_reasons():
    with AuthServer() as srv:
        qa = SimpleNamespace(PUBLIC={"GET /"})
        res = run_engine(srv, qa, spec=SPEC_NO_FLOWS)      # no logout/refresh documented: they cannot be discovered
        assert res["status"] == trust.DEGRADED
        checks = {b["check"] for b in res["not_testable"]}
        assert "AUTH-TOKEN-AFTER-LOGOUT" in checks and "AUTH-REFRESH-REUSE" in checks and "AUTH-RESET-REUSE" in checks, checks
        assert res["findings"] == [], res["findings"]


def test_opaque_cookie_session_not_jwt():
    with AuthServer() as srv:
        res = run_engine(srv, cred="cookie")
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])   # JWT checks are N/A, every flow knob is set
        assert not [f for f in res["findings"] if f["kind"].startswith("AUTH-JWT")], res["findings"]
        assert any("not a JWT" in n for n in res["notes"]), res["notes"]


def test_engine_talks_only_through_api():
    """Static check: the engine module must not import any network library (all traffic goes through api.Api, which is local-only)."""
    source = (Path(__file__).resolve().parent / "auth_attacks.py").read_text(encoding="utf-8")
    for banned in ("import urllib", "from urllib", "import socket", "import http.client", "from http", "import requests", "import subprocess"):
        assert banned not in source, f"auth_attacks.py must not contain {banned!r}"
    try:
        api_mod.Api("http://example.com")
    except SystemExit:
        return
    raise AssertionError("api.Api must refuse a non-local base URL")


def test_claim_trust_detected_on_route_that_denies_role():
    """Admin route trusts the unsigned role claim; the role's own token is DENIED there (the control), and the edited
    claims with the original signature are accepted. Only that route is affected."""
    with AuthServer(trust_role_claim=True) as srv:
        res = run_engine(srv)
        check_buggy("claim_trust", ["AUTH-JWT-TAMPER"], res)
        tamper = [f for f in res["findings"] if f["kind"] == "AUTH-JWT-TAMPER"]
        assert tamper and all(f["endpoint"] == "GET /api/admin" for f in tamper), tamper
        assert "DENIES this role" in tamper[0]["detail"], tamper[0]["detail"]
        assert "the role's own token gets 403" in tamper[0]["control"], tamper[0]["control"]


def test_flows_discovered_without_qa_knobs():
    """No LOGIN/LOGOUT/REFRESH in qa-spec: login comes from api.log, logout and refresh from the OpenAPI document."""
    with AuthServer(logout_revoke=False, refresh_single_use=False, verbose_login=True) as srv:
        qa = make_qa(srv, LOGIN=None, LOGOUT=None, REFRESH=None)
        res = run_engine(srv, qa)
        check_buggy("discovered", ["AUTH-TOKEN-AFTER-LOGOUT", "AUTH-REFRESH-REUSE", "AUTH-ENUM"], res)
        notes = " ".join(res["notes"])
        for word in ("LOGIN discovered from api.log", "LOGOUT discovered", "REFRESH discovered"):
            assert word in notes, notes
        assert "pw123" not in json.dumps(res, default=str), "a discovered password must never be printed"


def test_expiry_checked_by_waiting_without_key():
    """No weak secret: the engine mints a short-lived token, waits out its exp and replays it. The server ignores exp."""
    with AuthServer(ttl=2, no_exp=True) as srv:
        res = run_engine(srv)
        check_buggy("waited_expiry", ["AUTH-JWT-EXPIRED"], res)
        assert not [f for f in res["findings"] if f["kind"] == "AUTH-JWT-WEAK-SECRET"], "the server uses a random secret"


def test_expiry_honoured_when_waited_out():
    with AuthServer(ttl=2) as srv:
        res = run_engine(srv)
        assert res["findings"] == [], res["findings"]
        assert not [b for b in res["not_testable"] if b["check"] == "AUTH-JWT-EXPIRED"], res["not_testable"]
        assert any("waiting out" in n for n in res["notes"]), res["notes"]
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])


def test_expired_baseline_token_is_reauthenticated():
    with AuthServer(ttl=1) as srv:
        api = make_api(srv)
        time.sleep(1.2)                       # the spec-setup token has expired by now
        res = auth_attacks.run(api, SPEC, make_qa(srv))
        assert res["findings"] == [], res["findings"]
        assert any("re-authenticated" in n for n in res["notes"]), res["notes"]


def test_baseline_routes_come_first_under_endpoint_cap():
    """With a cap of one route, the route that accepts the role's token is chosen over the admin route that denies it."""
    with AuthServer(alg_none=True) as srv:
        res = run_engine(srv, make_qa(srv, AUTH_MAX_ENDPOINTS=1))
        check_buggy("cap_order", ["AUTH-JWT-ALG-NONE"], res)


ALL_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

# ---------- role-level path bypass through percent-encoding (gate matches the raw path, router decodes) ----------

import urllib.parse as _up  # noqa: E402
from http.server import BaseHTTPRequestHandler as _H, ThreadingHTTPServer as _S  # noqa: E402
import threading as _th  # noqa: E402


def _gate_server(decode_before_gate):
    class H(_H):
        def log_message(self, *a):
            pass

        def do_GET(self):
            who = {"Bearer admin-t": "admin", "Bearer user-t": "user"}.get(self.headers.get("Authorization", ""))
            raw = self.path.split("?")[0]
            gate_path = _up.unquote(raw) if decode_before_gate else raw          # the bug: gate looks at the raw path
            route = _up.unquote(raw)
            if who is None:
                code, body = 401, b'{"error":"auth"}'
            elif route == "/admin/users":
                ok = who == "admin" or (not gate_path.startswith("/admin"))
                code, body = (200, b'{"users":["a","b"]}') if ok else (403, b'{"error":"forbidden"}')
            elif route == "/me":
                code, body = 200, b'{"me":"x"}'
            else:
                code, body = 404, b'{"error":"nf"}'
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = _S(("127.0.0.1", 0), H)
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_gate(decode_before_gate):
    srv = _gate_server(decode_before_gate)
    try:
        doc = {"paths": {"/admin/users": {"get": {"security": [{"b": []}]}}, "/me": {"get": {"security": [{"b": []}]}}}}
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}",
                          {"admin": {"Authorization": "Bearer admin-t"}, "user_a": {"Authorization": "Bearer user-t"}})
        return auth_attacks.run(api, doc, SimpleNamespace(PROTECTED={"GET /admin/users"}))
    finally:
        srv.shutdown()


def test_percent_encoded_path_bypass_by_a_plain_role_is_found():
    r = _run_gate(decode_before_gate=False)
    hits = [f for f in r["findings"] if f["kind"] == "AUTH-PATH-BYPASS"]
    assert hits and any("user_a" in f["detail"] for f in hits), r["findings"]


def test_gate_that_decodes_first_has_no_path_bypass():
    r = _run_gate(decode_before_gate=True)
    assert [f for f in r["findings"] if f["kind"] == "AUTH-PATH-BYPASS"] == [], r["findings"]


# ---------- login discovery from the OpenAPI document and qa-spec.py when api.log never saw the login ----------

def test_spec_credentials_are_read_from_dicts_with_tuples_or_dicts_for_known_roles_only():
    qa = SimpleNamespace(USERS={"user_a": ("a@x.test", "pw1"), "ghost": ("g@x.test", "pw9")},
                         ACCOUNTS={"admin": {"email": "r@x.test", "password": "pw2"}}, HEADERS={"user_a": ("x",)}, _private={"user_a": ("p", "q")})
    got = auth_attacks.spec_credentials(qa, {"anon": {}, "user_a": {}, "admin": {}})
    assert got == {"user_a": ("a@x.test", "pw1"), "admin": ("r@x.test", "pw2")}, got


def test_login_is_discovered_from_openapi_and_spec_credentials_when_the_log_is_empty():
    class FakeApi:
        roles = {"anon": {}, "user_a": {"Authorization": "Bearer t-user"}}
        log = []

        def call(self, role, method, path, body=None, *a, **k):
            if path == "/login" and body == {"email": "a@x.test", "password": "pw1"}:
                return api_mod.Resp(200, json.dumps({"access_token": "tok-123", "refresh_token": "ref-456"}))
            return api_mod.Resp(401, "{}")
    doc = {"paths": {"/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}}}},
        "/password/forgot": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}}}}}}
    ctx = SimpleNamespace(api=FakeApi(), doc=doc, qa=SimpleNamespace(USERS={"user_a": ("a@x.test", "pw1")}))
    login, why = auth_attacks.discover_login_from_spec(ctx, {"role": "user_a", "kind": "bearer", "value": "t-user"})
    assert why is None and login["path"] == "/login" and login["token_key"] == "access_token" and login["refresh_key"] == "refresh_token", (login, why)
    ctx.qa = SimpleNamespace(USERS={})
    assert auth_attacks.discover_login_from_spec(ctx, {"role": "user_a", "kind": "bearer", "value": "t-user"})[0] is None


def test_jwt_lifetime_decides_how_serious_a_surviving_session_is():
    def tok(exp):
        seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        return "Bearer " + ".".join([seg({"alg": "HS256"}), seg({"sub": 1, **({"exp": exp} if exp is not None else {})}), "sig"])
    assert 80 < auth_attacks._jwt_seconds_left(tok(time.time() + 100)) <= 100
    assert auth_attacks._jwt_seconds_left(tok(time.time() + 10 * 24 * 3600)) > auth_attacks.STATELESS_LONG
    assert auth_attacks._jwt_seconds_left(tok(None)) is None                 # no exp: unknown lifetime, treated as not short-lived
    assert auth_attacks._jwt_seconds_left("Bearer opaque-session-id") is None
    assert auth_attacks._jwt_seconds_left("not a header") is None


# ---------- session fixation with a cookie the CLIENT chose (no cookie is issued before login) ----------

def _cookie_server(adopt):
    sessions = set()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj, cookie=None):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if cookie:
                self.send_header("Set-Cookie", f"sid={cookie}; Path=/; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path != "/login" or body.get("password") != "pw":
                return self._send(401, {"error": "bad credentials"})
            client = dict(c.strip().partition("=")[::2] for c in self.headers.get("Cookie", "").split(";") if c.strip()).get("sid")
            sid = client if (adopt and client) else secrets.token_hex(8)
            sessions.add(sid)
            return self._send(200, {"access_token": "tok-static"}, cookie=sid)

        def do_GET(self):
            cookies = dict(c.strip().partition("=")[::2] for c in self.headers.get("Cookie", "").split(";") if c.strip())
            if self.headers.get("Authorization") == "Bearer tok-static" or cookies.get("sid") in sessions:
                return self._send(200, {"me": "alice"})
            return self._send(401, {"error": "auth"})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_cookie(adopt):
    srv = _cookie_server(adopt)
    try:
        doc = {"paths": {"/login": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}}}}}},
            "/me": {"get": {"security": [{"b": []}]}}}}
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {"Authorization": "Bearer tok-static"}})
        return auth_attacks.run(api, doc, SimpleNamespace(USERS={"user_a": ("a@x.test", "pw")}, PROTECTED={"GET /me"}))
    finally:
        srv.shutdown()


def test_client_chosen_session_cookie_adopted_by_login_is_session_fixation():
    res = _run_cookie(adopt=True)
    hits = [f for f in res["findings"] if f["kind"] == "AUTH-SESSION-FIXATION"]
    assert hits and hits[0]["severity"] == "high", (res["findings"], res["notes"])


def test_login_that_issues_its_own_session_id_has_no_fixation_finding():
    res = _run_cookie(adopt=False)
    assert [f for f in res["findings"] if f["kind"] == "AUTH-SESSION-FIXATION"] == [], res["findings"]


# ---------- user enumeration through the forgot-password endpoint ----------

def _forgot_server(leaky):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            known = body.get("email") == "a@x.test"
            if self.path == "/login":
                code, obj = (200, {"access_token": "tok-static"}) if body.get("password") == "pw" else (401, {"error": "bad credentials"})
            elif self.path == "/password/forgot":
                code, obj = (202, {"status": "if the address exists a mail was sent"}) if (known or not leaky) else (404, {"error": "no such user"})
            else:
                code, obj = 404, {"error": "nf"}
            out = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def do_GET(self):
            code = 200 if self.headers.get("Authorization") == "Bearer tok-static" else 401
            out = b"{}"
            self.send_response(code)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_forgot(leaky):
    srv = _forgot_server(leaky)
    try:
        body = lambda *props: {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {p: {"type": "string"} for p in props}}}}}}
        doc = {"paths": {"/login": {"post": body("email", "password")}, "/password/forgot": {"post": body("email")},
                         "/me": {"get": {"security": [{"b": []}]}}}}
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {"Authorization": "Bearer tok-static"}})
        return auth_attacks.run(api, doc, SimpleNamespace(USERS={"user_a": ("a@x.test", "pw")}, PROTECTED={"GET /me"}))
    finally:
        srv.shutdown()


def test_forgot_password_that_answers_unknown_addresses_differently_is_enumeration():
    res = _run_forgot(leaky=True)
    hits = [f for f in res["findings"] if f["kind"] == "AUTH-ENUM" and "forgot" in f["endpoint"]]
    assert hits and hits[0]["severity"] == "medium", (res["findings"], res["notes"])


def test_forgot_password_with_one_uniform_answer_is_clean():
    res = _run_forgot(leaky=False)
    assert [f for f in res["findings"] if f["kind"] == "AUTH-ENUM" and "forgot" in f["endpoint"]] == [], res["findings"]


if __name__ == "__main__":
    passed, failed = 0, []
    for fn in ALL_TESTS:
        started = time.time()
        try:
            fn()
            passed += 1
            print(f"PASS {fn.__name__} ({time.time() - started:.1f}s)", flush=True)
        except AssertionError as exc:
            failed.append(fn.__name__)
            print(f"FAIL {fn.__name__}: {exc}", flush=True)
        except Exception as exc:  # a crash in a test is a failure, not a skip
            failed.append(fn.__name__)
            print(f"ERROR {fn.__name__}: {type(exc).__name__}: {exc}", flush=True)
    print(f"\n{passed} passed, {len(failed)} failed of {len(ALL_TESTS)}")
    sys.exit(1 if failed else 0)
