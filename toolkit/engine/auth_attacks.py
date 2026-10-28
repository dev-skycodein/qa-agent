"""Multi-step authentication and session attack engine. Defensive, LOCAL targets only: it talks only through api.Api.

DESIGN CANDIDATES (tree of thoughts)
  A. Token-type modules: one module per token family (JWT, opaque session cookie, reset token).
     + precise oracles, the token format is known. - three code paths; opaque tokens fall through unchecked.
  B. Generic credential mutation: take the role's credential, mutate it (strip the signature, change alg,
     flip bytes) and record what is accepted. + zero config, any token shape.
     - "rejected" proves little for opaque tokens; most mutations only mean something for JWT; large FP surface.
  C. Spec-driven flows: LOGIN / LOGOUT / REFRESH / RESET declare the flow and the engine runs fixed scripts over it.
     + the multi-step checks (logout, refresh reuse, reset reuse, fixation) cannot be inferred from OpenAPI.
     - needs the flow to be declared or discoverable; otherwise the check is NOT TESTABLE (degraded, never clean).

CHOSEN: A for the JWT checks (they run only when the credential parses as a JWT), C for the multi-step flows, and
stateless header/path bypass checks that need only the anonymous control.

Flow discovery (C without a hand-written qa.LOGIN/LOGOUT/REFRESH):
  LOGIN    the most recent 2xx POST in api.log whose JSON response carries the role's exact token and whose JSON request
           carries a user-like and a password-like field (the spec's own setup login). Credentials are read from memory,
           never printed; only the field names and the path go into notes.
  LOGOUT   POST operation in the OpenAPI document whose path says logout/signout/logoff.
  REFRESH  POST operation whose path says refresh or whose body has a refresh-like property.

Every finding needs a CONTROL and an ACCEPTED ATTACK request (2xx). The control is either the role's own token accepted
on that route, or the role's own token DENIED (401/403) on that route (privilege claims are then the only thing that
differs). Probes are GET except where a flow is declared or discovered (login, logout, refresh, reset) or the
method-override check (only when the spec has no POST on that path). Token values are redacted to 12 characters.

Knobs (qa-spec.py, all optional; a missing knob that cannot be discovered makes its check NOT TESTABLE, which degrades):
  PROTECTED   {"GET /api/profile"}  candidate protected paths (default: GET endpoints without path params)
  PUBLIC      {"GET /"}             never attacked, never reported as a bypass
  LOGIN       {"path", "user_key", "pass_key", "user", "password", "token_key", "refresh_key", "extra"}   (or discovered)
  LOGOUT      {"path", "method"}    ends the session of a LOGIN session                                  (or discovered)
  REFRESH     {"path", "body_key"}  refresh endpoint (needs LOGIN giving a refresh token)                 (or discovered)
  RESET       {"request": fn(api), "get_token": fn(api) -> str, "use": fn(api, token) -> Resp}
  ENUM_SAMPLES (default 10) timing samples per side; AUTH_MAX_ENDPOINTS (default 8) protected endpoints attacked
  AUTH_EXPIRY_MAX_WAIT (default 60) longest token lifetime the engine waits out to test expiry
"""
import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import statistics
import time

from api import TRANSPORT_ERROR, Resp, endpoints
import trust

ALG_NONE = ("none", "None", "NONE")
DENIED = (401, 403)
RATE_LIMITED = (423, 429)
MAX_ENDPOINTS_DEFAULT = 8
EXPIRY_MAX_WAIT_S = 60.0   # longest token lifetime the engine waits out (qa.AUTH_EXPIRY_MAX_WAIT overrides)
EXPIRY_MARGIN_S = 1.5      # wait this long past exp, so second rounding or clock jitter cannot be blamed on the server
RENEW_MARGIN_S = 3.0       # a baseline token expiring within this many seconds is re-authenticated first
ENUM_MIN_N = 8           # below this many samples per side the timing test is not run (NOT TESTABLE)
ENUM_T = 4.0             # Welch t threshold for the timing finding
ENUM_MIN_MS = 5.0        # and the median gap must be at least this many ms (local timing jitter is a few ms)
LOW_ENTROPY_BITS = 64    # an upper bound on guessing work below this is treated as predictable
USER_KEY_RE = re.compile(r"e-?mail|user|login|identifier|handle", re.I)
PASS_KEY_RE = re.compile(r"pass|pwd|secret", re.I)
PASS_KEY_PREF_RE = re.compile(r"pass|pwd", re.I)
REFRESH_KEY_RE = re.compile(r"refresh", re.I)
LOGOUT_RE = re.compile(r"log-?out|sign-?out|log-?off|end[-_]?session", re.I)
# Small built-in wordlist of HS256 secrets people actually ship. Checked offline with hmac; the secret is never printed.
WORDLIST = ("secret", "password", "changeme", "123456", "jwt_secret", "your-256-bit-secret", "supersecret", "secretkey",
            "key", "test", "default", "mysecret", "qwerty", "letmein", "admin", "dev", "development", "private",
            "password123", "12345678")


def red(value) -> str:
    text = str(value)
    return f"{text[:12]}...({len(text)} chars)"


def _short(text: str, n: int = 120) -> str:
    return text[:n].replace("\n", " ")


def _json(text):
    try:
        return json.loads(text) if isinstance(text, str) and text else None
    except ValueError:
        return None


# ---------- JWT helpers ----------

def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _enc(obj) -> str:
    return _b64e(json.dumps(obj, separators=(",", ":")).encode())


def parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header, payload = json.loads(_b64d(parts[0])), json.loads(_b64d(parts[1]))
    except (ValueError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return {"header": header, "payload": payload, "h": parts[0], "p": parts[1], "sig": parts[2],
            "signing": parts[0] + "." + parts[1]}


def _exp_of(token: str):
    """The exp claim of a JWT as a float, or None (not a JWT, or no numeric exp)."""
    jwt = parse_jwt(token) if isinstance(token, str) else None
    exp = jwt["payload"].get("exp") if jwt else None
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _tampered(payload: dict) -> dict:
    """The claims an attacker wants: another subject and admin rights."""
    tampered = dict(payload)
    if "sub" in tampered:
        v = tampered["sub"]
        tampered["sub"] = v + 1 if isinstance(v, int) else (str(int(v) + 1) if str(v).isdigit() else f"{v}-qa")
    tampered.update({"role": "admin", "admin": True, "is_admin": True})
    return tampered


def _payload_seg(jwt, payload) -> str:
    return jwt["p"] if payload == jwt["payload"] else _enc(payload)


def hs256(secret: str, signing: str) -> str:
    return _b64e(hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest())


def sign_token(header: dict, payload: dict, secret: str) -> str:
    signing = _enc(header) + "." + _enc(payload)
    return f"{signing}.{hs256(secret, signing)}"


def entropy_bits(token: str) -> float:
    """Upper bound on guessing work: length x log2(charset size of the token's character class). Not a measured entropy."""
    if token.isdigit():
        alpha = 10
    elif re.fullmatch(r"[0-9a-fA-F]+", token):
        alpha = 16
    elif re.fullmatch(r"[A-Za-z0-9]+", token):
        alpha = 62
    else:
        alpha = 64
    return len(token) * math.log2(alpha)


def welch(a, b):
    """Welch's t for two timing samples. None when either side has fewer than ENUM_MIN_N samples."""
    if len(a) < ENUM_MIN_N or len(b) < ENUM_MIN_N:
        return None
    diff = statistics.fmean(a) - statistics.fmean(b)
    se = math.sqrt(statistics.variance(a) / len(a) + statistics.variance(b) / len(b))
    t = diff / se if se > 0 else (math.copysign(math.inf, diff) if diff else 0.0)
    return {"t": t, "diff_ms": diff, "median_a": statistics.median(a), "median_b": statistics.median(b)}


# ---------- HTTP helpers ----------

def _hget(headers: dict, name: str):
    low = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == low:
            return v
    return None


def find_credentials(api):
    """Every role's Bearer or Cookie credential (one per role), user_a first. Basic/other schemes are not handled."""
    out = []
    for role in sorted((r for r in api.roles if r != "anon"), key=lambda r: r != "user_a"):
        hdrs = api.roles[role] or {}
        scheme, _, value = (_hget(hdrs, "Authorization") or "").partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            out.append({"kind": "bearer", "role": role, "value": value.strip()})
            continue
        for pair in (_hget(hdrs, "Cookie") or "").split(";"):
            name, eq, val = pair.strip().partition("=")
            if eq and name and val:
                out.append({"kind": "cookie", "role": role, "name": name, "value": val})
                break
    return out


def find_credential(api):
    creds = find_credentials(api)
    return creds[0] if creds else None


def cred_headers(cred, value):
    if cred["kind"] == "bearer":
        return {"Authorization": f"Bearer {value}"}
    return {"Cookie": f"{cred['name']}={value}"}


def _set_cookie(resp):
    raw = _hget(resp.headers or {}, "Set-Cookie")
    if not raw:
        return None
    name, eq, val = raw.split(";", 1)[0].strip().partition("=")
    return (name, val) if eq and name else None


def _dig(data, dotted):
    """Value at a dotted key path ('data.token') of a JSON object, or None."""
    node = data
    for part in str(dotted).split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _find_value(data, value, prefix=""):
    """Dotted key path of the first (top-level or nested) key whose value equals `value`."""
    if isinstance(data, dict):
        for k, v in data.items():
            if v == value:
                return prefix + k
            if isinstance(v, dict):
                found = _find_value(v, value, prefix + k + ".")
                if found:
                    return found
    return None


def _find_str_key(data, rx, prefix=""):
    """Dotted path of the first non-empty string value whose key matches `rx`."""
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and v and rx.search(k):
                return prefix + k
            if isinstance(v, dict):
                found = _find_str_key(v, rx, prefix + k + ".")
                if found:
                    return found
    return None


def _session(resp, spec):
    """(headers of the new session or None, refresh token or None): JSON token first, then a Set-Cookie session."""
    data = resp.json if isinstance(resp.json, dict) else {}
    token = _dig(data, spec.get("token_key", "token"))
    refresh = _dig(data, spec.get("refresh_key", "refresh_token"))
    refresh = refresh if isinstance(refresh, str) and refresh else None
    if isinstance(token, str) and token:
        return {"Authorization": f"Bearer {token}"}, refresh
    cookie = _set_cookie(resp)
    if cookie:
        return {"Cookie": f"{cookie[0]}={cookie[1]}"}, refresh
    return None, refresh


def _cred_from_headers(headers, role):
    if "Authorization" in headers:
        return {"kind": "bearer", "role": role, "value": headers["Authorization"][len("Bearer "):]}
    name, _, value = headers["Cookie"].partition("=")
    return {"kind": "cookie", "role": role, "name": name, "value": value}


# ---------- flow discovery ----------

def discover_login(api, token):
    """The login that issued `token`, read from api.log: the most recent 2xx POST whose JSON response carries the token
    and whose JSON request carries a user-like and a password-like string field. Returns (login dict, None) or
    (None, reason). The user and password values stay in memory; notes only name the fields and the path."""
    reason = "no POST in api.log returned this token"
    for entry in reversed(api.log):
        if entry.get("method") != "POST" or not 200 <= (entry.get("status") or 0) < 300:
            continue
        req = entry.get("request")
        data = _json(entry.get("body"))
        tkey = _find_value(data, token) if isinstance(data, dict) else None
        if not tkey or not isinstance(req, dict):
            continue
        user_key = next((k for k, v in req.items() if isinstance(v, str) and USER_KEY_RE.search(k)), None)
        pass_key = max((k for k, v in req.items() if isinstance(v, str) and PASS_KEY_RE.search(k)),
                       key=lambda k: bool(PASS_KEY_PREF_RE.search(k)), default=None)
        if not user_key or not pass_key:
            reason = f"POST {entry['path']} issued the token but its request has no user and password field"
            continue
        return {"path": entry["path"], "user_key": user_key, "pass_key": pass_key, "user": req[user_key],
                "password": req[pass_key], "token_key": tkey,
                "refresh_key": _find_str_key(data, REFRESH_KEY_RE) or "refresh_token",
                "extra": {k: v for k, v in req.items() if k not in (user_key, pass_key)}}, None
    return None, reason


NOT_LOGIN_RE = re.compile(r"forgot|reset|regist|sign-?up|change|confirm|verify|recover|invite|logout|sign-?out", re.I)


def spec_credentials(qa, roles):
    """{role: (user, password)} read from module-level dicts of qa-spec.py: USERS = {"user_a": ("a@x.test", "pw")} or
    {"user_a": {"email": ..., "password": ...}}. Only roles the engine really has are kept."""
    out = {}
    for name in dir(qa):
        v = getattr(qa, name, None)
        if name.startswith("_") or not isinstance(v, dict):
            continue
        for role, val in v.items():
            if role not in roles:
                continue
            if isinstance(val, (tuple, list)) and len(val) >= 2 and all(isinstance(x, str) for x in val[:2]):
                out.setdefault(role, (val[0], val[1]))
            elif isinstance(val, dict):
                u = next((x for k, x in val.items() if isinstance(x, str) and USER_KEY_RE.search(k)), None)
                p = next((x for k, x in val.items() if isinstance(x, str) and PASS_KEY_RE.search(k)), None)
                if u and p:
                    out.setdefault(role, (u, p))
    return out


def discover_login_from_spec(ctx, cred):
    """Fallback when api.log never saw the login (the spec logs in with its own HTTP client): the login operation is a POST of the
    OpenAPI document with a user-like and a password-like body field, and the credentials come from qa-spec.py (spec_credentials).
    The candidate is proven by calling it: a 2xx JSON answer carrying a token. Returns (login dict, None) or (None, reason)."""
    creds = spec_credentials(ctx.qa, ctx.api.roles)
    pair = creds.get(cred["role"]) or next(iter(creds.values()), None)
    if pair is None:
        return None, "no credentials found in qa-spec.py (a dict such as USERS = {role: (user, password)})"
    for ep in endpoints(ctx.doc):
        if ep["method"] != "POST" or ep["path_params"] or NOT_LOGIN_RE.search(ep["path"]):
            continue
        props = (ep.get("body_schema") or {}).get("properties") or {}
        user_key = next((k for k in props if USER_KEY_RE.search(k)), None)
        pass_key = next((k for k in props if PASS_KEY_RE.search(k)), None)
        if not user_key or not pass_key:
            continue
        r = ctx.api.call("anon", "POST", ep["path"], {user_key: pair[0], pass_key: pair[1]})
        data = r.json if r.ok and isinstance(r.json, dict) else None
        tkey = next((k for k, v in (data or {}).items() if isinstance(v, str) and re.search("token", k, re.I)
                     and not REFRESH_KEY_RE.search(k)), None)
        if tkey:
            return {"path": ep["path"], "user_key": user_key, "pass_key": pass_key, "user": pair[0], "password": pair[1],
                    "token_key": tkey, "refresh_key": _find_str_key(data, REFRESH_KEY_RE) or "refresh_token", "extra": {}}, None
    return None, "no POST operation with a user and a password field returned a token for the credentials in qa-spec.py"


def discover_flows(doc):
    """LOGOUT and REFRESH from the OpenAPI document (POST operations without path params)."""
    logout = refresh = None
    for ep in endpoints(doc):
        if ep["method"] != "POST" or ep["path_params"]:
            continue
        path, summary = ep["path"], ep.get("summary") or ""
        schema = ep.get("body_schema") if isinstance(ep.get("body_schema"), dict) else {}
        rkey = next((k for k in (schema.get("properties") or {}) if REFRESH_KEY_RE.search(k)), None)
        if LOGOUT_RE.search(path):
            logout = logout or {"path": path, "method": "POST"}
        elif REFRESH_KEY_RE.search(path) or rkey:
            refresh = refresh or {"path": path, "body_key": rkey or "refresh_token"}
        elif LOGOUT_RE.search(summary):
            logout = logout or {"path": path, "method": "POST"}
    return {"logout": logout, "refresh": refresh}


def _resolve_flows(ctx, cred):
    """Set ctx.login / ctx.logout / ctx.refresh: declared in qa-spec.py first, else discovered (noted either way)."""
    ctx.login = getattr(ctx.qa, "LOGIN", None)
    ctx.logout = getattr(ctx.qa, "LOGOUT", None)
    ctx.refresh = getattr(ctx.qa, "REFRESH", None)
    found = discover_flows(ctx.doc)
    if ctx.logout is None and found["logout"]:
        ctx.logout = found["logout"]
        ctx.note(f"LOGOUT discovered in the OpenAPI document: POST {ctx.logout['path']}")
    if ctx.refresh is None and found["refresh"]:
        ctx.refresh = found["refresh"]
        ctx.note(f"REFRESH discovered in the OpenAPI document: POST {ctx.refresh['path']} (body key {ctx.refresh['body_key']!r})")
    if ctx.login is None and cred is not None and cred["kind"] == "bearer":
        login, why = discover_login(ctx.api, cred["value"])
        if login:
            ctx.login = login
            ctx.note(f"LOGIN discovered from api.log: POST {login['path']} (user field {login['user_key']!r}, "
                     f"password field {login['pass_key']!r}, token at {login['token_key']!r})")
        else:
            login, why2 = discover_login_from_spec(ctx, cred)
            if login:
                ctx.login = login
                ctx.note(f"LOGIN discovered from the OpenAPI document and qa-spec.py credentials: POST {login['path']} "
                         f"(user field {login['user_key']!r}, password field {login['pass_key']!r}, token at {login['token_key']!r})")
            else:
                ctx.note(f"LOGIN not discovered: {why}; {why2}")


# ---------- context ----------

class _Ctx:
    def __init__(self, api, doc, qa):
        self.api, self.doc, self.qa = api, doc, qa
        self.login = self.logout = self.refresh = None     # flows, see _resolve_flows
        self.findings, self.notes, self.blocked = [], [], []      # blocked: (check, reason) = NOT TESTABLE
        self.probes = 0
        self.public_paths = {k.split(" ", 1)[-1] for k in getattr(qa, "PUBLIC", set())}
        self.catch_all = None          # body of an unknown path that answers 2xx (SPA fallback): never evidence of a bypass
        self.signing_key = None        # HS256 secret recovered from the wordlist; kept in memory, never printed
        self.post_paths = {e["path"] for e in endpoints(doc) if e["method"] == "POST"}

    def req(self, method, path, body=None, headers=None) -> Resp:
        self.probes += 1
        try:
            return self.api.call("anon", method, path, body, None, None, headers)
        except SystemExit as exc:          # api.local_url refuses a path it cannot send safely: nothing was sent
            return Resp(TRANSPORT_ERROR, f"path refused by api: {exc}")

    def add(self, kind, severity, endpoint, detail, control="", attack="", sequence=None):
        finding = {"kind": kind, "severity": severity, "endpoint": endpoint, "detail": detail,
                   "control": control, "attack": attack}
        if sequence:
            finding["sequence"] = sequence
        self.findings.append(finding)

    def blocked_by(self, check, reason):
        if (check, reason) not in self.blocked:
            self.blocked.append((check, reason))

    def note(self, text):
        if text not in self.notes:
            self.notes.append(text)


def _is_public(ctx, path) -> bool:
    return path in ctx.public_paths


def _guard(ctx, check, fn):
    try:
        fn()
    except Exception as exc:                # one broken check must not sink the others
        ctx.blocked_by(check, f"crashed: {type(exc).__name__}: {str(exc)[:120]}")


# ---------- detection ----------

def _detect(ctx):
    """-> (protected paths: anon GET 401/403, public_ok: anon GET 2xx). Only GET is ever sent here."""
    explicit = getattr(ctx.qa, "PROTECTED", None)
    if explicit is not None:
        cands = []
        for item in explicit:
            method, _, path = str(item).partition(" ")
            if method.upper() != "GET" or not path.startswith("/"):
                ctx.note(f"PROTECTED entry {item!r} ignored: only GET paths are probed (this engine sends no writes for detection)")
                continue
            cands.append(path)
    else:
        cands = [e["path"] for e in endpoints(ctx.doc) if e["method"] == "GET" and not e["path_params"]]
    protected, public_ok = [], []
    for path in sorted(set(cands)):
        r = ctx.req("GET", path)
        if _is_public(ctx, path):                 # a plain GET of a public page is not an attack; it may issue a pre-login cookie
            if r.ok:
                public_ok.append(path)
            continue
        if r.status in DENIED:
            protected.append(path)
        elif r.ok:
            public_ok.append(path)
    return protected, public_ok


def _catch_all(ctx):
    r = ctx.req("GET", f"/qa-nonexistent-{secrets.token_hex(4)}")
    if r.ok:
        ctx.catch_all = r.text


# ---------- credential renewal ----------

def _mint(ctx, login, role):
    """A new session from `login` (a LOGIN dict): the credential, or None when the login gives no session."""
    headers, _ = _session(_login(ctx, login, login["user"], login["password"]), login)
    return _cred_from_headers(headers, role) if headers else None


def _fresh(ctx, cred):
    """A baseline JWT that expires within RENEW_MARGIN_S is replaced by a new login (the spec's setup token may be short-lived)."""
    exp = _exp_of(cred["value"]) if cred["kind"] == "bearer" else None
    if exp is None or exp - time.time() > RENEW_MARGIN_S:
        return cred
    login, why = discover_login(ctx.api, cred["value"])
    if login is None and cred["role"] == "qa-login":
        login = ctx.login
    new = _mint(ctx, login, cred["role"]) if login else None
    if new is None:
        ctx.note(f"{cred['role']}: token expires within {RENEW_MARGIN_S:.0f} s and could not be renewed ({why})")
        return cred
    ctx.note(f"{cred['role']}: baseline token was near expiry, re-authenticated with the login that issued it")
    return new


# ---------- JWT checks ----------

def _jwt_endpoint(ctx, cred, path, jwt):
    """Claim and signature checks on one protected route. Control: the role's own token accepted there, or DENIED there.
    On a denied route the attack payload carries the privilege claims, so only the signature checks run (an unsigned token
    accepted on such a route is the claim-trust defect, not a plain alg defect)."""
    ep = f"GET {path}"
    garbage = ctx.req("GET", path, headers=cred_headers(cred, "x.y.z"))
    if garbage.status not in DENIED:
        ctx.blocked_by("AUTH-JWT-*", f"{ep}: an arbitrary bearer value gets {garbage.status}; a different defect, JWT checks suppressed")
        return
    canonical = ctx.req("GET", path, headers=cred_headers(cred, cred["value"]))
    if canonical.ok:
        control = f"legit token {red(cred['value'])} -> {canonical.status}; anon -> 401/403; arbitrary value -> {garbage.status}"
        base_payload, denied = jwt["payload"], False
    elif canonical.status in DENIED:
        control = f"the role's own token gets {canonical.status} on this route; arbitrary value -> {garbage.status}"
        base_payload, denied = _tampered(jwt["payload"]), True
    else:
        ctx.blocked_by("AUTH-JWT-*", f"{ep}: the role's own token gets {canonical.status}: no control for the JWT checks on this route")
        return
    h = jwt["header"]
    if not denied:
        for alg in ALG_NONE:                                  # unsigned token, original claims (no privilege change)
            forged = f"{_enc({**h, 'alg': alg})}.{_payload_seg(jwt, base_payload)}."
            r = ctx.req("GET", path, headers=cred_headers(cred, forged))
            if r.ok:
                ctx.add("AUTH-JWT-ALG-NONE", "high", ep,
                        f"server accepts an unsigned JWT with alg {alg!r}: anyone can mint a token for any identity",
                        control=control, attack=f"alg={alg!r}, empty signature, token {red(forged)} -> {r.status}")
                break
    nosig_payload = base_payload
    r = ctx.req("GET", path, headers=cred_headers(cred, f"{jwt['h']}.{_payload_seg(jwt, nosig_payload)}."))
    if r.ok:
        ctx.add("AUTH-JWT-NOSIG", "high", ep,
                "server accepts a JWT whose signature was removed" + (" and whose privilege claims were edited, on a route that denies this role" if denied else ""),
                control=control, attack=f"signature stripped, token {red(jwt['h'] + '.' + jwt['p'] + '.')} -> {r.status}")

    tampered = _tampered(jwt["payload"])
    if tampered != jwt["payload"]:
        forged = f"{jwt['h']}.{_enc(tampered)}.{jwt['sig']}"       # ORIGINAL signature over a changed payload
        r = ctx.req("GET", path, headers=cred_headers(cred, forged))
        if r.ok:
            ctx.add("AUTH-JWT-TAMPER", "high", ep,
                    ("payload edited (role/admin claims) and the original signature accepted on a route that DENIES this role: "
                     "privilege taken from unverified claims" if denied else
                     "payload edited (sub/role/admin/is_admin) but the original signature is still accepted: the signature is not verified"),
                    control=control, attack=f"changed claims with original signature, token {red(forged)} -> {r.status}")


def _weak_secret(ctx, cred, jwt):
    """HS256 signature checked offline against the built-in wordlist (the secret is never printed)."""
    alg = jwt["header"].get("alg")
    if alg == "HS256" and jwt["sig"]:
        for idx, secret in enumerate(WORDLIST):
            if hmac.compare_digest(hs256(secret, jwt["signing"]), jwt["sig"]):
                ctx.signing_key = secret
                ctx.add("AUTH-JWT-WEAK-SECRET", "high", f"token ({cred['kind']} of {cred['role']})",
                        f"HS256 signature verifies with built-in wordlist entry #{idx} (the secret is not printed). "
                        "Anyone with that entry can mint tokens for any identity",
                        control="signature recomputed locally with hmac-sha256 (no network)",
                        attack=f"{len(WORDLIST)} wordlist candidates tried, match at #{idx}")
                break
    elif alg != "HS256":
        ctx.note(f"AUTH-JWT-WEAK-SECRET: not applicable: alg is {alg!r}, only HS256 is checked")


def _jwt_expiry(ctx, cred, jwt, path):
    if "exp" not in jwt["payload"]:
        ctx.note("AUTH-JWT-EXPIRED: not applicable: the token has no exp claim")
        return
    if ctx.signing_key is not None:
        _expired_resigned(ctx, cred, jwt, path)
    else:
        _expired_waited(ctx, path)


def _expired_resigned(ctx, cred, jwt, path):
    """Expiry with a recovered key: re-sign the same claims with exp in the past."""
    check = "AUTH-JWT-EXPIRED"
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    fresh = sign_token(header, {**jwt["payload"], "exp": now + 3600}, ctx.signing_key)
    control = ctx.req("GET", path, headers=cred_headers(cred, fresh))
    if not control.ok:
        ctx.blocked_by(check, f"a correctly signed fresh token gets {control.status}: our signing does not match the server")
        return
    expired = sign_token(header, {**jwt["payload"], "exp": now - 3600}, ctx.signing_key)
    r = ctx.req("GET", path, headers=cred_headers(cred, expired))
    if r.ok:
        ctx.add("AUTH-JWT-EXPIRED", "high", f"GET {path}",
                "a token whose exp is one hour in the past is accepted (same claims, correct signature)",
                control=f"fresh token, same key -> {control.status}",
                attack=f"exp = now - 3600 -> {r.status}")


def _expired_waited(ctx, path):
    """Expiry without a key: mint a token, wait until its own exp has passed, replay it. Only when the lifetime is
    short enough (AUTH_EXPIRY_MAX_WAIT); a long-lived token is NOT TESTABLE, never clean."""
    check = "AUTH-JWT-EXPIRED"
    if ctx.login is None:
        ctx.blocked_by(check, "no signing key recovered and no login flow to mint a token whose expiry can be waited out")
        return
    cap = float(getattr(ctx.qa, "AUTH_EXPIRY_MAX_WAIT", EXPIRY_MAX_WAIT_S))
    fresh = _mint(ctx, ctx.login, "qa-fresh")
    if fresh is None:
        ctx.blocked_by(check, "the login gave no session token: nothing to time out")
        return
    exp = _exp_of(fresh["value"]) if fresh["kind"] == "bearer" else None
    if exp is None:
        ctx.note("AUTH-JWT-EXPIRED: not applicable: the session is not a JWT with a numeric exp")
        return
    left = exp - time.time()
    if left > cap:
        ctx.blocked_by(check, f"token lifetime is {left:.0f} s, above the {cap:.0f} s wait cap (qa.AUTH_EXPIRY_MAX_WAIT raises it): expiry not waited out")
        return
    control = ctx.req("GET", path, headers=cred_headers(fresh, fresh["value"]))
    if not control.ok:
        ctx.blocked_by(check, f"a fresh token gets {control.status} on GET {path}: no control for the expiry test")
        return
    time.sleep(max(0.0, exp + EXPIRY_MARGIN_S - time.time()))
    anon = ctx.req("GET", path)
    if anon.status not in DENIED:
        ctx.blocked_by(check, f"anonymous GET {path} gets {anon.status} after expiry: the route is no longer protected")
        return
    late = ctx.req("GET", path, headers=cred_headers(fresh, fresh["value"]))
    ctx.note(f"AUTH-JWT-EXPIRED: checked by waiting out a {left:.0f} s token lifetime (no signing key recovered)")
    if late.ok:
        ctx.add(check, "high", f"GET {path}",
                "a token is still accepted after its exp claim has passed: the exp claim is not checked",
                control=f"fresh token -> {control.status}; anonymous -> {anon.status} after expiry",
                attack=f"same token {red(fresh['value'])}, {time.time() - exp:.1f} s past exp -> {late.status}")


# ---------- multi-step flows (declared or discovered) ----------

def _login(ctx, login, user, password, headers=None):
    body = {**login.get("extra", {}), login.get("user_key", "username"): user, login.get("pass_key", "password"): password}
    return ctx.req("POST", login["path"], body, headers)


STATELESS_LONG = 24 * 3600            # a JWT that can still be replayed for more than a day after logout is not "short-lived"


def _jwt_seconds_left(header_value):
    """Seconds until exp of a bearer JWT in an Authorization header value, or None when it is not a JWT with a numeric exp."""
    token = header_value.split(" ", 1)[-1] if isinstance(header_value, str) else ""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        exp = json.loads(_b64d(parts[1])).get("exp")
    except Exception:
        return None
    return float(exp) - time.time() if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _logout(ctx, path):
    login, out = ctx.login, ctx.logout
    check = "AUTH-TOKEN-AFTER-LOGOUT"
    if not login or not out:
        ctx.blocked_by(check, "no login and logout flow: declare qa.LOGIN and qa.LOGOUT, or document the logout endpoint in the "
                              "OpenAPI spec (the login must appear in api.log)")
        return
    resp = _login(ctx, login, login["user"], login["password"])
    headers, _ = _session(resp, login)
    if headers is None:
        ctx.blocked_by(check, f"login gave no token or session cookie (status {resp.status})")
        return
    before = ctx.req("GET", path, headers=headers)
    if not before.ok:
        ctx.blocked_by(check, f"the session is not accepted before logout ({before.status})")
        return
    done = ctx.req(out.get("method", "POST"), out["path"], None, headers)
    if not done.ok:
        ctx.blocked_by(check, f"logout returned {done.status}: cannot show the session was ended")
        return
    after = ctx.req("GET", path, headers=headers)
    if after.ok:
        seq = [f"login -> session {red(next(iter(headers.values())))}", f"GET {path} -> {before.status}",
               f"{out.get('method', 'POST')} {out['path']} -> {done.status}", f"GET {path} with the same session -> {after.status}"]
        left = _jwt_seconds_left(next(iter(headers.values())))
        if left is None:                       # opaque token or session cookie: the server holds the state, so it could revoke it
            sev, text = "high", "the session still works after logout (token not revoked)"
        elif left > STATELESS_LONG:
            sev, text = "medium", (f"a stateless JWT with {int(left)} s of life left still works after logout: long-lived tokens "
                                   "need a revocation list (verify)")
        else:
            sev, text = "low", (f"the access JWT still works after logout ({int(left)} s of life left): a stateless token cannot be "
                                "revoked without a denylist, usually accepted when it is short-lived (verify)")
        ctx.add(check, sev, f"GET {path}", text,
                control=f"before logout -> {before.status}", attack=f"after logout -> {after.status}", sequence=seq)


COOKIE_NAMES = ("sid", "session", "sessionid", "session_id", "JSESSIONID", "connect.sid", "PHPSESSID")


def _cookie_session_names(doc):
    names = []
    for sch in ((doc.get("components") or {}).get("securitySchemes") or {}).values():
        if isinstance(sch, dict) and sch.get("type") == "apiKey" and sch.get("in") == "cookie" and sch.get("name"):
            names.append(sch["name"])
    return names + [n for n in COOKIE_NAMES if n not in names]


def _fixation_chosen(ctx, path):
    """Fixation without a pre-login cookie: send a cookie value WE chose with the login. When a later request with only that cookie is
    authenticated, the server adopted the attacker-chosen id as the session. Control: a random other value of the same cookie is denied.
    Returns True when the check could be run (found or clean), False when nothing applies."""
    check, login = "AUTH-SESSION-FIXATION", ctx.login
    for name in _cookie_session_names(ctx.doc):
        chosen = "qa-fixed-" + secrets.token_hex(6)
        hdr = {"Cookie": f"{name}={chosen}"}
        control = ctx.req("GET", path, headers={"Cookie": f"{name}=qa-other-{secrets.token_hex(6)}"})
        if control.ok or control.status not in DENIED:
            continue
        resp = _login(ctx, login, login["user"], login["password"], headers=hdr)
        if not resp.ok:
            continue
        after = ctx.req("GET", path, headers=hdr)
        if after.ok:
            rotated = _set_cookie(resp)
            seq = [f"GET {path} with an unrelated {name} cookie -> {control.status}",
                   f"POST {login['path']} with the chosen cookie {name}={red(chosen)} -> {resp.status}"
                   f"{' (Set-Cookie ' + rotated[0] + '=' + red(rotated[1]) + ')' if rotated else ''}",
                   f"GET {path} with only the chosen cookie -> {after.status}"]
            ctx.add(check, "high", f"GET {path}",
                    f"login adopted the session id chosen by the client (cookie {name}): the id an attacker fixed before login becomes the session",
                    control=f"unrelated {name} cookie -> {control.status}", attack=f"chosen {name} cookie after login -> {after.status}",
                    sequence=seq)
        return True
    return False


def _fixation(ctx, path, public_ok):
    check = "AUTH-SESSION-FIXATION"
    login = ctx.login
    if not login:
        ctx.blocked_by(check, "qa.LOGIN not declared and no login discovered in api.log")
        return
    pre = None
    for cand in public_ok:
        r = ctx.req("GET", cand)
        pre = _set_cookie(r) if r.ok else None
        if pre:
            break
    if pre is None:
        if not _fixation_chosen(ctx, path):
            ctx.note("AUTH-SESSION-FIXATION: no session cookie is issued before login and a client-chosen cookie is not adopted "
                     "(or the app has no cookie session)")
        return
    name, value = pre
    hdr = {"Cookie": f"{name}={value}"}
    control = ctx.req("GET", path, headers=hdr)
    if control.ok:
        ctx.note(f"AUTH-SESSION-FIXATION: not applicable: the pre-login cookie {name} already authenticates")
        return
    if control.status not in DENIED:
        ctx.blocked_by(check, f"pre-login session gets {control.status} on GET {path}: not a clean denial")
        return
    resp = _login(ctx, login, login["user"], login["password"], headers=hdr)
    if not resp.ok:
        ctx.blocked_by(check, f"login with the pre-login cookie gives {resp.status}")
        return
    after = ctx.req("GET", path, headers=hdr)
    rotated = _set_cookie(resp)
    rot_txt = "login issued a new session id" if rotated and rotated[1] != value else "login did not issue a new session id"
    if after.ok:
        seq = [f"pre-login cookie {name}={red(value)} issued", f"GET {path} with it -> {control.status}",
               f"POST {login['path']} with the same cookie -> {resp.status} ({rot_txt})", f"GET {path} with the same cookie -> {after.status}"]
        ctx.add(check, "high", f"GET {path}",
                f"a session id fixed before login is authenticated by login ({rot_txt.replace('login ', '')}): session fixation",
                control=f"pre-login cookie -> {control.status}", attack=f"same cookie after login -> {after.status}", sequence=seq)


FORGOT_RE = re.compile(r"forgot|recover|reset[-_]?request|password[-_]?reset(?!/)|lost[-_]?password", re.I)


def _norm_answer(resp):
    """Status plus the body with digits and long hex/uuid-like runs blanked: ids, timestamps and tokens must not count as a difference."""
    text = re.sub(r"[0-9a-f]{8,}|\d+", "#", resp.text or "")
    return resp.status, text.strip()


def _enum_forgot(ctx):
    """A forgot-password endpoint must answer an address that has an account and one that has none in the same way. Control: the same
    request repeated gives the same answer each time. Attack: known vs unknown address differ (status or normalised body)."""
    check = "AUTH-ENUM"
    login = ctx.login
    if not login or "@" not in str(login.get("user", "")):
        ctx.note("AUTH-ENUM (forgot password): needs an e-mail style login user to know one existing address")
        return
    for ep in endpoints(ctx.doc):
        props = (ep.get("body_schema") or {}).get("properties") or {}
        field = next((k for k in props if USER_KEY_RE.search(k)), None)
        if ep["method"] != "POST" or ep["path_params"] or not FORGOT_RE.search(ep["path"]) or not field or any(PASS_KEY_RE.search(k) for k in props):
            continue
        known = {field: login["user"]}
        unknown = {field: f"qa-nobody-{secrets.token_hex(4)}@{login['user'].split('@', 1)[1]}"}
        a1, a2 = ctx.req("POST", ep["path"], known), ctx.req("POST", ep["path"], known)
        b1, b2 = ctx.req("POST", ep["path"], unknown), ctx.req("POST", ep["path"], unknown)
        if _norm_answer(a1) != _norm_answer(a2) or _norm_answer(b1) != _norm_answer(b2):
            ctx.note(f"AUTH-ENUM (forgot password) POST {ep['path']}: the same request does not repeat its answer (rate limit or noise): not compared")
            continue
        if _norm_answer(a1) != _norm_answer(b1):
            ctx.add(check, "medium", f"POST {ep['path']}",
                    f"forgot password answers an existing address ({a1.status}) and an unknown one ({b1.status}) differently: accounts can be enumerated",
                    control="the same request repeated gives the same answer",
                    attack=f"known -> {a1.status} {a1.text[:60]!r}; unknown -> {b1.status} {b1.text[:60]!r}")
        return


def _enum(ctx):
    check = "AUTH-ENUM"
    login = ctx.login
    if not login:
        ctx.blocked_by(check, "qa.LOGIN not declared and no login discovered in api.log")
        return
    user, pw = login["user"], login["password"]
    unknown = (f"qa-nouser-{secrets.token_hex(4)}@{user.partition('@')[2]}" if "@" in user else f"qa-nouser-{secrets.token_hex(4)}")
    real = _login(ctx, login, user, pw)
    if not real.ok:
        ctx.blocked_by(check, f"correct credentials give {real.status}: cannot compare failure answers")
        return
    nonce = secrets.token_hex(6)
    wrong = _login(ctx, login, user, "qa-wrong-" + nonce)
    nouser = _login(ctx, login, unknown, "qa-wrong-" + nonce)
    if wrong.status in RATE_LIMITED or nouser.status in RATE_LIMITED:
        ctx.blocked_by(check, f"rate limited during the comparison ({wrong.status}/{nouser.status})")
        return
    ep = f"POST {login['path']}"

    def norm(text):
        return text.replace(user, "<USER>").replace(unknown, "<USER>")
    if nouser.status != wrong.status or norm(nouser.text) != norm(wrong.text):
        ctx.add(check, "medium", ep, "failed-login answers differ between an unknown user and a wrong password: valid accounts can be listed",
                control=f"wrong password for a real user -> {wrong.status} {_short(wrong.text)!r}",
                attack=f"unknown user -> {nouser.status} {_short(nouser.text)!r}")

    n = int(getattr(ctx.qa, "ENUM_SAMPLES", 10))
    samples = {"unknown": [], "wrong": []}
    for i in range(n):                                       # alternate the order to cancel drift
        order = (("unknown", unknown), ("wrong", user)) if i % 2 == 0 else (("wrong", user), ("unknown", unknown))
        for label, who in order:
            t0 = time.perf_counter()
            r = _login(ctx, login, who, "qa-wrong-" + secrets.token_hex(4))
            samples[label].append((time.perf_counter() - t0) * 1000)
            if r.status in RATE_LIMITED:
                ctx.blocked_by(f"{check} (timing)", f"rate limited after {len(samples[label])} samples")
                return
    stat = welch(samples["unknown"], samples["wrong"])
    if stat is None:
        ctx.blocked_by(f"{check} (timing)", f"fewer than {ENUM_MIN_N} samples per side")
        return
    if abs(stat["t"]) > ENUM_T and abs(stat["diff_ms"]) >= ENUM_MIN_MS:
        ctx.add(check, "low", ep,
                f"login timing differs: unknown-user median {stat['median_a']:.1f} ms vs wrong-password median {stat['median_b']:.1f} ms; "
                f"Welch t={stat['t']:.1f} over n={n} per side (threshold |t|>{ENUM_T} and >= {ENUM_MIN_MS} ms). "
                "Local timing is noisy: confirm on a quiet machine with more samples",
                control=f"wrong-password samples n={n}", attack=f"unknown-user samples n={n}")


def _refresh(ctx):
    check = "AUTH-REFRESH-REUSE"
    login, rf = ctx.login, ctx.refresh
    if not login or not rf:
        ctx.blocked_by(check, "qa.LOGIN and qa.REFRESH must both be declared or discoverable (refresh endpoint in the OpenAPI spec)")
        return
    resp = _login(ctx, login, login["user"], login["password"])
    _, refresh = _session(resp, login)
    if not refresh:
        ctx.blocked_by(check, f"login returned no refresh token (refresh_key {login.get('refresh_key', 'refresh_token')!r})")
        return
    body = {rf.get("body_key", "refresh_token"): refresh}
    first = ctx.req("POST", rf["path"], body)
    if not first.ok:
        ctx.blocked_by(check, f"refresh with a fresh refresh token gives {first.status}")
        return
    second = ctx.req("POST", rf["path"], body)
    if second.ok:
        seq = [f"login -> refresh token {red(refresh)}", f"POST {rf['path']} -> {first.status}",
               f"POST {rf['path']} with the SAME token again -> {second.status}"]
        ctx.add(check, "high", f"POST {rf['path']}",
                "a refresh token is accepted twice: no single-use or rotation (some apps allow a short grace window: check the timing)",
                control=f"first use -> {first.status}", attack=f"second use -> {second.status}", sequence=seq)


def _reset(ctx):
    check = "AUTH-RESET-REUSE"
    rs = getattr(ctx.qa, "RESET", None)
    if not rs or not all(callable(rs.get(k)) for k in ("request", "get_token", "use")):
        ctx.blocked_by(check, "qa.RESET hooks request, get_token and use must all be declared")
        return
    rs["request"](ctx.api)
    t1 = rs["get_token"](ctx.api)
    if not t1:
        ctx.blocked_by(check, "get_token returned nothing after a reset request")
        return
    t1 = str(t1)
    first = rs["use"](ctx.api, t1)
    if not first.ok:
        ctx.blocked_by(check, f"the first use of the reset token gives {first.status}")
        return
    second = rs["use"](ctx.api, t1)
    if second.ok:
        ctx.add(check, "high", "reset flow", "a password-reset token is accepted twice: it is not single-use",
                control=f"first use -> {first.status}", attack=f"second use of {red(t1)} -> {second.status}",
                sequence=[f"reset request -> token {red(t1)}", f"use -> {first.status}", f"use again -> {second.status}"])
    rs["request"](ctx.api)
    t2 = rs["get_token"](ctx.api)
    if not t2:
        ctx.blocked_by(check, "get_token returned nothing on the second reset request (predictability not checked)")
        return
    t2 = str(t2)
    reason = None
    if t2 == t1:
        reason = ("medium", "two reset requests issued the same token (static token, or the app reuses an unexpired one: verify)")
    elif t1.isdigit() and t2.isdigit() and abs(int(t2) - int(t1)) <= 1000:
        reason = ("high", f"consecutive reset tokens differ by {int(t2) - int(t1)}: sequential, guessable")
    else:
        bits = min(entropy_bits(t1), entropy_bits(t2))
        if bits < LOW_ENTROPY_BITS:
            reason = ("medium", f"reset token charset bound is ~{bits:.0f} bits (< {LOW_ENTROPY_BITS}): guessable")
    if reason:
        ctx.add(check, reason[0], "reset flow", f"predictable reset token: {reason[1]}",
                control="two reset requests for the same account", attack=f"tokens {red(t1)} and {red(t2)}")


# ---------- bypass checks (anonymous, no credential needed) ----------

def _header_bypass(ctx, path, legit_text):
    ep = f"GET {path}"
    variants = [
        ("X-Forwarded-For", "GET", path, {"X-Forwarded-For": "127.0.0.1"}),
        ("X-Forwarded-Host", "GET", path, {"X-Forwarded-Host": "localhost"}),
        ("X-Original-URL", "GET", "/", {"X-Original-URL": path}),
        ("X-HTTP-Method-Override", "POST", path, {"X-HTTP-Method-Override": "GET"}),
    ]
    for name, method, target, extra in variants:
        if method == "POST" and path in ctx.post_paths:
            ctx.note(f"X-HTTP-Method-Override not probed on {path}: the spec has a POST there, an anonymous POST could write")
            continue
        r = ctx.req(method, target, None, extra)
        if not r.ok:
            continue
        same = legit_text is not None and r.text == legit_text
        if name == "X-Original-URL" and not same:
            continue      # the base page answering 2xx proves nothing: only the protected content itself counts
        if name != "X-Original-URL" and ctx.catch_all is not None and r.text == ctx.catch_all:
            continue
        ctx.add("AUTH-HEADER-BYPASS", "high" if same else "medium", ep,
                f"{name} turns anonymous 401/403 into {r.status} on {method} {target}"
                + ("" if same else " (body differs from the authenticated answer: verify)"),
                control=f"anon GET {path} -> 401/403",
                attack=f"anon {method} {target} with {name}: {list(extra.values())[0]} -> {r.status}, body {'== authenticated' if same else 'differs'}")


def _variants(path):
    parts = path.split("/")
    out = [("trailing slash", path + "/"), ("uppercase", path.upper()),
           ("semicolon parameter", path + ";qa=1"), ("json suffix", path + ".json")]
    first = parts[1] if len(parts) > 1 else ""
    if first and first[0].isalpha():          # a gate that matches the raw path misses a percent-encoded letter the router decodes
        out.append(("percent-encoded first letter", f"/%{ord(first[0]):02x}{first[1:]}" + "".join("/" + p for p in parts[2:])))
    if len(parts) >= 3:
        head, tail = "/".join(parts[:2]), "/".join(parts[2:])
        out += [("double slash", f"{head}//{tail}"), ("dot segment", f"{head}/./{tail}"), ("encoded slash", f"{head}%2f{tail}"),
                ("double-encoded slash", f"{head}%252f{tail}"), ("segment parameter", f"{head};x=1/{tail}")]
    return out


def _denied_roles(ctx, path):
    """Configured non-anonymous roles whose canonical request to `path` is denied (401/403): the control for a role-level bypass."""
    return [role for role in ctx.api.roles if role != "anon" and ctx.api.call(role, "GET", path).status in (401, 403)]


def _path_bypass(ctx, path, legit_text):
    ep = f"GET {path}"
    attackers = [("anon", None)] + [(role, role) for role in _denied_roles(ctx, path)]
    for name, variant in _variants(path):
        if variant == path or _is_public(ctx, variant):
            continue
        for who, role in attackers:
            r = ctx.req("GET", variant) if role is None else ctx.api.call(role, "GET", variant)
            if not r.ok:
                continue
            if ctx.catch_all is not None and r.text == ctx.catch_all:
                continue
            same = legit_text is not None and r.text == legit_text
            ctx.add("AUTH-PATH-BYPASS", "high" if same else "medium", ep,
                    f"{who} GET {variant} ({name}) answers {r.status} while the canonical {path} answers 401/403"
                    + ("" if same else " (body differs from the authenticated answer: verify)"),
                    control=f"{who} GET {path} -> 401/403", attack=f"{who} GET {variant} -> {r.status}, body {'== authenticated' if same else 'differs'}")


# ---------- entry point ----------

def run(api, spec_doc, qa) -> dict:
    ctx = _Ctx(api, spec_doc, qa)
    creds = find_credentials(api)
    login0 = getattr(qa, "LOGIN", None)
    if not creds and login0:
        headers, _ = _session(_login(ctx, login0, login0["user"], login0["password"]), login0)
        if headers:
            creds = [_cred_from_headers(headers, "qa-login")]
    if not creds:
        return trust.mark({"engine": "auth", "findings": [], "notes": ["no Bearer or Cookie credential in any role and qa.LOGIN gave none"],
                           "probes": ctx.probes},
                          trust.SKIPPED, "no auth detected: no role has a Bearer/Cookie credential and qa.LOGIN did not yield one")

    _resolve_flows(ctx, creds[0])
    creds = [_fresh(ctx, c) for c in creds]          # short-lived tokens from the spec's setup are renewed first
    cred = creds[0]
    protected, public_ok = _detect(ctx)
    _catch_all(ctx)
    jwt = parse_jwt(cred["value"])

    # baseline: the first credential each route accepts (any role). A route with no accepted credential is still tested,
    # because its control is the denial itself.
    baseline = {}
    for path in protected:
        for c in creds:
            r = ctx.req("GET", path, headers=cred_headers(c, c["value"]))
            if r.ok:
                baseline[path] = (c, r.text)
                break
    cap = int(getattr(qa, "AUTH_MAX_ENDPOINTS", MAX_ENDPOINTS_DEFAULT))
    targets = sorted(protected, key=lambda p: p not in baseline)[:cap]      # routes with a baseline first
    for path in protected:
        if path not in baseline:
            ctx.note(f"no credential of any role is accepted on GET {path}: that route is tested on its denial control only")
    if not targets:
        ctx.blocked_by("AUTH-*", "no protected endpoint: no GET endpoint without path params answers 401/403 to anonymous "
                                 "(set qa.PROTECTED to name the protected GET paths)")
    elif not baseline:
        ctx.blocked_by("AUTH-*", "no role's credential is accepted on any protected GET endpoint: no baseline for the session checks")
    # the flow checks log in as the primary credential, so the anchor route must accept THAT credential
    anchor = (next((p for p in targets if p in baseline and baseline[p][0] is cred), None)
              or next((p for p in targets if p in baseline), None) or (targets[0] if targets else None))

    for path in targets:
        legit_text = baseline[path][1] if path in baseline else None
        _guard(ctx, "AUTH-HEADER-BYPASS", lambda p=path, t=legit_text: _header_bypass(ctx, p, t))
        _guard(ctx, "AUTH-PATH-BYPASS", lambda p=path, t=legit_text: _path_bypass(ctx, p, t))

    if jwt is None:
        ctx.note("AUTH-JWT-*: not applicable: the credential is not a JWT (opaque token or cookie value)")
    else:
        for path in targets:
            _guard(ctx, "AUTH-JWT-*", lambda p=path: _jwt_endpoint(ctx, cred, p, jwt))
        if anchor:
            _guard(ctx, "AUTH-JWT-WEAK-SECRET", lambda: _weak_secret(ctx, cred, jwt))
            _guard(ctx, "AUTH-JWT-EXPIRED", lambda: _jwt_expiry(ctx, cred, jwt, anchor))

    if anchor:
        _guard(ctx, "AUTH-TOKEN-AFTER-LOGOUT", lambda: _logout(ctx, anchor))
        _guard(ctx, "AUTH-SESSION-FIXATION", lambda: _fixation(ctx, anchor, public_ok))
        _guard(ctx, "AUTH-REFRESH-REUSE", lambda: _refresh(ctx))
        _guard(ctx, "AUTH-RESET-REUSE", lambda: _reset(ctx))
        _guard(ctx, "AUTH-ENUM", lambda: _enum_forgot(ctx))
        _guard(ctx, "AUTH-ENUM", lambda: _enum(ctx))        # last: it sends failed logins to the LOGIN user (lockout risk)

    res = {"engine": "auth", "findings": ctx.findings, "notes": ctx.notes, "probes": ctx.probes,
           "not_testable": [{"check": c, "reason": r} for c, r in ctx.blocked]}
    if ctx.blocked:
        head = "; ".join(f"{c}: {r}" for c, r in ctx.blocked[:4])
        more = f" (+{len(ctx.blocked) - 4} more)" if len(ctx.blocked) > 4 else ""
        return trust.mark(res, trust.DEGRADED, ("not testable: " + head + more)[:400])
    return trust.mark(res, trust.RAN_OK)
