"""Negative / boundary engine: break every input the OpenAPI schema declares, one field at a time.

Why: valid-only fuzzing never reaches the `catch {}` / unvalidated-cast paths where real apps return 500s, accept garbage
or leak internals. This engine starts from a VALID request (baseline) and applies ONE mutation at a time:

  body fields   null, wrong type, missing (required), invalid enum, empty / whitespace-only / huge / NUL / unicode / SQL-ish
                strings, negative / zero / huge / fractional numbers, non-array for arrays, non-object for objects
  body level    malformed JSON, JSON array instead of object, empty body
  path ids      nonexistent id, "0", "-1", huge number, SQL-ish, traversal, NUL, 5000 chars
  query params  invalid enum / NUL / huge / SQL-ish / repeated value

Oracles (each finding is a CANDIDATE: reproduce it as a PoC before reporting):
  NEG-5XX        server error on malformed input (should be 4xx)                                          medium
  NEG-NO-RESPONSE  no HTTP response at all (connection dropped / timeout) on malformed input: crash or hang  medium
  NEG-LEAK       response body shows a stack trace, SQL/driver error, absolute path, key or secret          medium
  NEG-INJECTION  SQL-shaped input is INTERPRETED, shown by a differential against a benign control: a 5xx or DB error text
                 only on the payload (medium; high with a DB error text), or a boolean-blind pair where the TRUE answer differs
                 from the FALSE answer and the FALSE answer equals the benign one (high). The payload is tagged with a unique
                 word after its comment marker, so an exact-match hit on data the engine stored cannot pass as injection.
                 Acceptance alone is never evidence (a free-form text field accepts any text).         high / medium
  NEG-ACCEPTED   2xx for input that is invalid by the schema (bad enum / type / null / missing required), or a write on a
                 nonexistent id, or whitespace-only text where minLength >= 1, or SQL-shaped text accepted where the benign
                 value is rejected (acceptance only)                                                          low
  MASS-ASSIGN    privileged extra field (role, isAdmin, userId, id, ...) is applied. Confirmed when the control response
                 (same request without the extra field) had a different value or a read-back GET shows it     high/medium
  XREF-IDOR      a body field that references another user's resource (ticketId, order_id, ...) is accepted      high
  (no NEG-ERROR finding) a baseline answered 4xx is a note: accept-invalid checks are skipped for that endpoint, run DEGRADED.
                 A baseline 5xx is reported once as NEG-5XX ("baseline"); its mutations' 5xx answers are not repeated.
                 A DELETE (or cancel) baseline changes the resource: later probes of that endpoint are noted as not independent.

qa-spec.py (all optional):
  NEG_SKIP     {"POST /api/x"}            endpoints this engine must not touch (in addition to SKIP)
  NEG_ROLE     {"PATCH /api/x/{id}": "admin"}   role that sends the requests (default: ADMIN_ROLE for ADMIN_ONLY, else OWNER or user_a)
  BODIES       valid baseline bodies (same as authz)
  NEG_MAX      max requests per endpoint (default 160)
"""
import json
import re
from urllib.parse import quote

from api import WRITE_METHODS, endpoints, example, extract_id, fill, key, prefix_of, resolve
import trust

LEAK_PATTERNS = [
    ("stack trace", re.compile(r"(\n\s+at\s+\S+\s+\(.*:\d+:\d+\))|(Traceback \(most recent call last\))|(File \"[^\"]+\", line \d+)")),
    ("db/driver error", re.compile(r"SQLSTATE|psycopg|pg_catalog|sqlite3\.\w*Error|PrismaClient\w*Error|Invalid `prisma\.|MongoServerError|E11000|"
                                   r"duplicate key value violates|ORA-\d{5}|You have an error in your SQL syntax|SequelizeDatabaseError|"
                                   r"sqlalchemy\.exc|django\.db\.utils|Unique constraint failed|SQLITE_ERROR|SQLITE_CONSTRAINT|"
                                   r"syntax error at or near|unterminated quoted string", re.I)),
    ("absolute path", re.compile(r"[A-Za-z]:[\\/]+(Users|Windows|Program Files)[\\/]|/(home|Users|var/www|usr/(local/)?lib|app|srv)/[\w.-]+/")),
    ("secret/key", re.compile(r"AIza[0-9A-Za-z_\-]{30,}|(?<![A-Za-z0-9])sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}")),
    ("JWT in an error response", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),      # 2xx login/register tokens are intended: errors only
    ("third-party error", re.compile(r"googleapis\.com|generativelanguage|api\.openai\.com|api\.stripe\.com|"
                                     r"Method doesn't allow unregistered callers|API key (not valid|must be set)", re.I)),
]

CANARY = "<i>qa-canary-html</i>"      # outbound.py looks for this verbatim in mail / LLM prompts / webhooks
BIG = "A" * 10_000
STRING_MUTATIONS = [
    ("empty", ""), ("whitespace_only", "   "), ("huge", BIG), ("nul_byte", "a\x00b"), ("unicode", "‮\U0001d518ñ́\U0001f600"),
    ("sql_ish", "' OR '1'='1' --"), ("sql_comment", "' OR 1=1--"), ("html", CANARY), ("number_as_string", "12345678901234567890"),
    ("regex_meta", "([a-"),       # invalid regex: unescaped user text inside a $regex / RegExp / LIKE-style filter blows up (500)
]
BENIGN = "qa-benign-zz"            # same shape as a payload but harmless: the control of every injection differential


def _benign() -> str:
    """A harmless control value that is new every time: a reused one hits "already exists" (409) on unique columns, which is a
    conflict with a row WE created, not a validation verdict (measured false positive: register email, found by the clean control)."""
    _COUNTER[0] += 1
    return f"{BENIGN}{_COUNTER[0]}"
SQLI_KINDS = ("sql_ish", "sql_comment")
_DB_ERROR = next(rx for label, rx in LEAK_PATTERNS if label == "db/driver error")
_TAG = [0]


def tagged(payload: str) -> str:
    """The payload plus a unique word after its SQL comment marker. A commented-out tautology still works in SQL, but a string
    the engine never stored cannot be an exact-match hit. (Measured false positive: the engine created a promo code equal to
    the payload through POST /promo-codes, then the same payload 'matched' it on POST /subscriptions.)"""
    _TAG[0] += 1
    return f"{payload}qa{_TAG[0]}"


def false_of(payload: str):
    """The payload with its tautology made false (OR -> AND, '1'='1' -> '1'='2', 1=1 -> 1=2), or None if it has none."""
    out = payload.replace("OR '1'='1'", "AND '1'='2'").replace("OR 1=1", "AND 1=2")
    return out if out != payload else None


def _strip(text: str, value: str) -> str:
    """The answer body with the value we sent removed and digit runs masked (ids and counters change on every request)."""
    return re.sub(r"\d+", "N", (text or "").replace(value, "<payload>"))


def sqli_differential(send, payload: str, benign):
    """Is the SQL-shaped string `payload` interpreted by the server? send(value) -> Resp (None when the budget is spent).
    Returns {"sev": "high" | "medium" | None, "why", "true": Resp, "benign": Resp}, or None when nothing could be compared.

    Acceptance alone is never a signal. Two differential signals count:
      error    the tagged payload gets a 5xx (or a DB error text) and the benign value does not: high with a DB error text,
               medium without one (a candidate: a quote that breaks the app is a SQL error until proven otherwise)
      boolean  the tagged TRUE answer differs from the tagged FALSE answer, while the FALSE answer equals the benign answer
               (status and body, each with its own value removed). A login bypass (TRUE 200, FALSE 401, benign 401) is this.
    """
    t_val = tagged(payload)
    t = send(t_val)
    if t is None:
        return None
    b_val = benign()
    b = send(b_val)
    if b is None or t.transport or b.transport:
        return None
    out = {"sev": None, "why": "", "true": t, "benign": b}
    if t.server_error:
        if b.server_error:
            return out                       # both broken: a generic 5xx, not a differential
        db = bool(_DB_ERROR.search(t.text or ""))
        out.update(sev="high" if db else "medium",
                   why=("a database error text" if db else f"a 5xx") + f" on the payload only (benign value: {b.status})")
        return out
    if _DB_ERROR.search(t.text or "") and not _DB_ERROR.search(b.text or ""):
        out.update(sev="high", why="a database error text in the answer to the payload only")
        return out
    f_base = false_of(payload)
    if f_base is None:
        return out
    f_val = tagged(f_base)
    f = send(f_val)
    if f is None or f.transport:
        return out
    if 409 in (t.status, f.status, b.status):
        return out                           # a conflict says nothing about the value
    if (f.status, _strip(f.text, f_val)) != (b.status, _strip(b.text, b_val)):
        return out                           # the FALSE payload must behave like a plain non-match
    if (t.status, _strip(t.text, t_val)) == (f.status, _strip(f.text, f_val)):
        return out                           # TRUE and FALSE answer alike: the payload is not interpreted
    out.update(sev="high", why=f"boolean-blind: TRUE answered {t.status}, FALSE answered {f.status}, benign {b.status}")
    return out
SQLI_KINDS_ALL = SQLI_KINDS + ("union_probe",)
NUMBER_MUTATIONS = [("negative", -1), ("zero", 0), ("huge", 2 ** 63), ("fractional", 1.5), ("nan_string", "NaN"), ("float_max", 1.7e308)]
PATH_IDS = ["__qa_nonexistent__", "0", "-1", "99999999999999999999", "' OR 1=1--", "../../etc/passwd", "%00", "A" * 5000]
PRIVILEGED = {"role": "ADMIN", "isAdmin": True, "is_admin": True, "admin": True, "verified": True, "emailVerified": True,
              "balance": 999999, "credit": 999999, "permissions": ["*"], "userId": "__qa_forced_owner__", "user_id": "__qa_forced_owner__",
              "ownerId": "__qa_forced_owner__", "owner_id": "__qa_forced_owner__", "id": "__qa_forced_id__",
              "createdAt": "1999-01-01T00:00:00.000Z", "created_at": "1999-01-01T00:00:00.000Z"}
PRIVILEGED_ALT = {"role": "admin", "isAdmin": 1, "is_admin": 1, "admin": 1, "type": "admin", "userType": "admin", "accessLevel": 99,
                  "status": "approved", "price": 0, "discount": 100, "deluxeToken": "x"}   # lowercase / numeric variants: validators are often case-exact
ROLE_KEYS = {"role", "isAdmin", "is_admin", "admin", "type", "userType", "accessLevel", "verified", "emailVerified", "permissions", "balance", "credit"}


def value_repr(v):
    return repr(v if len(str(v)) < 60 else str(v)[:57] + "...")


_COUNTER = [0]


def _unique(body):
    """Copy of body with email / username values made unique, so repeated creates do not hit a 409 on a unique column.
    Code-like values (code, sku, handle, slug, login) are left as they are: a suffix changes them (country_code "US" -> "US7")
    and breaks the mass-assign baseline. A repeat create of such a value may 409; the callers treat that as a setup failure."""
    _COUNTER[0] += 1
    out = dict(body)
    for k, v in body.items():
        if isinstance(v, str) and re.search(r"e-?mail|user-?name", k, re.I):
            out[k] = "{}+qa{}@{}".format(*v.partition("@")[::2][:1], _COUNTER[0], v.partition("@")[2]) if "@" in v else f"{v}{_COUNTER[0]}"
    return out


def _type_name(schema):
    if "enum" in schema:
        return "enum"
    return schema.get("type") or ("object" if "properties" in schema else "string")


def _wrong_type(schema):
    t = _type_name(schema)
    return {"string": 12345, "enum": 12345, "integer": "not-a-number", "number": "not-a-number", "boolean": "yes",
            "array": "not-an-array", "object": "not-an-object"}.get(t, 12345)


def field_mutations(name, schema, required, spec):
    """[(kind, value_or_MISSING, invalid_by_schema)] for one body field."""
    schema = resolve(schema, spec)
    t = _type_name(schema)
    out = [("null", None, name in required), ("wrong_type", _wrong_type(schema), True)]
    if name in required:
        out.append(("missing", MISSING, True))
    if t == "enum":
        out.append(("invalid_enum", "__qa_invalid__", True))
        out.append(("enum_lowercase", str(schema["enum"][0]).lower() if isinstance(schema["enum"][0], str) else "x", False))   # many APIs normalise case: only 5xx counts
    elif t == "string":
        for kind, v in STRING_MUTATIONS:
            invalid = (kind in ("empty", "whitespace_only") and schema.get("minLength", 0) >= 1) or (kind == "huge" and schema.get("maxLength", 10 ** 9) < len(BIG))
            out.append((kind, v, invalid))
    elif t in ("integer", "number"):
        for kind, v in NUMBER_MUTATIONS:
            out.append((kind, v, (kind == "negative" and schema.get("minimum", -10 ** 9) >= 0) or (kind == "fractional" and t == "integer")))
    elif t == "array":
        out += [("empty_array", [], schema.get("minItems", 0) >= 1), ("huge_array", [example(schema.get("items", {}), spec)] * 500, False)]
    elif t == "object":
        out.append(("empty_object", {}, bool(schema.get("required"))))
    return out


class _Missing:
    def __repr__(self):
        return "<MISSING>"


MISSING = _Missing()


def _flatten(node, prefix=""):
    """{dotted.key: value} of every scalar in a JSON document (keys also by bare name)."""
    out = {}
    if isinstance(node, dict):
        for k, v in node.items():
            out.update(_flatten(v, f"{prefix}{k}."))
            if not isinstance(v, (dict, list)):
                out[f"{prefix}{k}"] = v
    elif isinstance(node, list):
        for i, v in enumerate(node[:20]):
            out.update(_flatten(v, f"{prefix}{i}."))
    return out


def _find_key(doc, name):
    return [v for k, v in _flatten(doc).items() if k == name or k.endswith("." + name)]


def _leaks(text, ok=False):
    """Leak labels found in a response body. On a 2xx (ok=True) the body is normal content: error-text patterns do not apply
    to it (JWT and third-party error text), and a URL is data (CDN or API host, /app/<x>/ path), so the absolute-path pattern
    does not read inside URLs. Secrets are still searched in the whole body (a key can sit in a URL's query string)."""
    out = []
    for label, rx in LEAK_PATTERNS:
        if ok and label in ("JWT in an error response", "third-party error"):
            continue
        scan = re.sub(r"https?://\S+", " ", text or "") if (ok and label == "absolute path") else (text or "")
        if rx.search(scan):
            out.append(label)
    return out


def run(api, spec_doc, qa, max_per_endpoint=None) -> dict:
    eps = endpoints(spec_doc)
    skip = set(getattr(qa, "SKIP", set())) | set(getattr(qa, "NEG_SKIP", set()))
    admin_only = set(getattr(qa, "ADMIN_ONLY", set())) | {key(e) for e in eps if "/admin" in e["path"]}
    admin_role = getattr(qa, "ADMIN_ROLE", "admin")
    owner_map = getattr(qa, "OWNER", {})
    roles_override = getattr(qa, "NEG_ROLE", {})
    bodies = getattr(qa, "BODIES", {})
    cap = max_per_endpoint or getattr(qa, "NEG_MAX", 160)
    findings, notes, seen = [], [], set()
    sent = [0]
    base5 = [False]                    # the current endpoint's baseline answered 5xx (see check_response)
    skipped = [0]                      # probes refused by the per-endpoint cap: counted, reported, never silently dropped

    def role_for(ep):
        k = key(ep)
        if k in roles_override:
            return roles_override[k]
        if k in admin_only and admin_role in api.roles:
            return admin_role
        return owner_map.get(k, "user_a") if owner_map.get(k, "user_a") in api.roles else next((r for r in api.roles if r != "anon"), "anon")

    hooks = getattr(qa, "BODY_HOOKS", {})
    try:
        ctx = (getattr(qa, "fresh_state", lambda api: {})(api)) or {}      # real ids for BODY_HOOKS (e.g. replies need a ticketId)
    except Exception as exc:
        ctx = {}
        notes.append(f"fresh_state() failed ({type(exc).__name__}: {exc}); BODY_HOOKS baselines may be invalid")

    def baseline(ep):
        if key(ep) in bodies:                                   # an explicit valid sample wins; hooks are only for generated bodies
            return json.loads(json.dumps(bodies[key(ep)]))
        elif ep["body_schema"] is not None and ep["method"] in WRITE_METHODS:
            body = example(ep["body_schema"], spec_doc)
        else:
            return None
        if key(ep) in hooks and body is not None:
            try:
                body = hooks[key(ep)](body, ctx)
            except Exception:
                pass
        return body

    creators = {}
    for e in eps:
        if e["method"] == "POST" and not e["path_params"] and key(e) not in skip:
            creators[e["path"].rstrip("/")] = e

    def make_resource(collection, role=None):
        c = creators.get(collection)
        if not c:
            return None
        r = api.call(role or role_for(c), "POST", c["path"], baseline(c))
        sent[0] += 1
        return extract_id(r.json) if r.ok else None

    def add(kind, severity, ep, detail, resp=None, request=None, dedupe=None):
        dk = (kind, key(ep), dedupe or detail[:60])
        if dk in seen:
            return
        seen.add(dk)
        findings.append({"kind": kind, "severity": severity, "endpoint": key(ep), "detail": detail,
                         "status": getattr(resp, "status", None), "response": (resp.text[:200] if resp is not None else ""),
                         "request": json.dumps(request, default=str)[:300] if request is not None else None})

    def check_response(ep, resp, desc, request, invalid=False, baseline_ok=True, write_on_missing=False):
        # a baseline that already answers 5xx is one finding; its mutations' 5xx answers would only repeat it (30 copies measured)
        if resp.server_error and not (base5[0] and desc != "baseline"):
            add("NEG-5XX", "medium", ep, f"{desc} -> {resp.status} (expected 4xx)", resp, request, dedupe=desc)
        elif resp.transport:       # no HTTP answer at all: the app dropped the connection, hung or crashed (or the client hit a socket limit)
            add("NEG-NO-RESPONSE", "medium", ep, f"{desc} -> no HTTP response ({resp.text[:80]}): app crashed, hung or dropped the connection",
                resp, request, dedupe=desc)
        for label in _leaks(resp.text, ok=resp.ok):
            add("NEG-LEAK", "medium", ep, f"{desc} -> response leaks {label}", resp, request, dedupe=label)
        if invalid and resp.ok and baseline_ok:
            add("NEG-ACCEPTED", "low", ep, f"{desc} -> {resp.status} accepted (schema says invalid)", resp, request, dedupe=desc)
        if write_on_missing and resp.ok:
            add("NEG-ACCEPTED", "medium", ep, f"{desc} -> {resp.status} on a nonexistent resource", resp, request, dedupe=desc)

    for ep in eps:
        k = key(ep)
        if k in skip:
            continue
        role = role_for(ep)
        budget = [cap]
        skipped_at_start = skipped[0]
        base_body = baseline(ep)
        values = {}
        ok_ids = True
        # --- resource id for endpoints under /collection/{id}
        if ep["path_params"]:
            if len(ep["path_params"]) == 1:
                coll = prefix_of(ep["path"], ep["path_params"][0])
                rid = make_resource(coll, owner_map.get(f"POST {coll}") or None)
                if rid is None:
                    notes.append(f"{k}: could not create a resource under {coll} (add BODIES for its POST); path-id probes only")
                    ok_ids = False
                values[ep["path_params"][0]] = rid if rid is not None else "__qa_nonexistent__"
            else:
                notes.append(f"{k}: several path params, only nonexistent-id probes")
                ok_ids = False
        path = fill(ep["path"], values)
        qdefaults = {q["name"]: str(example(q["schema"], spec_doc)) for q in ep.get("query_params", []) if q["required"]}

        def send(body=None, path_=None, query=None, raw=None, ctrl=False):
            if budget[0] <= 0:
                skipped[0] += 1
                return None
            budget[0] -= 1
            sent[0] += 1
            return api.call(role, ep["method"], path_ or path, body, {**qdefaults, **(query or {})} or None, raw=raw)

        base_resp = send(base_body)
        if base_resp is None:
            notes.append(f"{k}: request cap {cap} reached before the baseline request: endpoint not probed")
            continue
        baseline_ok = base_resp.ok
        base5[0] = base_resp.server_error
        if not baseline_ok and base_resp.status < 500:
            notes.append(f"{k}: baseline request got {base_resp.status} as {role}; accept-invalid checks skipped (add BODIES['{k}'])")
        check_response(ep, base_resp, "baseline", base_body)
        if baseline_ok and (ep["method"] == "DELETE" or re.search(r"cancel", ep["path"], re.I)):
            # the baseline changed the resource it targets: probes sent after it see the state it left (e.g. a 404 for a deleted id)
            notes.append(f"{k}: the baseline {ep['method']} changed the resource it targets; later probes of this endpoint see that state, "
                         "so they are not independent of the baseline")

        # --- body mutations
        schema = ep["body_schema"]
        if ep["method"] in WRITE_METHODS and schema is not None and (schema.get("type") == "object" or "properties" in schema):
            props = schema.get("properties", {})
            required = set(schema.get("required", []))
            body0 = base_body if isinstance(base_body, dict) else {}
            for name, sub in props.items():
                if name not in body0:
                    body0 = {**body0, name: example(sub, spec_doc)}
                for kind, value, invalid in field_mutations(name, sub, required, spec_doc):
                    body = {n: v for n, v in body0.items() if n != name} if value is MISSING else {**body0, name: value}
                    resp = send(body)
                    if resp is None:
                        continue                       # refused by the cap: counted in skipped, the next probes are counted too
                    check_response(ep, resp, f"{name}={kind}", {name: "<MISSING>" if value is MISSING else (str(value)[:40])}, invalid, baseline_ok)
                    if kind in SQLI_KINDS and _type_name(resolve(sub, spec_doc)) == "string":
                        verdict = sqli_differential(lambda v: send({**body0, name: v}), value, _benign)
                        if verdict is not None and verdict["sev"]:
                            add("NEG-INJECTION", verdict["sev"], ep, f"{name}: SQL-shaped input is interpreted by the server ({verdict['why']}); "
                                "SQL injection candidate (this engine sends no NoSQL payloads): reproduce before reporting", verdict["true"], {name: value}, dedupe=name)
                        elif verdict is not None and verdict["true"].ok and not verdict["benign"].ok:
                            add("NEG-ACCEPTED", "low", ep, f"{name}: SQL-shaped input is accepted ({verdict['true'].status}) while the benign value is "
                                f"rejected ({verdict['benign'].status}); acceptance alone is not injection evidence", verdict["true"], {name: value}, dedupe=name)
            # body level
            for kind, raw in [("malformed_json", b'{"a": '), ("json_array", b"[1,2,3]"), ("empty_body", b""), ("json_null", b"null")]:
                resp = send(raw=raw)
                if resp is not None:
                    check_response(ep, resp, f"body={kind}", None, kind in ("json_array", "json_null", "malformed_json"), baseline_ok)

        # --- path-id mutations (nonexistent / hostile ids)
        if len(ep["path_params"]) == 1 and k not in skip:
            for bad in PATH_IDS:
                resp = send(base_body, path_=fill(ep["path"], {ep["path_params"][0]: quote(bad, safe="%./")}))
                if resp is None:
                    continue
                shown = bad if len(bad) < 30 else bad[:12] + f"...({len(bad)} chars)"
                check_response(ep, resp, f"{ep['path_params'][0]}={shown!r}", None, False, baseline_ok,
                               write_on_missing=(ep["method"] in WRITE_METHODS and bad == "__qa_nonexistent__"))

        # --- query-param mutations
        for q in ep.get("query_params", []):
            sch = resolve(q["schema"], spec_doc)
            vals = [("invalid_enum", "__qa_invalid__"), ("nul", "a\x00b"), ("huge", BIG), ("sql_ish", "' OR '1'='1' --"), ("sql_comment", "' OR 1=1--"),
                    ("union_probe", "')) UNION SELECT 1,2,3,4,5,6,7,8,9--"), ("repeated", ["a", "b"])]
            if _type_name(sch) in ("integer", "number"):
                vals += [("negative", "-1"), ("huge_number", "9" * 30), ("not_a_number", "abc")]
            for kind, v in vals:
                resp = send(base_body, query={q["name"]: v})
                if resp is None:
                    continue
                check_response(ep, resp, f"?{q['name']}={kind}", None, False, baseline_ok)
                # the same differential as bodies: a tagged TRUE / FALSE / benign comparison; a payload that merely matches data
                # the engine stored (exact-match filter) cannot answer differently, because the tagged form was never stored
                if kind in SQLI_KINDS_ALL and isinstance(v, str):
                    verdict = sqli_differential(lambda x: send(base_body, query={q["name"]: x}), v, _benign)
                    if verdict is not None and verdict["sev"]:
                        add("NEG-INJECTION", verdict["sev"], ep, f"?{q['name']}={value_repr(v)}: the query/filter interprets the input "
                            f"({verdict['why']}); injection candidate: reproduce before reporting", verdict["true"], {q["name"]: v}, dedupe=q["name"])

        # --- mass assignment (create / update with privileged extras)
        if ep["method"] in ("POST", "PUT", "PATCH") and isinstance(base_body, dict):
            props = set((schema or {}).get("properties", {}))
            for variant in (PRIVILEGED, PRIVILEGED_ALT):
                extras = {n: v for n, v in variant.items() if n not in props}
                control = send(_unique(base_body))
                resp = send({**_unique(base_body), **extras})
                if resp is not None and resp.ok and resp.json is not None:
                    after = None
                    new_id = extract_id(resp.json)
                    if new_id is not None and ep["method"] == "POST":
                        for g in eps:
                            if g["method"] == "GET" and len(g["path_params"]) == 1 \
                                    and prefix_of(g["path"], g["path_params"][0]) == ep["path"].rstrip("/"):
                                after = api.call(role, "GET", fill(g["path"], {g["path_params"][0]: new_id}))
                                sent[0] += 1
                                break
                    elif ep["method"] in ("PUT", "PATCH") and values:
                        for g in eps:
                            if g["method"] == "GET" and g["path"] == ep["path"]:
                                after = api.call(role, "GET", path)
                                sent[0] += 1
                                break
                    for name, value in extras.items():
                        got = _find_key(resp.json, name)
                        if not any(v == value for v in got):
                            continue
                        ctrl_vals = _find_key(control.json, name) if control is not None and control.json is not None else []
                        persisted = after is not None and after.ok and any(v == value for v in _find_key(after.json, name))
                        differs = bool(ctrl_vals) and all(v != value for v in ctrl_vals)
                        if persisted or differs:
                            sev = "high" if name in ROLE_KEYS else "medium"
                            why = "read-back shows it stored" if persisted else f"control request returned {ctrl_vals[:1]}"
                            add("MASS-ASSIGN", sev, ep, f"extra field {name}={value!r} is applied ({why})", resp, {name: value}, dedupe=name)
                        elif after is None:
                            add("MASS-ASSIGN", "low", ep, f"extra field {name}={value!r} is reflected in the response (no read-back endpoint "
                                "to prove it is stored; verify manually)", resp, {name: value}, dedupe=name)

        # --- cross-reference IDOR: body field pointing at another user's resource
        if ep["method"] in ("POST", "PUT", "PATCH") and isinstance(base_body, dict) and "user_b" in api.roles and role != "user_b":
            for name in list(base_body):
                m = re.fullmatch(r"(.+?)(?:_id|Id|ID)", name)
                if not m:
                    continue
                stem = re.sub(r"[^a-z]", "", m.group(1).lower())
                coll = next((c for c in creators if re.sub(r"[^a-z]", "", c.split("/")[-1].lower()).rstrip("s") == stem.rstrip("s")), None)
                if not coll:
                    continue
                if budget[0] <= 0:
                    skipped[0] += 2                    # the control and the attack request this check would send
                    continue
                owner = owner_map.get(f"POST {coll}", "user_a")
                if owner == "user_b" or owner not in api.roles:
                    continue
                victim_id = make_resource(coll, owner)
                own_id = make_resource(coll, "user_b")
                if victim_id is None or own_id is None:
                    continue
                ctrl = api.call("user_b", ep["method"], path, {**base_body, name: own_id})
                att = api.call("user_b", ep["method"], path, {**base_body, name: victim_id})
                sent[0] += 2
                if ctrl.ok and att.ok:
                    # medium: the server accepted the reference. No effect on user_a's data was read back, so access is not proven
                    add("XREF-IDOR", "medium", ep, f"user_b's request referencing user_a's {coll} via body field {name} was accepted "
                        f"({att.status}); no effect on user_a's data was read back (not proven access)", att,
                        {name: victim_id}, dedupe=name)

        if skipped[0] > skipped_at_start:
            notes.append(f"{k}: request cap {cap} reached: {skipped[0] - skipped_at_start} probe(s) not sent "
                         "(later field mutations, mass-assign, path and query probes); raise NEG_MAX in qa-spec.py to cover them")

    res = {"engine": "negative", "findings": _group(findings), "notes": notes, "requests": sent[0], "raw_findings": len(findings),
           "probes_skipped": skipped[0]}
    if notes:
        return trust.mark(res, trust.DEGRADED, f"{len(notes)} probe group(s) skipped or limited: " + notes[0][:140])
    return trust.mark(res, trust.RAN_OK)


def _group(findings):
    """One finding per (kind, endpoint) for the noisy classes; the individual mutations stay in `examples`."""
    merge = {"NEG-5XX", "NEG-NO-RESPONSE", "NEG-ACCEPTED", "NEG-LEAK"}
    out, buckets = [], {}
    for f in findings:
        if f["kind"] in merge:
            buckets.setdefault((f["kind"], f["endpoint"]), []).append(f)
        else:
            out.append(f)
    for (kind, endpoint), group in buckets.items():
        shown = "; ".join(g["detail"].split(" -> ")[0] for g in group[:8]) + (f"; +{len(group) - 8} more" if len(group) > 8 else "")
        out.append({"kind": kind, "severity": max((g["severity"] for g in group), key={"low": 0, "medium": 1, "high": 2}.get), "endpoint": endpoint,
                    "detail": f"{len(group)} input(s): {shown}", "status": group[0]["status"], "response": group[0]["response"],
                    "examples": [{"detail": g["detail"], "request": g["request"], "status": g["status"]} for g in group]})
    return out
