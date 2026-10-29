"""Shared helpers for the QA engines: OpenAPI loading, schema -> example / Hypothesis strategy,
and a role-aware HTTP client that only talks to local hosts. Stdlib only (hypothesis optional,
imported lazily by `strategy`)."""
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BODY_CAP = 8000          # chars of each response kept in api.log["body"]
MAX_READ = 4_000_000       # bytes read from any one response; a hostile or buggy app cannot make the engine hold a huge body
TRANSPORT_ERROR = 599    # pseudo-status: no HTTP response at all (refused, reset, timeout). NOT a server answer, so not a 5xx finding


def assert_local(url: str) -> None:
    """Refuse anything that is not an http(s) URL on a loopback host (file://localhost/..., ftp://localhost/... are refused too)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in LOCAL_HOSTS:
        raise SystemExit(f"refusing non-local target: {url}")


_PLAIN_HEADERS = {"accept", "accept-encoding", "accept-language", "user-agent", "connection"}


class _LocalRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to local hosts. A redirect to anywhere else is not followed (the 3xx comes back as the response),
    and credentials are dropped when the redirect changes host:port, so a role token never leaves this machine."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlparse(urllib.parse.urljoin(req.full_url, newurl))
        if target.scheme not in ("http", "https") or target.hostname not in LOCAL_HOSTS:
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        origin, new_origin = urllib.parse.urlparse(req.full_url), target
        if new is not None and (origin.scheme, origin.netloc) != (new_origin.scheme, new_origin.netloc):
            # another scheme or host:port: drop EVERY request header except the plain ones. A role's credential can be any
            # header name (X-API-Key, X-Auth-Token, a CSRF header), not only Authorization / Cookie.
            for name in list(new.headers) + list(new.unredirected_hdrs):
                if name.lower() not in _PLAIN_HEADERS:
                    new.remove_header(name)
        return new


# ProxyHandler({}) = never use HTTP(S)_PROXY / the Windows proxy settings: engine traffic goes straight to the local target, so a
# role token cannot be handed to a proxy (and a dead proxy cannot turn every probe into a fake 599).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _LocalRedirects)


def urlopen_local(url, timeout=30):
    """urlopen for LOCAL targets only: refuses non-local hosts, ignores proxy settings, follows only local redirects."""
    assert_local(url if isinstance(url, str) else url.full_url)
    return _OPENER.open(url, timeout=timeout)


def local_url(base: str, path: str) -> str:
    """base + path, refusing anything that would leave the base's host:port (e.g. path '@evil.example/x' or '//evil.example')."""
    if not path.startswith("/") or path.startswith("//") or "\\" in path.split("?", 1)[0]:
        raise SystemExit(f"refusing path that is not a plain absolute path: {path!r}")
    url = base + path
    assert_local(url)
    if urllib.parse.urlparse(url).netloc != urllib.parse.urlparse(base).netloc:
        raise SystemExit(f"refusing path that changes the target host: {path!r}")
    return url


class Resp:
    def __init__(self, status: int, text: str, headers=None):
        self.status, self.text, self.headers = status, text, headers or {}
        try:
            self.json = json.loads(text) if text else None
        except ValueError:
            self.json = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def transport(self) -> bool:
        """True when there was no HTTP response (connection refused / reset / timeout), see TRANSPORT_ERROR."""
        return self.status == TRANSPORT_ERROR

    @property
    def server_error(self) -> bool:
        return 500 <= self.status < 600 and not self.transport

    def __repr__(self):
        return f"<Resp {self.status} {self.text[:80]!r}>"


class Api:
    """roles: {"user_a": {"Authorization": "Bearer ..."}, ...}; "anon" (no headers) always exists."""

    def __init__(self, base_url: str, roles: dict | None = None):
        assert_local(base_url)
        self.base = base_url.rstrip("/")
        self.roles = {"anon": {}, **(roles or {})}
        self.log: list[dict] = []

    @property
    def base_url(self) -> str:
        """Alias of `base`: the name a qa-spec author reaches for first."""
        return self.base

    def call(self, role: str, method: str, path: str, body=None, query: dict | None = None,
             raw: bytes | None = None, headers: dict | None = None) -> Resp:
        """raw: send these bytes as the body instead of json.dumps(body) (malformed JSON probes);
        headers: extra request headers (override the role's)."""
        url = local_url(self.base, path)          # raises before any network I/O
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        headers = {"Content-Type": "application/json", **self.roles.get(role, {}), **(headers or {})}
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        msg = None
        try:
            with _OPENER.open(req, timeout=30) as r:
                msg = r.headers
                resp = Resp(r.status, r.read(MAX_READ).decode("utf-8", "replace"), dict(r.headers))
        except urllib.error.HTTPError as e:
            msg = e.headers
            resp = Resp(e.code, e.read(MAX_READ).decode("utf-8", "replace"), dict(e.headers))
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, http.client.HTTPException) as e:
            resp = Resp(TRANSPORT_ERROR, f"connection error: {e}")
        self.log.append({"role": role, "method": method, "path": path, "status": resp.status,
                         "request": body if raw is None else "<raw>", "response": resp.text[:300], "query": query,
                         "body": resp.text[:BODY_CAP],          # full-ish body for the invariant miner; "response" stays short for reports
                         "resp_headers": header_dict(msg)})     # every response header; Set-Cookie values all kept
        return resp


def header_dict(message) -> dict:
    """Response headers for api.log (key 'resp_headers'): lower-cased names. A repeated header is joined with ', ', except
    Set-Cookie, which is joined with newlines so every cookie survives (an Expires date contains a comma)."""
    out: dict = {}
    for name, value in (message.items() if message is not None else []):
        low = name.lower()
        out[low] = out[low] + ("\n" if low == "set-cookie" else ", ") + value if low in out else value
    return out


# ---------- OpenAPI ----------

SPEC_MAX_READ = 32_000_000      # bytes: an OpenAPI document larger than this is refused (it was read whole before)


def load_openapi(src: str) -> dict:
    """src: local URL (http://127.0.0.1:8000/openapi.json) or a file path. The document is capped at SPEC_MAX_READ bytes.
    The timeout is per socket operation, not for the whole download."""
    if urllib.parse.urlparse(src).scheme in ("http", "https"):
        assert_local(src)
        with _OPENER.open(src, timeout=30) as r:
            raw = r.read(SPEC_MAX_READ + 1)
    else:
        if Path(src).stat().st_size > SPEC_MAX_READ:
            raise SystemExit(f"refusing OpenAPI file over {SPEC_MAX_READ} bytes: {src}")
        raw = Path(src).read_bytes()
    if len(raw) > SPEC_MAX_READ:
        raise SystemExit(f"refusing OpenAPI document over {SPEC_MAX_READ} bytes: {src}")
    return json.loads(raw.decode("utf-8"))


def resolve(schema, spec, depth=0):
    if not isinstance(schema, dict) or depth > 8:
        return schema or {}
    if "$ref" in schema:
        node = spec
        for part in schema["$ref"].lstrip("#/").split("/"):
            part = urllib.parse.unquote(part).replace("~1", "/").replace("~0", "~")      # RFC 6901 + URI fragment encoding
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return resolve(node, spec, depth + 1)
    for key in ("allOf",):
        if key in schema:
            merged: dict = {}
            for sub in schema[key]:
                sub = resolve(sub, spec, depth + 1)
                merged = {**merged, **sub, "properties": {**merged.get("properties", {}), **sub.get("properties", {})},
                          "required": merged.get("required", []) + sub.get("required", [])}
            return merged
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [resolve(s, spec, depth + 1) for s in schema[key]]
            options = [o for o in options if o.get("type") != "null"] or options
            return options[0] if options else {}
    return schema


def endpoints(spec: dict) -> list[dict]:
    """[{method, path, params, tags, summary, body_schema, query_schema}] for every operation."""
    out = []
    for path, item in (spec.get("paths") or {}).items():
        shared = item.get("parameters", [])
        for method in METHODS:
            op = item.get(method.lower())
            if not isinstance(op, dict):          # `"get": {}` is a (bare) operation too; only a non-object is skipped
                continue
            params = shared + op.get("parameters", [])
            body = None
            content = (op.get("requestBody") or {}).get("content", {})
            if "application/json" in content:
                body = resolve(content["application/json"].get("schema", {}), spec)
            out.append({
                "method": method, "path": path,
                "path_params": re.findall(r"\{(\w+)\}", path),
                "tags": op.get("tags", []), "summary": op.get("summary", ""),
                "body_schema": body, "spec": spec,
                "query_required": [p["name"] for p in params if p.get("in") == "query" and p.get("required")],
                "query_params": [{"name": p["name"], "schema": resolve(p.get("schema", {}), spec), "required": bool(p.get("required"))}
                                 for p in params if p.get("in") == "query"],
            })
    return out


def key(ep: dict) -> str:
    return f"{ep['method']} {ep['path']}"


def fill(path: str, values: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1), "1")), path)


def prefix_of(path: str, param: str) -> str:
    """'/orders/{order_id}/status', 'order_id' -> '/orders'  (the collection a path param belongs to)."""
    return path.split("{" + param + "}")[0].rstrip("/")


def extract_id(body):
    if isinstance(body, dict):
        for k in ("id", "_id", "uuid", "pk"):
            if k in body and isinstance(body[k], (str, int)):
                return body[k]
        for k, v in body.items():
            if k.endswith("_id") and isinstance(v, (str, int)):
                return v
        for k in ("data", "result", "item"):
            if isinstance(body.get(k), dict):
                return extract_id(body[k])
    return None


# ---------- schema -> example ----------

# One valid value per string format, shared by example() and strategy(). Same uuid as schema_fuzz.SAMPLE (v4, RFC 4122 variant).
FORMAT_SAMPLES = {"email": "qa@example.com", "date-time": "2026-01-01T00:00:00Z", "date": "2026-01-01",
                  "uuid": "3f2504e0-4f89-41d3-9a0c-0305e82c3301", "uri": "https://example.com/qa",
                  "ipv4": "192.0.2.1", "hostname": "qa.example.com"}     # ipv4: TEST-NET-1 (RFC 5737), never routed


def example(schema, spec, depth=0):
    """Smallest valid-looking value for a JSON schema."""
    schema = resolve(schema, spec)
    if "example" in schema:
        return schema["example"]
    if "enum" in schema:
        return schema["enum"][0]
    t = schema.get("type")
    fmt = schema.get("format")
    if t == "object" or "properties" in schema:
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if depth > 5:
            return {}
        return {k: example(v, spec, depth + 1) for k, v in props.items() if k in required or depth == 0}
    if t == "array":
        n = max(1, schema.get("minItems", 1))
        return [example(schema.get("items", {}), spec, depth + 1) for _ in range(n)] if depth <= 5 else []
    if t in ("integer", "number"):
        lo = schema.get("minimum", schema["exclusiveMinimum"] + 1 if "exclusiveMinimum" in schema else 1)
        value = max(lo, 1)
        if "maximum" in schema:
            value = min(value, schema["maximum"])
        return int(value) if t == "integer" else float(value)
    if t == "boolean":
        return True
    if fmt in FORMAT_SAMPLES:
        return FORMAT_SAMPLES[fmt]
    # `pattern` is NOT honoured: a pattern-only string still gets the plain "qa..." value below; give the schema an example or enum instead.
    n = max(schema.get("minLength", 1), 1)
    return ("qa" * n)[:max(n, 2) if schema.get("maxLength", 99) >= 2 else schema["maxLength"]]


def strategy(schema, spec, depth=0):
    """Hypothesis strategy for a JSON schema (valid inputs, boundaries included)."""
    from hypothesis import strategies as st
    schema = resolve(schema, spec)
    if "enum" in schema:
        return st.sampled_from(schema["enum"])
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if depth > 4:
            return st.just({})
        fields = {k: strategy(v, spec, depth + 1) for k, v in props.items()}
        req = {k: v for k, v in fields.items() if k in required}
        opt = {k: v for k, v in fields.items() if k not in required}
        return st.fixed_dictionaries(req, optional=opt)
    if t == "array":
        item = strategy(schema.get("items", {}), spec, depth + 1)
        return st.lists(item, min_size=schema.get("minItems", 0), max_size=min(schema.get("maxItems", 4), 4))
    if t == "integer":
        lo = schema.get("minimum", schema.get("exclusiveMinimum", -1) + 1 if "exclusiveMinimum" in schema else -5)
        hi = schema.get("maximum", lo + 50)
        return st.integers(min_value=int(lo), max_value=max(int(lo), int(hi)))      # maximum < minimum is an invalid schema: do not crash
    if t == "number":
        lo = schema.get("minimum", 0)
        return st.floats(min_value=float(lo), max_value=max(float(lo), float(schema.get("maximum", lo + 1000))),
                         allow_nan=False, allow_infinity=False)
    if t == "boolean":
        return st.booleans()
    if schema.get("format") in FORMAT_SAMPLES:
        return st.just(FORMAT_SAMPLES[schema["format"]])
    # `pattern` is NOT honoured: a pattern-only string still draws plain printable text.
    lo, hi = schema.get("minLength", 0), min(schema.get("maxLength", 20), 20)
    return st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=lo, max_size=max(lo, hi))
