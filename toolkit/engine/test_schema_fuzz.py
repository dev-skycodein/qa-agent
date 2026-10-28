"""Tests for schema_fuzz.py (the `schema` engine): validator table, example enumeration, and one BUGGY app per finding kind
plus a clean variant that must yield zero findings. Every test starts its own stdlib ThreadingHTTPServer on 127.0.0.1.

  python toolkit/engine/test_schema_fuzz.py        (stdlib only; also collectable by pytest)
"""
import json
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402
import schema_fuzz as sf  # noqa: E402
import trust  # noqa: E402

ROLES = {"user_a": {"Authorization": "Bearer t-a"}}


class App:
    """Records every request; routes: {"METHOD /path": fn(body, query) -> (status, payload)}. A raising route answers 500."""

    def __init__(self, routes):
        self.routes, self.seen = routes, []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode("utf-8") if n else ""
                parts = urllib.parse.urlsplit(self.path)
                body = json.loads(raw) if raw else None
                query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
                outer.seen.append({"method": self.command, "path": parts.path, "body": body, "query": query,
                                   "auth": self.headers.get("Authorization")})
                fn = outer._route_for(self.command, parts.path)
                try:
                    status, payload = fn(body, query) if fn else (404, {"error": "no route"})
                except Exception:
                    status, payload = 500, 'Traceback (most recent call last):\n  File "/srv/app.py", line 3'
                text = payload if isinstance(payload, str) else json.dumps(payload)
                data = text.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _go

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def _route_for(self, method, path):
        """An exact route, else a route whose {placeholders} each match one path segment (e.g. 'GET /gadgets/{gid}')."""
        fn = self.routes.get(f"{method} {path}")
        if fn is not None:
            return fn
        for k, f in self.routes.items():
            m, _, tpl = k.partition(" ")
            pat = "^" + "[^/]+".join(re.escape(x) for x in re.split(r"\{\w+\}", tpl)) + "$"
            if m == method and "{" in tpl and re.match(pat, path):
                return f
        return None

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def _json_body(schema):
    return {"content": {"application/json": {"schema": schema}}}


CARD = {"type": "object", "required": ["kind", "card_no"],
        "properties": {"kind": {"enum": ["card"]}, "card_no": {"type": "string", "minLength": 4, "maxLength": 19}}}
BANK = {"type": "object", "required": ["kind", "iban"],
        "properties": {"kind": {"enum": ["bank"]}, "iban": {"type": "string", "minLength": 8}}}
ITEM = {"type": "object", "required": ["quantity"],
        "properties": {"quantity": {"type": "integer", "minimum": 0, "maximum": 10}, "note": {"type": "string", "nullable": True}}}
NOTE = {"type": "object", "required": ["text"], "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 50}}}
NOTE_RESP = {"type": "object", "required": ["id", "price"], "additionalProperties": False,
             "properties": {"id": {"type": "integer"}, "price": {"type": "integer"},
                            "tags": {"type": "array", "items": {"type": "string"}}, "status": {"enum": ["open", "closed"]}}}
NOTE_ERR = {"type": "object", "required": ["detail"], "properties": {"detail": {"type": "string"}}}
ORDER_RESP = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}, "kind": {"type": "string"}}}
PING_OK = {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}


def spec_full():
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
        "/orders": {"post": {"requestBody": _json_body({"oneOf": [CARD, BANK]}),
                             "responses": {"201": {"description": "ok", **_json_body(ORDER_RESP)}}}},
        "/items": {"post": {"requestBody": _json_body(ITEM),
                            "responses": {"201": {"description": "ok", **_json_body({"type": "object", "required": ["id"],
                                                                                     "properties": {"id": {"type": "integer"}}})}}}},
        "/notes": {"post": {"requestBody": _json_body(NOTE),
                            "responses": {"201": {"description": "ok", **_json_body(NOTE_RESP)},
                                          "400": {"description": "bad", **_json_body(NOTE_ERR)}}}},
        "/ping": {"get": {"parameters": [{"name": "mode", "in": "query", "schema": {"enum": ["a", "b", "c"]}}],
                          "responses": {"200": {"description": "ok", **_json_body(PING_OK)}}}},
    }}


def clean_routes():
    return {
        "POST /orders": lambda b, q: (201, {"id": 1, "kind": b["kind"]}),
        "POST /items": lambda b, q: (201, {"id": 7}),
        "POST /notes": lambda b, q: (201, {"id": 3, "price": 12, "tags": ["a"], "status": "open"}),
        "GET /ping": lambda b, q: (200, {"ok": True}),
    }


def run_engine(routes, spec=None, qa=None, **kw):
    app = App(routes)
    try:
        client = api.Api(app.url, ROLES)
        res = sf.run(client, spec or spec_full(), qa or SimpleNamespace(), **kw)
        return res, app
    finally:
        app.stop()


def pairs(res):
    return {(f["kind"], f["endpoint"]) for f in res["findings"]}


def kinds_of(res, kind):
    return [f for f in res["findings"] if f["kind"] == kind]


# ---------- validator table ----------

SPEC_REFS = {"components": {"schemas": {"Pet": {"type": "string"}}}}

VALIDATOR_TABLE = [
    ({"type": "integer"}, 3, True),
    ({"type": "integer"}, 3.5, False),
    ({"type": "integer"}, 3.0, True),
    ({"type": "integer"}, True, False),
    ({"type": "number"}, True, False),
    ({"type": "number"}, 2.5, True),
    ({"type": "string", "minLength": 2}, "a", False),
    ({"type": "string", "minLength": 2}, "ab", True),
    ({"type": "string", "maxLength": 3}, "abcd", False),
    ({"type": "string", "format": "email"}, "nope", False),
    ({"type": "string", "format": "email"}, "a@b.co", True),
    ({"type": "string", "format": "date-time"}, "2026-01-01T00:00:00Z", True),
    ({"type": "string", "format": "date-time"}, "2026-01-01", False),
    ({"type": "string", "pattern": "^a+$"}, "aab", False),
    ({"type": "string", "pattern": "^a+$"}, "aa", True),
    ({"type": "string", "pattern": "(["}, "x", True),                       # an invalid pattern in the spec is ignored
    ({"type": "integer", "minimum": 1, "maximum": 5}, 0, False),
    ({"type": "integer", "minimum": 1, "maximum": 5}, 5, True),
    ({"type": "integer", "minimum": 1, "maximum": 5}, 6, False),
    ({"type": "integer", "exclusiveMinimum": 0}, 0, False),                # 3.1 numeric exclusive form
    ({"type": "integer", "exclusiveMinimum": 0}, 1, True),
    ({"type": "integer", "minimum": 0, "exclusiveMinimum": True}, 0, False),   # 3.0 boolean exclusive form
    ({"type": "integer", "minimum": 0, "exclusiveMinimum": True}, 1, True),
    ({"type": "number", "exclusiveMaximum": 10}, 10, False),
    ({"type": "number", "exclusiveMaximum": 10}, 9.5, True),
    ({"type": "array", "minItems": 1, "items": {"type": "string"}}, [], False),
    ({"type": "array", "minItems": 1, "items": {"type": "string"}}, ["a"], True),
    ({"type": "array", "items": {"type": "string"}}, [1], False),
    ({"type": "array", "maxItems": 1}, [1, 2], False),
    ({"type": "object"}, [], False),
    ({"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}, {}, False),
    ({"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}, {"a": 1}, False),
    ({"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}, {"a": "x"}, True),
    ({"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}, {"a": "x", "b": 1}, False),
    ({"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": False}, {"a": "x"}, True),
    ({"type": "string", "nullable": True}, None, True),
    ({"type": "string"}, None, False),
    ({"type": ["string", "null"]}, None, True),
    ({"enum": ["a", "b"]}, "c", False),
    ({"enum": ["a", "b"]}, "a", True),
    ({"enum": [1]}, True, False),                                             # JSON true is not 1
    ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 1.5, False),
    ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, "x", True),
    ({"oneOf": [{"type": "string"}, {"type": "integer"}]}, "x", True),
    ({"allOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]}, {"a": 1}, False),
    ({"allOf": [{"type": "object", "required": ["a"]}, {"type": "object", "required": ["b"]}]}, {"a": 1, "b": 2}, True),
    ({"$ref": "#/components/schemas/Pet"}, 1, False),
    ({"$ref": "#/components/schemas/Pet"}, "x", True),
    ({}, {"anything": [1, None]}, True),
]


def test_validator_table():
    for schema, value, want_valid in VALIDATOR_TABLE:
        got = sf.check(value, schema, SPEC_REFS)
        assert (not got) == want_valid, f"schema={schema} value={value!r} expected valid={want_valid}, errors={got}"


def test_validator_reports_exact_path_and_value():
    schema = {"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"type": "string"}}}}}
    errs = sf.check({"a": {"b": 12.5}}, schema, {})
    assert errs == [("$.a.b", "expected string, got number", 12.5)], errs


def test_external_ref_is_unresolvable_not_silently_valid():
    try:
        sf.check(1, {"$ref": "http://evil.example/s.json"}, {})
    except sf.Unresolvable as e:
        assert "external" in str(e)
    else:
        raise AssertionError("an external $ref was accepted as valid")


# ---------- example enumeration ----------

def test_branch_examples_cover_every_branch_enum_nullable_and_boundary():
    schema = {"oneOf": [CARD, BANK]}
    labels = [e["label"] for e in sf.branch_examples(schema, {}, 40)]
    assert any(l.startswith("oneOf[0]") for l in labels) and any(l.startswith("oneOf[1]") for l in labels), labels
    bodies = [e["value"] for e in sf.branch_examples(schema, {}, 40)]
    assert {"kind": "bank", "iban": "xxxxxxxx"} in bodies, bodies          # bank branch at its minLength boundary
    q = sf.branch_examples(ITEM, {}, 40)
    values = {json.dumps(e["value"], sort_keys=True) for e in q}
    assert json.dumps({"quantity": 0}, sort_keys=True) in values and json.dumps({"quantity": 10}, sort_keys=True) in values
    assert json.dumps({"quantity": 1, "note": None}, sort_keys=True) in values   # nullable null, one field changed
    enum3 = {"type": "object", "required": ["s"], "properties": {"s": {"enum": ["a", "b", "c"]}}}
    assert {e["value"]["s"] for e in sf.branch_examples(enum3, {}, 40)} == {"a", "b", "c"}


def test_branch_examples_are_all_schema_valid_and_baseline_first():
    for schema in (CARD, BANK, ITEM, NOTE, {"oneOf": [CARD, BANK]}, {"type": "array", "items": ITEM, "maxItems": 3}):
        out = sf.branch_examples(schema, {}, 40)
        assert out, schema
        for e in out:
            assert not sf.check(e["value"], schema, {}), (schema, e)
    assert sf.branch_examples(ITEM, {}, 40)[0]["value"] == {"quantity": 1}  # natural value first, not the bound


def test_uncovered_branch_is_reported():
    schema = {"oneOf": [CARD, {"type": "object", "required": ["x"], "properties": {"x": {"type": "string", "minLength": 9, "maxLength": 3}}}]}
    assert sf.uncovered_branches(schema, {}) == ["oneOf[1]"]


# ---------- engine: clean variant must yield ZERO findings ----------

def test_clean_app_zero_findings_and_ran_ok():
    res, app = run_engine(clean_routes())
    assert res["findings"] == [], res["findings"]
    assert trust.resolve(res)[0] == trust.RAN_OK, res
    assert app.seen, "the engine sent nothing"


# ---------- SCHEMA-VALID-5XX ----------

def test_schema_valid_5xx_buggy_branch_is_found():
    routes = clean_routes()

    def orders(b, q):
        if b["kind"] == "bank":                 # the second oneOf branch is valid per the spec and crashes
            raise RuntimeError("bank branch not implemented")
        return 201, {"id": 1, "kind": b["kind"]}
    routes["POST /orders"] = orders
    res, _ = run_engine(routes)
    assert pairs(res) == {("SCHEMA-VALID-5XX", "POST /orders")}, res["findings"]
    f = res["findings"][0]
    assert f["status"] == 500 and '"bank"' in f["detail"] and "identical resend -> 500" in f["detail"], f


def test_5xx_that_does_not_reproduce_is_not_reported():
    routes = clean_routes()
    calls = {"n": 0}

    def flaky(b, q):
        if b["kind"] == "bank":
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("one-off")
        return 201, {"id": 1, "kind": b["kind"]}
    routes["POST /orders"] = flaky
    res, _ = run_engine(routes)
    assert kinds_of(res, "SCHEMA-VALID-5XX") == [], res["findings"]
    assert any("not reproduced" in n for n in res["notes"]), res["notes"]


# ---------- SCHEMA-REJECTS-VALID ----------

def test_rejects_valid_boundary_buggy_is_found():
    routes = clean_routes()

    def items(b, q):
        if b["quantity"] < 1:                   # minimum 0 is valid per the spec; the app wrongly says no
            return 422, {"error": "quantity must be >= 1"}
        return 201, {"id": 7}
    routes["POST /items"] = items
    res, _ = run_engine(routes)
    assert pairs(res) == {("SCHEMA-REJECTS-VALID", "POST /items")}, res["findings"]
    f = res["findings"][0]
    assert f["status"] == 422 and f["control"] == "baseline" and "quantity" in f["detail"], f


def test_rejects_without_a_2xx_control_is_not_reported():
    routes = clean_routes()
    routes["POST /items"] = lambda b, q: (422, {"error": "always no"})   # the baseline itself is rejected
    res, _ = run_engine(routes)
    assert kinds_of(res, "SCHEMA-REJECTS-VALID") == [], res["findings"]
    assert res["status"] == trust.DEGRADED, res
    assert any("no 2xx control" in n for n in res["notes"]), res["notes"]


def test_conflict_looking_4xx_is_not_reported_as_rejects():
    routes = clean_routes()
    routes["POST /items"] = lambda b, q: ((409, {"error": "already exists"}) if b["quantity"] == 0 else (201, {"id": 7}))
    res, _ = run_engine(routes)
    assert kinds_of(res, "SCHEMA-REJECTS-VALID") == [], res["findings"]


# ---------- SCHEMA-DRIFT ----------

def test_response_drift_buggy_is_found_with_path_and_value():
    routes = clean_routes()

    def notes(b, q):
        if len(b["text"]) >= 50:                # documented 400 answers with the wrong shape
            return 400, {"msg": "too long"}
        return 201, {"id": 3, "price": "12.50", "tags": [5], "status": "open", "debug": "x"}
    routes["POST /notes"] = notes
    res, _ = run_engine(routes)
    assert pairs(res) == {("SCHEMA-DRIFT", "POST /notes"), ("SCHEMA-REJECTS-VALID", "POST /notes")}, res["findings"]
    drift = [(f["path"], f["value"]) for f in kinds_of(res, "SCHEMA-DRIFT")]
    assert ("$.price", "12.50") in drift, drift
    assert ("$.tags[0]", 5) in drift, drift
    assert ("$.debug", "x") in drift, drift
    assert ("$.detail", {"msg": "too long"}) in drift, drift     # the documented 400 is checked too
    f = [x for x in kinds_of(res, "SCHEMA-DRIFT") if x["path"] == "$.price"][0]
    assert "12.50" in f["detail"] and f["severity"] == "low", f


def test_non_json_body_against_json_schema_is_drift():
    routes = clean_routes()
    routes["GET /ping"] = lambda b, q: (200, "<html>maintenance</html>")
    res, _ = run_engine(routes)
    assert ("SCHEMA-DRIFT", "GET /ping") in pairs(res), res["findings"]


# ---------- id discovery, roles, pattern branches, boundaries and required fields ----------

GADGET = {"type": "object", "required": ["id", "name"], "properties": {"id": {"type": "integer"}, "name": {"type": "string"}}}
GADGET_LIST = {"type": "object", "required": ["items"], "properties": {"items": {"type": "array", "items": GADGET}}}
GADGET_IN = {"type": "object", "required": ["name"], "properties": {"name": {"type": "string", "minLength": 1}}}
PRICE_IN = {"type": "object", "required": ["price"], "properties": {"price": {"oneOf": [
    {"type": "number", "minimum": 0}, {"type": "string", "pattern": r"^\d+(\.\d{1,2})?$"}]}}}
PRICE_OUT = {"type": "object", "required": ["id", "price"], "properties": {"id": {"type": "integer"}, "price": {"type": "number"}}}
TITLE_IN = {"type": "object", "required": ["title"], "properties": {"title": {"type": "string", "minLength": 1, "maxLength": 200}}}
TITLE_OUT = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}
REVIEW_IN = {"type": "object", "required": ["rating"], "properties": {
    "rating": {"type": "integer", "minimum": 1, "maximum": 5}, "text": {"type": "string", "maxLength": 2000, "default": ""}}}
REVIEW_OUT = {"type": "object", "required": ["id", "rating", "text"], "properties": {
    "id": {"type": "integer"}, "rating": {"type": "integer"}, "text": {"type": "string"}}}


def _resp(schema):
    return {"description": "ok", **_json_body(schema)}


def spec_round2():
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
        "/gadgets": {"get": {"responses": {"200": _resp(GADGET_LIST)}},
                     "post": {"requestBody": _json_body(GADGET_IN), "responses": {"201": _resp(GADGET)}}},
        "/gadgets/{gid}": {"parameters": [{"name": "gid", "in": "path", "required": True, "schema": {"type": "integer"}}],
                           "get": {"responses": {"200": _resp(GADGET)}}},
        "/books": {"get": {"responses": {"200": _resp(GADGET_LIST)}}},
        "/prices": {"post": {"requestBody": _json_body(PRICE_IN), "responses": {"201": _resp(PRICE_OUT)}}},
        "/titles": {"post": {"requestBody": _json_body(TITLE_IN), "responses": {"201": _resp(TITLE_OUT)}}},
        "/books/{bid}/reviews": {"parameters": [{"name": "bid", "in": "path", "required": True, "schema": {"type": "integer"}}],
                                 "post": {"requestBody": _json_body(REVIEW_IN), "responses": {"201": _resp(REVIEW_OUT)}}},
    }}


def clean_round2():
    return {
        "GET /gadgets": lambda b, q: (200, {"items": [{"id": 42, "name": "x"}]}),
        "POST /gadgets": lambda b, q: (201, {"id": 7, "name": b["name"]}),
        "GET /gadgets/{gid}": lambda b, q: (200, {"id": 42, "name": "x"}),
        "GET /books": lambda b, q: (200, {"items": [{"id": 7, "name": "b"}]}),
        "POST /prices": lambda b, q: (201, {"id": 1, "price": float(b["price"])}),
        "POST /titles": lambda b, q: (201, {"id": 1}),
        "POST /books/{bid}/reviews": lambda b, q: (201, {"id": 5, "rating": b["rating"], "text": b.get("text", "")}),
    }


def test_round2_clean_app_zero_findings_and_no_id_gaps():
    res, _ = run_engine(clean_round2(), spec=spec_round2())
    assert res["findings"] == [], res["findings"]
    assert not [n for n in res["notes"] if n.startswith("GAP") and ("gid" in n or "bid" in n)], res["notes"]


def test_path_param_id_is_taken_from_the_collection_answer():
    res, app = run_engine(clean_round2(), spec=spec_round2())
    assert any(s["path"] == "/gadgets/42" for s in app.seen), [s["path"] for s in app.seen][:20]
    assert any(s["path"] == "/books/7/reviews" for s in app.seen), [s["path"] for s in app.seen][:20]


def test_path_param_id_comes_from_a_create_when_the_list_is_empty():
    routes = clean_round2()
    routes["GET /gadgets"] = lambda b, q: (200, {"items": []})
    res, app = run_engine(routes, spec=spec_round2())
    assert any(s["path"] == "/gadgets/7" for s in app.seen), [s["path"] for s in app.seen][:20]


def test_owner_role_not_configured_falls_back_to_a_role_that_is_accepted():
    app = App(clean_round2())
    try:
        client = api.Api(app.url, {"librarian": {"Authorization": "Bearer t-lib"}})
        res = sf.run(client, spec_round2(), SimpleNamespace())
    finally:
        app.stop()
    posts = [s for s in app.seen if s["method"] == "POST" and s["path"] == "/gadgets"]
    assert posts and all(s["auth"] == "Bearer t-lib" for s in posts), posts[:2]
    assert not [n for n in res["notes"] if n.startswith("GAP") and "no 2xx control" in n], res["notes"]


def test_pattern_string_branch_is_sent_and_its_drift_is_found():
    routes = clean_round2()
    routes["POST /prices"] = lambda b, q: (201, {"id": 1, "price": b["price"]})     # stores and returns the string as sent
    res, _ = run_engine(routes, spec=spec_round2())
    drift = [(f["path"], f["value"]) for f in kinds_of(res, "SCHEMA-DRIFT") if f["endpoint"] == "POST /prices"]
    assert ("$.price", "0") in drift, drift


def test_exact_max_length_rejected_is_found_with_the_boundary_label():
    routes = clean_round2()
    routes["POST /titles"] = lambda b, q: ((400, {"error": "title must be at most 200 characters"})
                                          if len(b["title"]) >= 200 else (201, {"id": 1}))
    res, _ = run_engine(routes, spec=spec_round2())
    rej = kinds_of(res, "SCHEMA-REJECTS-VALID")
    assert rej and rej[0]["endpoint"] == "POST /titles" and "title=maxLength=200" in rej[0]["detail"], res["findings"]


def test_missing_required_field_in_a_post_answer_is_drift():
    routes = clean_round2()
    routes["POST /books/{bid}/reviews"] = lambda b, q: (201, {"id": 5, "rating": b["rating"]} if not b.get("text")
                                                       else {"id": 5, "rating": b["rating"], "text": b["text"]})
    res, _ = run_engine(routes, spec=spec_round2())
    drift = [(f["path"], f["detail"]) for f in kinds_of(res, "SCHEMA-DRIFT") if f["endpoint"] == "POST /books/{bid}/reviews"]
    assert any(p == "$.text" and "required property missing" in d for p, d in drift), drift


def test_regex_sampler_produces_strings_the_pattern_matches():
    import random
    for pat in (r"^\d+(\.\d{1,2})?$", r"^[a-z]{3}-\d{2}$", r"^(foo|bar)+$", r"^[^@\s]+@[^@\s]+$", r"^[A-Z][a-z]*\s?\w+$"):
        assert sf.regex_sample(pat) is not None and re.search(pat, sf.regex_sample(pat)), pat
        for seed in range(8):
            v = sf.regex_sample(pat, random.Random(seed))
            assert v is not None and re.search(pat, v), (pat, v)
    assert sf.regex_sample(r"^(?=a)a$") is None, "a lookahead is not generated: the sampler must say so"


# ---------- designated values only back REJECTS (no invented boundary) ----------

CATEGORY_IN = {"type": "object", "required": ["category"], "properties": {"category": {"type": "integer"}}}


def spec_category():
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
        "/cats": {"post": {"requestBody": _json_body(CATEGORY_IN), "responses": {"201": _resp(TITLE_OUT)}}}}}


def test_invented_zero_on_unconstrained_integer_is_not_a_rejects_finding():
    # The app refuses category 0 (a foreign key that must exist). The schema declares no minimum, so 0 is invented:
    # the 422 is a note, never a SCHEMA-REJECTS-VALID finding (the regression seen on the E-catalog clean variant).
    routes = {"POST /cats": lambda b, q: ((422, {"error": "unknown category"}) if b["category"] == 0 else (201, {"id": 1}))}
    res, app = run_engine(routes, spec=spec_category())
    assert kinds_of(res, "SCHEMA-REJECTS-VALID") == [], res["findings"]
    assert any("is not reported" in n and "does not declare" in n for n in res["notes"]), res["notes"]
    assert any(s["body"] == {"category": 0} for s in app.seen), "the invented value must still be sent (5xx and drift)"


def test_declared_minimum_zero_is_still_a_rejects_finding():
    res, _ = run_engine(clean_round2() | {"POST /prices": lambda b, q: (422, {"error": "no"}) if b["price"] == 0
                                          else (201, {"id": 1, "price": float(b["price"])})}, spec=spec_round2())
    assert any(f["endpoint"] == "POST /prices" for f in kinds_of(res, "SCHEMA-REJECTS-VALID")), res["findings"]


# ---------- SCHEMA-ACCEPTS-INVALID (PUT/PATCH with an out-of-contract enum or pattern value) ----------

PRICE_OUT2 = {"type": "object", "required": ["id", "currency"], "properties": {"id": {"type": "integer"}, "currency": {"type": "string"}}}
PRICE_PATCH = {"type": "object", "properties": {"currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
                                                "stock": {"type": "integer", "minimum": 0}}}


def spec_patch():
    return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {
        "/prices": {"get": {"responses": {"200": _resp({"type": "object", "required": ["items"], "properties": {
            "items": {"type": "array", "items": PRICE_OUT2}}})}}},
        "/prices/{pid}": {"parameters": [{"name": "pid", "in": "path", "required": True, "schema": {"type": "integer"}}],
                          "get": {"responses": {"200": _resp(PRICE_OUT2)}},
                          "patch": {"requestBody": _json_body(PRICE_PATCH), "responses": {"200": _resp(PRICE_OUT2)}}}}}


def clean_patch_routes():
    def patch(b, q):
        if "currency" in b and b["currency"] not in ("USD", "EUR", "GBP"):
            return 422, {"error": "validation_failed"}
        return 200, {"id": 42, "currency": b.get("currency", "USD")}
    return {"GET /prices": lambda b, q: (200, {"items": [{"id": 42, "currency": "USD"}]}),
            "GET /prices/{pid}": lambda b, q: (200, {"id": 42, "currency": "USD"}),
            "PATCH /prices/{pid}": patch}


def test_accepts_invalid_enum_on_patch_buggy_is_found_with_control_and_restore():
    routes = clean_patch_routes()

    def buggy(b, q):                                  # checks only the length of currency (3 characters)
        c = b.get("currency")
        if c is not None and not (isinstance(c, str) and len(c) == 3):
            return 422, {"error": "validation_failed"}
        return 200, {"id": 42, "currency": c or "USD"}
    routes["PATCH /prices/{pid}"] = buggy
    res, app = run_engine(routes, spec=spec_patch())
    acc = kinds_of(res, "SCHEMA-ACCEPTS-INVALID")
    assert acc and acc[0]["endpoint"] == "PATCH /prices/{pid}" and acc[0]["field"] == "currency", res["findings"]
    assert acc[0]["status"] == 200, acc[0]
    patches = [s["body"] for s in app.seen if s["method"] == "PATCH"]
    i = patches.index({"currency": "zzz"})                 # the invalid write (same-length text of "USD")
    assert patches[i - 1] == {"currency": "USD"}, "the valid control write must come right before the invalid one"
    assert patches[i + 2] == {"currency": "USD"} or {"currency": "USD"} in patches[i + 1:i + 3], \
        "the original value must be written back right after the invalid write"


def test_accepts_invalid_enum_on_patch_clean_is_zero_findings():
    res, _ = run_engine(clean_patch_routes(), spec=spec_patch())
    assert kinds_of(res, "SCHEMA-ACCEPTS-INVALID") == [], res["findings"]


def test_accepts_invalid_is_not_evaluated_without_a_valid_control():
    routes = clean_patch_routes()
    routes["PATCH /prices/{pid}"] = lambda b, q: (422, {"error": "always no"})
    res, _ = run_engine(routes, spec=spec_patch())
    assert kinds_of(res, "SCHEMA-ACCEPTS-INVALID") == [], res["findings"]
    assert any("valid control write answered 422" in n for n in res["notes"]), res["notes"]


# ---------- novelty, caps, seed ----------

def test_novelty_stop_rule_and_per_endpoint_cap():
    res, _ = run_engine(clean_routes(), per_endpoint=100)
    assert res["endpoints"]["GET /ping"]["signatures"] == 1, res["endpoints"]
    # 1 baseline + 3 enum variants + STALE_LIMIT repeats of an already-seen signature, then the loop stops
    assert res["endpoints"]["GET /ping"]["probes"] == 1 + 3 + sf.STALE_LIMIT, res["endpoints"]
    res2, _ = run_engine(clean_routes(), per_endpoint=2)
    assert all(v["probes"] <= 2 for v in res2["endpoints"].values()), res2["endpoints"]
    assert res2["status"] == trust.DEGRADED, "cut-short deterministic coverage must degrade the engine"


def test_global_budget_degrades_and_caps_probes():
    res, app = run_engine(clean_routes(), max_probes=3)
    assert res["probes"] == 3 and len(app.seen) == 3, (res["probes"], len(app.seen))
    assert res["status"] == trust.DEGRADED and "cut short" in res["status_reason"], res


def test_seed_makes_the_request_sequence_reproducible():
    _, a1 = run_engine(clean_routes(), seed=7)
    _, a2 = run_engine(clean_routes(), seed=7)
    strip = lambda app: [(s["method"], s["path"], s["body"], s["query"]) for s in app.seen]
    assert strip(a1) == strip(a2) and len(a1.seen) > 10


# ---------- qa-spec knobs ----------

def test_skip_bodies_and_public_knobs():
    qa = SimpleNamespace(SKIP={"POST /orders"}, BODIES={"POST /items": {"quantity": 7}}, PUBLIC={"GET /ping"})
    res, app = run_engine(clean_routes(), qa=qa)
    assert not any(s["path"] == "/orders" for s in app.seen), "SKIP was ignored"
    first_items = [s for s in app.seen if s["path"] == "/items"][0]
    assert first_items["body"] == {"quantity": 7}, first_items                  # BODIES is the baseline
    pings = [s for s in app.seen if s["path"] == "/ping"]
    assert pings and all(s["auth"] is None for s in pings), pings               # PUBLIC is sent as anon
    notes_items = [s for s in app.seen if s["path"] == "/notes"]
    assert notes_items and all(s["auth"] == "Bearer t-a" for s in notes_items)  # others keep the owner role
    assert res["status"] == trust.RAN_OK, res


def test_unresolvable_ref_degrades_and_sends_nothing():
    spec = {"openapi": "3.0.3", "paths": {"/x": {"post": {
        "requestBody": _json_body({"$ref": "http://evil.example/schema.json"}),
        "responses": {"200": {"description": "ok"}}}}}}
    res, app = run_engine({"POST /x": lambda b, q: (200, {})}, spec=spec)
    assert app.seen == [], app.seen
    assert res["status"] == trust.DEGRADED and "external" in res["status_reason"], res


def test_nothing_to_fuzz_is_skipped_not_clean():
    spec = {"openapi": "3.0.3", "paths": {"/x": {"delete": {"responses": {"204": {"description": "gone"}}}}}}
    res, app = run_engine({}, spec=spec)
    assert res["status"] == trust.SKIPPED and res["probes"] == 0 and app.seen == [], res


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"SCHEMA FUZZ OK: {len(tests)} tests")
