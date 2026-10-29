"""Tests for audit batch 4: exposure (C-M1, C-M2, C-M4), schema_fuzz (C-M5, C-M6), differential (C-M8, C-M9, C-M10, C-L11).

  python toolkit/engine/test_audit_batch4.py        (stdlib only; also collectable by pytest)
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402
import differential as df  # noqa: E402
import exposure  # noqa: E402
import schema_fuzz as sf  # noqa: E402
import trust  # noqa: E402


# ---------- exposure ----------

class ExpApi:
    roles = {"anon": {}}

    def __init__(self, entries=(), get_calls=None):
        self.log = [{"role": "user_a", "method": m, "path": p, "status": s, "body": json.dumps(b)} for m, p, s, b in entries]
        self.get_calls = get_calls if get_calls is not None else []

    def call(self, role, method, path, *a, **k):
        self.get_calls.append((role, method, path))


def _exp(entries, qa=None):
    r = exposure.run(ExpApi(entries), {}, qa)
    return r, {(f["endpoint"], f["detail"].split("'")[1], f["severity"]) for f in r["findings"]}


def test_c_m2_passenger_and_shape_words_are_not_secrets():
    _, k = _exp([("GET", "/trips", 200, {"passenger": "Ali Khan"})])
    assert k == set(), k
    _, k = _exp([("GET", "/ui", 200, {"classname": "btn", "hotpot": "x", "shadow": "soft", "shape": "round", "shared": "yes"})])
    assert k == set(), k


def test_c_m2_password_reset_url_is_not_hidden_by_the_url_safe_list():
    _, k = _exp([("GET", "/me", 200, {"id": 1, "password_reset_url": "https://app.example/reset?token=" + "k" * 40})])
    assert k == {("GET /me", "password_reset_url", "high")}, k


def test_c_m1_password_hash_on_an_issuing_looking_path_is_reported():
    # '/authors' contains 'auth' but is not an auth path: the plain-text hash must be seen
    _, k = _exp([("POST", "/authors", 201, {"id": 1, "password_hash": "hunter2plain"})])
    assert k == {("POST /authors", "password_hash", "high")}, k


def test_c_m1_password_echoed_by_a_real_register_endpoint_is_reported_but_its_token_is_not():
    _, k = _exp([("POST", "/auth/register", 201, {"id": 1, "password": "hunter2plain", "access_token": "t" * 40})])
    assert k == {("POST /auth/register", "password", "high")}, k


def test_c_m1_camelcase_access_token_on_a_profile_is_reported():
    _, k = _exp([("GET", "/me", 200, {"id": 1, "accessToken": "t" * 40})])
    assert k == {("GET /me", "accessToken", "low")}, k


def test_c_m4_sweep_sends_the_get_and_says_so_in_the_notes():
    calls = []
    doc = {"paths": {"/logout": {"get": {}}}}
    r = exposure.run(ExpApi(get_calls=calls), doc, None)
    assert calls == [("anon", "GET", "/logout")], calls
    assert any("GETs" in n and "qa.SKIP" in n for n in r["notes"]), r["notes"]


def test_c_m4_sweep_respects_qa_skip():
    calls = []
    doc = {"paths": {"/logout": {"get": {}}}}
    exposure.run(ExpApi(get_calls=calls), doc, SimpleNamespace(SKIP={"GET /logout"}))
    assert calls == [], calls


# ---------- schema_fuzz ----------

class FakeClient:
    roles = {"user_a": {}}

    def __init__(self, fn):
        self.fn = fn

    def call(self, role, method, path, body=None, query=None):
        status, payload = self.fn(method, path, body, query)
        return api.Resp(status, json.dumps(payload) if payload is not None else "")


def _spec(paths, components=None):
    d = {"openapi": "3.0.3", "paths": paths}
    if components:
        d["components"] = components
    return d


def _run_sf(sp, fn):
    return sf.run(FakeClient(fn), sp, SimpleNamespace(), max_probes=200)


def _kinds(res):
    return {f["kind"] for f in res["findings"]}


def _shop(method, path, body, query):
    if method == "POST" and path == "/items":
        if isinstance(body, dict) and isinstance(body.get("qty"), int) and body["qty"] % 5 != 0:
            return 422, {"error": "qty must be a multiple of 5"}
        return 201, {"id": 1}
    return 404, {}


SP_MULTIPLE = _spec({"/items": {"post": {
    "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["qty"], "properties": {
        "qty": {"type": "integer", "minimum": 3, "maximum": 100, "multipleOf": 5, "example": 15}}}}}},
    "responses": {"201": {"description": "ok", "content": {"application/json": {"schema": {"type": "object",
                                                                                          "properties": {"id": {"type": "integer"}}}}}}}}}})


def test_c_m5_multipleOf_is_degraded_not_a_rejects_finding():
    res = _run_sf(SP_MULTIPLE, _shop)
    assert "SCHEMA-REJECTS-VALID" not in _kinds(res), res["findings"]
    assert res["status"] == trust.DEGRADED, res["status"]
    assert any("multipleOf" in n and n.startswith("GAP") for n in res["notes"]), res["notes"]


def test_c_m5_writeOnly_field_absent_from_a_response_is_not_drift():
    def profile(method, path, body, query):
        return (200, {"username": "ann"}) if method == "GET" and path == "/profile" else (404, {})
    sp = _spec({"/profile": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
        "type": "object", "required": ["username", "password"], "properties": {
            "username": {"type": "string"}, "password": {"type": "string", "writeOnly": True}}}}}}}}}})
    res = _run_sf(sp, profile)
    assert "SCHEMA-DRIFT" not in _kinds(res), res["findings"]
    assert res["status"] == trust.DEGRADED, res["status"]


def test_c_m5_every_listed_unsupported_keyword_degrades_the_operation():
    for kw in ("uniqueItems", "patternProperties", "minProperties", "not", "if", "readOnly"):
        schema = {"type": "object", "properties": {"x": {"type": "string", f"{kw}": True if kw != "not" else {"type": "integer"}}}}
        assert sf._op_unsupported({"body": schema, "query": [], "responses": {}}, {}) == {kw}, kw


def test_c_m5_a_property_named_not_is_not_an_unsupported_keyword():
    schema = {"type": "object", "properties": {"not": {"type": "string"}, "if": {"type": "integer"}}}
    assert sf._op_unsupported({"body": schema, "query": [], "responses": {}}, {}) == set()


def test_c_m5_date_format_rejects_month_13_and_day_45():
    assert sf.check("2026-13-45", {"type": "string", "format": "date"}, {})
    assert sf.check("2026-02-30", {"type": "string", "format": "date"}, {})
    assert sf.check("2026-03-14", {"type": "string", "format": "date"}, {}) == []
    assert sf.check("2026-01-01T25:00:00Z", {"type": "string", "format": "date-time"}, {})
    assert sf.check("2026-01-01T10:20:30Z", {"type": "string", "format": "date-time"}, {}) == []


def test_c_m5_invalid_date_in_a_response_is_drift():
    def events(method, path, body, query):
        return (200, {"day": "2026-13-45"}) if method == "GET" and path == "/events" else (404, {})
    sp = _spec({"/events": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {
        "type": "object", "properties": {"day": {"type": "string", "format": "date"}}}}}}}}}})
    res = _run_sf(sp, events)
    assert "SCHEMA-DRIFT" in _kinds(res), res["findings"]


def test_c_m6_ref_response_is_checked_and_its_drift_found():
    def thing(method, path, body, query):
        return (200, {"name": "x"}) if method == "GET" and path == "/things" else (404, {})
    sp = _spec({"/things": {"get": {"responses": {"200": {"$ref": "#/components/responses/Ok"}}}}},
               components={"responses": {"Ok": {"description": "ok", "content": {"application/json": {"schema": {
                   "type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}}}}}})
    res = _run_sf(sp, thing)
    assert res["status"] != trust.SKIPPED, res
    assert "SCHEMA-DRIFT" in _kinds(res), res["findings"]


def test_c_m6_ref_response_without_json_is_still_not_fuzzed_as_json():
    sp = _spec({"/x": {"get": {"responses": {"200": {"$ref": "#/components/responses/Plain"}}}}},
               components={"responses": {"Plain": {"description": "text only", "content": {"text/plain": {"schema": {"type": "string"}}}}}})
    assert sf._has_json_response({"200": {"$ref": "#/components/responses/Plain"}}, sp) is False


# ---------- differential ----------

def test_c_m8_vary_skips_classifier_and_identifier_fields_but_still_varies_emails():
    subs = {}
    out = df._vary({"email": "a@x.com", "country_code": "US", "postal_code": "12345", "customer_id": "c1", "sku": "AB"}, 1, subs)
    assert out["email"] == "a+r1@x.com", out
    assert out["country_code"] == "US" and out["postal_code"] == "12345" and out["customer_id"] == "c1", out
    assert out["sku"] == "AB-r1", out            # sku is still an identifier to make unique


def test_c_m9_allow_list_matches_a_list_item_path_literally():
    assert df._allowed("POST /items", "items[*].priority", ["POST /items items[*].priority"])
    assert df._allowed("POST /items", "items[*].priority", ["POST /items items[*].*"])
    assert not df._allowed("POST /items", "items[*].name", ["POST /items items[*].priority"])
    assert df._allowed("GET /x", "", ["GET /*"]) is True
    assert not df._allowed("GET /x", "", ["GET /y"])


def test_c_m10_paging_oracles_accept_data_results_and_count():
    ra = {"method": "GET", "tpl": "/things", "query": None, "variant": "past-end"}
    assert df._page_size_of({"data": [1], "total": 30, "page_size": 10}) == (30, 10)
    assert df._page_size_of({"results": [1], "count": 30, "page_size": 10}) == (30, 10)
    assert df._paging_kind("len", "data.#len", ra) == "past-end"
    assert df._paging_kind("len", "results.#len", ra) == "past-end"
    assert df._paging_kind("len", "items.#len", ra) == "past-end"
    assert df._paging_kind("len", "data.#len", dict(ra, variant="")) == "default"   # no page size sent: the default-size oracle
    assert df._paging_kind("len", "name.#len", ra) is None
    assert df._items({"results": [{"id": 1, "status": "x"}]}, {"param": "status"}, {}, {}) == [{"id": "1", "f": "x"}]
    assert df._items({"items": [{"id": 1, "status": "x"}]}, {"param": "status"}, {}, {}) == [{"id": "1", "f": "x"}]
    assert df._items({"id": 1}, {"param": "status"}, {}, {}) is None


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"AUDIT BATCH 4 OK: {len(tests)} tests")
