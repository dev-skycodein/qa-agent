"""MR-FILTER-PARTITION and MR-SEARCH-CASE of metamorphic.py, on a small list API with a boolean filter and a text search.

  python toolkit/engine/test_metamorphic_extra.py        (also collectable by pytest)

bugs: 'case' = search is case-sensitive; 'inverted_with_filter' = in_stock=false returns the in-stock items when another filter is set;
'bool_ignored' = in_stock=false is ignored (returns everything). `doc_case` makes the OpenAPI say the search is case-insensitive.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import metamorphic  # noqa: E402

NAMES = ["Smart Plug", "Smart Watch", "Garden Hose", "Garden Shears", "Desk Lamp", "Desk Chair",
         "Router Pro", "Router Mini", "Camera Lens", "Camera Strap", "Kettle Steel", "Kettle Glass"]
ITEMS = [{"id": i + 1, "name": n, "category": 1 + i % 3, "stock": (i % 4) * 5} for i, n in enumerate(NAMES)]


def make_doc(doc_case):
    q_desc = "Substring search on the name." + (" Case-insensitive." if doc_case else "")
    return {"openapi": "3.0.0", "paths": {"/items": {"get": {"parameters": [
        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        {"name": "offset", "in": "query", "schema": {"type": "integer"}},
        {"name": "q", "in": "query", "description": q_desc, "schema": {"type": "string"}},
        {"name": "in_stock", "in": "query", "schema": {"type": "boolean"}},
        {"name": "category", "in": "query", "schema": {"type": "integer"}}],
        "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object"}}}}}}}}}


def start(bugs):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            rows = list(ITEMS)
            if "category" in q:
                rows = [r for r in rows if r["category"] == int(q["category"])]
            if "q" in q:
                needle = q["q"] if "case" in bugs else q["q"].lower()
                rows = [r for r in rows if needle in (r["name"] if "case" in bugs else r["name"].lower())]
            if "in_stock" in q:
                want = q["in_stock"] == "true"
                if "bool_ignored" in bugs and not want:
                    pass
                elif "inverted_with_filter" in bugs and not want and "category" in q:
                    rows = [r for r in rows if r["stock"] > 0]
                elif "swapped_with_filter" in bugs and "category" in q:      # a consistent partition, but the meaning is swapped
                    rows = [r for r in rows if (r["stock"] > 0) != want]
                else:
                    rows = [r for r in rows if (r["stock"] > 0) == want]
            total = len(rows)
            off, lim = int(q.get("offset", 0)), int(q.get("limit", 10))
            body = json.dumps({"items": rows[off:off + lim], "total": total}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(bugs=(), doc_case=False):
    srv = start(set(bugs))
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {}})
        return metamorphic.run(api, make_doc(doc_case), SimpleNamespace())
    finally:
        srv.shutdown()


def kinds(res):
    return {(f["kind"], f["severity"]) for f in res["findings"]}


def test_clean_app_has_no_partition_or_search_finding_and_both_ran():
    res = run(doc_case=True)
    assert res["findings"] == [], [(f["kind"], f["detail"][:140]) for f in res["findings"]]
    for k in ("MR-FILTER-PARTITION", "MR-SEARCH-CASE"):
        assert res["relations"][k]["clean"] >= 1, (k, res["relations"][k])


def test_boolean_filter_ignored_is_found():
    assert ("MR-FILTER-PARTITION", "medium") in kinds(run(["bool_ignored"]))


def test_boolean_filter_inverted_only_with_a_second_filter_is_found_and_names_the_filter():
    res = run(["inverted_with_filter"])
    hits = [f for f in res["findings"] if f["kind"] == "MR-FILTER-PARTITION"]
    assert hits and any("category" in f["detail"] for f in hits), res["findings"]
    assert not any("with" in f["detail"] and "category" not in f["detail"] for f in hits)


def test_swapped_boolean_under_a_second_filter_is_found_by_composition_not_partition():
    res = run(["swapped_with_filter"])
    hits = [f for f in res["findings"] if f["kind"] == "MR-FILTER-PARTITION"]
    assert hits and all("category" in f["detail"] for f in hits), res["findings"]
    assert any("alone" in f["detail"] for f in hits)          # the composition wording


def test_case_sensitive_search_is_medium_when_documented_insensitive():
    assert ("MR-SEARCH-CASE", "medium") in kinds(run(["case"], doc_case=True))


def test_case_sensitive_search_is_only_low_when_the_document_is_silent():
    k = kinds(run(["case"], doc_case=False))
    assert ("MR-SEARCH-CASE", "low") in k and ("MR-SEARCH-CASE", "medium") not in k


# ---------- unique fields: the engine must not die on its own 409 ----------

MODE = {}


def start_unique():
    store = {}

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

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/items":
                return self._send(200, {"items": list(store.values()), "total": len(store)})
            i = path.rsplit("/", 1)[-1]
            return self._send(200, store[int(i)]) if i.isdigit() and int(i) in store else self._send(404, {"error": "nf"})

        def do_DELETE(self):
            i = urlparse(self.path).path.rsplit("/", 1)[-1]
            if MODE.get("delete") == "soft" and i.isdigit() and int(i) in store:
                store[int(i)] = {**store[int(i)], "deleted": True, "deleted_at": "2026-01-01T00:00:00Z"}
                return self._send(204, {})
            if MODE.get("delete") == "leftover":
                return self._send(204, {})              # says gone, keeps the item and gives no sign of deletion
            return self._send(204, {}) if store.pop(int(i), None) else self._send(404, {"error": "nf"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if any(v["sku"].lower() == str(body.get("sku", "")).lower() for v in store.values()):
                return self._send(409, {"error": "sku already exists"})
            n = max(store, default=0) + 1
            store[n] = {"id": n, **body}
            return self._send(201, store[n])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


UNIQUE_DOC = {"openapi": "3.0.0", "paths": {
    "/items": {"get": {"responses": {"200": {"description": "ok"}}},
               "post": {"requestBody": {"content": {"application/json": {"schema": {
                   "type": "object", "required": ["sku", "name"],
                   "properties": {"sku": {"type": "string", "pattern": "^[A-Za-z0-9-]+$", "maxLength": 32},
                                  "name": {"type": "string"}}}}}}, "responses": {"201": {"description": "created"}}}},
    "/items/{item_id}": {"get": {"responses": {"200": {"description": "ok"}}},
                         "delete": {"responses": {"204": {"description": "gone"}}}}}}


def _delete_run(mode):
    MODE["delete"] = mode
    srv = start_unique()
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {}})
        return metamorphic.run(api, UNIQUE_DOC, SimpleNamespace())
    finally:
        srv.shutdown()
        MODE.clear()


def test_documented_soft_delete_is_not_a_leftover_finding():
    res = _delete_run("soft")
    assert [f for f in res["findings"] if f["kind"] == "MR-DELETE-GONE"] == [], res["findings"]


def test_item_still_served_after_delete_without_any_deleted_marker_is_a_finding():
    res = _delete_run("leftover")
    assert any(f["kind"] == "MR-DELETE-GONE" and f["severity"] == "high" for f in res["findings"]), res["findings"]


def test_repeated_creates_get_distinct_unique_values_instead_of_409():
    srv = start_unique()
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {}})
        res = metamorphic.run(api, UNIQUE_DOC, SimpleNamespace())
    finally:
        srv.shutdown()
    st = res["relations"]
    assert st["MR-WRITE-ROUNDTRIP"]["clean"] >= 1 and st["MR-DELETE-GONE"]["clean"] >= 1, st
    assert not any("409" in n for n in res["notes"]), [n for n in res["notes"] if "409" in n]
    assert res["findings"] == [], res["findings"]


# ---------- MR-BULK-ATOMIC: a rejected bulk request must leave nothing behind ----------

BULK_MODE = {}


def start_bulk():
    store = []

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

        def do_GET(self):
            return self._send(200, {"items": store, "total": len(store)})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            path = urlparse(self.path).path
            rows = body if path.endswith("/bulk") else [body]
            bad = [r for r in rows if "name" not in r]
            if path.endswith("/bulk") and BULK_MODE.get("partial"):
                for r in rows:                      # the bug: commit while validating
                    if "name" not in r:
                        return self._send(422, {"error": "name required"})
                    store.append({"id": len(store) + 1, **r})
            if bad:
                return self._send(422, {"error": "name required"})
            for r in rows:
                store.append({"id": len(store) + 1, **r})
            return self._send(201, {"id": len(store)} if not path.endswith("/bulk") else {"created": len(rows)})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def bulk_doc(described_atomic):
    item = {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}
    return {"openapi": "3.0.0", "paths": {
        "/items": {"get": {"responses": {"200": {"description": "ok"}}},
                   "post": {"requestBody": {"content": {"application/json": {"schema": item}}}, "responses": {"201": {"description": "c"}}}},
        "/items/bulk": {"post": {"summary": "Create many items" + (" (all-or-nothing)" if described_atomic else ""),
                                 "requestBody": {"content": {"application/json": {"schema": {"type": "array", "items": item}}}},
                                 "responses": {"201": {"description": "c"}}}}}}


def _bulk_run(partial, described):
    BULK_MODE.clear()
    BULK_MODE["partial"] = partial
    srv = start_bulk()
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}", {"user_a": {}})
        return metamorphic.run(api, bulk_doc(described), SimpleNamespace())
    finally:
        srv.shutdown()
        BULK_MODE.clear()


def test_bulk_partial_commit_is_found_and_medium_when_documented_all_or_nothing():
    res = _bulk_run(partial=True, described=True)
    hits = [f for f in res["findings"] if f["kind"] == "MR-BULK-ATOMIC"]
    assert hits and hits[0]["severity"] == "medium", res["findings"]


def test_bulk_partial_commit_is_low_when_atomicity_is_not_documented():
    res = _bulk_run(partial=True, described=False)
    assert [f["severity"] for f in res["findings"] if f["kind"] == "MR-BULK-ATOMIC"] == ["low"], res["findings"]


def test_atomic_bulk_has_no_finding_and_the_relation_ran():
    res = _bulk_run(partial=False, described=True)
    assert [f for f in res["findings"] if f["kind"] == "MR-BULK-ATOMIC"] == [], res["findings"]
    assert res["relations"]["MR-BULK-ATOMIC"]["clean"] >= 1, res["relations"]["MR-BULK-ATOMIC"]


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"METAMORPHIC EXTRA OK: {len(tests)} tests")
