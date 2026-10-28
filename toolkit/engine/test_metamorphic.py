"""Tests for metamorphic.py: one buggy variant per relation must be detected, the clean app must give zero findings.

  python toolkit/engine/test_metamorphic.py        (stdlib only; also collectable by pytest)

The app is a stdlib ThreadingHTTPServer on an ephemeral port (127.0.0.1, port 0): no shared ports.
Each bug is a switch in FakeApp.bugs; the clean app has none.
"""
import json
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402
import metamorphic  # noqa: E402
import trust  # noqa: E402

SEED_ITEMS = [
    {"id": 1, "name": "delta", "category": "a", "price": 40},
    {"id": 2, "name": "alpha", "category": "b", "price": 10},
    {"id": 3, "name": "gamma", "category": "a", "price": 70},
    {"id": 4, "name": "bravo", "category": "c", "price": 20},
    {"id": 5, "name": "echo", "category": "b", "price": 90},
    {"id": 6, "name": "charlie", "category": "c", "price": 30},
    {"id": 7, "name": "foxtrot", "category": "a", "price": 60},
    {"id": 8, "name": "hotel", "category": "c", "price": 5},
]
SEED_LABELS = [{"id": 1, "name": "bug", "color": "red"}, {"id": 2, "name": "docs", "color": "blue"},
               {"id": 3, "name": "ux", "color": "green"}]
KNOWN = {"limit", "offset", "sort", "order", "category", "name", "page", "per_page"}
CATS = ("a", "b", "c")
ERR = b'{"error":"bad request"}'


class FakeApp:
    """In-memory CRUD app. bugs (all optional):
    offbyone (page windows after the first skip one item), total_wrong (total + 1), limit_huge_500 (limit > 100 -> 500),
    filter_ignored, sort_ignored, order_ignored, param_order_filter (category filter only when it is the first param),
    labels_shuffle (label list rotated per read), labels_drop (every other label read drops the last label),
    roundtrip_upper (item names stored upper-cased), put_history (PUT appends to a history list),
    delete_leaves (DELETE says 204 and keeps the item), delete_twice_500 (DELETE of a missing item -> 500),
    unknown_500 (any unknown query param -> 500), head_404 (HEAD /items -> 404), notes_zero_based (page numbers from 0),
    stats_stale (DELETE does not decrement the /stats total), child_leak (comments of a deleted item stay readable),
    sort_desc_lexical (sort=price&order=desc compares prices as text), price_as_string (list answers price as text),
    name_prefix (the exact name filter matches by prefix)."""

    def __init__(self, bugs=()):
        self.bugs = set(bugs)
        self.lock = threading.Lock()
        self.items = {r["id"]: dict(r) for r in SEED_ITEMS}
        self.next_item = 9
        self.stat_total = len(self.items)
        self.comments = {}
        self.next_comment = 1
        self.labels = {r["id"]: dict(r) for r in SEED_LABELS}
        self.next_label = 4
        self.label_reads = 0
        self.notes = [{"id": i, "title": f"note-{i}"} for i in range(1, 8)]

    def handle(self, method, raw_path, raw_body):
        with self.lock:
            try:
                return self._route(method, raw_path, raw_body)
            except Exception as exc:                       # a bug in this fake app must show up as a 500, not hang
                return 500, json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode()

    def _route(self, method, raw_path, raw_body):
        url = urllib.parse.urlsplit(raw_path)
        path = url.path.rstrip("/") or "/"
        pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
        q = dict(pairs)
        if method == "HEAD" and "head_404" in self.bugs and path == "/items":
            return 404, b'{"error":"not found"}'
        if method in ("GET", "HEAD") and "unknown_500" in self.bugs and any(k not in KNOWN for k, _ in pairs):
            return 500, b'{"error":"boom"}'
        body = None
        if raw_body:
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except ValueError:
                return 400, ERR
        m = "GET" if method == "HEAD" else method
        if path == "/ping" and m == "GET":
            return 200, b'{"ok": true}'
        if path == "/items":
            if m == "GET":
                return self.list_items(pairs, q)
            if m == "POST":
                return self.create_item(body)
        if path == "/notes" and m == "GET":
            return self.list_notes(q)
        if path == "/stats" and m == "GET":
            return 200, json.dumps({"total": self.stat_total, "served_at": time.time()}).encode()
        if path == "/labels":
            if m == "GET":
                return self.list_labels()
            if m == "POST":
                return self.create_label(body)
        parts = path.split("/")
        if len(parts) == 4 and parts[1] == "items" and parts[2].isdigit() and parts[3] == "comments":
            return self.comments_of(int(parts[2]), m, body)
        if len(parts) == 3 and parts[1] in ("items", "labels") and parts[2].isdigit():
            return self.one(parts[1], int(parts[2]), m, body)
        return 404, b'{"error":"no route"}'

    def list_items(self, pairs, q):
        try:
            limit, offset = int(q.get("limit", 10)), int(q.get("offset", 0))
        except ValueError:
            return 400, ERR
        if limit < 1 or offset < 0:
            return 400, ERR
        if limit > 100 and "limit_huge_500" in self.bugs:
            return 500, b'{"error":"limit too large"}'
        limit = min(limit, 100)
        sort, order = q.get("sort"), q.get("order", "asc")
        if (sort is not None and sort not in ("name", "price")) or order not in ("asc", "desc"):
            return 400, ERR
        rows = sorted(self.items.values(), key=lambda r: r["id"])
        cat = q.get("category")
        if q.get("name") is not None and "filter_ignored" not in self.bugs:
            want = q["name"]
            if "name_prefix" in self.bugs:
                rows = [r for r in rows if r["name"].startswith(want)]
            else:
                rows = [r for r in rows if r["name"] == want]
        apply_filter = cat is not None and "filter_ignored" not in self.bugs
        if apply_filter and "param_order_filter" in self.bugs and pairs[0][0] != "category":
            apply_filter = False
        if apply_filter:
            rows = [r for r in rows if r["category"] == cat]
        if sort and "sort_ignored" not in self.bugs:
            desc = order == "desc" and "order_ignored" not in self.bugs
            if desc and sort == "price" and "sort_desc_lexical" in self.bugs:
                rows.sort(key=lambda r: (str(r[sort]), r["id"]), reverse=True)
            else:
                rows.sort(key=lambda r: (r[sort], r["id"]), reverse=desc)
        start = offset + (1 if "offbyone" in self.bugs and offset > 0 else 0)
        page = rows[start:start + limit]
        if "price_as_string" in self.bugs:
            page = [dict(r, price=str(r["price"])) for r in page]
        total = len(rows) + (1 if "total_wrong" in self.bugs else 0)
        return 200, json.dumps({"items": page, "total": total, "served_at": time.time()}).encode()

    def list_notes(self, q):
        try:
            page, per = int(q.get("page", 1)), int(q.get("per_page", 10))
        except ValueError:
            return 400, ERR
        if per < 1:
            return 400, ERR
        per = min(per, 100)
        if "notes_zero_based" in self.bugs:
            if page < 0:
                return 400, ERR
            start = page * per
        else:
            if page < 1:
                return 400, ERR
            start = (page - 1) * per + (1 if "offbyone" in self.bugs and page > 1 else 0)
        return 200, json.dumps({"data": self.notes[start:start + per]}).encode()

    def list_labels(self):
        self.label_reads += 1
        rows = [self.labels[k] for k in sorted(self.labels)]
        if "labels_shuffle" in self.bugs:
            rot = self.label_reads % len(rows)
            rows = rows[rot:] + rows[:rot]
        if "labels_drop" in self.bugs and self.label_reads % 2 == 0:
            rows = rows[:-1]
        return 200, json.dumps(rows).encode()

    def create_item(self, body):
        if not (isinstance(body, dict) and isinstance(body.get("name"), str) and body.get("category") in CATS
                and isinstance(body.get("price"), int) and body["price"] >= 0):
            return 400, ERR
        name = body["name"].upper() if "roundtrip_upper" in self.bugs else body["name"]
        rec = {"id": self.next_item, "name": name, "category": body["category"], "price": body["price"]}
        self.items[rec["id"]] = rec
        self.next_item += 1
        self.stat_total += 1
        return 201, json.dumps(rec).encode()

    def comments_of(self, rid, m, body):
        if rid not in self.items and "child_leak" not in self.bugs:
            return 404, b'{"error":"not found"}'
        if m == "GET":
            rows = self.comments.get(rid, [])
            return 200, json.dumps({"items": rows, "total": len(rows)}).encode()
        if m == "POST":
            if rid not in self.items:
                return 404, b'{"error":"not found"}'
            if not (isinstance(body, dict) and isinstance(body.get("text"), str)):
                return 400, ERR
            rec = {"id": self.next_comment, "item_id": rid, "text": body["text"]}
            self.next_comment += 1
            self.comments.setdefault(rid, []).append(rec)
            return 201, json.dumps(rec).encode()
        return 405, b'{"error":"method"}'

    def create_label(self, body):
        if not (isinstance(body, dict) and isinstance(body.get("name"), str) and isinstance(body.get("color"), str)):
            return 400, ERR
        rec = {"id": self.next_label, "name": body["name"], "color": body["color"]}
        self.labels[rec["id"]] = rec
        self.next_label += 1
        return 201, json.dumps(rec).encode()

    def one(self, coll, rid, m, body):
        store = self.items if coll == "items" else self.labels
        if rid not in store:
            if m == "DELETE" and coll == "items" and "delete_twice_500" in self.bugs:
                return 500, b'{"error":"null pointer"}'
            return 404, b'{"error":"not found"}'
        if m == "GET":
            return 200, json.dumps(store[rid]).encode()
        if m == "PUT":
            fields = ("name", "category", "price") if coll == "items" else ("name", "color")
            if not isinstance(body, dict) or any(k not in fields for k in body):
                return 400, ERR
            store[rid].update(body)
            if coll == "items" and "put_history" in self.bugs:
                store[rid].setdefault("history", []).append(body)
            return 200, json.dumps(store[rid]).encode()
        if m == "DELETE":
            if coll == "items" and "delete_leaves" in self.bugs:
                return 204, b""
            del store[rid]
            if coll == "items":
                if "stats_stale" not in self.bugs:
                    self.stat_total -= 1
                if "child_leak" not in self.bugs:
                    self.comments.pop(rid, None)
            return 204, b""
        return 405, b'{"error":"method"}'


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _serve(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        status, payload = self.server.app.handle(self.command, self.path, raw)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _serve


def start(bugs=()):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.app = FakeApp(bugs)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def run_engine(bugs=(), spec=None, **knobs):
    srv, base = start(bugs)
    try:
        client = api.Api(base, {"user_a": {"Authorization": "Bearer test-token"}})
        return metamorphic.run(client, spec if spec is not None else full_spec(), SimpleNamespace(**knobs))
    finally:
        srv.shutdown()
        srv.server_close()


def _int(name, lo=None, hi=None):
    s = {"type": "integer"}
    if lo is not None:
        s["minimum"] = lo
    if hi is not None:
        s["maximum"] = hi
    return {"name": name, "in": "query", "required": False, "schema": s}


def _body(schema):
    return {"required": True, "content": {"application/json": {"schema": schema}}}


COMMENT_BODY = {"type": "object", "required": ["text"], "properties": {"text": {"type": "string", "minLength": 1}}}
ITEM_BODY = {"type": "object", "required": ["name", "category", "price"],
             "properties": {"name": {"type": "string", "minLength": 1},
                            "category": {"type": "string", "enum": list(CATS)},
                            "price": {"type": "integer", "minimum": 0}}}
LABEL_BODY = {"type": "object", "required": ["name", "color"],
              "properties": {"name": {"type": "string"}, "color": {"type": "string"}}}
PATH_ID = [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}]
# api.endpoints() skips operations that are empty dicts, as real OpenAPI operations always carry responses
OP = {"responses": {"200": {"description": "ok"}}}


ITEM_RESP = {"type": "object", "required": ["id", "name", "category", "price"], "properties": {
    "id": {"type": "integer"}, "name": {"type": "string"}, "category": {"type": "string"}, "price": {"type": "integer"}}}
LIST_RESP = {"type": "object", "required": ["items", "total"], "properties": {
    "items": {"type": "array", "items": ITEM_RESP}, "total": {"type": "integer"}}}


def full_spec():
    return {"openapi": "3.0.3", "info": {"title": "metamorphic-test", "version": "1"}, "paths": {
        "/items": {"get": {"responses": {"200": {"description": "ok", "content": {"application/json": {"schema": LIST_RESP}}}},
                           "parameters": [
                       _int("limit", 1, 100), _int("offset", 0),
                       {"name": "sort", "in": "query", "schema": {"type": "string", "enum": ["name", "price"]}},
                       {"name": "order", "in": "query", "schema": {"type": "string", "enum": ["asc", "desc"]}},
                       {"name": "category", "in": "query", "schema": {"type": "string", "enum": list(CATS)}},
                       {"name": "name", "in": "query", "schema": {"type": "string"}}]},
                   "post": {"requestBody": _body(ITEM_BODY)}},
        "/items/{id}": {"parameters": PATH_ID, "get": OP, "put": {"requestBody": _body(ITEM_BODY)}, "delete": OP},
        "/notes": {"get": {"parameters": [_int("page", 1), _int("per_page", 1, 100)], "responses": OP["responses"]}},
        "/labels": {"get": OP, "post": {"requestBody": _body(LABEL_BODY)}},
        "/labels/{id}": {"parameters": PATH_ID, "get": OP, "put": {"requestBody": _body(LABEL_BODY)}, "delete": OP},
        "/items/{id}/comments": {"parameters": PATH_ID, "get": OP, "post": {"requestBody": _body(COMMENT_BODY)}},
        "/stats": {"get": OP},
    }}


def ping_spec():
    return {"openapi": "3.0.3", "paths": {"/ping": {"get": OP}}}


def no_get_spec():
    hook = {"type": "object", "properties": {"url": {"type": "string"}}}
    return {"openapi": "3.0.3", "paths": {"/hooks": {"post": {"requestBody": _body(hook)}}}}


def assert_detects(kind, *bugs):
    res = run_engine(bugs)
    found = [f for f in res["findings"] if f["kind"] == kind]
    assert found, (kind, bugs, [(f["kind"], f["endpoint"], f["detail"][:140]) for f in res["findings"]],
                   res["notes"][:6])
    for f in found:
        assert f["detail"] and f["sequence"], f"finding without evidence: {f}"
    return found


# ---------- clean control ----------

def test_clean_app_gives_zero_findings_and_every_relation_ran():
    res = run_engine()
    assert res["findings"] == [], [(f["kind"], f["endpoint"], f["detail"][:160]) for f in res["findings"]]
    status, reason = trust.resolve(res)
    assert status == trust.RAN_OK, (status, reason, res["notes"])
    for kind in (k for k in metamorphic.RELATIONS if k not in metamorphic.OPTIONAL):      # optional ones need a boolean / search parameter
        st = res["relations"][kind]
        assert st["clean"] >= 1 and st["violations"] == 0, (kind, st)
    assert "served_at" in res["volatile_learned"], res["volatile_learned"]


# ---------- one buggy variant per relation ----------

def test_page_union_detects_off_by_one_window():
    found = assert_detects("MR-PAGE-UNION", "offbyone")
    assert any("missing" in f["detail"] or "duplicates" in f["detail"] for f in found)


def test_page_union_accepts_zero_based_page_numbers():
    res = run_engine(("notes_zero_based",))
    assert not [f for f in res["findings"] if f["kind"] == "MR-PAGE-UNION"], res["findings"]
    assert res["relations"]["MR-PAGE-UNION"]["clean"] >= 1, res["relations"]["MR-PAGE-UNION"]


def test_page_total_detects_wrong_total():
    assert_detects("MR-PAGE-TOTAL", "total_wrong")


def test_page_total_detects_huge_limit_500():
    assert_detects("MR-PAGE-TOTAL", "limit_huge_500")


def test_filter_subset_detects_ignored_filter():
    assert_detects("MR-FILTER-SUBSET", "filter_ignored")


def test_sort_order_detects_ignored_sort():
    assert_detects("MR-SORT-ORDER", "sort_ignored")


def test_sort_order_detects_ignored_order_param():
    assert_detects("MR-SORT-ORDER", "order_ignored")


def test_read_idempotent_detects_reordered_reads_as_low():
    found = assert_detects("MR-READ-IDEMPOTENT", "labels_shuffle")
    assert any(f["severity"] == "low" for f in found), found


def test_read_idempotent_detects_dropped_item():
    found = assert_detects("MR-READ-IDEMPOTENT", "labels_drop")
    assert any(f["severity"] == "medium" for f in found), found


def test_write_roundtrip_detects_changed_field():
    assert_detects("MR-WRITE-ROUNDTRIP", "roundtrip_upper")


def test_put_idempotent_detects_growing_state():
    assert_detects("MR-PUT-IDEMPOTENT", "put_history")


def test_delete_gone_detects_resource_left_behind():
    assert_detects("MR-DELETE-GONE", "delete_leaves")


def test_delete_gone_detects_second_delete_500():
    assert_detects("MR-DELETE-GONE", "delete_twice_500")


def test_param_order_detects_order_dependent_answer():
    assert_detects("MR-PARAM-ORDER", "param_order_filter")


def test_unknown_param_detects_500():
    assert_detects("MR-UNKNOWN-PARAM", "unknown_500")


def test_head_get_detects_head_404():
    assert_detects("MR-HEAD-GET", "head_404")


def test_exact_filter_matching_a_strict_substring_is_detected():
    found = assert_detects("MR-FILTER-SUBSET", "name_prefix")
    assert any("strict substring" in f["detail"] and "name" in f["detail"] for f in found), found


def test_count_agree_detects_stale_counter():
    found = assert_detects("MR-COUNT-AGREE", "stats_stale")
    assert any("/stats" in f["detail"] and "total" in f["detail"] for f in found), found


def test_delete_gone_detects_child_collection_still_listing_items():
    found = assert_detects("MR-DELETE-GONE", "child_leak")
    assert any("/comments" in f["detail"] and "still lists" in f["detail"] for f in found), found


def test_sort_order_detects_lexical_descending_sort():
    found = assert_detects("MR-SORT-ORDER", "sort_desc_lexical")
    assert any("price" in f["detail"] for f in found), found


def test_sort_order_detects_numbers_rendered_as_strings():
    found = assert_detects("MR-SORT-ORDER", "price_as_string")
    assert any("declares integer" in f["detail"] for f in found), found


def test_paging_repeat_is_a_finding_and_does_not_block_the_other_relations():
    res = run_engine(("offbyone",))
    assert [f for f in res["findings"] if f["kind"] == "MR-PAGE-UNION"], res["findings"]
    for kind in ("MR-SORT-ORDER", "MR-FILTER-SUBSET", "MR-PAGE-TOTAL"):
        assert res["relations"][kind]["inconclusive"] == 0, (kind, res["relations"][kind], res["notes"][:4])


def test_empty_collection_is_seeded_from_the_example_body_then_cleaned_up():
    srv, base = start()
    try:
        app = srv.app
        app.labels = {}                                  # the collection starts empty
        client = api.Api(base, {"user_a": {"Authorization": "Bearer test-token"}})
        spec = {"openapi": "3.0.3", "paths": {
            "/labels": {"get": OP, "post": {"requestBody": _body(LABEL_BODY)}},
            "/labels/{id}": {"parameters": PATH_ID, "get": OP, "delete": OP}}}
        res = metamorphic.run(client, spec, SimpleNamespace())
        assert app.labels == {}, f"seeded labels were not deleted again: {app.labels}"
        assert any(n.startswith("seeded ") and "/labels" in n for n in res["notes"]), res["notes"]
        assert any(n.startswith("created items cleaned up: ") for n in res["notes"]), res["notes"]
        assert res["relations"]["MR-DELETE-GONE"]["clean"] >= 1, res["relations"]["MR-DELETE-GONE"]
        assert res["findings"] == [], res["findings"]
    finally:
        srv.shutdown()
        srv.server_close()


# ---------- status, knobs and guards ----------

def test_no_applicable_relation_is_skipped_no_spec():
    res = run_engine(spec=no_get_spec())
    assert trust.resolve(res)[0] == trust.SKIPPED, trust.resolve(res)


def test_missing_relations_degrade_status_and_are_noted():
    res = run_engine(spec=ping_spec())
    status, reason = trust.resolve(res)
    assert status == trust.DEGRADED, (status, reason)
    assert any("relation not applicable" in n for n in res["notes"]), res["notes"]
    assert res["findings"] == [], res["findings"]


def test_knob_skip_disables_a_relation_and_an_endpoint():
    res = run_engine(("filter_ignored",), METAMORPHIC_SKIP={"MR-FILTER-SUBSET"})
    assert not [f for f in res["findings"] if f["kind"] == "MR-FILTER-SUBSET"], res["findings"]
    assert res["relations"]["MR-FILTER-SUBSET"]["skipped"] >= 1, res["relations"]["MR-FILTER-SUBSET"]
    res2 = run_engine(("filter_ignored",), METAMORPHIC_SKIP={"GET /items"})
    assert not [f for f in res2["findings"] if f["kind"] == "MR-FILTER-SUBSET"], res2["findings"]


def test_flaky_violation_is_not_reported_but_a_reproduced_one_is():
    dummy = SimpleNamespace(roles={"anon": {}}, log=[])
    ctx = metamorphic.Ctx(dummy, {}, SimpleNamespace())
    calls = {"n": 0}

    def once():
        calls["n"] += 1
        return ("medium", "seen once") if calls["n"] == 1 else None

    metamorphic.run_instance(ctx, "MR-SORT-ORDER", "GET /x", "GET /x", once)
    assert ctx.findings == [] and ctx.stats["MR-SORT-ORDER"]["inconclusive"] == 1, ctx.stats["MR-SORT-ORDER"]
    metamorphic.run_instance(ctx, "MR-SORT-ORDER", "GET /y", "GET /y", lambda: ("medium", "always"))
    assert len(ctx.findings) == 1 and ctx.findings[0]["endpoint"] == "GET /y", ctx.findings


if __name__ == "__main__":
    tests = sorted((name, fn) for name, fn in globals().items() if name.startswith("test_") and callable(fn))
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except AssertionError as exc:
            failed += 1
            print("FAIL", name, str(exc)[:600])
        except Exception as exc:
            failed += 1
            print("ERROR", name, type(exc).__name__, str(exc)[:300])
    print(f"{len(tests) - failed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
