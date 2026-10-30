"""Tests for differential.py with our own stdlib servers (ephemeral ports, loopback only).

  python toolkit/engine/test_differential.py        (also collectable by pytest)

Apps: A = old version; B = A with planted regressions; A2 = A with other random ids / timestamps / counters / nonces (zero findings
expected: noise learning works). A server's `offset` makes its request counter start elsewhere, like an app that ran for a while.
"""
import json
import random
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import differential as d  # noqa: E402
import trust  # noqa: E402
from api import Api  # noqa: E402

DOC = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
    "/health": {"get": {"responses": {"200": {"description": "ok"}}}},
    "/items": {
        "get": {"responses": {"200": {"description": "ok"}}},
        "post": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}},
                 "responses": {"201": {"description": "ok"}}}},
    "/items/{item_id}": {
        "get": {"parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}},
        "put": {"parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}},
                "responses": {"200": {"description": "ok"}}},
        "delete": {"parameters": [{"name": "item_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
}, "components": {"schemas": {"Item": {"type": "object", "required": ["name"], "properties": {
    "name": {"type": "string"}, "qty": {"type": "integer"}}}}}}


class App:
    """In-memory items API. Options: uuid_ids, offset, regress (plant B's regressions), version."""

    def __init__(self, uuid_ids=False, offset=0, regress=False, version="1"):
        self.items, self.counter, self.next_id = {}, offset, 1
        self.uuid_ids, self.regress, self.version = uuid_ids, regress, version
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj, extra=None):
                with outer.lock:
                    outer.counter += 1
                    if isinstance(obj, dict):
                        obj = {**obj, "served": outer.counter, "nonce": "".join(random.choice("abcxyz") for _ in range(7)),
                               "request_id": str(uuid.uuid4())}
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                try:
                    return json.loads(self._raw or b"null")
                except ValueError:
                    return None

            def _item(self, it):
                out = {"id": it["id"], "name": it["name"], "qty": it["qty"], "created_at": it["created_at"]}
                if outer.regress:
                    out["name"] = str(it["name"]).upper()          # planted: value change
                    del out["qty"]                                  # planted: field removed
                return out

            def _route(self):
                # a real server reads the request body before it answers, even a 404; otherwise Windows resets the connection
                n = int(self.headers.get("Content-Length") or 0)
                self._raw = self.rfile.read(n) if n > 0 else b""
                p = self.path.split("?")[0].rstrip("/")
                m = self.command
                if p == "/health" and m == "GET":
                    extra = {"X-Frame-Options": "DENY"} if outer.regress else None
                    body = {"status": "ok", "version": outer.version}
                    if outer.regress:
                        body["extra"] = True                        # planted: field added
                    return self._send(200, body, extra)
                if p == "/items" and m == "POST":
                    b = self._body() or {}
                    with outer.lock:
                        iid = str(uuid.uuid4()) if outer.uuid_ids else outer.next_id
                        outer.next_id += 1
                        it = {"id": iid, "name": b.get("name", ""), "qty": b.get("qty", 0),
                              "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                        outer.items[str(iid)] = it
                    out = self._item(it)
                    if outer.regress:
                        out["qty"] = str(it["qty"])                 # planted: type change int -> string
                    return self._send(201, out)
                if p == "/items" and m == "GET":
                    return self._send(200, {"items": [self._item(i) for i in outer.items.values()]})
                if p.startswith("/items/"):
                    it = outer.items.get(p.split("/")[2])
                    if it is None:
                        return self._send(404, {"detail": "not found"})
                    if m == "GET":
                        return self._send(200, self._item(it))
                    if m == "PUT":
                        if outer.regress:
                            return self._send(500, {"detail": "boom"})   # planted: 2xx -> 5xx
                        b = self._body() or {}
                        it.update(name=b.get("name", it["name"]), qty=b.get("qty", it["qty"]))
                        return self._send(200, self._item(it))
                    if m == "DELETE":
                        del outer.items[p.split("/")[2]]
                        return self._send(200, {"deleted": True})
                return self._send(404, {"detail": "no route"})

            do_GET = do_POST = do_PUT = do_DELETE = _route

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def qa_for(base_b=None, **kw):
    return SimpleNamespace(DIFF_BASE_URL=base_b, **kw)


def kinds(res):
    return {(f["kind"], f.get("path")) for f in res["findings"]}


def test_identical_code_with_other_ids_timestamps_counters_gives_zero_findings():
    a, a2 = App(), App(uuid_ids=True, offset=500)
    try:
        res = d.run(Api(a.url), DOC, qa_for(a2.url))
        assert res["findings"] == [], res["findings"]
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])
        assert res["probes"] > 0
        assert any("served" in str(v) for v in res["noise_learned"].values()), res["noise_learned"]   # it really learned the counter
    finally:
        a.stop(); a2.stop()


def test_without_noise_learning_the_same_pair_does_report_noise():
    a, a2 = App(), App(uuid_ids=True, offset=500)
    try:
        res = d.run(Api(a.url), DOC, qa_for(a2.url, DIFF_NOISE_RUNS=0))
        assert any(f["path"].endswith("served") for f in res["findings"]), "noise learning would be a no-op if this were empty"
        assert res["status"] == trust.DEGRADED and "noise learning disabled" in "\n".join(res["notes"])
    finally:
        a.stop(); a2.stop()


def test_planted_regressions_are_found_with_evidence():
    a, b = App(), App(uuid_ids=True, offset=500, regress=True)
    try:
        res = d.run(Api(a.url), DOC, qa_for(b.url))
        by = {(f["kind"], f["endpoint"], f["path"]): f for f in res["findings"]}
        st = by[("DIFF-STATUS", "PUT /items/{item_id}", "$status")]
        assert st["severity"] == "high" and "200 -> 500" in st["detail"] and "boom" in st["detail"]
        rem = by[("DIFF-SHAPE", "GET /items/{item_id}", "qty")]
        assert rem["severity"] == "medium" and "removed" in rem["detail"]
        typ = by[("DIFF-SHAPE", "POST /items", "qty")]
        assert typ["severity"] == "medium" and "number -> string" in typ["detail"]
        val = by[("DIFF-BODY", "GET /items/{item_id}", "name")]
        assert "'qa'" in val["detail"] and "'QA'" in val["detail"]
        add = by[("DIFF-SHAPE", "GET /health", "extra")]
        assert add["severity"] == "info"
        ver = [f for f in res["findings"] if f["path"] == "version"]
        assert ver == []                                    # same version string on both here
        hdr = by[("DIFF-HEADER", "GET /health", "$header.x-frame-options")]
        assert hdr["severity"] == "info"
        assert "A (old) answered" in st["detail"] and "B (new) answered" in st["detail"] and st["sequence"]
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])
        assert not any(f["path"].endswith(("served", "nonce", "request_id", "created_at")) for f in res["findings"]), res["findings"]
    finally:
        a.stop(); b.stop()


def test_expect_changes_allow_list_suppresses_only_the_listed_change():
    a, b = App(), App(uuid_ids=True, offset=500, regress=True, version="2")
    try:
        full = d.run(Api(a.url), DOC, qa_for(b.url))
        assert ("DIFF-BODY", "version") in kinds(full)
        expect = ["GET /health version", "PUT /items/{item_id} $status"]
        res = d.run(Api(a.url), DOC, qa_for(b.url, DIFF_EXPECT=expect))
        assert ("DIFF-BODY", "version") not in kinds(res)
        assert ("DIFF-STATUS", "$status") not in kinds(res)
        assert ("DIFF-SHAPE", "qty") in kinds(res)           # unrelated regressions stay
        assert any("suppressed" in n for n in res["notes"])
        whole = d.run(Api(a.url), DOC, qa_for(b.url, DIFF_EXPECT=["GET /items/{item_id}"]))      # "METHOD path" = whole endpoint
        assert not [f for f in whole["findings"] if f["endpoint"] == "GET /items/{item_id}"]
    finally:
        a.stop(); b.stop()


def test_missing_second_version_is_skipped_not_clean():
    a = App()
    try:
        res = d.run(Api(a.url), DOC, qa_for(None))
        assert res["status"] == trust.SKIPPED and "DIFF_BASE_URL" in res["status_reason"] and res["findings"] == []
        res = d.run(Api(a.url), DOC, qa_for(a.url))
        assert res["status"] == trust.ERRORED
    finally:
        a.stop()


def test_env_var_supplies_second_version():
    import os
    a, a2 = App(), App()
    os.environ["QA_DIFF_BASE_URL"] = a2.url
    try:
        res = d.run(Api(a.url), DOC, qa_for(None))
        assert res["status"] == trust.RAN_OK and res["probes"] > 0
    finally:
        os.environ.pop("QA_DIFF_BASE_URL", None)
        a.stop(); a2.stop()


def test_dead_b_is_errored_not_clean():
    a, b = App(), App()
    dead = b.url
    b.stop()
    try:
        res = d.run(Api(a.url), DOC, qa_for(dead))
        assert res["status"] == trust.ERRORED and res["findings"] == []
    finally:
        a.stop()


def test_non_local_b_is_refused():
    a = App()
    try:
        res = d.run(Api(a.url), DOC, qa_for("http://example.com"))
        assert res["status"] == trust.ERRORED and "non-local" in res["status_reason"]
    finally:
        a.stop()


def _record_log(base):
    rec = Api(base)
    r = rec.call("anon", "POST", "/items", {"name": "qa", "qty": 1})
    iid = r.json["id"]
    rec.call("anon", "GET", f"/items/{iid}")
    rec.call("anon", "PUT", f"/items/{iid}", {"name": "qa2", "qty": 2})
    rec.call("anon", "GET", "/health")
    return rec.log


def test_replay_mode_maps_ids_and_finds_regressions():
    src, a, a2, b = App(), App(), App(uuid_ids=True, offset=700), App(uuid_ids=True, offset=300, regress=True)
    try:
        log = _record_log(src.url)
        clean = d.replay_log(Api(a.url), Api(a2.url), log)
        assert clean["findings"] == [], clean["findings"]
        assert clean["status"] == trust.RAN_OK, (clean["status"], clean["status_reason"])
        res = d.replay_log(Api(a.url), Api(b.url), log)
        assert ("DIFF-STATUS", "$status") in kinds(res) and ("DIFF-SHAPE", "qty") in kinds(res), res["findings"]
        assert d.replay_log(Api(a.url), Api(b.url), [])["status"] == trust.DEGRADED
    finally:
        for s in (src, a, a2, b):
            s.stop()


def test_cli_writes_report_and_exit_code():
    a, b = App(), App(uuid_ids=True, offset=500, regress=True)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "openapi.json"
            doc.write_text(json.dumps(DOC), encoding="utf-8")
            allow = Path(tmp) / "allow.json"
            allow.write_text(json.dumps(["GET /health extra"]), encoding="utf-8")
            code = d.main(["--a", a.url, "--b", b.url, "--openapi", str(doc), "--out", str(Path(tmp) / "out"),
                           "--expect-changes", str(allow), "--seed", "3"])
            assert code == 1
            data = json.loads((Path(tmp) / "out" / "differential.json").read_text(encoding="utf-8"))
            assert data["status"] == trust.RAN_OK and not [f for f in data["findings"] if f["path"] == "extra"]
            assert (Path(tmp) / "out" / "differential.md").read_text(encoding="utf-8").startswith("# Differential")
            code2 = d.main(["--a", a.url, "--b", a.url, "--openapi", str(doc), "--out", str(Path(tmp) / "out2")])
            assert code2 == 0
    finally:
        a.stop(); b.stop()


def test_diff_records_unit_cases():
    mk = lambda **kw: {"status": 200, "ctype": "application/json", "hnames": [], "is_json": True, "json": {}, "text": "", **kw}
    assert d.diff_records(mk(json={"a": 1}), mk(json={"a": 1.0})) == []
    assert d.diff_records(mk(json={"a": 1}), mk(json={"a": True}))[0][0] == "type"
    assert d.diff_records(mk(json={"a": None}), mk(json={"a": 1}))[0][0] == "type"
    assert d.diff_records(mk(json={"l": [1, 2]}), mk(json={"l": [1]}))[0][:2] == ("len", "l.#len")
    assert d.diff_records(mk(), mk(status=500)) == [("status", "$status", 200, 500)]
    assert d._status_sev(200, 503) == "high" and d._status_sev(200, 404) == "medium" and d._status_sev(500, 200) == "info"


# ---------------------------------------------------------------- probes, defaults, filters, state (tasks-like API)

PRIORITIES = ["low", "medium", "high"]
TASK_DOC = {"openapi": "3.0.3", "info": {"title": "tasks", "version": "1"}, "paths": {
    "/tasks": {
        "get": {"parameters": [
            {"name": "priority", "in": "query", "schema": {"type": "string", "enum": PRIORITIES}},
            {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}],
            "responses": {"200": {"description": "ok"}}},
        "post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["title"], "properties": {
                     "title": {"type": "string"}, "priority": {"type": "string", "enum": PRIORITIES},
                     "tags": {"type": "array", "items": {"type": "string"}}}}}}},
                 "responses": {"201": {"description": "created", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Task"}}}}}},
    },
    "/tasks/{id}": {
        "get": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}},
        "patch": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                  "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
                      "title": {"type": "string"}, "priority": {"type": "string", "enum": PRIORITIES}}}}}},
                  "responses": {"200": {"description": "ok"}}},
        "delete": {"parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"204": {"description": "deleted"}}},
    },
}, "components": {"schemas": {"Task": {"type": "object", "properties": {
    "id": {"type": "string"}, "title": {"type": "string"},
    "priority": {"type": "string", "enum": PRIORITIES, "default": "medium"}, "tags": {"type": "array", "items": {"type": "string"}}}}}}}


class TaskSvc:
    """Small tasks API. Flags plant ONE regression each on the B side:
    default_priority ('low' = default changed), empty_tags_500 (a valid [] crashes), unknown_400 (unknown id: 404 -> 400),
    ignore_priority_filter (the filter is silently ignored and any priority is accepted).
    noise=True adds a request id and a counter to every answer; uuid_ids / offset change the ids and the counter's start."""

    def __init__(self, uuid_ids=True, offset=0, noise=True, **flags):
        self.flags = {"default_priority": "medium", "empty_tags_500": False, "unknown_400": False,
                      "ignore_priority_filter": False, **flags}
        self.tasks, self.uuid_ids, self.noise, self.counter, self.next_id = {}, uuid_ids, noise, offset, 1
        self.lock = threading.Lock()
        svc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, obj):
                with svc.lock:
                    svc.counter += 1
                    if obj is not None and svc.noise:
                        obj = {**obj, "request_id": uuid.uuid4().hex, "served": svc.counter}
                data = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(code)
                if obj is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)

            def _route(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n > 0 else b""          # read the body first, also on 404 (see App)
                try:
                    body = json.loads(raw) if raw else None
                except ValueError:
                    body = "<invalid>"
                url = self.path.split("?", 1)
                parts = [x for x in url[0].split("/") if x]
                query = dict(q.split("=", 1) for q in url[1].split("&")) if len(url) > 1 and url[1] else {}
                m = self.command
                if parts == ["tasks"] and m == "POST":
                    if not isinstance(body, dict) or not isinstance(body.get("title"), str) or not body["title"]:
                        return self._reply(400, {"error": "validation_error"})
                    pr = body.get("priority")
                    if pr is not None and pr not in PRIORITIES:
                        return self._reply(400, {"error": "validation_error"})
                    tags = body.get("tags")
                    if tags is not None and not (isinstance(tags, list) and all(isinstance(t, str) for t in tags)):
                        return self._reply(400, {"error": "validation_error"})
                    if tags == [] and svc.flags["empty_tags_500"]:
                        return self._reply(500, {"error": "internal"})
                    with svc.lock:
                        tid = str(uuid.uuid4()) if svc.uuid_ids else str(svc.next_id)
                        svc.next_id += 1
                        task = {"id": tid, "title": body["title"], "priority": pr or svc.flags["default_priority"],
                                "tags": tags or []}
                        svc.tasks[tid] = task
                    return self._reply(201, dict(task))
                if parts == ["tasks"] and m == "GET":
                    pr = query.get("priority")
                    if pr is not None and not svc.flags["ignore_priority_filter"] and pr not in PRIORITIES:
                        return self._reply(400, {"error": "validation_error"})
                    try:
                        limit = int(query.get("limit", 20))
                    except ValueError:
                        return self._reply(400, {"error": "validation_error"})
                    if not 1 <= limit <= 100:
                        return self._reply(400, {"error": "validation_error"})
                    with svc.lock:
                        rows = [t for t in svc.tasks.values()
                                if svc.flags["ignore_priority_filter"] or pr is None or t["priority"] == pr]
                        items = [dict(t) for t in rows[:limit]]
                    return self._reply(200, {"items": items, "total": len(rows)})
                if len(parts) == 2 and parts[0] == "tasks":
                    with svc.lock:                      # build the answer under the lock, send it after (_reply locks too)
                        task = svc.tasks.get(parts[1])
                        if task is None:
                            answer = (400, {"error": "bad_request"}) if (m == "GET" and svc.flags["unknown_400"]) \
                                else (404, {"error": "not_found"})
                        elif m == "GET":
                            answer = (200, dict(task))
                        elif m == "DELETE":
                            del svc.tasks[parts[1]]
                            answer = (204, None)
                        elif m == "PATCH" and isinstance(body, dict) and body.get("priority", "low") in PRIORITIES:
                            task.update({k: v for k, v in body.items() if k in ("title", "priority")})
                            answer = (200, dict(task))
                        else:
                            answer = (400, {"error": "validation_error"})
                    return self._reply(*answer)
                return self._reply(404, {"error": "no_route"})

            do_GET = do_POST = do_PATCH = do_DELETE = _route

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def _by(res):
    return {(f["kind"], f["endpoint"], f["path"]): f for f in res["findings"]}


def test_probes_find_status_change_on_valid_empty_array():
    a, b = TaskSvc(), TaskSvc(empty_tags_500=True)
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        f = _by(res)[("DIFF-STATUS", "POST /tasks", "$status")]
        assert f["severity"] == "high" and "201 -> 500" in f["detail"] and "probe empty:tags" in f["detail"], f["detail"]
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])
        off = d.run(Api(a.url), TASK_DOC, qa_for(b.url, DIFF_PROBES=False))
        assert not [x for x in off["findings"] if "probe" in x["detail"]], "DIFF_PROBES=False must not run the probes"
    finally:
        a.stop(); b.stop()


def test_documented_default_change_on_minimal_create_is_diff_default():
    a, b = TaskSvc(), TaskSvc(default_priority="low")
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        f = _by(res)[("DIFF-DEFAULT", "POST /tasks", "priority")]
        assert f["severity"] == "medium" and "'medium'" in f["detail"] and "'low'" in f["detail"] and "minimal" in f["detail"], f["detail"]
    finally:
        a.stop(); b.stop()


def test_unknown_id_error_code_change_is_medium_status():
    a, b = TaskSvc(), TaskSvc(unknown_400=True)
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        f = _by(res)[("DIFF-STATUS", "GET /tasks/{id}", "$status")]
        assert f["severity"] == "medium" and "404 -> 400" in f["detail"] and "unknown-id" in f["detail"], f["detail"]
    finally:
        a.stop(); b.stop()


def test_filter_silently_ignored_is_diff_filter_and_bad_enum_is_status():
    a, b = TaskSvc(), TaskSvc(ignore_priority_filter=True)
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        by = _by(res)
        f = by[("DIFF-FILTER", "GET /tasks", "$filter.priority=low")]
        assert f["severity"] == "medium" and "A (old) returned 1 item(s) (0 with another priority)" in f["detail"], f["detail"]
        assert "B (new) returned 3 item(s) (2 with another priority)" in f["detail"], f["detail"]
        assert by[("DIFF-STATUS", "GET /tasks", "$status")]["severity"] == "low"          # 400 -> 200 on the bogus value
        assert not [x for x in res["findings"] if x["kind"] == "DIFF-BODY" and x["endpoint"] == "GET /tasks"
                    and "items" in x["path"]], "the filter difference is reported once, as DIFF-FILTER"
    finally:
        a.stop(); b.stop()


def test_no_regression_pair_with_probes_and_noise_has_zero_findings():
    a, a2 = TaskSvc(), TaskSvc(uuid_ids=False, offset=700)
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(a2.url))
        assert res["findings"] == [], res["findings"]
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])
        assert res["probes"] > 40, res["probes"]
    finally:
        a.stop(); a2.stop()


def test_unequal_pre_run_state_is_labelled_and_degrades():
    a, b = TaskSvc(), TaskSvc()
    try:
        Api(a.url).call("anon", "POST", "/tasks", {"title": "leftover from an earlier session"})      # A is not empty
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        assert res["status"] == trust.DEGRADED and "pre-run state differs" in res["status_reason"], (res["status"], res["status_reason"])
        aggregates = [f for f in res["findings"] if f["endpoint"] == "GET /tasks" and "UNEQUAL STATE" in f["detail"]]
        assert aggregates and all(f["severity"] == "info" for f in aggregates), res["findings"]
        assert not [f for f in res["findings"] if "UNEQUAL STATE" in f["detail"] and f["severity"] != "info"]
    finally:
        a.stop(); b.stop()


def test_probe_budget_caps_the_probes_and_says_so():
    a, b = TaskSvc(), TaskSvc(empty_tags_500=True)
    old = d.PROBE_BUDGET
    d.PROBE_BUDGET = 3
    try:
        res = d.run(Api(a.url), TASK_DOC, qa_for(b.url))
        assert any("probe budget" in n for n in res["notes"]), res["notes"]
        assert not [f for f in res["findings"] if "probe" in f["detail"]]
    finally:
        d.PROBE_BUDGET = old
        a.stop(); b.stop()


def test_body_variants_and_documented_defaults_units():
    schema = TASK_DOC["paths"]["/tasks"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    names = [n for n, _ in d.body_variants(schema, TASK_DOC, {"title": "t", "priority": "high", "tags": ["x"]})]
    for want in ("minimal", "empty:title", "empty:tags", "enum=low:priority", "missing:title", "type:tags"):
        assert want in names, (want, names)
    ep = next(e for e in d.endpoints(TASK_DOC) if e["method"] == "POST" and e["path"] == "/tasks")
    assert d.documented_defaults(TASK_DOC, ep) == {"priority": "medium"}
    assert d._omit(TASK_DOC, ep, {"title": "t"}) == {"priority": "medium"} and d._omit(TASK_DOC, ep, {"priority": "low"}) == {}
    assert d._status_sev(404, 400) == "medium" and d._status_sev(200, 201) == "low"


def _main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception as exc:        # noqa: BLE001
            failed += 1
            import traceback
            traceback.print_exc()
            print("FAIL", name, exc)
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())


def test_pick_role_uses_a_plain_role_of_any_name():
    api = SimpleNamespace(roles={"anon": {}, "admin": {"t": "x"}, "buyer": {"t": "b"}})
    assert d._pick_role(api, SimpleNamespace(), {"role": None, "key": "POST /x"}) == "buyer"
