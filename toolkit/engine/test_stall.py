"""An app that stops answering must end the run quickly, with a report that names the request. It must never hang the toolkit.

  python toolkit/engine/test_stall.py        (also collectable by pytest)
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import api as api_mod  # noqa: E402
import trust  # noqa: E402

SECONDS = {}                        # path -> seconds the fake app takes to answer


class Handler(BaseHTTPRequestHandler):
    def _answer(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        time.sleep(SECONDS.get(self.path.split("?")[0], 0))
        data = b'{"ok": true}'
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


def _server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _client(srv, timeout=0.1):
    api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}")
    api.timeout = timeout
    return api


def test_three_lost_requests_in_a_row_mark_the_app_stalled_and_name_the_first():
    srv, SECONDS["/slow"] = _server(), 2
    api = _client(srv)
    for i in range(3):
        assert api.call("anon", "POST", "/slow", {"n": i}).transport
    assert api.stalled["method"] == "POST" and api.stalled["path"] == "/slow" and '"n": 0' in api.stalled["request"]


def test_requests_after_the_stall_are_not_sent():
    srv, SECONDS["/slow"] = _server(), 2
    api = _client(srv)
    for _ in range(3):
        api.call("anon", "GET", "/slow")
    started = time.time()
    r = api.call("anon", "GET", "/fast")
    assert r.transport and time.time() - started < 0.05 and len(api.log) == 4


def test_a_single_lost_request_is_forgiven():
    srv, SECONDS["/slow"] = _server(), 2
    api = _client(srv)
    api.call("anon", "GET", "/slow")
    api.call("anon", "GET", "/slow")
    assert api.call("anon", "GET", "/fast").ok
    api.call("anon", "GET", "/slow")
    assert api.stalled is None


def test_the_timeout_can_be_set_from_the_environment(monkeypatch):
    monkeypatch.setenv("QA_REQUEST_TIMEOUT", "7")
    assert api_mod.Api("http://127.0.0.1:1").timeout == 7


def test_requests_that_were_never_sent_are_not_reported_as_findings():
    import negative_engine
    from types import SimpleNamespace
    srv = _server()
    api = _client(srv)
    api.roles["user_a"] = {"t": "a"}
    api.stalled = {"role": "user_a", "method": "GET", "path": "/x", "request": "null"}
    doc = {"paths": {"/items": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}}}}
    r = negative_engine.run(api, doc, SimpleNamespace(BODIES={"POST /items": {"name": "x"}}))
    assert [f for f in r["findings"] if f["kind"] == "NEG-NO-RESPONSE"] == []


def test_run_py_stops_and_still_writes_a_report_naming_the_request():
    srv, SECONDS["/freeze"] = _server(), 3
    with tempfile.TemporaryDirectory() as d:
        spec, doc = Path(d) / "qa-spec.py", Path(d) / "openapi.json"
        spec.write_text("def setup(api):\n    return {'user_a': {'t': 'a'}, 'user_b': {'t': 'b'}}\n\n\n"
                        "PUBLIC = {'POST /freeze'}\nBODIES = {'POST /freeze': {'email': 'a@b.c'}}\n"
                        "RACES = [{'name': 'r', 'setup': lambda api, ctx: {}, 'check': lambda api, results, ctx: results}]\n", encoding="utf-8")
        schema = {"type": "object", "properties": {"email": {"type": "string"}}}
        doc.write_text(json.dumps({"paths": {"/freeze": {"post": {"requestBody": {"content": {"application/json": {"schema": schema}}}}}}}), encoding="utf-8")
        started = time.time()
        p = subprocess.run([sys.executable, str(HERE / "run.py"), "--base-url", f"http://127.0.0.1:{srv.server_address[1]}", "--spec", str(spec),
                            "--openapi", str(doc), "--out", str(Path(d) / "out"), "--engines", "negative,race"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env={**os.environ, "QA_REQUEST_TIMEOUT": "1"}, timeout=60)
        assert time.time() - started < 30
        assert p.returncode == 2, p.stdout[-500:] + p.stderr[-500:]
        results = {r["engine"]: r for r in json.loads((Path(d) / "out" / "engines.json").read_text(encoding="utf-8"))}
        found = results["app-health"]["findings"][0]
        assert found["kind"] == "APP-UNRESPONSIVE" and found["endpoint"] == "POST /freeze" and "email" in found["detail"]
        assert trust.resolve(results["race"])[0] == trust.ERRORED and "did not run" in trust.resolve(results["race"])[1]
        assert trust.resolve(results["negative"])[0] == trust.DEGRADED
