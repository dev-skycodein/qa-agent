"""Regression tests for audit batch 1 (A-M7..A-M13, A-L1, A-L2, A-L9, A-L10, A-L11).

  python -m pytest toolkit/engine/test_audit_batch1.py -q

Loopback servers only (ephemeral ports). No browser, no engine run, no app start, no port 8765.
"""
import http.server
import json
import os
import sqlite3
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402
import autospec  # noqa: E402
import dbcheck  # noqa: E402
import outbound  # noqa: E402
import safe_run  # noqa: E402
import sink  # noqa: E402


# ---------- A-M7: safe_run.check_safe / remote_hosts ----------

@pytest.mark.parametrize("text", ["http://127.0.0.1.evil.com/x", "psql -h 203.0.113.9 -U u db", "curl http://evil.sh:8080/",
                                  "http://localhost.evil.example/x", "curl evil.example:8080"])
def test_m7_remote_host_forms_are_flagged(text):
    assert safe_run.remote_hosts(text), text


@pytest.mark.parametrize("text", ["http://127.0.0.1:8000/x", "python app.py --host 127.0.0.1 --port 8000", "http://localhost:3000",
                                  "http://[::1]:8000/", "{sink_http}"])
def test_m7_local_forms_are_not_flagged(text):
    assert safe_run.remote_hosts(text) == [], text


def test_m7_check_safe_refuses_bare_ip_override_and_dotted_loopback_name():
    with pytest.raises(SystemExit):
        safe_run.check_safe({"env_overrides": {"DB_HOST": "203.0.113.9"}, "run_cmd_argv": ["x"]})
    with pytest.raises(SystemExit):
        safe_run.check_safe({"env_overrides": {"LLM_BASE_URL": "http://127.0.0.1.evil.com"}, "run_cmd_argv": ["x"]})


def test_m7_reset_cmd_argv_cmd_script_is_refused():
    with pytest.raises(SystemExit):
        safe_run.check_safe({"run_cmd_argv": ["python", "app.py"], "reset_cmd_argv": ["setup.cmd"]})
    safe_run.check_safe({"run_cmd_argv": ["python", "app.py"], "reset_cmd_argv": ["python", "seed.py"]})


# ---------- A-M8: docstring claim matches the measured boundary ----------

def test_m8_sink_docstring_states_the_proxy_only_limit():
    doc = sink.__doc__
    assert "ignore" in doc and "NOT covered" in doc and "Do not claim" in doc


def test_m8_sink_env_has_no_smtp_variable():
    s = sink.Sink(os.path.join(os.environ.get("TMP", "."), "m8.jsonl"))
    try:
        assert not any("SMTP" in k.upper() for k in s.env())
    finally:
        s.stop()


# ---------- A-M9 / A-L10 / A-L11: sink redaction, chunked bodies, card and encoded leaks ----------

def test_m9_credential_like_header_names_are_redacted():
    out = sink.redact_headers([("X-Goog-Api-Key", "AIza" + "B" * 35), ("X-Auth-Token", "tok"), ("Accept", "application/json")])
    assert out["X-Goog-Api-Key"] == "<redacted>" and out["X-Auth-Token"] == "<redacted>" and out["Accept"] == "application/json"


def test_m9_scrub_text_removes_query_key_and_password():
    text, hits = sink.scrub_text('http://api.example.invalid/v1?api_key=SECRETVALUE123456 {"password": "hunter2hunter2"}', "body")
    assert "SECRETVALUE" not in text and "hunter2" not in text
    assert {h["label"] for h in hits} >= {"api key / token in payload or URL", "password in payload"}


def test_l11_card_numbers_amex_and_discover_are_detected():
    for number in ("378282246310005", "6011111111111117", "4111111111111111"):
        text, hits = sink.scrub_text(f'{{"card": "{number}"}}', "body")
        assert number not in text and any(h["label"] == "card number" for h in hits), number


def test_l10_chunked_request_body_is_stored_and_scrubbed(tmp_path):
    log = tmp_path / "sink.jsonl"
    s = sink.Sink(str(log))
    try:
        import http.client
        body = b'{"password": "hunter2hunter2", "note": "hello"}'
        conn = http.client.HTTPConnection("127.0.0.1", s.http_port, timeout=5)
        conn.putrequest("POST", "/chunk")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        conn.send(b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
        conn.getresponse().read()
        conn.close()
    finally:
        s.stop()
    entries = [e for e in sink.read_log(str(log)) if e["kind"] == "http"]
    assert entries and "hello" in entries[0]["body"], entries
    assert "hunter2" not in entries[0]["body"] and entries[0]["body_leaks"]


def test_l11_base64_smtp_password_is_found_by_outbound(tmp_path):
    import base64
    log = tmp_path / "smtp.jsonl"
    inner = base64.b64encode(b'{"password": "hunter2hunter2"}\r\nhello').decode()
    entry = {"t": 1, "kind": "smtp", "from": "a", "to": ["b"], "subject": "hi", "headers": "Content-Transfer-Encoding: base64",
             "body": inner}
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    res = outbound.run(str(log), type("Q", (), {})())
    assert any(f["kind"] == "OUTBOUND-LEAK" and "password" in f["detail"] for f in res["findings"]), res["findings"]


def test_l11_outbound_reports_every_canary_endpoint(tmp_path):
    log = tmp_path / "canary.jsonl"
    canary = "<i>qa-canary-html</i>"
    rows = [{"t": 1, "kind": "http", "via": "proxy", "host": "a.example.invalid", "path": "/x", "headers": {}, "body": "p " + canary},
            {"t": 2, "kind": "http", "via": "proxy", "host": "b.example.invalid", "path": "/y", "headers": {}, "body": "q " + canary}]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    res = outbound.run(str(log), type("Q", (), {})())
    eps = [f["endpoint"] for f in res["findings"] if f["kind"] == "CANARY-IN-PROMPT"]
    assert len(eps) == 2, eps


# ---------- A-M11: dbcheck local guard ----------

class _Qa:
    def __init__(self, driver, url_env="BATCH1_DB_URL", checks=None):
        self.DB = {"driver": driver, "url_env": url_env}
        self.DB_CHECKS = checks or [{"name": "c", "sql": "SELECT 1", "collection": "x", "filter": {}}]


def _run_db(monkeypatch, url, driver, checks=None):
    monkeypatch.setenv("BATCH1_DB_URL", url)
    return dbcheck.run(_Qa(driver, checks=checks))


def test_m11_mongo_multi_host_with_remote_member_is_refused(monkeypatch):
    res = _run_db(monkeypatch, "mongodb://127.0.0.1:27017,evil.com:27017/db", "mongo")
    assert res["status"] == "errored" and "evil.com" in res["notes"][0], res


def test_m11_sqlite_url_with_network_host_is_refused(monkeypatch):
    res = _run_db(monkeypatch, "sqlite://evil.com/x.db", "sqlite", [{"name": "c", "sql": "SELECT 1"}])
    assert res["status"] == "errored", res


def test_m11_unset_url_does_not_default_to_a_host(monkeypatch):
    monkeypatch.delenv("BATCH1_DB_URL", raising=False)
    res = dbcheck.run(_Qa("postgres"))
    assert res["status"] == "errored" and "not set" in res["notes"][0], res


def test_m11_missing_sqlite_file_is_not_created(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = _run_db(monkeypatch, "sqlite:///stray_batch1.db", "sqlite", [{"name": "c", "sql": "SELECT 1"}])
    assert not (tmp_path / "stray_batch1.db").exists()
    assert res["notes"] and "not found" in res["notes"][0], res


def test_m11_local_sqlite_still_checked(tmp_path, monkeypatch):
    db = tmp_path / "ok.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE t (title TEXT)")
    con.execute("INSERT INTO t VALUES ('')")
    con.commit()
    con.close()
    monkeypatch.chdir(tmp_path)
    res = _run_db(monkeypatch, "sqlite:///ok.db", "sqlite", [{"name": "blank titles", "sql": "SELECT title FROM t WHERE title = ''"}])
    assert res["status"] == "ran_ok" and res["findings"], res


# ---------- A-L1 / A-M12 / A-L2: api.py ----------

@pytest.mark.parametrize("url", ["file://localhost/etc/passwd", "ftp://localhost/x"])
def test_l1_assert_local_refuses_non_http_schemes(url):
    with pytest.raises(SystemExit):
        api.assert_local(url)


def test_l1_assert_local_still_accepts_loopback_http():
    api.assert_local("http://127.0.0.1:8000/x")
    api.assert_local("http://localhost:8000/")


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen = {}

    def do_GET(self):
        type(self).seen = {k.lower(): v for k, v in self.headers.items()}
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def _redirector(target_port_holder):
    class Redir(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target_port_holder['port']}/landed")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    return Redir


def test_m12_custom_credential_headers_are_dropped_on_cross_port_redirect():
    holder = {}
    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    holder["port"] = target.server_address[1]
    redir = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _redirector(holder))
    for srv in (target, redir):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = api.Api(f"http://127.0.0.1:{redir.server_address[1]}",
                         {"user_a": {"Authorization": "Bearer T1", "X-API-Key": "K-123", "X-CSRF-Token": "C-9"}})
        r = client.call("user_a", "GET", "/start")
        assert r.status == 200
        got = _Recorder.seen
        assert "x-api-key" not in got and "x-csrf-token" not in got and "authorization" not in got, got
    finally:
        target.shutdown()
        redir.shutdown()


def test_m12_scheme_change_drops_credentials():
    req = urllib.request.Request("http://127.0.0.1:9/x", headers={"Authorization": "Bearer T1", "X-API-Key": "K"})
    new = api._LocalRedirects().redirect_request(req, None, 302, "Found", {}, "https://127.0.0.1:9/x")
    assert new is not None and not new.has_header("Authorization") and not new.has_header("X-API-Key")


def test_l2_load_openapi_refuses_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "SPEC_MAX_READ", 1000)
    p = tmp_path / "big.json"
    p.write_text('{"openapi": "3.0.3", "paths": {}}' + " " * 2000, encoding="utf-8")
    with pytest.raises(SystemExit):
        api.load_openapi(str(p))
    small = tmp_path / "small.json"
    small.write_text('{"openapi": "3.0.3", "paths": {}}', encoding="utf-8")
    assert api.load_openapi(str(small))["openapi"] == "3.0.3"


# ---------- A-M13: autospec ----------

def _project(tmp_path):
    (tmp_path / "pages/api").mkdir(parents=True)
    (tmp_path / "pages/api/indexer.ts").write_text("export default function handler(req, res) { res.json({}) }\n")
    (tmp_path / "pages/api/index.ts").write_text("export default function handler(req, res) { res.json({}) }\n")
    (tmp_path / "app/api/wrapped").mkdir(parents=True)
    (tmp_path / "app/api/wrapped/route.ts").write_text("export const GET = withAuth(async () => Response.json({}))\n")
    (tmp_path / "app/api/docs").mkdir(parents=True)
    (tmp_path / "app/api/docs/route.ts").write_text("export async function GET() { return Response.json({}) }\n")
    (tmp_path / "app/api/nx").mkdir(parents=True)
    (tmp_path / "app/api/nx/route.ts").write_text("export const { GET, POST } = handlers\n")
    return tmp_path


def test_m13_pages_path_only_strips_trailing_index(tmp_path):
    ops, _ = autospec.discover(_project(tmp_path), "")
    paths = {o["path"] for o in ops if o["file"].startswith("pages/")}
    assert paths == {"/api/indexer", "/api"}, paths


def test_m13_wrapped_auth_is_seen_and_skips_are_noted(tmp_path):
    ops, notes = autospec.discover(_project(tmp_path), "")
    wrapped = [o for o in ops if o["path"] == "/api/wrapped"]
    assert wrapped and wrapped[0]["auth"] is True
    assert any("docs/route.ts" in n and "NOT read" in n for n in notes), notes
    assert any("nx/route.ts" in n and "not parsed" in n for n in notes), notes


def test_m13_job_get_is_not_a_body_field():
    fields, _, _ = autospec.body_fields("const job = mk(); const v = job.get('leak_field')")
    assert fields == []
    fields, _, _ = autospec.body_fields("const data = await req.json(); const v = data.get('real_field')")
    assert fields == ["real_field"]
