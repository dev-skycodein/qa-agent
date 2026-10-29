"""Audit fixes A-H2, A-H3, A-H4 (see QA_TOOLKIT_AUDIT.md section 3).

  A-H2  safe_run refuses to start when the port already has a listener.
  A-H3  the app and reset_cmd get only an allow-listed parent environment (plus the target's own env).
  A-H4  secrets in raw request headers are reported (OUTBOUND-LEAK) before the sink redacts them.

  python -m uv run --no-project --python 3.12 --with hypothesis --with pytest python -m pytest toolkit/engine/test_audit_fixes_a.py -q
"""
import json
import os
import socket
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import outbound  # noqa: E402
import safe_run  # noqa: E402
import sink as sink_mod  # noqa: E402

# a made-up token; built from parts so the file itself does not look like a real JWT to the release scanner
FAKE_JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ0ZXN0LXVzZXIifQ", "signaturepartabcdef"])


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---- A-H2: port check -------------------------------------------------------------------------------------------

def test_port_in_use_detects_a_listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        assert safe_run.port_in_use(srv.getsockname()[1]) is True
    finally:
        srv.close()


def test_port_in_use_false_for_a_free_port():
    assert safe_run.port_in_use(_free_port()) is False


def test_main_refuses_busy_port_before_starting_anything(tmp_path, monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    profile = {"app_dir": str(tmp_path), "port": port, "health_path": "/", "sink": False, "blank_keys": [], "unsafe_vars": [],
               "env_overrides": {}, "run_cmd_argv": [sys.executable, "-c", "pass"]}
    pj = tmp_path / "profile.json"
    pj.write_text(json.dumps(profile), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["safe_run.py", "--profile", str(pj), "--", sys.executable, "-c", "pass"])
    try:
        with pytest.raises(SystemExit) as exc:
            safe_run.main()
    finally:
        srv.close()
    assert "already has a listener" in str(exc.value)
    assert not (tmp_path / "app.log").exists()          # the app log is opened only after the refusal point


# ---- A-H3: allow-listed environment ----------------------------------------------------------------------------

def test_scrub_env_keeps_allow_list_and_drops_secrets():
    parent = {"PATH": "p", "SYSTEMROOT": "s", "USERPROFILE": "u", "TEMP": "t", "DATABASE_URL": "postgres://x",
              "AWS_SECRET_ACCESS_KEY": "a", "OPENAI_API_KEY": "o", "GITHUB_TOKEN": "g"}
    kept, dropped = safe_run.scrub_env(parent)
    assert set(kept) == {"PATH", "SYSTEMROOT", "USERPROFILE", "TEMP"}
    assert dropped == sorted({"DATABASE_URL", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN"})


def test_scrub_env_is_case_insensitive_for_windows_names():
    kept, dropped = safe_run.scrub_env({"Path": "p", "systemroot": "s"})
    assert set(kept) == {"Path", "systemroot"} and dropped == []


def test_scrub_env_profile_can_allow_more_names():
    kept, dropped = safe_run.scrub_env({"NODE_OPTIONS": "x", "SECRET_X": "y"}, extra_allow=["NODE_OPTIONS"])
    assert set(kept) == {"NODE_OPTIONS"} and dropped == ["SECRET_X"]


def test_app_process_does_not_receive_a_parent_secret(tmp_path, monkeypatch):
    """End to end on one tiny child process (no engine, no network): the app dumps its own env names."""
    monkeypatch.setenv("QA_TEST_FAKE_SECRET", "fake-value-not-real")
    # the app itself serves the port (the test process must not hold it: the port check would refuse)
    app = tmp_path / "app.py"
    app.write_text(
        "import os, json, http.server, socketserver\n"
        "open('app_env.json', 'w').write(json.dumps(sorted(os.environ)))\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()\n"
        "    def log_message(self, *a):\n"
        "        pass\n"
        "socketserver.TCPServer.allow_reuse_address = True\n"
        "socketserver.TCPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n",
        encoding="utf-8")
    port = _free_port()
    profile = {"app_dir": str(tmp_path), "port": port, "health_path": "/", "sink": False, "blank_keys": [], "unsafe_vars": [],
               "env_overrides": {"QA_TARGET_OWN": "1"}, "run_cmd_argv": [sys.executable, "app.py"]}
    pj = tmp_path / "profile.json"
    pj.write_text(json.dumps(profile), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["safe_run.py", "--profile", str(pj), "--wait", "30", "--", sys.executable, "-c", "pass"])
    with pytest.raises(SystemExit) as exc:
        safe_run.main()
    assert exc.value.code == 0
    names = set(json.loads((tmp_path / "app_env.json").read_text(encoding="utf-8")))
    assert "QA_TEST_FAKE_SECRET" not in names
    assert "QA_TARGET_OWN" in names and "PATH" in names


# ---- A-H4: raw header scan before redaction -----------------------------------------------------------------------

def test_header_secret_hits_scans_raw_values_and_keeps_no_secret():
    hits = sink_mod.header_secret_hits([("Authorization", "Bearer " + FAKE_JWT), ("Host", "example.test")])
    assert hits == [{"label": "session JWT sent to third party", "header": "Authorization", "chars": len(FAKE_JWT)}]
    assert FAKE_JWT not in json.dumps(hits)


def test_header_secret_hits_finds_sk_key_in_cookie():
    hits = sink_mod.header_secret_hits([("Cookie", "sid=sk-" + "a" * 30)])
    assert hits and hits[0]["header"] == "Cookie" and hits[0]["label"].startswith("api key")


def test_header_secret_hits_clean_headers_give_nothing():
    assert sink_mod.header_secret_hits([("Accept", "application/json"), ("User-Agent", "qa")]) == []


def test_sink_records_header_leak_and_stores_only_redacted_headers(tmp_path):
    log = tmp_path / "sink.jsonl"
    s = sink_mod.Sink(str(log))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(s.http_url + "/v1/chat", data=b'{"prompt": "hello"}', method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + FAKE_JWT})
        with opener.open(req, timeout=10) as r:
            assert r.status == 200
    finally:
        s.stop()
    raw = log.read_text(encoding="utf-8")
    assert FAKE_JWT not in raw                           # the header value never reaches the run folder
    entry = sink_mod.read_log(str(log))[0]
    assert entry["headers"]["Authorization"] == "<redacted>"
    assert entry["header_leaks"][0]["header"] == "Authorization"


def test_outbound_reports_header_leak_with_redacted_detail(tmp_path):
    log = tmp_path / "sink.jsonl"
    entry = {"kind": "http", "via": "proxy", "method": "POST", "host": "llm.example.test", "path": "/v1/chat",
             "headers": {"Authorization": "<redacted>"},
             "header_leaks": [{"label": "session JWT sent to third party", "header": "Authorization", "chars": len(FAKE_JWT)}],
             "body": "{}"}
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    res = outbound.run(str(log), SimpleNamespace(SINK_CHECKS=[]))
    leaks = [f for f in res["findings"] if f["kind"] == "OUTBOUND-LEAK"]
    assert len(leaks) == 1 and leaks[0]["severity"] == "high" and leaks[0]["endpoint"] == "llm.example.test"
    assert "Authorization" in leaks[0]["detail"] and FAKE_JWT not in json.dumps(res)


def test_outbound_clean_headers_no_leak(tmp_path):
    log = tmp_path / "sink.jsonl"
    entry = {"kind": "http", "via": "proxy", "method": "GET", "host": "x.test", "path": "/", "headers": {"Accept": "*/*"},
             "header_leaks": [], "body": ""}
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    res = outbound.run(str(log), SimpleNamespace(SINK_CHECKS=[]))
    assert not [f for f in res["findings"] if f["kind"] == "OUTBOUND-LEAK"]
