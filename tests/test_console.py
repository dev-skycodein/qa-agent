"""Tests for qa_console.py (no engines, no app needed):  python tests/test_console.py"""
import http.client
import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))      # repo root: qa_console.py lives there
import qa_console as qc


def _finding(kind="BOLA/IDOR", endpoint="GET /orders/{id}", detail="user_b read order 17 of user_a", sev="high", seed=None):
    f = {"kind": kind, "endpoint": endpoint, "detail": detail, "severity": sev, "seed": seed}
    f["fingerprint"] = qc.fingerprint(f)
    return f


def _make_run(root: Path, name: str, findings, trust_obj=None, target="demo", canary=None):
    d = root / name
    d.mkdir(parents=True)
    (d / "manifest.json").write_text(json.dumps({"target": target, "git": "abc", "seeds": [None], "canary": canary,
                                                 "commands": [["python", "run.py"]], "n_findings": len(findings)}), encoding="utf-8")
    (d / "trust.json").write_text(json.dumps(trust_obj if trust_obj is not None else
                                             {"engines": [], "errored": [], "degraded": [], "skipped": [], "ran_ok": ["authz"], "verdict": "ok"}),
                                  encoding="utf-8")
    (d / "findings.jsonl").write_text("".join(json.dumps(f) + "\n" for f in findings), encoding="utf-8")
    return d


def test_fingerprint_ignores_ids_but_not_kind_or_endpoint():
    a = qc.fingerprint(_finding(detail="read order 17"))
    assert a == qc.fingerprint(_finding(detail="read order 9001"))
    assert a != qc.fingerprint(_finding(kind="PRIV-ESC"))
    assert a != qc.fingerprint(_finding(endpoint="GET /users/{id}"))


def test_fingerprint_survives_run_to_run_noise():
    a = _finding(kind="STATEFUL-INVARIANT", endpoint="(sequence)", detail="stock_conserved: stock 10 != expected 3 (orders {197: 'shipped'})")
    b = _finding(kind="STATEFUL-INVARIANT", endpoint="(sequence)", detail="stock_conserved: stock 16 != expected 8 (orders {52: 'cancelled'})")
    assert a["fingerprint"] == b["fingerprint"]
    assert a["fingerprint"] != _finding(kind="STATEFUL-INVARIANT", endpoint="(sequence)", detail="other_check: x")["fingerprint"]
    p1 = _finding(kind="OUTBOUND-LEAK", endpoint="127.0.0.1:53059", detail="password in payload: ...pw1")
    p2 = _finding(kind="OUTBOUND-LEAK", endpoint="127.0.0.1:55599", detail="password in payload: ...pw2")
    assert p1["fingerprint"] == p2["fingerprint"]


def test_hit_rate_is_an_interval_not_a_percentage():
    assert qc.hit_rate(1, 1) == ""
    text = qc.hit_rate(8, 8)
    assert "8/8" in text and "CI" in text and "100%-100%" not in text
    assert qc.seed_count({"manifest": {"seeds": [1, 2, 3]}}) == 3 and qc.seed_count({"manifest": {"seeds": [None]}}) == 1


def test_diff_new_fixed_persistent():
    keep, gone, fresh = _finding(), _finding(kind="NEG-5XX"), _finding(kind="MASS-ASSIGN")
    d = qc.diff_runs({"findings": [keep, gone]}, {"findings": [keep, fresh]})
    assert [f["kind"] for f in d["new"]] == ["MASS-ASSIGN"]
    assert [f["kind"] for f in d["fixed"]] == ["NEG-5XX"]
    assert [f["kind"] for f in d["persistent"]] == ["BOLA/IDOR"]


def test_derived_profile_adds_reset_cmd_argv_and_leaves_the_source_alone():
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "profile.json"
        src.write_text(json.dumps({"name": "x", "port": 1}), encoding="utf-8")
        cfg = {"name": "x", "profile": str(src), "reset_cmd_argv": ["echo", "fresh"]}
        out = qc.derive_profile(cfg, Path(tmp) / "run-1")
        derived = json.loads(Path(out["profile"]).read_text(encoding="utf-8"))
        assert derived["reset_cmd_argv"] == ["echo", "fresh"] and derived["name"] == "x"
        assert "reset_cmd" not in derived                                                    # a shell string is never copied from a target
        assert "reset_cmd" not in json.loads(src.read_text(encoding="utf-8"))               # the registered profile is untouched
        assert Path(out["profile"]).parent.name == "run-1" and cfg["profile"] == str(src)
        plain = qc.derive_profile({"name": "x", "profile": str(src)}, Path(tmp) / "run-2")
        assert "reset_cmd" not in json.loads(Path(plain["profile"]).read_text(encoding="utf-8"))


def test_missing_generated_profile_gives_a_helpful_error():
    with tempfile.TemporaryDirectory() as tmp:
        try:
            qc.derive_profile({"name": "demo", "profile": str(Path(tmp) / "nope.json")}, Path(tmp) / "run")
        except SystemExit as e:
            assert "selftest" in str(e) and "generated" in str(e)
            return
    raise AssertionError("a missing profile did not stop the run")


def test_every_registered_target_parses():
    for t in sorted(qc.TARGETS.glob("*.toml")):
        cfg = qc.load_target(t.stem)
        assert cfg["spec"] and cfg["profile"], t


def test_run_state_never_reads_broken_or_canary_failure_as_full():
    ok = {"errored": [], "degraded": [], "skipped": []}
    assert qc.run_state({"manifest": {}, "trust": ok}) == "FULL"
    assert qc.run_state({"manifest": {}, "trust": {**ok, "degraded": ["authz"]}}) == "PARTIAL"
    assert qc.run_state({"manifest": {}, "trust": {**ok, "errored": ["dbcheck"]}}) == "BROKEN"
    assert qc.run_state({"manifest": {}, "trust": {}}) == "BROKEN"                      # no trust.json at all
    assert qc.run_state({"manifest": {"canary": "fail"}, "trust": ok}) == "UNTRUSTED"


def test_server_is_token_gated_host_checked_read_only_and_escapes_html():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _make_run(root, "20260101-000001-demo", [_finding(detail="<script>alert(1)</script>")])
        old = qc.RUNS
        qc.RUNS = root
        srv = qc.http.server.ThreadingHTTPServer(("127.0.0.1", 0), qc.make_handler("tok", []))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]

        def req(method, path, host=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request(method, path, headers={"Host": host or f"127.0.0.1:{port}"})
            r = c.getresponse()
            return r.status, r.read().decode()
        try:
            assert req("GET", "/")[0] == 403                                         # no token
            assert req("GET", "/?t=wrong")[0] == 403
            assert req("GET", "/?t=tok", host="evil.example")[0] == 403              # DNS rebinding
            assert req("POST", "/?t=tok")[0] == 405 and req("DELETE", "/?t=tok")[0] == 405
            status, body = req("GET", "/?t=tok")
            assert status == 200 and "20260101-000001-demo" in body
            assert req("GET", "/run/..%2f..%2fetc?t=tok")[0] == 404                  # id is looked up, never used as a path
            status, body = req("GET", "/run/20260101-000001-demo?t=tok")
            assert status == 200 and "<script>alert(1)" not in body and "&lt;script&gt;" in body
        finally:
            srv.shutdown()
            qc.RUNS = old


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok  ", name)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print("FAIL", name, "-", type(exc).__name__, exc)
    sys.exit(1 if failed else 0)
