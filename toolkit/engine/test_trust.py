"""Tests for the engine status contract (trust.py) and for run.py's refusal to look clean when it is not.

  python toolkit/engine/test_trust.py        (stdlib only; also collectable by pytest)
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import trust  # noqa: E402


def test_missing_status_is_degraded_not_ok():
    assert trust.resolve({"engine": "x", "findings": []})[0] == trust.DEGRADED


def test_engine_error_beats_declared_status():
    r = trust.mark({"engine": "x", "findings": [], "engine-error": "Traceback\nValueError: boom"}, trust.RAN_OK)
    status, reason = trust.resolve(r)
    assert status == trust.ERRORED and "boom" in reason


def test_mark_rejects_unknown_status():
    try:
        trust.mark({}, "fine")
    except ValueError:
        return
    raise AssertionError("unknown status accepted")


def test_exit_codes_separate_broken_from_findings():
    ok = trust.mark({"engine": "a", "findings": []}, trust.RAN_OK)
    bad = {"engine": "b", "findings": [], "engine-error": "x"}
    deg = trust.mark({"engine": "c", "findings": []}, trust.DEGRADED, "half")
    hit = trust.mark({"engine": "d", "findings": [{"severity": "high"}]}, trust.RAN_OK)
    info = trust.mark({"engine": "e", "findings": [{"severity": "info"}]}, trust.RAN_OK)
    assert trust.exit_code([ok]) == 0
    assert trust.exit_code([ok, bad]) == 2
    assert trust.exit_code([ok, deg]) == 0 and trust.exit_code([ok, deg], strict=True) == 2
    assert trust.exit_code([hit]) == 0 and trust.exit_code([hit], fail_on_findings=True) == 1
    assert trust.exit_code([info], fail_on_findings=True) == 0
    assert trust.exit_code([hit, bad], fail_on_findings=True) == 2          # broken beats findings


def test_verdict_never_claims_clean_when_something_did_not_run():
    skipped = trust.mark({"engine": "scenario", "findings": []}, trust.SKIPPED, "no SCENARIOS")
    text = " ".join(trust.header_lines([skipped]))
    assert "PARTIAL" in text and "ALL ENGINES RAN" not in text
    err = {"engine": "dbcheck", "findings": [], "engine-error": "x"}
    assert "NOT TRUSTED" in " ".join(trust.header_lines([err]))
    ok = trust.mark({"engine": "authz", "findings": []}, trust.RAN_OK)
    assert "ALL ENGINES RAN" in " ".join(trust.header_lines([ok]))


def _run_py(args):
    return subprocess.run([sys.executable, str(HERE / "run.py"), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def test_run_py_unreadable_openapi_is_an_errored_row_and_exit_2():
    with tempfile.TemporaryDirectory() as d:
        spec = Path(d) / "qa-spec.py"
        spec.write_text("def setup(api):\n    return {}\n", encoding="utf-8")
        p = _run_py(["--base-url", "http://127.0.0.1:9", "--spec", str(spec), "--openapi", str(Path(d) / "missing.json"),
                     "--out", str(Path(d) / "out")])
        assert p.returncode == 2, p.stdout[-500:] + p.stderr[-500:]
        results = json.loads((Path(d) / "out" / "engines.json").read_text(encoding="utf-8"))
        assert trust.resolve(results[0])[0] == trust.ERRORED
        assert (Path(d) / "out" / "trust.json").exists()
        assert "NOT TRUSTED" in (Path(d) / "out" / "engines.md").read_text(encoding="utf-8")


def test_run_py_broken_spec_is_an_errored_row_and_exit_2():
    with tempfile.TemporaryDirectory() as d:
        spec = Path(d) / "qa-spec.py"
        spec.write_text("raise RuntimeError('spec is broken')\n", encoding="utf-8")
        p = _run_py(["--base-url", "http://127.0.0.1:9", "--spec", str(spec), "--out", str(Path(d) / "out")])
        assert p.returncode == 2, p.stdout[-500:] + p.stderr[-500:]
        results = json.loads((Path(d) / "out" / "engines.json").read_text(encoding="utf-8"))
        assert trust.resolve(results[0])[0] == trust.ERRORED and "spec is broken" in trust.resolve(results[0])[1]


def test_cross_check_downgrades_ran_ok_with_zero_probes():
    r = trust.mark({"engine": "authz", "findings": [], "probes": 0}, trust.RAN_OK)
    trust.cross_check([r], request_count=5)
    assert trust.resolve(r)[0] == trust.DEGRADED and "0 probes" in r["status_reason"]


def test_cross_check_downgrades_when_api_log_empty():
    r = trust.mark({"engine": "negative", "findings": [], "probes": 3}, trust.RAN_OK)
    trust.cross_check([r], request_count=0)
    assert trust.resolve(r)[0] == trust.DEGRADED and "0 requests" in r["status_reason"]


def test_cross_check_leaves_honest_ran_ok_alone():
    r = trust.mark({"engine": "authz", "findings": [], "probes": 4}, trust.RAN_OK)
    trust.cross_check([r], request_count=10)
    assert trust.resolve(r)[0] == trust.RAN_OK


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
