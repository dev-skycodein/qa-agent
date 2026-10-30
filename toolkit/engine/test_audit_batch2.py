"""Tests for audit batch 2: coverage verdict and route order, run.py setup/sink/engine exits, qa_console multi-seed and sort,
multi_run report, scenario/race/workflow engines that used to report a silent ran_ok on a skipped or unverified path."""
import contextlib
import datetime as real_dt
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import coverage  # noqa: E402
import multi_run  # noqa: E402
import race_engine  # noqa: E402
import run  # noqa: E402
import scenario_engine  # noqa: E402
import scenarios_lib  # noqa: E402
import trust  # noqa: E402
import workflow_chains  # noqa: E402

sys.path.insert(0, str(ROOT))
import qa_console as qc  # noqa: E402


class Resp:
    def __init__(self, status, body=None):
        self.status, self.json, self.ok, self.text, self.headers = status, body, 200 <= status < 300, "", {}


class FakeApi:
    base = "http://127.0.0.1:9"

    def __init__(self, roles=None):
        self.roles = {"anon": {}, **(roles or {"user_a": {"Authorization": "Bearer a"}})}
        self.log, self.sent = [], []

    def call(self, role, method, path, body=None, *a, **k):
        self.sent.append((role, method, path))
        return Resp(201, {"id": 1})


# ---------- coverage (A-M2, A-L12) ----------

def _cov(log, spec):
    api = FakeApi()
    api.log = log
    return coverage.run(api, spec)


def test_coverage_never_2xx_is_degraded_with_count():
    spec = {"paths": {"/items": {"get": {}}, "/orders": {"get": {}}}}
    r = _cov([{"method": "GET", "path": "/items", "role": "anon", "status": 500}], spec)
    assert r["status"] == trust.DEGRADED
    assert "2 endpoint(s) never answered 2xx" in r["status_reason"]


def test_coverage_all_answered_2xx_stays_ran_ok():
    spec = {"paths": {"/items": {"get": {}}}}
    r = _cov([{"method": "GET", "path": "/items", "role": "anon", "status": 200}], spec)
    assert r["status"] == trust.RAN_OK


def test_coverage_literal_route_is_not_counted_under_template_route():
    spec = {"paths": {"/orders/{id}": {"get": {}}, "/orders/export": {"get": {}}}}
    r = _cov([{"method": "GET", "path": "/orders/export", "role": "anon", "status": 200}], spec)
    assert r["table"]["GET /orders/export"] == {"anon": {"2xx": 1}}
    assert r["table"]["GET /orders/{id}"] == {}


# ---------- run.py (A-M3, A-M4, A-L15) ----------

def _spec_file(tmp_path, body):
    p = tmp_path / "spec.py"
    p.write_text(body, encoding="utf-8")
    return str(p)


def _openapi(tmp_path):
    p = tmp_path / "openapi.json"
    p.write_text(json.dumps({"openapi": "3.0.0", "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}}}),
                 encoding="utf-8")
    return str(p)


def _main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["run.py", *argv])
    with pytest.raises(SystemExit) as info:
        run.main()
    return info.value.code


def test_setup_sys_exit_still_writes_engines_json_and_exit_is_not_1(tmp_path, monkeypatch):
    monkeypatch.delenv("QA_SINK_LOG", raising=False)
    spec = _spec_file(tmp_path, 'def setup(api):\n    raise SystemExit("setup asked to stop")\n')
    out = tmp_path / "out"
    code = _main(monkeypatch, ["--base-url", "http://127.0.0.1:1", "--spec", spec, "--openapi", _openapi(tmp_path),
                               "--out", str(out), "--engines", ""])
    assert code == trust.EXIT_ENGINE_BROKE
    results = json.loads((out / "engines.json").read_text(encoding="utf-8"))
    assert results[0]["engine"] == "setup" and "engine-error" in results[0]


def test_sink_off_shows_explicit_degraded_outbound_row(tmp_path, monkeypatch):
    monkeypatch.delenv("QA_SINK_LOG", raising=False)
    spec = _spec_file(tmp_path, 'def setup(api):\n    return {"user_a": {"Authorization": "Bearer x"}}\n')
    out = tmp_path / "out"
    _main(monkeypatch, ["--base-url", "http://127.0.0.1:1", "--spec", spec, "--openapi", _openapi(tmp_path),
                        "--out", str(out), "--engines", ""])
    rows = {r["engine"]: r for r in json.loads((out / "engines.json").read_text(encoding="utf-8"))}
    assert rows["outbound"]["status"] == trust.DEGRADED
    assert "sink off" in rows["outbound"]["status_reason"]
    verdict = json.loads((out / "trust.json").read_text(encoding="utf-8"))["verdict"]
    assert "ALL ENGINES RAN" not in verdict and "outbound" in verdict


def test_finish_tolerates_finding_without_keys(tmp_path):
    results = [{"engine": "x", "findings": [{"kind": "K"}], "status": trust.RAN_OK, "status_reason": ""}]
    args = SimpleNamespace(fail_on_findings=False, strict=False)
    code = run.finish(results, tmp_path / "o", args)
    assert code == trust.EXIT_OK
    assert "**? K** `?`" in (tmp_path / "o" / "engines.md").read_text(encoding="utf-8")


# ---------- qa_console (A-M5, A-L4, A-L6 not fixed) ----------

FIXED = real_dt.datetime(2026, 10, 29, 12, 0, 0)
OK = [{"engine": "authz", "findings": [], "status": "ran_ok", "status_reason": ""},
      {"engine": "negative", "findings": [], "status": "ran_ok", "status_reason": ""}]
DEG = [{"engine": "authz", "findings": [], "status": "degraded", "status_reason": "user_b missing"},
       {"engine": "negative", "findings": [], "status": "ran_ok", "status_reason": ""}]


@pytest.fixture
def console(tmp_path, monkeypatch):
    prof = tmp_path / "profile.json"
    prof.write_text('{"base_url": "http://127.0.0.1:8765"}', encoding="utf-8")
    monkeypatch.setattr(qc, "RUNS", tmp_path / "runs")
    monkeypatch.setattr(qc, "load_target", lambda name: {"name": "t", "profile": str(prof), "spec": "x.py"})
    fixed_cls = type("FixedDT", (real_dt.datetime,), {"now": classmethod(lambda cls, tz=None: FIXED)})
    monkeypatch.setattr(qc, "datetime", SimpleNamespace(datetime=fixed_cls))
    return tmp_path


def _run_seeds(monkeypatch, seeds, outputs):
    calls = []

    def fake_run(cmd, **kw):
        if "--out" not in cmd:                              # git rev-parse / git status
            return SimpleNamespace(stdout="", stderr="", returncode=0)
        out = Path(cmd[cmd.index("--out") + 1])
        out.mkdir(parents=True, exist_ok=True)
        (out / "engines.json").write_text(json.dumps(outputs[len(calls)]), encoding="utf-8")
        calls.append(cmd)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(qc.subprocess, "run", fake_run)
    a = SimpleNamespace(target="t", seeds=seeds, canary=False, engines=None, fail_on_findings=False, strict=False,
                        shuffle_engines=False)
    with contextlib.redirect_stdout(io.StringIO()):
        qc.cmd_run(a)
    run_dir = sorted((qc.RUNS).iterdir())[-1]
    return json.loads((run_dir / "trust.json").read_text(encoding="utf-8"))


def test_multi_seed_keeps_degraded_from_later_seed(console, monkeypatch):
    trust_json = _run_seeds(monkeypatch, "1,2", [OK, DEG])
    assert trust_json["degraded"] == ["authz"]
    assert "ALL ENGINES RAN" not in trust_json["verdict"]


def test_duplicate_seed_does_not_replace_first_seed_result(console, monkeypatch):
    trust_json = _run_seeds(monkeypatch, "1,1", [DEG, OK])
    assert trust_json["degraded"] == ["authz"]


def test_print_run_orders_severities_critical_high_medium_low_info(capsys):
    def find(sev, i):
        return {"kind": "K", "severity": sev, "endpoint": f"GET /e{i}", "detail": f"d{i}", "fingerprint": f"fp{i}", "seed": None}
    r = {"id": "x", "manifest": {"target": "t", "git": "g", "canary": None, "seeds": [None]},
         "trust": {"engines": [], "verdict": "v"},
         "findings": [find("low", 1), find("info", 2), find("critical", 3), find("medium", 4), find("high", 5)]}
    qc.print_run(r)
    order = [line.split("]")[0].split("[")[1].strip() for line in capsys.readouterr().out.splitlines() if line.startswith("  [")]
    assert order == ["critical", "high", "medium", "low", "info"]


# ---------- multi_run (A-M6) ----------

def test_multi_report_lists_failed_seed_and_degraded_engine(tmp_path, monkeypatch):
    F = {"kind": "BOLA", "severity": "high", "endpoint": "GET /x/{id}", "detail": "user_b reads user_a item 7"}
    plan = {1: [{"engine": "authz", "findings": [F], "status": "ran_ok", "status_reason": ""}],
            2: None,
            3: [{"engine": "negative", "findings": [], "status": "degraded", "status_reason": "BODIES empty"}]}

    def fake_run(cmd, **kw):
        seed = int(cmd[cmd.index("--seed") + 1])
        d = Path(cmd[cmd.index("--out") + 1])
        if plan[seed] is not None:
            d.mkdir(parents=True, exist_ok=True)
            (d / "engines.json").write_text(json.dumps(plan[seed]), encoding="utf-8")
        return SimpleNamespace(stdout="", stderr="", returncode=1 if plan[seed] is None else 0)

    monkeypatch.setattr(multi_run.subprocess, "run", fake_run)
    out = tmp_path / "multi"
    monkeypatch.setattr(sys, "argv", ["multi_run.py", "--profile", "p.json", "--spec", "s.py", "--out", str(out), "--seeds", "1,2,3"])
    with contextlib.redirect_stdout(io.StringIO()):
        multi_run.main()
    md = (out / "multi.md").read_text(encoding="utf-8")
    assert "| 1/3 | authz | high | BOLA" in md
    assert "| 2 | (whole run) | ERRORED |" in md
    assert "| 3 | negative | DEGRADED | BODIES empty |" in md


# ---------- scenario engine (A-M14, scenarios_lib part) ----------

def test_scenario_precondition_failure_is_setup_failed_not_ran_ok():
    sc = scenarios_lib.stale_session("stale", login=lambda api: {"Authorization": "x"},
                                     protected=lambda api, h: Resp(401), revoke=lambda api, ctx: None)
    r = scenario_engine.run(FakeApi(), {}, SimpleNamespace(SCENARIOS=[sc]))
    assert r["status"] == trust.SETUP_FAILED
    assert r["findings"] == []


def test_scenario_real_violation_still_a_finding_and_ran_ok():
    sc = scenarios_lib.stale_session("stale", login=lambda api: {"Authorization": "x"},
                                     protected=lambda api, h: Resp(200), revoke=lambda api, ctx: None)
    r = scenario_engine.run(FakeApi(), {}, SimpleNamespace(SCENARIOS=[sc]))
    assert r["status"] == trust.RAN_OK
    assert len(r["findings"]) == 1


# ---------- race engine (B-M10) ----------

def _race(monkeypatch, races):
    captured = []

    def fake_race(method, url, n, headers, body=None, per_request_headers=None):
        captured.append(headers)
        return [(201, None)] * n

    monkeypatch.setattr(race_engine, "race", fake_race)
    r = race_engine.run(FakeApi(), {}, SimpleNamespace(RACES=races))
    return r, captured


def test_race_check_that_checks_nothing_is_degraded(monkeypatch):
    r, _ = _race(monkeypatch, [{"name": "oversell", "n": 3,
                                "setup": lambda api, ctx: {"method": "POST", "path": "/x", "role": "user_a", "body": {}},
                                "check": lambda api, results, ctx: None}])
    assert r["status"] == trust.DEGRADED and "oversell" in r["status_reason"]


def test_race_without_a_role_uses_a_plain_role_of_any_name(monkeypatch):
    monkeypatch.setattr(race_engine, "race", lambda method, url, n, headers, body=None, per_request_headers=None: [(201, None)] * n)
    api = FakeApi()
    api.roles = {"anon": {}, "buyer": {"t": "b"}, "seller": {"t": "s"}}
    def check(api, results, ctx):
        return len(results) and None
    races = [{"name": "r", "n": 2, "setup": lambda api, ctx: {"method": "POST", "path": "/x", "body": {}}, "check": check}]
    r = race_engine.run(api, {}, SimpleNamespace(RACES=races))
    assert r["status"] == trust.RAN_OK


def test_race_unknown_role_is_not_sent_anonymous(monkeypatch):
    r, captured = _race(monkeypatch, [{"name": "r", "n": 3,
                                       "setup": lambda api, ctx: {"method": "POST", "path": "/x", "role": "usr_a", "body": {}},
                                       "check": lambda api, results, ctx: None}])
    assert captured == []
    assert r["status"] == trust.ERRORED and r["findings"] == []          # every race setup-failed: the engine did no work


def test_race_missing_check_is_spec_error_not_invariant_finding(monkeypatch):
    r, _ = _race(monkeypatch, [{"name": "r", "n": 3,
                                "setup": lambda api, ctx: {"method": "POST", "path": "/x", "role": "user_a", "body": {}}}])
    assert [f["kind"] for f in r["findings"]] == []
    assert r["status"] == trust.ERRORED


def test_race_attempts_zero_runs_one_burst_and_does_not_crash(monkeypatch):
    r, captured = _race(monkeypatch, [{"name": "r", "n": 3, "attempts": 0,
                                       "setup": lambda api, ctx: {"method": "POST", "path": "/x", "role": "user_a", "body": {}},
                                       "check": lambda api, results, ctx: None if results else "no response"}])
    assert len(captured) == 1
    assert r["status"] == trust.RAN_OK


# ---------- workflow chains (B-M13) ----------

def test_workflow_idempotency_only_is_degraded_not_ran_ok():
    spec = {"paths": {"/orders": {"post": {
        "parameters": [{"name": "Idempotency-Key", "in": "header", "required": False}],
        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {
            "item": {"type": "string"}, "qty": {"type": "integer"}}}}}},
        "responses": {"201": {"description": "ok"}}}}}}
    api = FakeApi()
    r = workflow_chains.run(api, spec, SimpleNamespace(BODIES={"POST /orders": {"item": "widget", "qty": 2}}))
    assert r["probes"] == 2
    assert r["status"] == trust.DEGRADED
    assert "chain oracles not run" in r["status_reason"]
