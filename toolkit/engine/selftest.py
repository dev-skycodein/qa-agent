"""Toolkit self-test: run the /qa-hunt engines against the demo Flask shop (16 planted bugs, different stack
from an internal test app) and assert every bug class is found. Needs only `python` + uv (downloads flask/hypothesis).

  python engine/selftest.py               # ~3-6 min, exit code 0 = engines work (the canary)
  python engine/selftest.py --with-clean  # + the same engines on the FIXED demo app: no high/medium finding allowed (false-positive control)

Expected (17 checks): BOLA/IDOR, MISSING-AUTH, PRIV-ESC (authz), a stateful invariant failure, RACE-INVARIANT (oversell),
NEG-5XX (non-integer quantity), NEG-LEAK (traceback in error body), MASS-ASSIGN (role on register), XREF-IDOR (review of
someone else's order), CANARY-IN-EMAIL (unescaped note in HTML mail), OUTBOUND-LEAK (password sent to analytics),
SCENARIO (illegal order status transition accepted), NEG-INJECTION on POST /auth/login (planted SQL injection),
EXPOSURE-SECRET-FIELD (password in GET /me), AUTH-TOKEN-AFTER-LOGOUT, LOGIC-NEGATIVE-VALUE (bounds ignored), and a RACE-INVARIANT
named "double cancel". Limit: the bugs are the same author's as the engines, so a pass shows the engines work, not how many
bugs nobody thought of they would find.

The canary also fails when any engine ERRORED (trust.py status), not only when a class is missing: an engine that crashed is
not "found nothing". The clean control reuses the app with `DEMO_FIXED=1` (every planted bug fixed); a high/medium finding
there is a false positive of the engines (or a bug the fix forgot: read the finding before blaming either).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLKIT = Path(__file__).resolve().parent.parent
DEMO = TOOLKIT / "examples" / "demo-flask-shop"
OUT = DEMO / "qa-report"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import trust  # noqa: E402

WANT = {"BOLA/IDOR", "MISSING-AUTH", "PRIV-ESC", "STATEFUL-INVARIANT", "RACE-INVARIANT",
        "NEG-5XX", "NEG-LEAK", "MASS-ASSIGN", "XREF-IDOR", "CANARY-IN-EMAIL", "OUTBOUND-LEAK", "SCENARIO",
        "EXPOSURE-SECRET-FIELD", "AUTH-TOKEN-AFTER-LOGOUT", "LOGIC-NEGATIVE-VALUE"}
QA_HUNT_ENGINES = "authz,negative,stateful,race,scenario,static,auth,exposure,logic"      # keep equal to commands/qa-hunt.md


def run_engines(out: Path, fixed: bool = False, bugs: str | None = None, engines: str | None = None, examples: int = 40,
                seed: int = 1, port: int = 8765):
    """One full pass of the engines against the demo app. -> (results | None, proc).
    fixed=True: every planted bug fixed (clean control); bugs="3,5": only those planted bugs (see app.py); default: all of them."""
    for leftover in DEMO.glob("qa_demo_flask_shop.db"):
        leftover.unlink()
    subprocess.run([sys.executable, str(TOOLKIT / "engine" / "detect.py"), str(DEMO), "--out", str(out / "profile.json")],
                   check=True, capture_output=True)
    prof = json.loads((out / "profile.json").read_text(encoding="utf-8"))          # wire the app's outbound integrations to the sink
    prof["env_overrides"].update({"SMTP_HOST": "{sink_smtp_host}", "SMTP_PORT": "{sink_smtp_port}", "ANALYTICS_URL": "{sink_http}/track"})
    if fixed:
        prof["env_overrides"]["DEMO_FIXED"] = "1"
    elif bugs:
        prof["env_overrides"]["DEMO_BUGS"] = bugs
    (out / "profile.json").write_text(json.dumps(prof, indent=2), encoding="utf-8")
    cmd = [sys.executable, str(TOOLKIT / "engine" / "safe_run.py"), "--profile", str(out / "profile.json"), "--port", str(port), "--",
           sys.executable, "-m", "uv", "run", "--no-project", "--python", "3.12", "--with", "hypothesis",
           "python", str(TOOLKIT / "engine" / "run.py"), "--spec", str(DEMO / "qa-spec.py"), "--openapi", str(DEMO / "openapi.json"),
           "--out", str(out), "--examples", str(examples), "--steps", "12", "--seed", str(seed)]
    cmd += ["--engines", engines or QA_HUNT_ENGINES]
    (out / "engines.json").unlink(missing_ok=True)   # a stale file from an earlier run must never stand in for this run's output
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env={**os.environ, "PYTHONUTF8": "1"})
    for leftover in DEMO.glob("qa_demo_flask_shop.db"):
        leftover.unlink()
    try:
        return json.loads((out / "engines.json").read_text(encoding="utf-8")), proc
    except FileNotFoundError:
        return None, proc


def check_planted() -> int:
    results, proc = run_engines(OUT, fixed=False)
    if proc.returncode != 0:
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        print(f"SELFTEST FAILED: engine run exited with code {proc.returncode}")
        return 1
    if results is None:
        print(proc.stdout[-2000:], proc.stderr[-2000:])
        print("SELFTEST FAILED: engines produced no output")
        return 1
    kinds = {f["kind"] for r in results for f in r.get("findings", [])}
    errors = [r["engine"] for r in results if trust.resolve(r)[0] == trust.ERRORED]
    missing = WANT - kinds
    if not any(f["kind"] == "NEG-INJECTION" and "/auth/login" in f["endpoint"] for r in results for f in r.get("findings", [])):
        missing.add("NEG-INJECTION on POST /auth/login")          # a NEG-INJECTION on any other endpoint was a false positive (see check_clean)
    if not any(f["kind"] == "RACE-INVARIANT" and "double cancel" in str(f.get("detail")) for r in results for f in r.get("findings", [])):
        missing.add("RACE-INVARIANT named double cancel")
    print("found:", sorted(kinds))
    if missing or errors:
        print("SELFTEST FAILED: missing", sorted(missing), "engine errors", errors)
        return 1
    print(f"SELFTEST OK: all {len(WANT) + 2} planted bug classes found on a non-FastAPI stack")
    return 0


def check_clean() -> int:
    """False-positive control: same engines, same spec, app with every planted bug fixed."""
    tmp = Path(tempfile.mkdtemp(prefix="qa-selftest-clean-"))
    try:
        results, proc = run_engines(tmp, fixed=True)
        if proc.returncode != 0:
            print(proc.stdout[-2000:], proc.stderr[-2000:])
            print(f"CLEAN CONTROL FAILED: engine run exited with code {proc.returncode}")
            return 1
        if results is None:
            print(proc.stdout[-2000:], proc.stderr[-2000:])
            print("CLEAN CONTROL FAILED: engines produced no output")
            return 1
        errors = [r["engine"] for r in results if trust.resolve(r)[0] == trust.ERRORED]
        loud = [(r["engine"], f) for r in results for f in r.get("findings", []) if f.get("severity") in ("high", "medium")]
        quiet = [(r["engine"], f) for r in results for f in r.get("findings", []) if f.get("severity") in ("low", "info")]
        for eng, f in loud:
            print(f"  FALSE POSITIVE? [{f['severity']}] {eng} {f['kind']} {f['endpoint']}: {str(f['detail'])[:160]}")
        print(f"clean control: {len(loud)} high/medium, {len(quiet)} low/info finding(s) on the fixed app")
        if errors or loud:
            print("CLEAN CONTROL FAILED:", f"{len(loud)} high/medium finding(s)" if loud else "", "engine errors " + str(errors) if errors else "")
            return 1
        print("CLEAN CONTROL OK: no high/medium finding on the fixed demo app")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    code = check_planted()
    if "--with-clean" in sys.argv:
        code = max(code, check_clean())
    return code


if __name__ == "__main__":
    sys.exit(main())
