"""One-command health check for the QA toolkit. Run it in a normal terminal:

  python qa_check.py              # interactive menu
  python qa_check.py --quick      # preflight + safety + trust tests + unit tests + selftest (~10 min)
  python qa_check.py --full       # quick + selftest x3 consistency + clean control (longer)

Every step prints PASS / FAIL / SKIP / WARN with a reason. Full output of every step goes to
logs/qa-check-<time>.log. Exit code 0 = no FAIL. Stdlib only, so it runs on the system python.
"""
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"

PASS, FAIL, SKIP, WARN = "PASS", "FAIL", "SKIP", "WARN"


class Result:
    def __init__(self, name, status, reason="", log=""):
        self.name, self.status, self.reason, self.log = name, status, reason, log


def tail(text, n=12):
    lines = [l for l in text.splitlines() if l.strip()]
    return "\n".join(lines[-n:])


def run_cmd(cmd, cwd, timeout, log_fh):
    log_fh.write(f"\n$ {' '.join(map(str, cmd))}\n")
    log_fh.flush()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout, env={**os.environ, "PYTHONUTF8": "1"})
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "") if isinstance(e.stdout, str) else "timeout"
        log_fh.write(out + "\n[TIMEOUT]\n")
        return None, out + "\n[TIMEOUT]"
    out = p.stdout + p.stderr
    log_fh.write(out + f"\n[exit {p.returncode}]\n")
    return p.returncode, out


# ---------- steps ----------

def step_versions(log_fh):
    notes = []
    ok = sys.version_info >= (3, 10)
    notes.append(f"python {sys.version.split()[0]}")
    if not ok:
        return Result("python version", FAIL, "need >= 3.10")
    # engines call uv as `python -m uv`, so a uv binary on PATH is not required
    uv_ok = subprocess.run([sys.executable, "-m", "uv", "--version"], capture_output=True).returncode == 0
    node_ok = shutil.which("node") is not None
    if not uv_ok:
        return Result("python + uv + node", FAIL, "python -m uv not runnable; engines need it")
    if not node_ok:
        return Result("python + uv + node", WARN, "node not on PATH (needed only for the Node validators)")
    return Result("python + uv + node", PASS, "; ".join(notes) + ", python -m uv, node found")


def step_safety(log_fh):
    code, out = run_cmd([sys.executable, str(ROOT / "toolkit" / "engine" / "test_api_safety.py")], ROOT, 300, log_fh)
    if code is None:
        return Result("api safety tests", FAIL, "timed out", out)
    if code == 0:
        return Result("api safety tests", PASS, "egress + path safety tests green", out)
    return Result("api safety tests", FAIL, "see log: " + tail(out, 3).replace("\n", " | "), out)


def step_selftest(log_fh):
    code, out = run_cmd([sys.executable, str(ROOT / "toolkit" / "engine" / "selftest.py")], ROOT, 900, log_fh)
    if code is None:
        return Result("engine selftest (demo app)", FAIL, "timed out after 15 min", out)
    if code == 0:
        return Result("engine selftest (demo app)", PASS, "all planted bug classes found", out)
    return Result("engine selftest (demo app)", FAIL, tail(out, 2).replace("\n", " | "), out)


def step_trust(log_fh):
    code, out = run_cmd([sys.executable, str(ROOT / "toolkit" / "engine" / "test_trust.py")], ROOT, 300, log_fh)
    if code is None:
        return Result("trust contract tests", FAIL, "timed out", out)
    if code == 0:
        return Result("trust contract tests", PASS, "status contract + run.py exit codes green", out)
    return Result("trust contract tests", FAIL, "see log: " + tail(out, 3).replace("\n", " | "), out)


def step_console(log_fh):
    for name in ("test_console.py", "test_target_guard.py"):
        code, out = run_cmd([sys.executable, str(ROOT / "tests" / name)], ROOT, 300, log_fh)
        if code != 0:
            return Result("console tests", FAIL, f"{name}: " + ("timed out" if code is None else tail(out, 3).replace("\n", " | ")), out)
    if code is None:
        return Result("console tests", FAIL, "timed out", out)
    if code != 0:
        return Result("console tests", FAIL, tail(out, 3).replace("\n", " | "), out)
    return Result("console tests", PASS, "diff / fingerprint / reset / read-only server safety green", out)


def step_unit_tests(log_fh):
    files = ["test_stats.py", "test_invariant_miner.py", "test_authz.py", "test_detect.py", "test_gate.py", "test_preflight.py", "test_security_fixes.py",
             "test_safe_run.py", "test_api_schema.py",
             "test_schema_fuzz.py", "test_metamorphic.py", "test_logic_engine.py", "test_auth_attacks.py",
             "test_differential.py", "test_shrink.py", "test_exposure.py", "test_metamorphic_extra.py", "test_workflow_chains.py",
             "toolkit/test_rules_from_llm.py", "toolkit/test_synthesize_provider.py"]
    for name in files:
        path = ROOT / name if name.startswith("toolkit/") else ROOT / "toolkit" / "engine" / name
        code, out = run_cmd([sys.executable, str(path)], ROOT, 300, log_fh)
        if code != 0:
            return Result("engine unit tests", FAIL, f"{name}: " + ("timed out" if code is None else tail(out, 2).replace("\n", " | ")), out)
    return Result("engine unit tests", PASS, "stats, miner, authz, auth, schema, differential and workflow tests green")


def step_clean_control(log_fh):
    """False-positive control: the engines on the FIXED demo app must report no high/medium finding."""
    code, out = run_cmd([sys.executable, str(ROOT / "toolkit" / "engine" / "selftest.py"), "--with-clean"], ROOT, 1800, log_fh)
    if code is None:
        return Result("clean control (fixed demo app)", FAIL, "timed out after 30 min", out)
    if code == 0:
        return Result("clean control (fixed demo app)", PASS, "no high/medium finding on the fixed app", out)
    return Result("clean control (fixed demo app)", FAIL, tail(out, 3).replace("\n", " | "), out)


def step_selftest_repeat(k):
    """The canary must be reproducible: k/k passes or the instrument itself is untrustworthy."""
    def check(log_fh):
        passed, last = 0, ""
        for _ in range(k):
            code, out = run_cmd([sys.executable, str(ROOT / "toolkit" / "engine" / "selftest.py")], ROOT, 900, log_fh)
            last = tail(out, 2).replace("\n", " | ")
            passed += code == 0
        if passed == k:
            return Result(f"selftest x{k} consistency", PASS, f"{k}/{k} runs found every planted class")
        kind = "FLAKY" if passed else "BROKEN"
        return Result(f"selftest x{k} consistency", FAIL, f"{kind}: {passed}/{k} passed; last: {last}")
    check.__name__ = f"selftest_x{k}"
    return check


QUICK = [step_versions, step_safety, step_trust, step_console, step_unit_tests, step_selftest]
FULL = QUICK + [step_selftest_repeat(3), step_clean_control]


def execute(steps, label):
    LOGS.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = LOGS / f"qa-check-{stamp}.log"
    results = []
    print(f"== {label} ==  (full log: {log_path})")
    with log_path.open("w", encoding="utf-8") as log_fh:
        for fn in steps:
            print(f"  running {fn.__name__} ...", flush=True)
            try:
                r = fn(log_fh)
            except Exception as e:  # a crashing check must show up as FAIL, never disappear
                r = Result(fn.__name__, FAIL, f"check crashed: {type(e).__name__}: {e}")
            results.append(r)
            print(f"  [{r.status}] {r.name}: {r.reason}", flush=True)
    counts = {s: sum(1 for r in results if r.status == s) for s in (PASS, FAIL, SKIP, WARN)}
    print(f"\nSUMMARY  PASS={counts[PASS]}  FAIL={counts[FAIL]}  WARN={counts[WARN]}  SKIP={counts[SKIP]}")
    print("VERDICT:", "BROKEN - see FAIL lines above and the log" if counts[FAIL] else "no FAIL - toolkit checks green")
    return 1 if counts[FAIL] else 0


def menu():
    options = {
        "1": ("Quick check (preflight, safety, tests, selftest)", QUICK),
        "2": ("Full check (quick + selftest x3 + clean control, long)", FULL),
        "3": ("Preflight only (tools)", QUICK[:1]),
        "4": ("Safety tests only", [step_safety]),
        "5": ("Engine selftest only", [step_selftest]),
        "q": None,
    }
    while True:
        print("\nQA toolkit check")
        for k, v in options.items():
            print(f"  {k}) {v[0] if v else 'quit'}")
        choice = input("choose: ").strip().lower()
        if choice == "q" or choice == "":
            return 0
        if choice in options and options[choice]:
            label, steps = options[choice]
            return execute(steps, label)
        print("unknown choice")


def main(argv):
    if "--quick" in argv:
        return execute(QUICK, "quick")
    if "--full" in argv:
        return execute(FULL, "full")
    return menu()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
