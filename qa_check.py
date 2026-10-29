"""One-command health check for the QA toolkit. Run it in a normal terminal (outside Claude):

  python qa_check.py              # interactive menu
  python qa_check.py --quick      # preflight + safety + trust tests + selftest (~2-3 min)
  python qa_check.py --full       # quick + selftest x3 consistency + a seeded benchmark (needs its own data) (~30+ min, needs Mongo running)

Every step prints PASS / FAIL / SKIP / WARN with a reason. Full output of every step goes to
logs/qa-check-<time>.log. Exit code 0 = no FAIL. Stdlib only, so it runs on the system python.
"""
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"
# Optional local targets: set these env vars to enable the SKIP-by-default checks; unset = SKIP with reason.
SEEDED_BENCH = Path(os.environ.get("QA_SEEDED_BENCH", "unset/seeded-benchmark.json"))
EXTRA_DIR = Path(os.environ.get("QA_EXTRA_TARGET_DIR", "unset/extra-target"))
JUICE_DIR = Path(os.environ.get("QA_JUICE_DIR", "unset/juice-shop"))

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
        return Result("python + uv + node", WARN, "node not on PATH (only lms/juice need it)")
    return Result("python + uv + node", PASS, "; ".join(notes) + ", python -m uv, node found")


def step_paths(log_fh):
    problems = []
    if not (ROOT / "toolkit" / "engine" / "selftest.py").exists():
        problems.append("toolkit/engine missing (wrong folder?)")
    if not SEEDED_BENCH.exists():
        return Result("hardcoded target paths", WARN,
                      f"seeded benchmark data not found at {SEEDED_BENCH} (only --full needs it)")
    try:
        seeds = json.loads(SEEDED_BENCH.read_text(encoding="utf-8"))
        repo = Path(seeds.get("repo", ""))
        if not repo.exists():
            problems.append(f"seeds.json repo path missing: {repo}")
    except Exception as e:
        problems.append(f"seeds.json unreadable: {e}")
    if problems:
        return Result("hardcoded target paths", FAIL, "; ".join(problems))
    return Result("hardcoded target paths", PASS, "toolkit + seeded benchmark data resolve")


def step_port(name, port, needed_for):
    def check(log_fh):
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect(("127.0.0.1", port))
            return Result(name, PASS, f"port {port} open")
        except OSError:
            return Result(name, SKIP, f"port {port} closed; start it only for {needed_for}")
        finally:
            s.close()
    check.__name__ = "port_" + str(port)
    return check


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
    for name in ("test_console.py", "test_mutate.py", "test_target_guard.py"):
        code, out = run_cmd([sys.executable, str(ROOT / "tests" / name)], ROOT, 300, log_fh)
        if code != 0:
            return Result("console + mutation tests", FAIL, f"{name}: " + ("timed out" if code is None else tail(out, 3).replace("\n", " | ")), out)
    return Result("console + mutation tests", PASS, "diff / fingerprint / reset / read-only server safety and mutation judging green", out)


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
            return Result("stats + miner + authz tests", FAIL, f"{name}: " + ("timed out" if code is None else tail(out, 2).replace("\n", " | ")), out)
    return Result("stats + miner + authz tests", PASS, "Wilson/bounds, mined-invariant and authz-oracle tests green")


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


def step_bench(log_fh):
    if not SEEDED_BENCH.exists():
        return Result("seeded benchmark", SKIP, "seeds.json not found")
    code, out = run_cmd([sys.executable, str(ROOT / "benchmarks" / "bench.py"), str(SEEDED_BENCH), "--checks", "engines"],
                        ROOT, 4 * 3600, log_fh)
    if code is None:
        return Result("seeded benchmark", FAIL, "timed out", out)
    last = tail(out, 1)
    if code == 0:
        return Result("seeded benchmark", PASS, last, out)
    return Result("seeded benchmark", FAIL, last, out)


def step_lms_present(log_fh):
    if not EXTRA_DIR.exists():
        return Result("extra target clone", SKIP, f"not at {EXTRA_DIR}")
    return Result("extra target clone", PASS, "present (its own tests are not run here)")


def step_juice_present(log_fh):
    if not JUICE_DIR.exists():
        return Result("juice-shop clone", SKIP, f"not at {JUICE_DIR}")
    built = (JUICE_DIR / "node_modules").exists()
    return Result("juice-shop clone", WARN if not built else PASS,
                  "present, node_modules " + ("found" if built else "missing (npm install not run)"))


QUICK = [step_versions, step_paths, step_port("mongo (benchmark)", 27017, "--full bench"),
         step_port("postgres (extra target)", 5433, "extra target runs"), step_safety, step_trust, step_console, step_unit_tests, step_selftest]
FULL = QUICK + [step_selftest_repeat(3), step_clean_control, step_bench, step_lms_present, step_juice_present]


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
        "1": ("Quick check (preflight + safety + selftest)", QUICK),
        "2": ("Full check (quick + seeded benchmark, long)", FULL),
        "3": ("Preflight only (tools, paths, ports)", QUICK[:3]),
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
