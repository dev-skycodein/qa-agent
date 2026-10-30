"""qa_check.py must run every test file, and its --full step must not depend on a folder this release does not ship.

  python tests/test_qa_check.py        (also collectable by pytest)
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import qa_check  # noqa: E402


def test_the_suite_step_runs_the_whole_test_folders_not_a_hand_kept_list():
    calls = []
    original = qa_check.run_cmd
    qa_check.run_cmd = lambda cmd, cwd, timeout, log_fh: (calls.append(cmd) or (0, "ok"))
    try:
        r = qa_check.step_unit_tests(None)
    finally:
        qa_check.run_cmd = original
    assert r.status == qa_check.PASS and len(calls) == 1
    assert "pytest" in calls[0] and "tests" in calls[0] and "toolkit/engine" in calls[0]


def test_a_failing_suite_is_a_fail():
    original = qa_check.run_cmd
    qa_check.run_cmd = lambda cmd, cwd, timeout, log_fh: (1, "1 failed, 3 passed")
    try:
        assert qa_check.step_unit_tests(None).status == qa_check.FAIL
    finally:
        qa_check.run_cmd = original


def test_bench_step_skips_when_the_bench_script_is_not_in_this_release(tmp_path):
    seeds, original = tmp_path / "seeds.json", qa_check.SEEDED_BENCH
    seeds.write_text("{}", encoding="utf-8")
    qa_check.SEEDED_BENCH = seeds
    try:
        r = qa_check.step_bench(None)
    finally:
        qa_check.SEEDED_BENCH = original
    assert r.status == qa_check.SKIP and "bench.py" in r.reason


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and name != "test_bench_step_skips_when_the_bench_script_is_not_in_this_release" and callable(fn):
            fn()
            print(f"ok {name}")
