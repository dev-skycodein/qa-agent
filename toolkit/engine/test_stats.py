"""python toolkit/engine/test_stats.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats  # noqa: E402


def test_wilson_known_values():
    lo, hi = stats.wilson(8, 8)
    assert 0.67 < lo < 0.69 and hi == 1.0                       # 8/8 does NOT mean 100%: lower bound ~68%
    lo, hi = stats.wilson(0, 10)
    assert lo == 0.0 and 0.25 < hi < 0.31
    lo, hi = stats.wilson(5, 10)
    assert 0.23 < lo < 0.25 and 0.75 < hi < 0.77


def test_wilson_empty_sample_is_total_ignorance():
    assert stats.wilson(0, 0) == (0.0, 1.0)


def test_miss_bound_matches_rule_of_three():
    assert abs(stats.miss_bound(10) - 0.259) < 0.002            # exact bound; rule of three would say 0.30
    assert abs(stats.miss_bound(300) - 3 / 300) < 0.0005
    assert stats.miss_bound(0) == 1.0


def test_runs_needed_and_attempts():
    assert stats.runs_needed(0.01) == 299                       # ~3/eps
    assert stats.attempts_for(0.5, 0.99) == 7                   # a coin-flip bug needs 7 tries for 99%
    assert stats.attempts_for(0.7, 0.99) == 4


def test_describe_never_hides_a_zero():
    assert "could still be hiding" in stats.describe(0, 5)
    assert "6/8" in stats.describe(6, 8) and "CI" in stats.describe(6, 8)


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
