"""Tests for the statistical improvement gate.

  python toolkit/engine/test_gate.py
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate  # noqa: E402


def test_accept_when_recall_up_fp_zero_no_regression():
    old = {"hits": 10, "trials": 12, "clean_fp": 0,
           "per_bug": {"1": {"hit": True}, "2": {"hit": True}, "3": {"hit": False}}}
    new = {"hits": 12, "trials": 12, "clean_fp": 0,
           "per_bug": {"1": {"hit": True}, "2": {"hit": True}, "3": {"hit": True}}}
    d = gate.decide(old, new, baseline_recall=0.5)
    assert d["accepted"], d


def test_reject_on_clean_fp():
    old = {"hits": 12, "trials": 12, "clean_fp": 0, "per_bug": {}}
    new = {"hits": 12, "trials": 12, "clean_fp": 2, "per_bug": {}}
    d = gate.decide(old, new, baseline_recall=0.5)
    assert not d["accepted"] and any("clean_fp" in r for r in d["reasons"])


def test_reject_on_regression():
    old = {"hits": 2, "trials": 2, "clean_fp": 0,
           "per_bug": {"1": {"hit": True}, "2": {"hit": True}}}
    new = {"hits": 1, "trials": 2, "clean_fp": 0,
           "per_bug": {"1": {"hit": True}, "2": {"hit": False}}}
    d = gate.decide(old, new, baseline_recall=0.0)
    assert not d["accepted"] and any("regression" in r for r in d["reasons"])


def test_reject_low_wilson_lower():
    old = {"hits": 12, "trials": 12, "clean_fp": 0, "per_bug": {}}
    new = {"hits": 1, "trials": 12, "clean_fp": 0, "per_bug": {}}
    d = gate.decide(old, new)  # baseline = old Wilson lower ~0.75+
    assert not d["accepted"] and any("Wilson" in r or "baseline" in r for r in d["reasons"])


def test_demo_accept_and_reject_pair():
    """Phase 4 exit criterion: one accepted and one rejected decision on demo-shaped summaries."""
    baseline = {"hits": 11, "trials": 12, "clean_fp": 0,
                "per_bug": {str(i): {"hit": True} for i in range(1, 12)} | {"12": {"hit": False}}}
    better = {"hits": 12, "trials": 12, "clean_fp": 0,
              "per_bug": {str(i): {"hit": True} for i in range(1, 13)}}
    worse = {"hits": 8, "trials": 12, "clean_fp": 1,
             "per_bug": {str(i): {"hit": i <= 8} for i in range(1, 13)}}
    assert gate.decide(baseline, better, baseline_recall=0.7)["accepted"]
    assert not gate.decide(baseline, worse, baseline_recall=0.7)["accepted"]


def test_reject_regression_in_hits_trials_shape():
    """per_bug in the documented {hits, trials} shape (no 'hit' key) must still catch a bug that was hit and is now missed."""
    old = {"hits": 3, "trials": 3, "clean_fp": 0, "per_bug": {"1": {"hits": 3, "trials": 3}}}
    new = {"hits": 3, "trials": 3, "clean_fp": 0, "per_bug": {"1": {"hits": 0, "trials": 3}}}
    d = gate.decide(old, new, baseline_recall=0.0, flake_limit=1.0)
    assert not d["accepted"] and d["metrics"]["regressions"] == ["1"], d


def test_deterministic_miss_is_not_flake():
    """A bug missed on every repeat is a recall problem, not flakiness; it must not inflate the flake rate."""
    old = {"hits": 1, "trials": 2, "clean_fp": 0, "per_bug": {"1": {"hits": 1, "trials": 1}, "2": {"hits": 0, "trials": 1}}}
    new = {"hits": 6, "trials": 12, "clean_fp": 0, "per_bug": {"1": {"hits": 6, "trials": 6}, "2": {"hits": 0, "trials": 6}}}
    d = gate.decide(old, new, baseline_recall=0.0)
    assert d["metrics"]["flake"] == 0.0 and d["accepted"], d


def test_real_flake_is_still_caught():
    old = {"hits": 3, "trials": 3, "clean_fp": 0, "per_bug": {"1": {"hits": 3, "trials": 3}}}
    new = {"hits": 3, "trials": 6, "clean_fp": 0, "per_bug": {"1": {"hits": 3, "trials": 6}}}
    d = gate.decide(old, new, baseline_recall=0.0)
    assert not d["accepted"] and any("flake" in r for r in d["reasons"]), d


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:
                failed += 1
                print("FAIL", name, e)
    raise SystemExit(failed)
