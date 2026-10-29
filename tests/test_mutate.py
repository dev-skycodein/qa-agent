"""Tests for the judging logic of mutate.py (no app, no engines):  python tests/test_mutate.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))      # repo root: mutate.py lives there
import mutate


def _res(*findings, errored=False):
    r = {"engine": "x", "findings": [{"kind": k, "severity": s, "endpoint": e, "detail": d} for k, s, e, d in findings], "status": "ran_ok"}
    if errored:
        r["engine-error"] = "boom"
    return [r]


def test_a_bug_is_a_hit_only_with_its_own_kind_and_endpoint():
    ok = mutate.evaluate(_res(("BOLA/IDOR", "high", "GET /orders/{order_id}", "user_b got 200")), {1})
    assert ok["hit"] == {1: True} and ok["unexplained"] == []
    wrong_endpoint = mutate.evaluate(_res(("BOLA/IDOR", "high", "PATCH /items/{id}", "x")), {1})
    assert wrong_endpoint["hit"] == {1: False}


def test_findings_no_active_bug_explains_are_reported_as_unexplained():
    r = mutate.evaluate(_res(("BOLA/IDOR", "high", "GET /orders/{order_id}", "d"), ("PRIV-ESC", "high", "POST /admin/reset-prices", "d")), {1})
    assert len(r["unexplained"]) == 1 and "PRIV-ESC" in r["unexplained"][0]


def test_low_info_and_known_noise_are_not_unexplained():
    r = mutate.evaluate(_res(("NEG-ACCEPTED", "low", "POST /items", "d"), ("OUTBOUND-ATTEMPT", "info", "h", "d"),
                             ("OUTBOUND-EMAIL", "medium", "smtp", "d")), set())
    assert r["unexplained"] == []


def test_clean_control_counts_everything_loud_as_unexplained():
    r = mutate.evaluate(_res(("NEG-5XX", "medium", "POST /items", "price=huge")), set())
    assert len(r["unexplained"]) == 1 and r["hit"] == {}


def test_errored_engines_are_listed():
    assert mutate.evaluate(_res(errored=True), set())["errored"] == ["x"]


def test_bug8_is_run_together_with_its_trigger():
    assert mutate.active_set(8) == {6, 8} and mutate.active_set(3) == {3}


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
