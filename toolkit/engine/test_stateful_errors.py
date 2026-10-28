"""stateful.py: an error of Hypothesis itself (no app failure recorded) is an engine error, never an app finding.

  python toolkit/engine/test_stateful_errors.py        (also collectable by pytest)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stateful  # noqa: E402

RECORDED = {"message": "inv_x: AssertionError: boom", "tail": []}


def hyp_error(name="FlakyStrategyDefinition"):
    """An exception whose class lives in hypothesis.errors, built without importing hypothesis (it is not installed for plain python)."""
    return type(name, (Exception,), {"__module__": "hypothesis.errors"})("Inconsistent data generation!")


def test_hypothesis_internal_error_without_recorded_failure_is_engine_error():
    assert stateful._is_engine_error(hyp_error(), None) is True


def test_same_error_with_a_recorded_app_failure_is_not():
    assert stateful._is_engine_error(hyp_error(), RECORDED) is False


def test_plain_assertion_without_recorded_failure_keeps_the_old_behaviour():
    assert stateful._is_engine_error(AssertionError("x"), None) is False


def test_health_check_failure_is_also_an_engine_error():
    assert stateful._is_engine_error(hyp_error("FailedHealthCheck"), None) is True


def test_real_hypothesis_classes_are_recognised_when_installed():
    import pytest
    errors = pytest.importorskip("hypothesis.errors")
    assert stateful._is_engine_error(errors.FlakyStrategyDefinition("x"), None) is True
    assert stateful._is_engine_error(errors.FailedHealthCheck("x"), None) is True
