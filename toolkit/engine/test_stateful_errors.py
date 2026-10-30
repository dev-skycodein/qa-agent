"""stateful.py: an error of Hypothesis itself (no app failure recorded) is an engine error, never an app finding.

  python toolkit/engine/test_stateful_errors.py        (also collectable by pytest)
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import stateful  # noqa: E402
import trust  # noqa: E402

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


def only_a_comment(api, log, ctx):
    # assert api.call("admin", "GET", "/me").json["balance"] >= 0
    """Written from the template, never filled in."""


def only_pass(api, log, ctx):
    pass


def real_check(api, log, ctx):
    assert api.call("admin", "GET", "/me").json["balance"] >= 0, "negative balance"


def check_on_the_log_only(api, log, ctx):
    assert not [e for e in log if e["status"] == 500]


def test_invariants_without_a_body_are_named():
    qa = SimpleNamespace(INVARIANTS=[only_a_comment, real_check, only_pass, lambda api, log, ctx: None])
    assert stateful.empty_invariants(qa) == ["only_a_comment", "only_pass", "<lambda>"]


def test_real_invariants_are_not_called_empty():
    assert stateful.empty_invariants(SimpleNamespace(INVARIANTS=[real_check, check_on_the_log_only])) == []


def test_a_callable_object_is_not_called_empty():
    class Check:
        def __call__(self, api, log, ctx):
            pass
    assert stateful.empty_invariants(SimpleNamespace(INVARIANTS=[Check()])) == []


class QuietApi:
    roles = {"anon": {}, "user_a": {"t": "a"}}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        return api_mod.Resp(200, "{}")


DOC = {"paths": {"/ping": {"post": {"summary": "write"}}}}


def test_empty_invariant_never_gives_ran_ok():
    import pytest
    pytest.importorskip("hypothesis")
    r = stateful.run(QuietApi(), DOC, SimpleNamespace(INVARIANTS=[only_pass]), max_examples=2, steps=2)
    assert r["status"] == trust.DEGRADED and "only_pass" in r["status_reason"]


def test_one_real_invariant_next_to_an_empty_one_is_still_degraded():
    import pytest
    pytest.importorskip("hypothesis")
    def holds(api, log, ctx):
        assert len(log) >= 0
    r = stateful.run(QuietApi(), DOC, SimpleNamespace(INVARIANTS=[holds, only_pass]), max_examples=2, steps=2)
    assert r["status"] == trust.DEGRADED and "only_pass" in r["status_reason"]


def test_real_invariant_still_gives_ran_ok():
    import pytest
    pytest.importorskip("hypothesis")
    def holds(api, log, ctx):
        assert len(log) >= 0
    assert stateful.run(QuietApi(), DOC, SimpleNamespace(INVARIANTS=[holds]), max_examples=2, steps=2)["status"] == trust.RAN_OK


def only_an_assignment(api, log, ctx):
    x = 1
    return x


def test_an_invariant_that_only_assigns_is_empty_too():
    assert stateful.empty_invariants(SimpleNamespace(INVARIANTS=[only_an_assignment])) == ["only_an_assignment"]


def test_a_search_that_sent_nothing_is_not_ran_ok():
    import pytest
    pytest.importorskip("hypothesis")
    def holds(api, log, ctx):
        assert len(log) >= 0
    doc = {"paths": {"/orders/{order_id}": {"patch": {"summary": "needs an id nobody gave"}}}}
    r = stateful.run(QuietApi(), doc, SimpleNamespace(INVARIANTS=[holds]), max_examples=2, steps=2)
    assert r["status"] == trust.DEGRADED and "no request" in r["status_reason"]
