"""Audit batch 5 (see QA_TOOLKIT_AUDIT.md): C-M11, C-M12, C-M13, C-L4 and D-M2.

  C-M11  an inclusion flag (include_archived) is not a partition: it is not used for MR-FILTER-PARTITION.
  C-M12  numeric-looking strings sorted as text are accepted (text order first, numeric order as the fallback).
  C-M13  AUTH-ENUM ignores per-request trace ids in the failure body (a trace-only difference is not a finding).
  C-L4   _tampered does not crash on a superscript digit ("²".isdigit() is True, int() rejects it).
  D-M2   synthesize.validate() refuses specs that import or call os / subprocess / eval / exec / __import__,
         and main() writes nothing for them.

  python -m uv run --no-project --python 3.12 --with hypothesis --with pytest python -m pytest toolkit/engine/test_audit_batch5.py -q
"""
import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ENGINE = Path(__file__).resolve().parent
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE.parent))
import api as API  # noqa: E402
import auth_attacks as A  # noqa: E402
import metamorphic as M  # noqa: E402
import synthesize as SY  # noqa: E402


def _fetch(table):
    """A fetch_all stand-in: table(extra_query) -> the items the listing would return for that query."""
    def fetch(ctx, col, extra=None):
        return table(dict(extra or {})), True, ""
    return fetch


# ---------- C-M11 ----------

def test_inclusion_flags_are_not_partition_candidates():
    params = [{"name": "include_archived", "schema": {"type": "boolean"}},
              {"name": "includeDeleted", "schema": {"type": "boolean"}},
              {"name": "with_hidden", "schema": {"type": "boolean"}},
              {"name": "in_stock", "schema": {"type": "boolean"}},
              {"name": "limit", "schema": {"type": "integer"}}]
    assert M.boolean_partition_params(params) == ["in_stock"]


def test_a_real_partition_overlap_is_still_reported(monkeypatch):
    data = {"true": [{"id": 1}, {"id": 2}], "false": [{"id": 2}, {"id": 3}]}
    monkeypatch.setattr(M, "fetch_all", _fetch(lambda e: data.get(e.get("in_stock"), [{"id": 1}, {"id": 2}, {"id": 3}])))
    kind, msg = M.partition_fn(None, {}, "in_stock", {})()
    assert kind == "medium" and "both returned" in msg


# ---------- C-M12 ----------

def _sorted_names(monkeypatch, names):
    monkeypatch.setattr(M, "item_field_type", lambda op, shape, field: None)
    monkeypatch.setattr(M, "fetch_all", _fetch(lambda e: [{"name": v} for v in names]))
    return M.sort_fn(None, {"op": {}, "shape": None}, "sort", "name", None)()


def test_numeric_text_sorted_as_text_is_not_flagged(monkeypatch):
    assert _sorted_names(monkeypatch, ["10", "100", "2", "9"]) is None


def test_numeric_text_sorted_as_numbers_is_not_flagged(monkeypatch):
    assert _sorted_names(monkeypatch, ["2", "9", "10", "100"]) is None


def test_numeric_text_in_neither_order_is_still_reported(monkeypatch):
    result = _sorted_names(monkeypatch, ["9", "2", "10", "100"])
    assert result is not None and result[0] == "medium" and "not monotone" in result[1]


# ---------- C-M13 ----------

def _enum_findings(nouser_text):
    """Run the AUTH-ENUM login comparison against a fake login: alice exists, the wrong password and an unknown user get different bodies."""
    traces = itertools.count(1)
    ctx = SimpleNamespace(login={"path": "/login", "user": "alice@x.io", "password": "pw"},
                          qa=SimpleNamespace(ENUM_SAMPLES=0), findings=[])

    def req(method, path, body=None, headers=None):
        if body.get("username") == "alice@x.io" and body.get("password") == "pw":
            return API.Resp(200, '{"token": "t"}')
        if body.get("username") == "alice@x.io":
            return API.Resp(401, json.dumps({"error": "invalid credentials", "trace": "%032x" % next(traces)}))
        return API.Resp(401, nouser_text(next(traces)))

    ctx.req = req
    ctx.add = lambda check, sev, ep, msg, **kw: ctx.findings.append((check, sev, msg))
    ctx.blocked_by = lambda check, reason: None
    ctx.note = lambda msg: None
    A._enum(ctx)
    return [f for f in ctx.findings if f[0] == "AUTH-ENUM"]


def test_per_request_trace_id_alone_is_not_an_enumeration_finding():
    assert _enum_findings(lambda n: json.dumps({"error": "invalid credentials", "trace": "%032x" % n})) == []


def test_a_different_message_for_an_unknown_user_is_still_a_finding():
    found = _enum_findings(lambda n: json.dumps({"error": "no such user"}))
    assert len(found) == 1 and found[0][1] == "medium"


# ---------- C-L4 ----------

def test_tampered_superscript_digit_does_not_raise():
    assert A._tampered({"sub": "²"})["sub"] == "²-qa"


def test_tampered_numeric_subject_is_incremented():
    assert A._tampered({"sub": "3"})["sub"] == "4"
    assert A._tampered({"sub": 7})["sub"] == 8


# ---------- D-M2 ----------
# The code strings below are INPUT to validate(), which only parses them (ast.parse). They are never executed.

@pytest.mark.parametrize("code", [
    "import os\nos.system('calc')\n",
    "import subprocess\nsubprocess.run(['calc'])\n",
    "import os.path\n",
    "from os import system\n",
    "x = eval('1 + 1')\n",
    "exec('x = 1')\n",
    "m = __import__('os')\n",
])
def test_validate_refuses_code_that_runs_commands_or_evaluates_strings(code):
    full = code + "setup = None\nPUBLIC = {}\nBODIES = {}\n"
    err = SY.validate(full)
    assert err is not None and err.startswith("FORBIDDEN"), err


def test_validate_accepts_a_plain_spec_and_still_reports_syntax_errors():
    assert SY.validate("setup = None\nPUBLIC = {}\nBODIES = {'POST /x': {'a': 1}}\n") is None
    assert SY.validate("def (:\n").startswith("SyntaxError")


def _main_with_llm_reply(monkeypatch, tmp_path, reply):
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}}), encoding="utf-8")
    out = tmp_path / "qa-spec.py"
    monkeypatch.setenv("QA_B5_TEST_KEY", "not-a-real-key")
    monkeypatch.setattr(SY, "call_llm", lambda *a, **k: reply)
    monkeypatch.setattr(sys, "argv", ["synthesize.py", "--openapi", str(spec), "--out", str(out), "--provider", "skycodein",
                                      "--key-env", "QA_B5_TEST_KEY", "--model", "test-model",
                                      "--api-url", "http://127.0.0.1:9/v1/chat/completions"])
    return out


def test_main_refuses_to_write_a_spec_that_runs_os_system(monkeypatch, tmp_path):
    out = _main_with_llm_reply(monkeypatch, tmp_path, "import os\nos.system('calc')\nsetup = None\nPUBLIC = {}\nBODIES = {}\n")
    with pytest.raises(SystemExit) as exc:
        SY.main()
    assert exc.value.code == 3
    assert not out.exists()


def test_main_still_writes_a_clean_spec(monkeypatch, tmp_path):
    out = _main_with_llm_reply(monkeypatch, tmp_path, "setup = None\nPUBLIC = {}\nBODIES = {}\n")
    SY.main()
    assert out.read_text(encoding="utf-8").startswith("setup = None")
