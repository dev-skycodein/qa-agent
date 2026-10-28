"""Tests for run.py --preflight: the spec is checked against the OpenAPI document and setup() without attack traffic."""
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run  # noqa: E402

DOC = {"paths": {"/items": {"get": {}}, "/items/{item_id}": {"delete": {}}}}


def _spec(**kw):
    base = {"PUBLIC": {"GET /items"}, "ADMIN_ONLY": {"DELETE /items/{item_id}"},
            "BODIES": {"POST /items": {"name": "x"}}, "OWNER": {}, "IDS": {}, "INVARIANTS": [],
            "RACES": [], "SCENARIOS": []}
    base.update(kw)
    return SimpleNamespace(**base)


def _run(qa, roles):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run.preflight(qa, DOC, roles)
    return code, buf.getvalue()


def test_ok_spec_exits_zero_and_says_no_attack_traffic():
    code, out = _run(_spec(), {"user_a": {"Authorization": "Bearer t"}})
    assert code == 0
    assert "[preflight] OK: 0 problem(s)" in out and "No attack traffic was sent" in out


def test_public_route_missing_from_openapi_is_a_problem():
    code, out = _run(_spec(PUBLIC={"GET /nope"}), {"user_a": {"Authorization": "Bearer t"}})
    assert code == 1
    assert "PUBLIC entry 'GET /nope' is not an operation" in out


def test_wrong_method_for_existing_path_is_a_problem():
    code, out = _run(_spec(ADMIN_ONLY={"GET /items/{item_id}"}), {"user_a": {"Authorization": "Bearer t"}})
    assert code == 1 and "ADMIN_ONLY entry 'GET /items/{item_id}'" in out


def test_no_roles_is_a_problem():
    code, out = _run(_spec(), {})
    assert code == 1 and "setup() returned no roles" in out


def test_empty_headers_for_a_role_is_a_problem():
    code, out = _run(_spec(), {"user_a": {}})
    assert code == 1 and "role 'user_a'" in out


def test_empty_optional_keys_are_notes_not_problems():
    code, out = _run(_spec(RACES=[], SCENARIOS=[], BODIES={}), {"user_a": {"Authorization": "Bearer t"}})
    assert code == 0
    assert "RACES is empty" in out and "SCENARIOS is empty" in out and "BODIES is empty" in out


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("test_preflight: all passed")
