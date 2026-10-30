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


ROLES = {"user_a": {"Authorization": "Bearer a"}, "user_b": {"Authorization": "Bearer b"}, "admin": {"Authorization": "Bearer c"}}
SHOP_ROLES = {"buyer": {"Authorization": "Bearer a"}, "seller": {"Authorization": "Bearer b"}, "admin": {"Authorization": "Bearer c"}}


def test_any_role_names_are_fine_when_two_plain_roles_and_the_admin_exist():
    code, out = _run(_spec(OWNER={"POST /items": "seller"}), SHOP_ROLES)
    assert code == 0 and "[preflight] OK: 0 problem(s)" in out


def test_owner_naming_an_unknown_role_is_a_problem():
    code, out = _run(_spec(OWNER={"POST /items": "user_a"}), SHOP_ROLES)
    assert code == 1 and "OWNER['POST /items'] names role 'user_a'" in out


def test_one_plain_role_is_a_problem_because_no_user_can_attack_another():
    code, out = _run(_spec(), {"user_a": ROLES["user_a"], "admin": ROLES["admin"]})
    assert code == 1 and "two non-admin roles" in out


def test_admin_only_routes_without_the_admin_role_are_a_problem():
    code, out = _run(_spec(), {"buyer": SHOP_ROLES["buyer"], "seller": SHOP_ROLES["seller"], "boss": ROLES["admin"]})
    assert code == 1 and "ADMIN_ROLE 'admin'" in out


def test_admin_paths_need_the_admin_role_even_when_admin_only_is_empty():
    doc = {"paths": {"/admin/reset": {"post": {}}}}
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run.preflight(_spec(PUBLIC=set(), ADMIN_ONLY=set()), doc, {"buyer": {"t": "a"}, "seller": {"t": "b"}})
    assert code == 1 and "ADMIN_ROLE 'admin'" in buf.getvalue()


def test_invariant_with_an_empty_body_is_a_problem():
    def no_negative_balance(api, log, ctx):
        """Nothing here yet."""
    code, out = _run(_spec(INVARIANTS=[no_negative_balance]), ROLES)
    assert code == 1 and "no_negative_balance" in out


def test_race_check_with_an_empty_body_is_a_problem():
    race = {"name": "oversell", "setup": lambda api, ctx: {}, "check": lambda api, results, ctx: None}
    code, out = _run(_spec(RACES=[race]), ROLES)
    assert code == 1 and "race 'oversell'" in out


def test_no_admin_role_and_no_admin_routes_is_only_a_note():
    code, out = _run(_spec(ADMIN_ONLY=set()), {"buyer": {"t": "a"}, "seller": {"t": "b"}})
    assert code == 0 and "ADMIN_ROLE 'admin' is not a role" in out


def test_one_plain_role_message_says_two_accounts_of_one_type_are_enough():
    _, out = _run(_spec(), {"user_a": ROLES["user_a"], "admin": ROLES["admin"]})
    assert "same user type" in out


def test_a_role_that_looks_like_the_admin_is_a_problem_when_admin_role_is_not_set():
    code, out = _run(_spec(ADMIN_ONLY=set()), {"buyer": {"t": "a"}, "seller": {"t": "b"}, "superadmin": {"t": "c"}})
    assert code == 1 and "'superadmin'" in out and "ADMIN_ROLE" in out


def test_setting_admin_role_clears_that_problem():
    code, _ = _run(_spec(ADMIN_ONLY=set(), ADMIN_ROLE="superadmin"), {"buyer": {"t": "a"}, "seller": {"t": "b"}, "superadmin": {"t": "c"}})
    assert code == 0


def test_ok_spec_exits_zero_and_says_no_attack_traffic():
    code, out = _run(_spec(), ROLES)
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
    code, out = _run(_spec(RACES=[], SCENARIOS=[], BODIES={}), ROLES)
    assert code == 0
    assert "RACES is empty" in out and "SCENARIOS is empty" in out and "BODIES is empty" in out


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("test_preflight: all passed")
