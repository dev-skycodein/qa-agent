"""exposure.py: secrets in responses, from the log only.

  python toolkit/engine/test_exposure.py        (also collectable by pytest)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exposure  # noqa: E402
import trust  # noqa: E402


class FakeApi:
    roles = {"anon": {}}

    def call(self, *a, **k):
        raise AssertionError("tests pass an empty OpenAPI, so no sweep request may be sent")

    def __init__(self, entries):
        self.log = [{"role": "user_a", "method": m, "path": p, "status": s, "body": json.dumps(b)} for m, p, s, b in entries]


def kinds(entries, qa=None):
    r = exposure.run(FakeApi(entries), {}, qa)
    return r, {(f["endpoint"], f["detail"].split("'")[1]) for f in r["findings"]}


def test_password_hash_field_is_high_and_value_is_redacted():
    r, k = kinds([("GET", "/customers/me", 200, {"id": 1, "email": "a@x", "password_sha256": "a" * 64})])
    assert k == {("GET /customers/me", "password_sha256")}, k
    f = r["findings"][0]
    assert f["severity"] == "high" and "a" * 10 not in f["detail"]


def test_login_token_is_not_a_finding_but_a_token_in_a_profile_is():
    _, k = kinds([("POST", "/auth/login", 200, {"access_token": "t" * 40, "refresh_token": "r" * 40})])
    assert k == set()
    _, k = kinds([("GET", "/me", 200, {"id": 1, "refresh_token": "r" * 40})])
    assert k == {("GET /me", "refresh_token")}


def test_bcrypt_value_found_under_innocent_name():
    _, k = kinds([("GET", "/users/7", 200, {"id": 7, "note": "$2b$12$" + "a" * 53})])
    assert k == {("GET /users/{id}", "note")}


def test_harmless_fields_and_booleans_and_errors_are_quiet():
    _, k = kinds([("GET", "/me", 200, {"id": 1, "has_password": True, "created_at": "x", "password_policy": "min 8 chars",
                                       "token_count": 3, "order_hash_id": None}),
                  ("GET", "/me", 403, {"password": "x" * 12})])
    assert k == set(), k


def test_weak_name_is_low_not_high():
    r, k = kinds([("POST", "/projects", 201, {"id": 1, "invite_code": "abcd1234efgh"})])
    assert k == {("POST /projects", "invite_code")} and r["findings"][0]["severity"] == "low"


def test_dedupe_per_endpoint_field_and_allow_list():
    e = [("GET", "/orders/1", 200, {"secret_note": "abc"}), ("GET", "/orders/2", 200, {"secret_note": "def"})]
    r, k = kinds(e)
    assert len(r["findings"]) == 1
    class Qa: EXPOSURE_ALLOW = {"GET /orders/{id} secret_note"}
    _, k = kinds(e, Qa)
    assert k == set()


def test_nothing_inspected_is_skipped_not_clean():
    r, _ = kinds([("GET", "/x", 500, {"error": "boom"})])
    assert trust.resolve(r)[0] == trust.SKIPPED


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"EXPOSURE OK: {len(tests)} tests")
