"""exposure.py: secrets in responses, from the log only.

  python toolkit/engine/test_exposure.py        (also collectable by pytest)
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
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


def _with_request(entries):
    """FakeApi whose log entries also carry the request body, as api.Api logs it."""
    fake = FakeApi([(m, p, s, b) for m, p, s, b, _ in entries])
    for row, (*_, sent) in zip(fake.log, entries):
        row["request"] = sent
    return fake


def test_weak_name_echoing_the_callers_own_value_is_quiet():
    # the negative engine's mass-assign probe sends deluxeToken="x"; an app that echoes unknown fields must not be a leak
    r = exposure.run(_with_request([("POST", "/items", 201, {"id": 1, "deluxeToken": "x"}, {"name": "a", "deluxeToken": "x"})]), {})
    assert r["findings"] == []


def test_weak_name_with_a_value_the_caller_did_not_send_is_still_reported():
    r = exposure.run(_with_request([("POST", "/items", 201, {"id": 1, "deluxeToken": "server-made"}, {"deluxeToken": "x"})]), {})
    assert [f["severity"] for f in r["findings"]] == ["low"]


def test_echoed_password_is_still_high():
    r = exposure.run(_with_request([("POST", "/users", 201, {"id": 1, "password": "hunter2"}, {"password": "hunter2"})]), {})
    assert [f["severity"] for f in r["findings"]] == ["high"], "echoing a password back is a real leak, never excused"


HASH = "$2b$12$" + "a" * 53


def _serve(body: str):
    """A real local HTTP server that answers every GET with `body`."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _users(n):
    return json.dumps([{"id": i, "email": f"u{i}@x.test", "password_hash": HASH} for i in range(n)])


def test_secret_in_a_response_longer_than_the_log_cap_is_found():
    srv = _serve(_users(300))
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}")
        assert api.call("anon", "GET", "/users").ok
        r = exposure.run(api, {}, None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["status"] == trust.RAN_OK and [f["severity"] for f in r["findings"]] == ["high"]


def test_log_still_keeps_only_the_capped_body_for_the_other_engines():
    srv = _serve(_users(300))
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}")
        api.call("anon", "GET", "/users")
    finally:
        srv.shutdown()
        srv.server_close()
    assert len(api.log[0]["body"]) == api_mod.BODY_CAP


def test_full_bodies_stop_at_the_memory_budget_and_the_run_says_so():
    srv = _serve(_users(300))
    try:
        api = api_mod.Api(f"http://127.0.0.1:{srv.server_address[1]}")
        api.full_body_budget = 100
        api.call("anon", "GET", "/users")
        r = exposure.run(api, {}, None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert r["status"] == trust.DEGRADED and "1 " in r["status_reason"]


def test_cut_body_is_never_counted_as_clean_next_to_a_small_response():
    log = FakeApi([("GET", "/items", 200, [{"id": 1}])])
    log.log.append({"role": "user_a", "method": "GET", "path": "/users", "status": 200, "body": _users(300)[:8000], "truncated": True})
    r = exposure.run(log, {}, None)
    assert r["status"] == trust.DEGRADED and "could not be read" in r["status_reason"]


def test_a_cut_html_page_on_an_error_status_changes_nothing():
    log = FakeApi([("GET", "/items", 200, [{"id": 1}])])
    log.log.append({"role": "user_a", "method": "GET", "path": "/x", "status": 500, "body": "<html>" * 2000, "truncated": True})
    assert exposure.run(log, {}, None)["status"] == trust.RAN_OK


def test_secret_far_down_a_list_is_found():
    rows = [{"id": i} for i in range(25)] + [{"id": 99, "password": "hunter2"}]
    _, k = kinds([("GET", "/users", 200, rows)])
    assert k == {("GET /users", "[*].password")}
