"""Unit tests for authz_matrix against an in-process fake API (no network, no app):  python toolkit/engine/test_authz.py

The fake service has one collection, /orders, owned by user_a. `mode` decides how GET /orders/{id} treats someone else.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import authz_matrix  # noqa: E402
import trust  # noqa: E402

SPEC = {"paths": {
    "/orders": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"qty": {"type": "integer"}}, "required": ["qty"]}}}}}},
    "/orders/{order_id}": {"get": {"summary": "read"}, "patch": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"status": {"type": "string"}}}}}}}},
}}


class FakeApi:
    """GET /orders/{id} for a non-owner: mode 'leak' returns the owner's data, 'generic' a 200 with an unrelated body,
    'deny' a 404. PATCH always succeeds for everyone in 'leak' mode (a write BOLA) and is denied otherwise."""

    def __init__(self, mode):
        self.mode, self.roles, self.log, self.orders = mode, {"anon": {}, "user_a": {"t": "a"}, "user_b": {"t": "b"}}, [], {}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        parts = path.strip("/").split("/")
        if method == "POST" and parts == ["orders"]:
            if role == "anon":
                return api_mod.Resp(401, "{}")
            oid = len(self.orders) + 1
            self.orders[oid] = {"id": oid, "owner": role, "qty": (body or {}).get("qty", 1)}
            return api_mod.Resp(201, __import__("json").dumps(self.orders[oid]))
        oid = int(parts[1])
        order = self.orders.get(oid)
        if method == "GET":
            if role == order["owner"]:
                return api_mod.Resp(200, __import__("json").dumps(order))
            if self.mode == "leak":
                return api_mod.Resp(200, __import__("json").dumps(order))
            if self.mode == "generic":
                return api_mod.Resp(200, '{"ok": true}')
            if self.mode == "rule":
                return api_mod.Resp(409, '{"detail": "illegal transition"}')
            return api_mod.Resp(404, "{}")
        if method == "PATCH":
            if role == order["owner"] or self.mode == "leak":
                if self.mode == "leak" and body:
                    order.update(body)  # write sticks → read-back confirms BOLA
                return api_mod.Resp(200, "{}")
            if self.mode == "write_ok_no_effect":
                return api_mod.Resp(200, "{}")  # 2xx but order unchanged → UNKNOWN-AUTH
            return api_mod.Resp(403, "{}")
        return api_mod.Resp(405, "{}")


def _run(mode):
    return authz_matrix.run(FakeApi(mode), SPEC, SimpleNamespace(PUBLIC={"POST /orders"}))


BOOK_SPEC = {"paths": {
    "/books": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]}}}}}},
    "/books/{title}": {"get": {"summary": "read"}},
}}


class UniqueBookApi:
    """POST /books with a title that already exists. `fail` is how the app says no: 'unique500' (a raw IntegrityError leaks as a
    500), 'conflict409', or 'plain500' (a 500 with no uniqueness hint: NOT a setup failure). `first_ok` lets the first create succeed
    so that only the repeated create (one per attacker probe) fails."""

    def __init__(self, fail, first_ok=True):
        self.fail, self.first_ok, self.roles, self.titles = fail, first_ok, {"anon": {}, "user_a": {"t": "a"}, "user_b": {"t": "b"}}, []

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        if method == "POST" and path.strip("/") == "books":
            if role == "anon":
                return api_mod.Resp(401, "{}")
            if self.first_ok and not self.titles:
                self.titles.append(body["title"])
                return api_mod.Resp(200, '{"id": 1, "title": "%s"}' % body["title"])
            return {"unique500": api_mod.Resp(500, "<title>sqlalchemy.exc.IntegrityError: UNIQUE constraint failed: books.title"),
                    "conflict409": api_mod.Resp(409, '{"detail": "title taken"}'),
                    "plain500": api_mod.Resp(500, "boom")}[self.fail]
        return api_mod.Resp(404, "{}")


def _run_books(fail, first_ok=True):
    return authz_matrix.run(UniqueBookApi(fail, first_ok), BOOK_SPEC, SimpleNamespace(PUBLIC={"POST /books"}))


def test_repeated_create_unique_500_is_setup_failed_not_degraded():
    res = _run_books("unique500")
    assert trust.resolve(res)[0] == trust.SETUP_FAILED, res
    assert res["setup_failed"] and "uniqueness" in res["setup_failed"][0]
    assert res["findings"] == []                    # nothing was probed, so nothing is claimed


def test_repeated_create_409_is_setup_failed():
    assert trust.resolve(_run_books("conflict409"))[0] == trust.SETUP_FAILED


def test_first_create_conflict_is_setup_failed():
    res = _run_books("unique500", first_ok=False)
    assert trust.resolve(res)[0] == trust.SETUP_FAILED and len(res["setup_failed"]) == 1


def test_plain_500_is_not_mistaken_for_setup_failed():
    """A 500 with no uniqueness hint is a different problem (the create is broken): it stays a degraded note."""
    res = _run_books("plain500", first_ok=False)
    assert res["setup_failed"] == [] and trust.resolve(res)[0] == trust.DEGRADED, res


def test_setup_failed_counts_as_not_clean_in_summary_and_strict_exit():
    res = _run_books("unique500")
    s = trust.summarize([res])
    assert s["setup_failed"] == ["authz"] and s["degraded"] == []
    assert "setup failed" in trust.verdict(s)
    assert trust.exit_code([res], strict=True) == trust.EXIT_ENGINE_BROKE and trust.exit_code([res]) == trust.EXIT_OK


def _get_findings(res):
    return [f for f in res["findings"] if f["endpoint"].startswith("GET ")]


def test_clean_service_has_no_findings_and_ran_ok():
    res = _run("deny")
    assert res["findings"] == [] and trust.resolve(res)[0] == trust.RAN_OK


def test_leak_is_high_and_says_the_body_is_the_owners():
    f = _get_findings(_run("leak"))
    assert f and all(x["severity"] == "high" for x in f)
    assert any(x["kind"] == "BOLA/IDOR" and "identical to the owner's" in x["detail"] for x in f), f


def test_generic_200_is_only_medium_and_asks_for_verification():
    f = _get_findings(_run("generic"))
    assert f and all(x["severity"] == "medium" for x in f), f
    assert all("differs from the owner's" in x["detail"] for x in f), f


def test_business_rule_conflict_after_no_access_check_is_reported():
    """The probe body is an illegal state transition, so the app answers 409 instead of 200: the request still got past any access check."""
    res = _run("rule")
    kinds = {(x["kind"], x["role"]) for x in res["findings"] if x["endpoint"].startswith("GET ")}
    assert ("AUTHZ-REACHED-LOGIC", "user_b") in kinds and ("AUTHZ-REACHED-LOGIC", "anon") in kinds, res["findings"]
    assert all(x["severity"] == "medium" and "409" in x["detail"] for x in res["findings"] if x["kind"] == "AUTHZ-REACHED-LOGIC")
    assert not any(x["kind"] in ("BOLA/IDOR", "MISSING-AUTH") for x in res["findings"] if x["endpoint"].startswith("GET "))


def test_denials_401_403_404_are_not_reported():
    assert all(x["kind"] != "AUTHZ-REACHED-LOGIC" for x in _run("deny")["findings"])


def test_write_bola_high_when_readback_shows_change():
    f = [x for x in _run("leak")["findings"] if x["endpoint"].startswith("PATCH ")]
    assert f and all(x["severity"] == "high" for x in f)
    assert any("read-back" in x["detail"] for x in f), f


class SubresourceApi:
    """/orders/{id} is readable, /orders/{id}/status is not (405), like a PATCH-only sub-action."""

    def __init__(self):
        self.order = {"id": 5, "owner": "user_a", "status": "placed"}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        if method == "GET" and path == "/orders/5":
            return api_mod.Resp(200, __import__("json").dumps(self.order))
        if method == "GET":
            return api_mod.Resp(405, "{}")
        if method == "PATCH":
            self.order.update(body or {})
        return api_mod.Resp(200, "{}")


def test_write_readback_on_subaction_path_uses_parent_resource():
    api = SubresourceApi()
    written = api.call("user_b", "PATCH", "/orders/5/status", {"status": "shipped"})
    kind, sev, detail = authz_matrix._write_readback(
        api, "user_a", {"method": "PATCH"}, "/orders/5/status", {"status": "shipped"}, written)
    assert (kind, sev) == ("BOLA/IDOR", "high") and "read-back" in detail, (kind, sev, detail)


def test_delete_readback_does_not_fall_back_to_parent():
    class GoneApi(SubresourceApi):
        def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
            return api_mod.Resp(404, "{}") if method == "GET" else api_mod.Resp(200, "{}")
    kind, sev, _ = authz_matrix._write_readback(GoneApi(), "user_a", {"method": "DELETE"}, "/orders/5", None, api_mod.Resp(200, "{}"))
    assert (kind, sev) == ("BOLA/IDOR", "high"), kind


def test_write_2xx_without_visible_effect_is_unknown_auth():
    f = [x for x in _run("write_ok_no_effect")["findings"] if x["endpoint"].startswith("PATCH ")]
    assert f and all(x["kind"] == "UNKNOWN-AUTH" and x["severity"] == "medium" for x in f), f


def _eps(doc):
    return api_mod.endpoints(doc)


def test_public_inferred_from_explicit_empty_security_when_document_describes_security():
    doc = {"paths": {"/health": {"get": {"security": []}}, "/me": {"get": {"security": [{"bearerAuth": []}]}},
                     "/open": {"get": {}}}}
    assert authz_matrix.inferred_public(doc, _eps(doc)) == {"GET /health"}      # /open says nothing: still checked


def test_global_empty_security_makes_operations_public_unless_they_require_a_scheme():
    doc = {"security": [], "paths": {"/a": {"get": {}}, "/b": {"get": {"security": [{"k": []}]}}}}
    assert authz_matrix.inferred_public(doc, _eps(doc)) == {"GET /a"}


def test_nothing_inferred_when_the_document_never_describes_security():
    doc = {"paths": {"/a": {"get": {}}, "/b": {"post": {"security": []}}}}
    assert authz_matrix.inferred_public(doc, _eps(doc)) == set()               # no real requirement anywhere: [] is boilerplate


def test_inferred_public_endpoint_is_not_missing_auth_but_undeclared_one_still_is():
    class Open:
        roles = {"anon": {}, "user_a": {"t": "a"}}
        log = []

        def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
            return api_mod.Resp(200, "{}")
    doc = {"paths": {"/health": {"get": {"security": []}}, "/notes": {"get": {"security": [{"bearerAuth": []}]}}}}
    r = authz_matrix.run(Open(), doc, SimpleNamespace())
    assert [f["endpoint"] for f in r["findings"]] == ["GET /notes"], r["findings"]
    assert r["inferred_public"] == ["GET /health"]


class TenantApi:
    """POST /projects creates a project for the calling role; GET /projects/{id}/audit-log should answer only the project's own members.
    mode 'some' = the bug: any role that belongs to ANY project passes the check."""

    def __init__(self, mode):
        self.mode, self.roles, self.log = mode, {"anon": {}, "user_a": {"t": "a"}, "user_b": {"t": "b"}}, []
        self.members = {}          # project id -> set of roles
        self.next = 0

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        if role == "anon":
            return api_mod.Resp(401, "{}")
        if method == "POST" and path == "/projects":
            self.next += 1
            self.members[self.next] = {role}
            return api_mod.Resp(201, '{"id": %d}' % self.next)
        parts = path.strip("/").split("/")
        if method == "GET" and len(parts) == 3 and parts[2] == "audit-log" and parts[1].isdigit():
            pid = int(parts[1])
            member = role in self.members.get(pid, set())
            anywhere = any(role in m for m in self.members.values())
            if member or (self.mode == "some" and anywhere):
                return api_mod.Resp(200, '{"events": ["project %d event"]}' % pid)
            return api_mod.Resp(404, "{}")
        return api_mod.Resp(404, "{}")


TENANT_SPEC = {"paths": {"/projects": {"post": {}}, "/projects/{pid}/audit-log": {"get": {}}}}


def test_membership_check_that_only_asks_for_any_project_is_found_because_attackers_own_one():
    r = authz_matrix.run(TenantApi("some"), TENANT_SPEC, SimpleNamespace())
    hits = [f for f in r["findings"] if f["endpoint"] == "GET /projects/{pid}/audit-log"]
    assert hits and hits[0]["kind"] == "BOLA/IDOR", r["findings"]


def test_proper_per_project_membership_check_has_no_finding():
    r = authz_matrix.run(TenantApi("proper"), TENANT_SPEC, SimpleNamespace())
    assert r["findings"] == [], r["findings"]


class MemberApi:
    """Projects with owners and members. mode 'open' = the bug: any member may PATCH the project; 'owner_only' = only the owner may."""

    def __init__(self, mode):
        self.mode, self.roles, self.log = mode, {"anon": {}, "user_a": {"t": "a"}, "user_b": {"t": "b"}}, []
        self.ids = {"user_a": 1, "user_b": 2}
        self.projects = {}
        self.next = 0

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        if role == "anon":
            return api_mod.Resp(401, "{}")
        parts = path.strip("/").split("/")
        if method == "GET" and parts == ["me"]:
            return api_mod.Resp(200, '{"id": %d, "email": "%s@x.test"}' % (self.ids[role], role))
        if method == "POST" and parts == ["projects"]:
            self.next += 1
            self.projects[self.next] = {"owner": role, "members": {role}, "name": "p"}
            return api_mod.Resp(201, '{"id": %d, "name": "p"}' % self.next)
        if len(parts) >= 2 and parts[0] == "projects" and parts[1].isdigit() and int(parts[1]) in self.projects:
            pr = self.projects[int(parts[1])]
            if role not in pr["members"]:
                return api_mod.Resp(404, "{}")
            if method == "POST" and parts[2:] == ["members"]:
                if role != pr["owner"]:
                    return api_mod.Resp(403, "{}")
                uid = (body or {}).get("user_id")
                pr["members"] |= {r for r, i in self.ids.items() if i == uid}
                return api_mod.Resp(201, "{}")
            if method == "PATCH" and len(parts) == 2:
                if role != pr["owner"] and self.mode == "owner_only":
                    return api_mod.Resp(403, "{}")
                pr["name"] = (body or {}).get("name", pr["name"])
                return api_mod.Resp(200, '{"id": %s, "name": "%s"}' % (parts[1], pr["name"]))
            if method == "GET" and len(parts) == 2:
                return api_mod.Resp(200, '{"id": %s, "name": "%s"}' % (parts[1], pr["name"]))
        return api_mod.Resp(404, "{}")


MEMBER_SPEC = {"paths": {
    "/me": {"get": {}},
    "/projects": {"post": {}},
    "/projects/{pid}": {"get": {}, "patch": {"summary": "Rename the project", "requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}},
    "/projects/{pid}/members": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["user_id", "role"], "properties": {"user_id": {"type": "integer"},
                                                                          "role": {"type": "string", "enum": ["owner", "member"]}}}}}}}},
}}


def test_member_who_can_change_the_project_settings_is_reported_for_review():
    r = authz_matrix.run(MemberApi("open"), MEMBER_SPEC, SimpleNamespace())
    hits = [f for f in r["findings"] if f["kind"] == "AUTHZ-MEMBER-WRITE"]
    assert hits and hits[0]["severity"] == "low", r["findings"]            # the document does not say the update is owner-only: low, verify


def test_member_write_is_medium_when_the_operation_says_owner_only():
    spec = {"paths": {**MEMBER_SPEC["paths"], "/projects/{pid}": {"get": {}, "patch": {
        **MEMBER_SPEC["paths"]["/projects/{pid}"]["patch"], "summary": "Rename the project (owners only)"}}}}
    r = authz_matrix.run(MemberApi("open"), spec, SimpleNamespace())
    assert [f["severity"] for f in r["findings"] if f["kind"] == "AUTHZ-MEMBER-WRITE"] == ["medium"], r["findings"]


def test_owner_only_update_has_no_member_write_finding():
    r = authz_matrix.run(MemberApi("owner_only"), MEMBER_SPEC, SimpleNamespace())
    assert [f for f in r["findings"] if f["kind"] == "AUTHZ-MEMBER-WRITE"] == [], r["findings"]


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
