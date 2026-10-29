"""Regression tests for audit defects B-H1 .. B-H5 (authz_matrix, negative_engine, stateful). In-process fakes, no network, no app.

  python toolkit/engine/test_audit_fixes_b.py        (also collectable by pytest)

B-H1  admin-only id endpoint: every non-admin role is probed, whichever role created the resource.
B-H2  id routes the authz engine cannot attack are noted and make the run DEGRADED (never a silent ran_ok).
B-H3  a write is reported only when the owner's read-back shows a changed value the attacker sent (no-op PATCH: no finding).
B-H4  the per-endpoint request cap is reported: a note, DEGRADED, and the number of probes not sent.
B-H5  an empty action set ends the stateful engine as ERRORED, never as a STATEFUL-INVARIANT finding.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import authz_matrix  # noqa: E402
import negative_engine  # noqa: E402
import stateful  # noqa: E402
import trust  # noqa: E402


def _qa(**kw):
    base = dict(ADMIN_ONLY=set(), IDS={}, OWNER={}, PUBLIC=set(), SKIP=set(), BODIES={}, OWNED_IDS={})
    base.update(kw)
    return SimpleNamespace(**base)


def _endpoints(res, kind=None):
    return [(f["kind"], f["endpoint"], f["role"], f["severity"]) for f in res["findings"] if kind is None or f["kind"] == kind]


# ---------------- B-H1 ----------------

class DeleteFake:
    """POST /items stores an item. DELETE /items/{id} succeeds for every non-anon role (a real PRIV-ESC if admin-only)."""

    def __init__(self, roles):
        self.roles = roles
        self.calls, self.items, self.n = [], {}, 0

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        self.calls.append((role, method, path))
        parts = path.strip("/").split("/")
        if role == "anon":
            return api_mod.Resp(401, "{}")
        if method == "POST" and parts == ["items"]:
            self.n += 1
            self.items[self.n] = {"id": self.n}
            return api_mod.Resp(201, json.dumps(self.items[self.n]))
        if method == "DELETE" and len(parts) == 2:
            return api_mod.Resp(200, "{}")
        return api_mod.Resp(404, "{}")


ITEMS_POST = {"post": {"requestBody": {"content": {"application/json": {"schema": {
    "type": "object", "properties": {"name": {"type": "string"}}}}}}}}
ITEMS_DELETE = {"delete": {"summary": "delete an item (admin only)"}}


def test_b_h1_user_a_is_probed_for_admin_only_id_endpoint_after_creator_loop():
    fake = DeleteFake({"anon": {}, "user_a": {}, "user_b": {}})
    spec = {"paths": {"/items": ITEMS_POST, "/items/{item_id}": ITEMS_DELETE}}
    res = authz_matrix.run(fake, spec, _qa(ADMIN_ONLY={"DELETE /items/{item_id}"}, IDS={"item_id": "999"}))
    assert [c for c in fake.calls if c[0] == "user_a" and c[1] == "DELETE"], "user_a was never probed on the admin-only DELETE"
    assert ("PRIV-ESC", "DELETE /items/{item_id}", "user_a", "high") in _endpoints(res), _endpoints(res)


def test_b_h1_every_non_admin_role_is_probed_without_creator():
    fake = DeleteFake({"anon": {}, "user_b": {}, "admin": {}})
    spec = {"paths": {"/items/{item_id}": ITEMS_DELETE}}
    res = authz_matrix.run(fake, spec, _qa(ADMIN_ONLY={"DELETE /items/{item_id}"}, IDS={"item_id": "999"}))
    probed = {c[0] for c in fake.calls if c[1] == "DELETE"}
    assert probed == {"user_b"}, f"admin role must not be probed as plain user, and user_b must be: {probed}"
    assert ("PRIV-ESC", "DELETE /items/{item_id}", "user_b", "high") in _endpoints(res)


# ---------------- B-H2 ----------------

class RouteFake:
    def __init__(self, mode):
        self.mode = mode
        self.roles = {"anon": {}, "user_a": {}, "user_b": {}}
        self.calls = []

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        self.calls.append((role, method, path))
        parts = path.strip("/").split("/")
        if self.mode == "users" and method == "GET" and len(parts) == 2:
            return api_mod.Resp(200, json.dumps({"id": parts[1]}))
        if self.mode == "nested" and method == "GET" and len(parts) == 4:
            return api_mod.Resp(200, "{}")
        if self.mode == "products":
            if method == "POST" and parts == ["products"]:
                return api_mod.Resp(201, json.dumps({"id": 7}))
            if method == "GET" and len(parts) == 2:
                return api_mod.Resp(401 if role == "anon" else 403, "{}")
        return api_mod.Resp(404, "{}")


def test_b_h2_unprobeable_id_route_is_noted_and_degraded():
    fake = RouteFake("users")
    res = authz_matrix.run(fake, {"paths": {"/users/{uid}": {"get": {"summary": "read a user"}}}}, _qa())
    assert not [c for c in fake.calls if c[0] == "anon"], "no probe should be sent for a route with no creator"
    assert res["status"] == trust.DEGRADED, res["status"]
    assert any("/users/{uid}" in n and "not probed" in n for n in res["notes"]), res["notes"]


def test_b_h2_nested_two_param_route_is_noted_and_degraded():
    fake = RouteFake("nested")
    res = authz_matrix.run(fake, {"paths": {"/orgs/{o}/members/{m}": {"get": {"summary": "read a member"}}}}, _qa())
    assert res["status"] == trust.DEGRADED, res["status"]
    assert any("/orgs/{o}/members/{m}" in n for n in res["notes"]), res["notes"]


def test_b_h2_child_of_a_failed_creator_keeps_setup_failed_status():
    class ConflictFake(RouteFake):
        def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
            if method == "POST":
                return api_mod.Resp(409, "{}")               # the create hits a uniqueness conflict: setup failed
            return api_mod.Resp(200, "{}")
    spec = {"paths": {"/products": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}}, "/products/{pid}": {"get": {"summary": "read"}}}}
    res = authz_matrix.run(ConflictFake("products"), spec, _qa())
    assert res["status"] == trust.SETUP_FAILED, (res["status"], res["notes"])
    assert not any("not probed" in n for n in res["notes"]), res["notes"]


def test_b_h2_probed_creator_route_is_not_noted():
    fake = RouteFake("products")
    spec = {"paths": {"/products": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}}, "/products/{pid}": {"get": {"summary": "read"}}}}
    res = authz_matrix.run(fake, spec, _qa())
    assert [c for c in fake.calls if c[0] == "anon" and c[1] == "GET"], "the creator route must still be probed"
    assert res["notes"] == [], res["notes"]
    assert res["status"] == trust.RAN_OK, res["status"]


# ---------------- B-H3 ----------------

class PatchFake:
    """POST /items stores {id, name}. GET returns the stored item. PATCH answers 200 to every role; `apply` decides whether it stores."""

    def __init__(self, apply):
        self.apply = apply
        self.roles = {"anon": {}, "user_a": {}, "user_b": {}}
        self.items = {}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        parts = path.strip("/").split("/")
        if method == "POST" and parts == ["items"]:
            if role == "anon":
                return api_mod.Resp(401, "{}")
            iid = len(self.items) + 1
            self.items[iid] = {"id": iid, "name": (body or {}).get("name")}
            return api_mod.Resp(201, json.dumps(self.items[iid]))
        if method == "PATCH" and len(parts) == 2 and parts[1].isdigit():
            if self.apply and int(parts[1]) in self.items and body:
                self.items[int(parts[1])].update(body)
            return api_mod.Resp(200, "{}")
        if method == "GET" and len(parts) == 2 and parts[1].isdigit():
            iid = int(parts[1])
            return api_mod.Resp(200, json.dumps(self.items[iid])) if iid in self.items else api_mod.Resp(404, "{}")
        return api_mod.Resp(404, "{}")


PATCH_SPEC = {"paths": {
    "/items": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}},
    "/items/{item_id}": {"patch": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": {"name": {"type": "string"}}}}}}}},
}}


def test_b_h3_noop_patch_is_not_reported_as_write_bola_but_anon_2xx_is_missing_auth():
    # policy: a logged-in attacker's no-op write is a note (could be legitimate shared access); an ANONYMOUS 2xx write is the
    # finding itself (anon has no legitimate access), whether or not the read-back shows a change
    fake = PatchFake(apply=False)
    res = authz_matrix.run(fake, PATCH_SPEC, _qa())
    write_findings = [f for f in res["findings"] if f["endpoint"].startswith("PATCH")]
    assert all(f["role"] == "anon" and f["kind"] == "MISSING-AUTH" for f in write_findings), write_findings
    assert any("no-op" in n for n in res["notes"]), res["notes"]


def test_b_h3_real_change_by_attacker_is_still_reported():
    fake = PatchFake(apply=True)
    qa = _qa(BODIES={"POST /items": {"name": "original"}, "PATCH /items/{item_id}": {"name": "hacked"}})
    res = authz_matrix.run(fake, PATCH_SPEC, qa)
    got = _endpoints(res)
    assert ("BOLA/IDOR", "PATCH /items/{item_id}", "user_b", "high") in got, got
    # anon's PATCH also stores the attacker value on its own fresh resource (original -> hacked): a proven write as anon
    assert ("MISSING-AUTH", "PATCH /items/{item_id}", "anon", "high") in got, got


# ---------------- B-H4 ----------------

class RecordFake:
    def __init__(self):
        self.roles = {"anon": {}, "user_a": {}, "user_b": {}}
        self.bodies = []

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        self.bodies.append(body)
        return api_mod.Resp(201, "{}")


def _things_spec(n_fields):
    props = {f"f{i:02d}": {"type": "string"} for i in range(1, n_fields + 1)}
    return {"paths": {"/things": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "properties": props, "required": []}}}}}}}}


def test_b_h4_cap_hit_is_noted_degraded_and_counted():
    fake = RecordFake()
    res = negative_engine.run(fake, _things_spec(12), _qa(SKIP=set(), NEG_ROLE={}))
    assert res["status"] == trust.DEGRADED, res["status"]
    assert res["probes_skipped"] > 0, res["probes_skipped"]
    assert any("request cap 160 reached" in n and "not sent" in n for n in res["notes"]), res["notes"]


def test_b_h4_small_endpoint_under_cap_is_ran_ok_with_no_skips():
    fake = RecordFake()
    res = negative_engine.run(fake, _things_spec(1), _qa(SKIP=set(), NEG_ROLE={}))
    assert res["probes_skipped"] == 0, res["probes_skipped"]
    assert not any("cap" in n for n in res["notes"]), res["notes"]


def test_b_h4_raised_cap_sends_the_late_field_mutations():
    fake = RecordFake()
    res = negative_engine.run(fake, _things_spec(12), _qa(SKIP=set(), NEG_ROLE={}, NEG_MAX=5000))
    late = [b for b in fake.bodies if isinstance(b, dict) and "f12" in b and "f11" in b and b["f12"] != b["f11"]]
    assert late, "the last field's mutations were not sent even with a raised cap"
    assert res["probes_skipped"] == 0, res["probes_skipped"]


# ---------------- B-H5 ----------------

class FiveHundredFake:
    def __init__(self, status):
        self.status = status
        self.roles = {"anon": {}, "user_a": {}}

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        return api_mod.Resp(self.status, "boom" if self.status >= 500 else "{}")


BOOM_SPEC = {"paths": {"/boom": {"post": {"requestBody": {"content": {"application/json": {"schema": {
    "type": "object", "properties": {"x": {"type": "integer"}}}}}}}}}}
SMALL = dict(max_examples=10, steps=6, time_budget=60, rounds=2, seed=1, attempts=1)


def test_b_h5_empty_action_set_after_real_5xx_is_not_a_finding():
    res = stateful.run(FiveHundredFake(500), BOOM_SPEC, _qa(), **SMALL)
    kinds = [f["detail"] for f in res["findings"]]
    assert len(res["findings"]) == 1, kinds
    assert "server error 500 on POST /boom" in kinds[0], kinds
    assert not any("InvalidArgument" in d or "length-zero" in d for d in kinds), kinds
    assert res["status"] == trust.ERRORED, res["status"]
    assert any("search ended early" in n for n in res["notes"]), res["notes"]


def test_b_h5_clean_app_has_no_finding_at_all():
    res = stateful.run(FiveHundredFake(201), BOOM_SPEC, _qa(), **SMALL)
    assert res["findings"] == [], res["findings"]


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print("PASS", t.__name__)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print("FAIL", t.__name__, type(exc).__name__, str(exc)[:300])
    print(f"{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
