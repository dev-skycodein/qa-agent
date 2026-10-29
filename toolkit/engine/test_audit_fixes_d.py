"""Regression tests for audit defects C-H1/A-M1 (py3.11 f-string SyntaxError), A-H1 (selftest return code and stale
engines.json), C-H5 (metamorphic delete check read with the wrong role) and C-H6 (volatile fields learned from one re-read).

  python -m uv run --no-project --python 3.12 --with hypothesis --with pytest python -m pytest toolkit/engine/test_audit_fixes_d.py -q

Nothing here starts a server, a selftest, or an engine run: subprocess calls are stubbed, and the metamorphic checks use an
in-memory fake API. The 3.11 parse check is run as a separate command (see the audit notes), not from here.
"""
import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import exposure  # noqa: E402
import metamorphic  # noqa: E402
import multi_run  # noqa: E402
import selftest  # noqa: E402

ENGINE_DIR = Path(__file__).resolve().parent


# ---------- C-H1 / A-M1: no backslash inside an f-string expression (a SyntaxError before Python 3.12) ----------

def _fstring_expressions_with_backslash(src: str):
    tree = ast.parse(src)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FormattedValue):
            seg = ast.get_source_segment(src, node.value) or ""
            if "\\" in seg:
                bad.append((node.lineno, seg))
    return bad


def test_checker_flags_a_backslash_inside_an_fstring_expression():
    bad_src = 'x = f"{re.sub(r\'\\d+\', \'#\', s)}"\n'
    assert _fstring_expressions_with_backslash(bad_src)


def test_exposure_and_multi_run_have_no_backslash_inside_fstring_expressions():
    for name in ("exposure.py", "multi_run.py"):
        src = (ENGINE_DIR / name).read_text(encoding="utf-8")
        assert _fstring_expressions_with_backslash(src) == [], name


def test_id_segment_normalisation_is_unchanged():
    assert exposure.ID_SEGMENT.sub("/{id}", "/items/12/orders/0a1b2c3d4e/x") == "/items/{id}/orders/{id}/x"
    assert exposure.ID_SEGMENT.sub("/{id}", "/items/names") == "/items/names"


def test_multi_run_signature_is_unchanged():
    f = {"kind": "BOLA/IDOR", "endpoint": "GET /items/{id}", "detail": "row 12 of 40, oid 0123456789abcdef01234567 e.g. x"}
    import re
    original = f"{f['kind']} | {f['endpoint']} | " + re.sub(r"[0-9a-f]{24}|\d+", "#", f["detail"].split(" e.g. ")[0])[:90]
    assert multi_run.signature(f) == original == "BOLA/IDOR | GET /items/{id} | row # of #, oid #"


# ---------- A-H1: selftest must not pass on a stale engines.json or on a non-zero engine exit ----------

def _stub_subprocess(monkeypatch, tmp_path, safe_rc, write_engines):
    """detect.py and safe_run.py are stubbed. `--out` is read from the command, so run_engines' directory is the one written to.
    write_engines(out_dir) decides what the engine run leaves behind."""
    real_run = selftest.subprocess.run

    def fake_run(cmd, *a, **kw):
        cmd = [str(p) for p in cmd]
        out = Path(cmd[cmd.index("--out") + 1]) if "--out" in cmd else None
        if any(p.endswith("detect.py") for p in cmd):
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps({"env_overrides": {}}), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if any(p.endswith("safe_run.py") for p in cmd):
            write_engines(Path(cmd[cmd.index("--out") + 1]))
            return SimpleNamespace(returncode=safe_rc, stdout="engine run output", stderr="")
        return real_run(cmd, *a, **kw)

    monkeypatch.setattr(selftest.subprocess, "run", fake_run)
    monkeypatch.setattr(selftest, "OUT", tmp_path)
    monkeypatch.setattr(selftest, "DEMO", tmp_path / "no-demo-here")       # never touch the demo app directory


def _full_engine_output(out_dir: Path):
    findings = [{"kind": k, "severity": "high", "endpoint": "GET /x", "detail": "d"} for k in sorted(selftest.WANT)]
    findings.append({"kind": "NEG-INJECTION", "severity": "high", "endpoint": "POST /auth/login", "detail": "d"})
    results = [{"engine": "all", "status": "ran_ok", "findings": findings}]
    (out_dir / "engines.json").write_text(json.dumps(results), encoding="utf-8")


def test_stale_engines_json_cannot_pass_when_the_run_fails(monkeypatch, tmp_path, capsys):
    tmp_path.mkdir(exist_ok=True)
    _full_engine_output(tmp_path)                                  # an earlier good run left this behind
    assert (tmp_path / "engines.json").exists()
    _stub_subprocess(monkeypatch, tmp_path, safe_rc=3, write_engines=lambda out: None)
    code = selftest.check_planted()
    printed = capsys.readouterr().out
    assert code == 1
    assert "SELFTEST OK" not in printed
    assert "SELFTEST FAILED: engine run exited with code 3" in printed
    assert not (tmp_path / "engines.json").exists()               # the stale file was removed before the run


def test_clean_exit_with_a_full_result_passes(monkeypatch, tmp_path, capsys):
    tmp_path.mkdir(exist_ok=True)
    _stub_subprocess(monkeypatch, tmp_path, safe_rc=0, write_engines=_full_engine_output)
    code = selftest.check_planted()
    printed = capsys.readouterr().out
    assert code == 0
    assert "SELFTEST OK" in printed


def test_clean_exit_without_engines_json_fails(monkeypatch, tmp_path, capsys):
    tmp_path.mkdir(exist_ok=True)
    _full_engine_output(tmp_path)                                 # stale
    _stub_subprocess(monkeypatch, tmp_path, safe_rc=0, write_engines=lambda out: None)
    code = selftest.check_planted()
    assert code == 1
    assert "SELFTEST OK" not in capsys.readouterr().out


def test_missing_bug_class_still_fails(monkeypatch, tmp_path, capsys):
    tmp_path.mkdir(exist_ok=True)

    def partial(out):
        (out / "engines.json").write_text(json.dumps([{"engine": "one", "status": "ran_ok", "findings": [
            {"kind": "BOLA/IDOR", "severity": "high", "endpoint": "GET /x", "detail": "d"}]}]), encoding="utf-8")
    _stub_subprocess(monkeypatch, tmp_path, safe_rc=0, write_engines=partial)
    assert selftest.check_planted() == 1
    assert "SELFTEST FAILED: missing" in capsys.readouterr().out


def test_clean_control_fails_on_non_zero_exit(monkeypatch, tmp_path, capsys):
    tmp_path.mkdir(exist_ok=True)
    _full_engine_output(tmp_path)
    _stub_subprocess(monkeypatch, tmp_path, safe_rc=3, write_engines=lambda out: None)
    assert selftest.check_clean() == 1
    assert "CLEAN CONTROL FAILED: engine run exited with code 3" in capsys.readouterr().out


# ---------- fake API for the metamorphic checks (no sockets) ----------

class FakeAPI:
    """Roles: user_a (default) and user_b (owner). Item and child collection are only creatable/deletable by user_b."""

    def __init__(self, mode="authz_first", child=False):
        self.roles = {"anon": {}, "user_a": {}, "user_b": {}}
        self.mode = mode
        self.child = child
        self.items = {}
        self.parts = {}
        self.n = 0
        self.log = []

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        self.log.append((role, method, path))
        parts = path.strip("/").split("/")
        if method == "POST" and parts == ["items"]:
            if role != "user_b":
                return api_mod.Resp(403, "{}")
            self.n += 1
            self.items[self.n] = {"id": self.n, "name": "x"}
            return api_mod.Resp(201, json.dumps(self.items[self.n]))
        if method == "POST" and len(parts) == 3 and parts[0] == "items" and parts[2] == "parts":
            if role != "user_b":
                return api_mod.Resp(403, "{}")
            pid = len(self.parts) + 1
            self.parts[pid] = {"id": pid, "item": int(parts[1])}
            return api_mod.Resp(201, json.dumps(self.parts[pid]))
        if method == "DELETE" and len(parts) == 2 and parts[0] == "items":
            if role != "user_b":
                return api_mod.Resp(403, "{}")
            if self.mode != "noop_delete":
                self.items.pop(int(parts[1]), None)
            return api_mod.Resp(200, "{}")
        if method == "GET" and len(parts) == 2 and parts[0] == "items":
            iid = int(parts[1])
            if role != "user_b":
                return api_mod.Resp(403, "{}")                     # authz first: the non-owner always gets 403
            if iid in self.items:
                return api_mod.Resp(200, json.dumps(self.items[iid]))
            return api_mod.Resp(404, "{}")
        if method == "GET" and len(parts) == 3 and parts[2] == "parts" and self.child:
            if role != "user_b":
                return api_mod.Resp(403, "{}")
            listed = [p for p in self.parts.values() if p["item"] == int(parts[1])]
            return api_mod.Resp(200, json.dumps(listed))
        return api_mod.Resp(404, "{}")


DELETE_SPEC = {"paths": {}}


def _delete_case(mode, child=False):
    fake = FakeAPI(mode=mode, child=child)
    ctx = metamorphic.Ctx(fake, DELETE_SPEC, SimpleNamespace())
    children = [("/items/{item_id}/parts", {"name": "p"})] if child else []
    fn = metamorphic.delete_fn(ctx, "/items", {"name": "x"}, "/items/{item_id}", "item_id", children)
    return fn(), fake


def test_delete_403_for_a_non_owner_after_a_real_delete_is_not_a_finding():
    result, fake = _delete_case("authz_first")
    assert result is None
    assert fake.items == {}


def test_delete_check_reads_back_as_the_owner_role():
    _, fake = _delete_case("authz_first")
    first_delete = next(i for i, c in enumerate(fake.log) if c[1] == "DELETE")
    gets_after_delete = [c for c in fake.log[first_delete:] if c[1] == "GET"]
    assert gets_after_delete, "the delete check must read the resource back"
    assert all(role == "user_b" for role, _, _ in gets_after_delete)


def test_delete_that_leaves_the_item_readable_is_still_a_high_finding():
    result, fake = _delete_case("noop_delete")
    assert result is not None and result[0] == "high"
    assert "still answers 200" in result[1]


def test_child_collection_still_listing_items_as_owner_is_a_medium_finding():
    # the item itself is really deleted (403/404 for the owner = gone), but its child collection still lists its parts
    fake = FakeAPI(mode="authz_first", child=True)
    ctx = metamorphic.Ctx(fake, DELETE_SPEC, SimpleNamespace())
    fn = metamorphic.delete_fn(ctx, "/items", {"name": "x"}, "/items/{item_id}", "item_id", [("/items/{item_id}/parts", {"name": "p"})])
    result = fn()
    assert result is not None
    assert result[0] == "medium"
    assert "still lists" in result[1]


def test_gone_statuses_are_defined_and_include_403_404_410():
    assert set(metamorphic.GONE_STATUS) == {403, 404, 410}


# ---------- C-H6: volatile fields are found with a bounded number of re-reads, spaced in time ----------

class TickAPI:
    """A GET whose 'ts' changes only when time has passed (the sleep counter stands in for the clock tick). 'name' is stable."""

    def __init__(self, ticks):
        self.roles = {"user_a": {}}
        self.log = []
        self.ticks = ticks

    def call(self, role, method, path, body=None, query=None, raw=None, headers=None):
        self.log.append((role, method, path))
        return api_mod.Resp(200, json.dumps({"id": 1, "name": "x", "ts": self.ticks[0]}))


def test_volatile_field_is_learned_when_it_changes_between_spaced_reads(monkeypatch):
    ticks = [0]
    fake = TickAPI(ticks)
    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        ticks[0] += 1                                            # a clock tick passes during each gap
    monkeypatch.setattr(metamorphic.time, "sleep", fake_sleep)
    ctx = metamorphic.Ctx(fake, {"paths": {}}, SimpleNamespace())
    metamorphic.learn_volatile(ctx, ["/items/1"])
    assert "ts" in ctx.learned
    assert "name" not in ctx.learned
    assert "ts" in ctx.volatile
    assert len([c for c in fake.log if c[1] == "GET"]) == metamorphic.VOLATILE_READS
    assert sleeps == [metamorphic.VOLATILE_GAP_S] * (metamorphic.VOLATILE_READS - 1)


def test_volatile_detection_is_bounded_and_spaced_by_the_documented_constants():
    assert metamorphic.VOLATILE_READS == 3
    assert metamorphic.VOLATILE_GAP_S == 0.05
    assert metamorphic.VOLATILE_GAP_S > 0.0156                    # longer than one Windows clock tick


def test_stable_fields_are_not_learned_as_volatile(monkeypatch):
    fake = TickAPI([7])                                             # ts is 7 on every read: nothing changes
    monkeypatch.setattr(metamorphic.time, "sleep", lambda s: None)
    ctx = metamorphic.Ctx(fake, {"paths": {}}, SimpleNamespace())
    metamorphic.learn_volatile(ctx, ["/items/1"])
    assert "ts" not in ctx.learned
    assert "name" not in ctx.learned
