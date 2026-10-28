"""Tests for shrink.py. Run only this file:

    python toolkit/engine/test_shrink.py        (script mode, prints PASS/FAIL per test)
    python -m pytest toolkit/engine/test_shrink.py

Uses its own in-memory ThreadingHTTPServer on an ephemeral port (127.0.0.1). Touches no other test or port.
"""
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import shrink  # noqa: E402
from shrink import (Replayer, ddmin, five_xx, greedy_steps, make_oracle, norm_path, shrink_fields,  # noqa: E402
                    shrink_finding, steps_from_log, parse_sequence_text, body_marker)
import trust  # noqa: E402


# ---------------------------------------------------------------- planted-bug app

class App:
    """Planted bug: export of an ARCHIVED item returns 500. Needs create -> archive -> export on the same id (3 steps).
    flaky=True: that 500 happens with probability 1/2 (an RNG that a reset does NOT reseed, so re-runs differ).
    boom: POST /boom always 500 (an unrelated bug, used for the signature-slippage test)."""

    def __init__(self, flaky=False, seed=7, bug=True):
        self.flaky, self.bug = flaky, bug
        self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        with self.lock:
            self.items, self.next_id = {}, 1


def make_server(app):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _route(self, method):
            parts = [p for p in self.path.split("?", 1)[0].split("/") if p]
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                body = json.loads(raw) if raw else None
            except ValueError:
                return self._send(400, {"detail": "bad json"})
            with app.lock:
                if method == "GET" and parts == ["health"]:
                    return self._send(200, {"ok": True})
                if method == "POST" and parts == ["notes"]:
                    return self._send(201, {"id": 0, "text": (body or {}).get("text")})
                if method == "POST" and parts == ["boom"]:
                    return self._send(500, {"detail": "boom trace"})
                if method == "POST" and parts == ["items"]:
                    i = app.next_id
                    app.next_id += 1
                    app.items[i] = {"name": (body or {}).get("name", ""), "archived": False}
                    return self._send(201, {"id": i, "name": app.items[i]["name"]})
                if len(parts) >= 2 and parts[0] == "items" and parts[1].isdigit():
                    i = int(parts[1])
                    item = app.items.get(i)
                    if item is None:
                        return self._send(404, {"detail": "no such item"})
                    if method == "POST" and parts[2:] == ["archive"]:
                        item["archived"] = True
                        return self._send(200, {"id": i, "archived": True})
                    if method == "GET" and parts[2:] == ["export"]:
                        if item["archived"] and app.bug and (not app.flaky or app.rng.random() < 0.5):
                            return self._send(500, {"detail": "export crashed"})
                        return self._send(200, {"id": i, "export": item["name"]})
                    if method == "GET" and len(parts) == 2:
                        return self._send(200, {"id": i, **item})
                return self._send(404, {"detail": "not found"})

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def step(idx, method, path, body=None, role="anon"):
    return {"idx": idx, "role": role, "method": method, "path": path, "body": body, "query": None}


def noisy_sequence():
    """18 steps. Planted failure = steps 5 (create), 11 (archive {{step_5}}), 16 (export {{step_5}}). Everything else is noise."""
    raw = [
        ("POST", "/items", {"name": "n0"}),          # 0 noise: creates id 1
        ("GET", "/health", None),                    # 1
        ("POST", "/notes", {"text": "a"}),           # 2
        ("GET", "/items/{{step_0.id}}", None),       # 3
        ("POST", "/items", {"name": "n1"}),          # 4 noise: creates id 2
        ("POST", "/items", {"name": "target"}),      # 5 PLANTED create
        ("GET", "/health", None),                    # 6
        ("POST", "/notes", {"text": "b"}),           # 7
        ("GET", "/items/{{step_4.id}}", None),       # 8
        ("POST", "/items", {"name": "n2"}),          # 9 noise
        ("GET", "/health", None),                    # 10
        ("POST", "/items/{{step_5.id}}/archive", None),   # 11 PLANTED archive
        ("POST", "/notes", {"text": "c"}),           # 12
        ("GET", "/items/{{step_9.id}}", None),       # 13
        ("GET", "/health", None),                    # 14
        ("POST", "/notes", {"text": "d"}),           # 15
        ("GET", "/items/{{step_5.id}}/export", None),     # 16 PLANTED failing export
        ("GET", "/health", None),                    # 17
    ]
    return [step(i, m, p, b) for i, (m, p, b) in enumerate(raw)]


PLANTED = (5, 11, 16)
TARGET = "5xx GET /items/{id}/export"


def _ids(steps):
    return [s["idx"] for s in steps]


# ---------------------------------------------------------------- pure ddmin

def test_ddmin_known_minimal_pairs():
    items = list(range(20))
    r = ddmin(items, lambda s: 3 in s and 11 in s)
    assert r["items"] == [3, 11], r
    assert r["one_minimal"] and not r["exhausted"]
    r = ddmin(items, lambda s: 5 in s)
    assert r["items"] == [5], r


def test_ddmin_empty_failure_and_no_need():
    r = ddmin(list(range(6)), lambda s: True)            # fails with nothing: minimal is empty
    assert r["items"] == [] and r["one_minimal"], r


def test_ddmin_random_monotone_gives_exact_required_set():
    rng = random.Random(1234)
    for _ in range(60):
        n = rng.randint(3, 25)
        need = set(rng.sample(range(n), rng.randint(1, min(4, n))))
        r = ddmin(list(range(n)), lambda s, need=need: need.issubset(s))
        assert r["items"] == sorted(need), (n, need, r)
        assert r["one_minimal"]


def test_ddmin_one_minimality_on_non_unique_minimum():
    """Predicate with several minimal sets: the result must still be 1-minimal (every single removal passes)."""
    rng = random.Random(99)
    pred = lambda s: sum(1 for x in s if x % 3 == 0) >= 2 and any(x % 5 == 1 for x in s)
    for _ in range(40):
        items = rng.sample(range(60), 25)
        if not pred(items):
            continue
        r = ddmin(items, pred)
        assert pred(r["items"]), r
        for j in range(len(r["items"])):
            assert not pred(r["items"][:j] + r["items"][j + 1:]), ("not 1-minimal", r["items"], j)


def test_ddmin_never_repeats_a_subset_and_respects_budget():
    seen = []

    def pred(s):
        seen.append(tuple(s))
        return 3 in s and 11 in s

    r = ddmin(list(range(20)), pred)
    assert len(seen) == len(set(seen)), "a subset was tested twice (cache broken)"
    assert r["trials"] == len(seen)
    capped = ddmin(list(range(20)), pred, max_trials=3)
    assert capped["exhausted"] and not capped["one_minimal"]
    assert pred(capped["items"]), "best-so-far must still fail"


def test_shrink_fields_drops_noise_and_shortens_values():
    steps = [{"idx": 0, "role": "anon", "method": "POST", "path": "/x", "body":
              {"qty": 37, "flag": True, "note": "hello world", "tags": ["a", "b", "c"], "extra": {"deep": 9}}, "query": None}]

    def fails(s):
        b = s[0]["body"]
        return b.get("qty", 0) >= 5 and b.get("flag") is not None

    out = shrink_fields(steps, fails)
    b = out["steps"][0]["body"]
    assert fails(out["steps"]) and out["fixpoint"]
    assert b == {"qty": 5, "flag": b["flag"]} or set(b) == {"qty", "flag"}, b
    assert b["qty"] == 5, b
    assert "note" not in b and "tags" not in b and "extra" not in b, b


def test_shrink_fields_keeps_placeholders_and_budget():
    steps = [step(0, "POST", "/a", {"ref": "{{step_0.id}}", "name": "long string value"})]
    out = shrink_fields(steps, lambda s: s[0]["body"].get("ref") == "{{step_0.id}}")
    assert out["steps"][0]["body"] == {"ref": "{{step_0.id}}"}, out

    def counting(s):
        raise shrink.BudgetExhausted()

    capped = shrink_fields(steps, counting)
    assert capped["exhausted"] and not capped["fixpoint"]


# ---------------------------------------------------------------- replay / oracle / slippage guard

def test_signature_normalisation_and_detectors():
    assert norm_path("/items/12/export?x=1") == "/items/{id}/export"
    assert norm_path("/orders/3f0e1d2c-aaaa-bbbb-cccc-0123456789ab/x") == "/orders/{id}/x"
    log = [{"method": "POST", "path": "/boom", "status": 500, "body": "boom trace"}]
    assert five_xx(log) == "5xx POST /boom"
    assert body_marker("boom")(log) == "body:boom POST /boom"
    assert body_marker("nope")(log) is None
    log[0]["status"] = 599
    assert five_xx(log) == "5xx POST /boom", "no HTTP answer must count as a 5xx failure, like stateful.py"


def test_replayer_substitutes_ids_and_counts_fresh_state():
    app = App()
    srv, base = make_server(app)
    try:
        resets = []
        rep = Replayer(base, reset=lambda: (resets.append(1), app.reset()))
        seq = noisy_sequence()
        out = rep.run(seq, five_xx)
        assert out["outcome"] == "fail" and out["sig"] == TARGET, out
        assert out["steps_run"] == 17, out                  # fails at the export: step index 16 is the 17th
        assert len(resets) == 1
        planted_only = [seq[i] for i in PLANTED]
        assert rep.run(planted_only, five_xx)["outcome"] == "fail"
        assert len(resets) == 2, "every trial must reset first"
    finally:
        srv.shutdown()


def test_oracle_refuses_a_different_failure_first():
    """Slippage guard: a sequence whose FIRST failure is an unrelated 500 must not count as the export bug."""
    app = App()
    srv, base = make_server(app)
    try:
        rep = Replayer(base, reset=app.reset)
        boom_first = [step(0, "POST", "/boom"), step(1, "POST", "/items", {"name": "t"}),
                      step(2, "POST", "/items/{{step_1.id}}/archive"), step(3, "GET", "/items/{{step_1.id}}/export")]
        oracle = make_oracle(rep, five_xx, TARGET)
        assert rep.run(boom_first, five_xx)["sig"] == "5xx POST /boom"
        assert oracle(boom_first) is False, "a different first failure must not satisfy the oracle"
        assert oracle(noisy_sequence()) is True
    finally:
        srv.shutdown()


def test_dangling_reference_is_invalid_not_failing():
    app = App()
    srv, base = make_server(app)
    try:
        rep = Replayer(base, reset=app.reset)
        seq = [noisy_sequence()[i] for i in (11, 16)]        # archive + export, their create was removed
        assert rep.run(seq, five_xx)["outcome"] == "invalid"
        assert make_oracle(rep, five_xx, TARGET)(seq) is False
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- the planted bug end to end

def test_ddmin_finds_exactly_the_three_planted_steps_on_the_real_app():
    app = App()
    srv, base = make_server(app)
    try:
        rep = Replayer(base, reset=app.reset)
        seq = noisy_sequence()
        calls_dd, calls_greedy = [], []
        oracle = make_oracle(rep, five_xx, TARGET)

        def counted_dd(s):
            calls_dd.append(1)
            return oracle(s)

        def counted_greedy(s):
            calls_greedy.append(1)
            return oracle(s)

        r = ddmin(seq, counted_dd)
        assert _ids(r["items"]) == list(PLANTED), _ids(r["items"])
        assert r["one_minimal"] and not r["exhausted"]
        g = greedy_steps(seq, counted_greedy)
        assert _ids(g["items"]) == list(PLANTED)
        # naive baseline = exhaustive search over every subset of at most 3 steps (what a brute force would try first)
        from math import comb
        exhaustive = sum(comb(len(seq), k) for k in range(1, 4))
        print(f"    trials: ddmin={len(calls_dd)}  linear-greedy={len(calls_greedy)}  exhaustive(<=3 steps)={exhaustive}"
              f"  (18 steps, planted {PLANTED})")
        assert len(calls_dd) < exhaustive, (len(calls_dd), exhaustive)
        # honest note: linear greedy was cheaper on this shape; the test does not claim ddmin beats it
        assert len(calls_greedy) < exhaustive
    finally:
        srv.shutdown()


def test_shrink_finding_confirmed_then_poc_reproduces_in_subprocess():
    app = App()
    srv, base = make_server(app)
    out_dir = tempfile.mkdtemp(prefix="shrink-test-")
    try:
        res = shrink_finding(noisy_sequence(), base, five_xx, reset=app.reset, runs=5, max_trials=400, out_dir=out_dir)
        assert res["status"] == trust.RAN_OK, (res["status"], res["status_reason"])
        assert res["steps_before"] == 18 and res["steps_after"] == 3, res
        assert res["repro"]["k"] == 5 and res["repro"]["n"] == 5 and res["repro"]["wilson_low"] > 0.5
        assert res["trials"] <= 400 and not res["budget_exhausted"] and res["fixpoint"]
        assert _ids(res["minimal_steps"]) == list(PLANTED)
        poc = res["poc_path"]
        assert poc and os.path.isfile(poc), res
        assert Path(poc).name.startswith("poc_5xx_") and Path(poc).name.endswith(".py")
        assert os.path.isfile(res["poc_md_path"])
    finally:
        srv.shutdown()

    # the PoC, run in a subprocess against a FRESH server (fresh app state), must reproduce
    fresh_app = App()
    srv2, base2 = make_server(fresh_app)
    try:
        p = subprocess.run([sys.executable, poc, base2], capture_output=True, text=True, timeout=60)
        assert p.returncode == 1, (p.returncode, p.stdout, p.stderr)
        assert "bug reproduced" in p.stdout, p.stdout
    finally:
        srv2.shutdown()
    # and it must PASS on a bug-free app
    clean_app = App(bug=False)
    srv3, base3 = make_server(clean_app)
    try:
        p = subprocess.run([sys.executable, poc, base3], capture_output=True, text=True, timeout=60)
        assert p.returncode == 0 and "PASS" in p.stdout, (p.returncode, p.stdout)
    finally:
        srv3.shutdown()


def test_poc_refuses_non_local_host_without_network():
    poc = _write_any_poc()
    p = subprocess.run([sys.executable, poc, "http://example.com"], capture_output=True, text=True, timeout=30)
    assert p.returncode == 2 and "REFUSED" in p.stderr, (p.returncode, p.stderr)


def _write_any_poc():
    app = App()
    srv, base = make_server(app)
    d = tempfile.mkdtemp(prefix="shrink-poc-")
    try:
        res = shrink_finding(noisy_sequence(), base, five_xx, reset=app.reset, runs=2, out_dir=d)
        return res["poc_path"]
    finally:
        srv.shutdown()


def test_non_reproducing_original_is_setup_failed_and_writes_no_poc():
    # 1) the bug needs the create step; the tail without it is a dangling reference
    app = App()
    srv, base = make_server(app)
    d = tempfile.mkdtemp(prefix="shrink-setup-")
    try:
        seq = [noisy_sequence()[i] for i in (11, 16)]
        res = shrink_finding(seq, base, five_xx, reset=app.reset, out_dir=d)
        assert res["status"] == trust.SETUP_FAILED, res["status"]
        assert res["poc_path"] is None and not list(Path(d).glob("poc_*")), "no PoC for a non-reproducing sequence"
    finally:
        srv.shutdown()
    # 2) bug-free app: the full sequence never fails
    clean = App(bug=False)
    srv2, base2 = make_server(clean)
    d2 = tempfile.mkdtemp(prefix="shrink-setup2-")
    try:
        res = shrink_finding(noisy_sequence(), base2, five_xx, reset=clean.reset, out_dir=d2)
        assert res["status"] == trust.SETUP_FAILED and res["poc_path"] is None, res
    finally:
        srv2.shutdown()


def test_flaky_bug_is_reported_flaky_not_confirmed():
    app = App(flaky=True, seed=7)
    srv, base = make_server(app)
    d = tempfile.mkdtemp(prefix="shrink-flaky-")
    try:
        res = shrink_finding(noisy_sequence(), base, five_xx, reset=app.reset, runs=5, max_trials=400, out_dir=d)
        k, n = res["repro"]["k"], res["repro"]["n"]
        assert 0 < k < n, f"seed chosen so the flake shows: got k={k} n={n}"
        assert res["flaky"] is True
        assert res["status"] == trust.DEGRADED and "FLAKY" in res["status_reason"], (res["status"], res["status_reason"])
        assert res["status"] != trust.RAN_OK
    finally:
        srv.shutdown()


def test_budget_exhausted_is_degraded_not_confirmed():
    app = App()
    srv, base = make_server(app)
    d = tempfile.mkdtemp(prefix="shrink-budget-")
    try:
        res = shrink_finding(noisy_sequence(), base, five_xx, reset=app.reset, runs=3, max_trials=4, out_dir=d)
        assert res["budget_exhausted"] and not res["fixpoint"], res
        assert res["status"] == trust.DEGRADED and "budget" in res["status_reason"], res["status_reason"]
        assert res["trials"] <= 4
        assert res["steps_after"] <= 18
    finally:
        srv.shutdown()


def test_steps_from_log_and_text_parser_agree():
    app = App()
    srv, base = make_server(app)
    try:
        seq = noisy_sequence()
        rep = Replayer(base, reset=app.reset)
        out = rep.run(seq, five_xx)
        steps = steps_from_log(out["log"])
        assert len(steps) == 17
        assert rep.run(steps, five_xx)["sig"] == TARGET, "log-derived steps must reproduce with exact id substitution"
        # the stateful text format: 'role METHOD path -> status request'
        text = ("Falsifying example: junk\nlast steps before failure:\n"
                "anon POST /items -> 201 {'name': 'target'}\n"
                "anon POST /items/1/archive -> 200 None\n"
                "anon GET /items/1/export -> 500 None\n"
                "traceback: ignored line\n")
        tsteps, statuses = parse_sequence_text(text)
        assert [s["method"] for s in tsteps] == ["POST", "POST", "GET"]
        assert tsteps[0]["body"] == {"name": "target"} and statuses == [201, 200, 500]
        assert tsteps[1]["path"] == "/items/{{step_0.id}}/archive", "text input guesses the id from the create"
    finally:
        srv.shutdown()


def test_cli_from_log_runs_end_to_end():
    app = App()
    srv, base = make_server(app)
    d = tempfile.mkdtemp(prefix="shrink-cli-")
    try:
        rep = Replayer(base, reset=app.reset)
        out = rep.run(noisy_sequence(), five_xx)
        logfile = os.path.join(d, "api.log.json")
        Path(logfile).write_text(json.dumps(out["log"]), encoding="utf-8")
        rc = shrink.main(["--log", logfile, "--base-url", base, "--runs", "2", "--out", os.path.join(d, "out")])
        # no --reset-cmd given: the repro is real but not on fresh state, so it is degraded (exit 1), and the PoC exists
        assert rc == 1, rc
        pocs = list(Path(d, "out").glob("poc_5xx_*.py"))
        assert pocs, "a reproduced sequence still gets its PoC"
        assert list(Path(d, "out").glob("*.md"))
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- script / pytest entry

def _all_tests():
    return [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]


def main() -> int:
    failed = 0
    for name, fn in _all_tests():
        try:
            fn()
            print(f"PASS {name}")
        except Exception:
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    total = len(_all_tests())
    print(f"\n{total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
