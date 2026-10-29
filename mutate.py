"""Mutation sweep on the demo shop: ground-truth recall, one planted bug at a time.

  python mutate.py                        # every bug alone + the clean control, all engines, ~4 min per pass
  python mutate.py --bugs 3,5,12 --repeat 2 --examples 25

For each planted bug the demo app is started with ONLY that bug active (DEMO_BUGS=n, see examples/demo-flask-shop/app.py), the
engines run, and the sweep records
  hit         the finding that bug is supposed to produce (kind + endpoint fragment) is present
  unexplained high/medium findings that none of the ACTIVE bugs can explain: crosstalk or false positives (the clean control,
              DEMO_FIXED=1, is the same measurement with no bug active)
  errored     engines whose trust status was `errored` (a pass with an errored engine is not evidence either way)
Output: runs/mutation-<time>/sweep.json and sweep.md (gitignored). Recall is printed as k/n with a Wilson interval (stats.py).

Honest limits: the 12 bugs are the same author's as the engines (selftest classes), so this measures isolation, repeatability and
crosstalk, not generalisation to bugs nobody thought of. A hit rate of 1/1 per bug is one sample: use --repeat. Bug 8 (traceback in
an error body) needs an error to exist, so it is run together with bug 6 (its trigger).
"""
import argparse
import datetime
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "toolkit" / "engine"))
import selftest  # noqa: E402
import stats  # noqa: E402
import trust  # noqa: E402

# bug id -> (name, [(finding kind, endpoint/detail fragment)] of which at least ONE must be present, extra kinds it may also cause)
BUGS = {
    1: ("IDOR on GET /orders/<id>", [("BOLA/IDOR", "GET /orders/")], set()),
    2: ("PATCH status without auth", [("MISSING-AUTH", "PATCH /orders/"), ("AUTHZ-REACHED-LOGIC", "PATCH /orders/")], {"BOLA/IDOR"}),
    3: ("/admin/reset-prices open to any user", [("PRIV-ESC", "/admin/reset-prices")], set()),
    4: ("no state-machine / double-cancel guard", [("SCENARIO", "order status machine")], {"STATEFUL-INVARIANT"}),
    5: ("check-then-act stock race", [("RACE-INVARIANT", "")], {"STATEFUL-INVARIANT"}),
    6: ("non-integer quantity -> 500", [("NEG-5XX", "POST /orders")], {"NEG-5XX", "NEG-ACCEPTED"}),
    7: ("mass assignment of role on register", [("MASS-ASSIGN", "/auth/register")], set()),
    8: ("traceback in error body", [("NEG-LEAK", "")], {"NEG-5XX", "NEG-ACCEPTED"}),
    9: ("review of someone else's order", [("XREF-IDOR", "/reviews")], set()),
    10: ("unescaped note in HTML mail", [("CANARY-IN-EMAIL", "")], set()),
    11: ("password sent to analytics", [("OUTBOUND-LEAK", "")], set()),
    12: ("SQL injection in login", [("NEG-INJECTION", "/auth/login")], {"NEG-5XX"}),      # string-built SQL also breaks on NUL bytes (measured, absent on the clean control)
}
NEEDS = {8: {6}}                                    # bug -> bugs that must also be active for it to be observable
ALWAYS_OK = {"OUTBOUND-ATTEMPT", "OUTBOUND-EMAIL", "INFERRED-INVARIANT"}


def active_set(bug: int) -> set:
    return {bug} | NEEDS.get(bug, set())


def evaluate(results: list, active: set) -> dict:
    """Judge one engine pass against the bugs that were active in it."""
    findings = [(r["engine"], f) for r in results for f in r.get("findings", [])]
    errored = [r["engine"] for r in results if trust.resolve(r)[0] == trust.ERRORED]
    explained_kinds = set(ALWAYS_OK)
    for b in active:
        explained_kinds |= {k for k, _ in BUGS[b][1]} | BUGS[b][2]
    unexplained = [f"{eng} {f['kind']} {f['endpoint']}: {str(f['detail'])[:110]}" for eng, f in findings
                   if f.get("severity") in ("high", "medium") and f["kind"] not in explained_kinds]
    hit = {}
    for b in active:
        hit[b] = any(f["kind"] == kind and frag in (f"{f['endpoint']} {f['detail']}") for _, f in findings for kind, frag in BUGS[b][1])
    return {"hit": hit, "unexplained": unexplained, "errored": errored, "n_findings": len(findings)}


def run_pass(bugs: set | None, args, label: str) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="qa-mutate-"))
    try:
        if bugs is None:                                                  # clean control
            results, proc = selftest.run_engines(tmp, fixed=True, engines=args.engines, examples=args.examples)
        else:
            results, proc = selftest.run_engines(tmp, bugs=",".join(map(str, sorted(bugs))), engines=args.engines, examples=args.examples)
        if results is None:
            return {"label": label, "harness_failure": (proc.stdout + proc.stderr)[-600:]}
        return {"label": label, **evaluate(results, bugs or set())}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bugs", default=",".join(map(str, BUGS)), help="comma list, default all")
    ap.add_argument("--repeat", type=int, default=1, help="independent passes per bug (fresh app DB each)")
    ap.add_argument("--engines", default=None, help="run.py --engines value (default: all default engines)")
    ap.add_argument("--examples", type=int, default=25)
    ap.add_argument("--no-clean", action="store_true", help="skip the clean control pass")
    a = ap.parse_args(argv)
    wanted = [int(x) for x in a.bugs.split(",") if x.strip()]
    out = ROOT / "runs" / f"mutation-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    out.mkdir(parents=True)
    rows, hits, trials = [], 0, 0
    plan = [(b, active_set(b)) for b in wanted for _ in range(a.repeat)] + ([] if a.no_clean else [(None, None)])
    for i, (b, active) in enumerate(plan, 1):
        label = "clean control" if b is None else f"bug {b}: {BUGS[b][0]}"
        print(f"[mutate] {i}/{len(plan)} {label} ...", flush=True)
        row = run_pass(active, a, label)
        row["bug"] = b
        rows.append(row)
        if "harness_failure" in row:
            print(f"[mutate]   HARNESS FAILURE: {row['harness_failure'][-200:]}", flush=True)
        elif b is not None:
            trials += 1
            hits += bool(row["hit"].get(b))
            print(f"[mutate]   {'HIT' if row['hit'].get(b) else 'MISS'}; unexplained high/medium: {len(row['unexplained'])}; errored engines: {row['errored'] or 'none'}", flush=True)
        else:
            print(f"[mutate]   clean control: {len(row['unexplained'])} unexplained high/medium finding(s); errored: {row['errored'] or 'none'}", flush=True)
        (out / "sweep.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")     # written after every pass: a stop loses at most one
    lines = ["# Mutation sweep (demo shop)", "", f"engines: {a.engines or 'default'}, examples {a.examples}, repeat {a.repeat}", "",
             "| bug | hit | unexplained high/medium | errored engines |", "|---|---|---|---|"]
    for r in rows:
        if "harness_failure" in r:
            lines.append(f"| {r['label']} | HARNESS FAILURE | | |")
        else:
            h = "-" if r["bug"] is None else ("HIT" if r["hit"].get(r["bug"]) else "MISS")
            lines.append(f"| {r['label']} | {h} | {len(r['unexplained'])} | {', '.join(r['errored']) or 'none'} |")
    lines += ["", f"**recall: {stats.describe(hits, trials)}**" if trials else "no bug passes ran"]
    for r in rows:
        for u in r.get("unexplained", []):
            lines.append(f"- unexplained in `{r['label']}`: {u}")
    (out / "sweep.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[-(2 + sum(len(r.get('unexplained', [])) for r in rows)):]))
    print(f"[mutate] written to {out}")
    return 0 if trials and hits == trials and not any(r.get("unexplained") or r.get("errored") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
