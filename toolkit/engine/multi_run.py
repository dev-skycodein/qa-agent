"""Run the engines several times with different seeds on a RESET app and report how reliably each finding shows up.

  python multi_run.py --profile qa-report/profile.json --spec qa-report/qa-spec.py --out qa-report/multi \
        --seeds 1,2,3 [--engines authz,negative,stateful,race,scenario] [--examples 30 --steps 12] [--with hypothesis --with pymongo]

Each seed = fresh DB (profile.reset_cmd) + safe_run + run.py --seed N. Output: <out>/seed-N/engines.{json,md} and <out>/multi.md with
`found in k/N seeds` per finding. Deterministic engines (authz, negative, race) should hit N/N; a stateful finding at 1/N means
the random search is the limiting factor (raise --examples/--steps or add a targeted scenario).
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import trust

HERE = Path(__file__).resolve().parent
NUMBER_OR_OID = re.compile(r"[0-9a-f]{24}|\d+")              # kept out of the f-string below: a backslash there is a SyntaxError on py3.11


def signature(f):
    detail = f["detail"].split(" e.g. ")[0]
    return f"{f['kind']} | {f['endpoint']} | " + NUMBER_OR_OID.sub("#", detail)[:90]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", default="1,2,3")
    ap.add_argument("--engines", default="authz,negative,stateful,race,scenario,static")
    ap.add_argument("--examples", default="30")
    ap.add_argument("--steps", default="12")
    ap.add_argument("--with", dest="withs", action="append", default=["hypothesis"])
    ap.add_argument("--wait", default="180")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    seeds = [int(x) for x in a.seeds.split(",")]
    seen: dict[str, dict] = {}
    not_clean = []                                          # (seed, engine, status, reason) for every seed/engine that did not run_ok
    for seed in seeds:
        d = out / f"seed-{seed}"
        cmd = [sys.executable, str(HERE / "safe_run.py"), "--profile", a.profile, "--wait", a.wait, "--",
               sys.executable, "-m", "uv", "run", "--no-project", "--python", "3.12"]
        for w in dict.fromkeys(a.withs):
            cmd += ["--with", w]
        cmd += ["python", str(HERE / "run.py"), "--spec", a.spec, "--out", str(d), "--seed", str(seed), "--engines", a.engines,
                "--examples", a.examples, "--steps", a.steps]
        print(f"[multi_run] seed {seed} ...", flush=True)
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (d.parent / f"seed-{seed}.log").write_text(p.stdout + p.stderr, encoding="utf-8")
        try:
            results = json.loads((d / "engines.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"[multi_run] seed {seed}: no engines.json (see seed-{seed}.log)")
            not_clean.append((seed, "(whole run)", trust.ERRORED, f"no engines.json (exit {p.returncode}); see seed-{seed}.log"))
            continue
        for r in results:
            status, reason = trust.resolve(r)
            if status != trust.RAN_OK:
                not_clean.append((seed, r.get("engine", "?"), status, reason))
            for f in r.get("findings", []):
                if f["severity"] == "info":
                    continue
                e = seen.setdefault(signature(f), {"finding": f, "seeds": set(), "engine": r["engine"]})
                e["seeds"].add(seed)
    lines = [f"# Multi-seed run ({len(seeds)} seeds: {seeds})", "", "| found in | engine | severity | kind | endpoint | detail |", "|---|---|---|---|---|---|"]
    for sig, e in sorted(seen.items(), key=lambda kv: (-len(kv[1]["seeds"]), kv[0])):
        f = e["finding"]
        lines.append(f"| {len(e['seeds'])}/{len(seeds)} | {e['engine']} | {f['severity']} | {f['kind']} | `{f['endpoint']}` | {f['detail'][:110]} |")
    if not_clean:
        lines += ["", "## Seeds and engines that did not run clean", "", "| seed | engine | status | reason |", "|---|---|---|---|"]
        for seed, eng, status, reason in not_clean:
            lines.append(f"| {seed} | {eng} | {status.upper()} | {str(reason).replace('|', '/')[:160]} |")
        lines += ["", "A seed or engine listed here did not check what the spec asks: a finding-free result from it is weak evidence."]
    else:
        lines += ["", "All seeds: every engine ran_ok."]
    (out / "multi.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
