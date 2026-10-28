"""Statistical gate for accepting a proposed change to specs / seeds (not engine code).

  python -m toolkit.engine.gate --old sweep-old.json --new sweep-new.json
  python toolkit/engine/gate.py --old ... --new ... [--baseline-recall 0.9] [--flake-limit 0.2]

Accept iff ALL of:
  1. Wilson lower bound of new recall >= baseline (default: Wilson lower of old, or --baseline-recall)
  2. clean-control false positives (high/medium unexplained) on new == 0
  3. no regression on paired bugs (a bug hit in old must still hit in new)
  4. flake rate (1 - hit_rate over repeats) <= --flake-limit

Input JSON shape (from mutate.py sweep.json or a hand-built summary):
  {
    "hits": 11, "trials": 12,           # or per_bug: {"1": {"hits": 3, "trials": 3}, ...}
    "clean_fp": 0,
    "per_bug": {"1": {"hit": true}, "2": {"hit": false}, ...}   # optional; used for paired regression
    "flake": 0.0                         # optional; else derived from per_bug hits/trials
  }
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats  # noqa: E402


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _bug(v) -> dict:
    """One per_bug entry -> {hits, trials, hit}; accepts {"hit": bool}, {"hits": n, "trials": m} or both."""
    v = v if isinstance(v, dict) else {"hit": bool(v)}
    if "hits" in v:
        h, t = int(v["hits"]), int(v.get("trials", v["hits"]) or 0)
    else:
        h, t = (1 if v.get("hit") else 0), 1
    return {"hits": h, "trials": t, "hit": h > 0}


def _normalize(raw: dict) -> dict:
    """Accept mutate sweep.json or a compact gate summary."""
    if "bugs" in raw or "passes" in raw:
        # mutate.py sweep shape: aggregate hits across bugs/repeats
        per_bug, hits, trials = {}, 0, 0
        clean_fp = 0
        for key, block in raw.items():
            if key in ("meta", "engines", "examples", "repeat"):
                continue
            if key in ("clean", "control") or (isinstance(block, dict) and block.get("active") == []):
                clean_fp = max(clean_fp, int(block.get("unexplained", block.get("clean_fp", 0)) or 0))
                continue
            if not isinstance(block, dict):
                continue
            # per-bug list of passes
            if "passes" in block:
                h = sum(1 for p in block["passes"] if p.get("hit"))
                t = len(block["passes"])
                per_bug[str(key)] = {"hits": h, "trials": t, "hit": h > 0}
                hits += h
                trials += t
            elif "hit" in block:
                h = 1 if block["hit"] else 0
                per_bug[str(key)] = {"hits": h, "trials": 1, "hit": bool(block["hit"])}
                hits += h
                trials += 1
            elif "hits" in block:
                h, t = int(block["hits"]), int(block.get("trials", block["hits"]))
                per_bug[str(key)] = {"hits": h, "trials": t, "hit": h > 0}
                hits += h
                trials += t
        if "summary" in raw:
            s = raw["summary"]
            hits = int(s.get("hits", hits))
            trials = int(s.get("trials", trials))
            clean_fp = int(s.get("clean_fp", clean_fp))
        return {"hits": hits, "trials": trials or 1, "clean_fp": clean_fp, "per_bug": per_bug,
                "flake": float(raw.get("flake", 0.0))}
    hits = int(raw.get("hits", 0))
    trials = int(raw.get("trials", max(hits, 1)))
    return {
        "hits": hits,
        "trials": trials,
        "clean_fp": int(raw.get("clean_fp", 0)),
        "per_bug": {str(k): _bug(v) for k, v in (raw.get("per_bug") or {}).items()},
        "flake": float(raw.get("flake", 0.0)),
    }


def _flake(norm: dict) -> float:
    """Mean miss rate over bugs that were hit at least once. A bug never hit is a recall problem (already counted by the
    Wilson bound and the regression check), not flakiness, so it is left out; otherwise a deterministic miss reads as flake 1.0."""
    if norm.get("flake"):
        return float(norm["flake"])
    rates = []
    for b in (norm.get("per_bug") or {}).values():
        t, h = int(b.get("trials", 0)), int(b.get("hits", 0))
        if t > 0 and h > 0:
            rates.append(1.0 - h / t)
    return sum(rates) / len(rates) if rates else 0.0


def decide(old: dict, new: dict, *, baseline_recall: float | None = None,
           flake_limit: float = 0.25) -> dict:
    """Return {accepted: bool, reasons: [...], metrics: {...}}."""
    o, n = _normalize(old), _normalize(new)
    reasons = []
    o_lo, _ = stats.wilson(o["hits"], o["trials"])
    n_lo, n_hi = stats.wilson(n["hits"], n["trials"])
    baseline = baseline_recall if baseline_recall is not None else o_lo
    if n_lo < baseline:
        reasons.append(f"recall Wilson lower {n_lo:.3f} < baseline {baseline:.3f} "
                       f"(new {n['hits']}/{n['trials']}, old {o['hits']}/{o['trials']})")
    if n["clean_fp"] > 0:
        reasons.append(f"clean_fp={n['clean_fp']} (must be 0)")
    regressions = []
    for bug, ob in (o.get("per_bug") or {}).items():
        if ob.get("hit") and not (n.get("per_bug") or {}).get(bug, {}).get("hit"):
            regressions.append(bug)
    if regressions:
        reasons.append("regression on bugs previously hit: " + ", ".join(regressions))
    flake = _flake(n)
    if flake > flake_limit:
        reasons.append(f"flake {flake:.2f} > limit {flake_limit:.2f}")
    return {
        "accepted": not reasons,
        "reasons": reasons or ["all gate checks passed"],
        "metrics": {
            "old_recall": o["hits"] / o["trials"] if o["trials"] else 0,
            "new_recall": n["hits"] / n["trials"] if n["trials"] else 0,
            "new_wilson": [n_lo, n_hi],
            "baseline": baseline,
            "clean_fp": n["clean_fp"],
            "flake": flake,
            "regressions": regressions,
        },
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--old", required=True, help="previous sweep/summary JSON")
    p.add_argument("--new", required=True, help="candidate sweep/summary JSON")
    p.add_argument("--baseline-recall", type=float, help="override baseline (default: old Wilson lower)")
    p.add_argument("--flake-limit", type=float, default=0.25)
    p.add_argument("--out", help="write decision JSON here")
    a = p.parse_args(argv)
    decision = decide(_load(a.old), _load(a.new), baseline_recall=a.baseline_recall, flake_limit=a.flake_limit)
    text = json.dumps(decision, indent=2)
    print(text)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
    print("GATE:", "ACCEPT" if decision["accepted"] else "REJECT")
    if not decision["accepted"]:
        for r in decision["reasons"]:
            print(" -", r)
    sys.exit(0 if decision["accepted"] else 1)


if __name__ == "__main__":
    main()
