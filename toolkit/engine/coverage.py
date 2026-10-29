"""API coverage: which (endpoint x role x status class) did the engines actually exercise?

A zero in this table is a blind spot, not a clean bill of health: the engines cannot find bugs behind a request they never
managed to make succeed (wrong baseline body, missing state, role without access). Written to <out>/coverage.json and
summarised as notes: endpoints never answered 2xx, endpoints never called as their owner role, endpoints with 5xx.
"""
import re
from collections import defaultdict

from api import TRANSPORT_ERROR, endpoints, key
import trust


def _rx(path: str):
    return re.compile("^" + re.sub(r"\\{[^/]+\\}", "[^/]+", re.escape(path)).rstrip("/") + "/?$")


def run(api, spec_doc) -> dict:
    eps = endpoints(spec_doc)
    table = {key(e): defaultdict(lambda: defaultdict(int)) for e in eps}
    # first match wins, so the most literal path must come first: "/orders/export" is not "/orders/{id}"
    matchers = [(e["method"], _rx(e["path"]), key(e)) for e in sorted(eps, key=lambda e: (e["path"].count("{"), -len(e["path"])))]
    for entry in api.log:
        path = entry["path"].split("?")[0]
        for method, rx, k in matchers:
            if entry["method"] == method and rx.match(path):
                table[k][entry["role"]]["conn" if entry["status"] == TRANSPORT_ERROR else f"{entry['status'] // 100}xx"] += 1
                break
    notes, findings = [], []
    never_ok, five = [], []
    for k, roles in table.items():
        total = defaultdict(int)
        for classes in roles.values():
            for c, n in classes.items():
                total[c] += n
        if not sum(total.values()):
            never_ok.append(f"{k} (never called)")
        elif not total.get("2xx"):
            never_ok.append(f"{k} (only {dict(total)})")
        if total.get("5xx"):
            five.append(f"{k} ({total['5xx']}x)")
    if never_ok:
        notes.append("BLIND SPOT - never answered 2xx, so nothing behind them was tested: " + "; ".join(never_ok))
    if five:
        notes.append("endpoints that returned 5xx during the run: " + "; ".join(five))
    exercised = sum(1 for k in table if any(c.get("2xx") for c in table[k].values()))
    status, reason = trust.RAN_OK, ""
    if never_ok:                       # a blind spot is not "absence of findings is real evidence"
        status = trust.DEGRADED
        reason = f"{len(never_ok)} endpoint(s) never answered 2xx: nothing behind them was tested"
    return {"engine": "coverage", "findings": findings, "notes": notes, "status": status, "status_reason": reason,
            "summary": {"endpoints": len(eps), "answered_2xx": exercised, "requests": len(api.log)},
            "table": {k: {r: dict(c) for r, c in roles.items()} for k, roles in table.items()}}
