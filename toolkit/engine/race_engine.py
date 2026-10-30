"""Race engine: fire N identical requests at once, then check an invariant.

qa-spec.py:
  RACES = [{
      "name": "oversell last unit",
      "setup": fn(api, ctx) -> {"method","path","body","role","per_request_headers": fn(i)->dict (optional)},
      "n": 15,
      "check": fn(api, results, ctx) -> None | str,               # return a message when the invariant broke
  }]
Built-in: any 5xx among the responses is reported. `ctx = fresh_state(api)` per race.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from race import race  # noqa: E402
from api import TRANSPORT_ERROR, default_owner  # noqa: E402
import trust  # noqa: E402


ATTEMPTS = 3                       # bursts per race (each on fresh state) before reporting "no violation"


def run(api, spec_doc, qa) -> dict:
    fresh = getattr(qa, "fresh_state", lambda api: {})
    findings, notes = [], []
    setup_failed = 0
    transport_lost = 0
    races = getattr(qa, "RACES", [])
    if not races:
        notes.append("no RACES in qa-spec.py (write one per money/stock/uniqueness invariant)")
    for scenario in races:
        if "setup" not in scenario or "check" not in scenario:    # a spec error must not become a RACE-INVARIANT finding
            notes.append(f"{scenario['name']}: spec error: a RACES entry needs 'setup' and 'check'; not run")
            setup_failed += 1
            continue
        # a race is timing-dependent: one clean burst proves nothing, so retry on fresh state until it breaks
        # (at least one burst: attempts: 0 would otherwise run nothing and leave `attempt` unbound)
        for attempt in range(max(1, int(scenario.get("attempts", ATTEMPTS)))):
            ctx = fresh(api) or {}
            try:
                req = scenario["setup"](api, ctx)
            except Exception as exc:
                notes.append(f"{scenario['name']}: setup failed ({type(exc).__name__}: {exc})")
                setup_failed += 1
                break
            role = req.get("role", default_owner(api.roles, getattr(qa, "ADMIN_ROLE", "admin")))
            if role not in api.roles:                              # an unknown role would silently send the burst anonymous
                notes.append(f"{scenario['name']}: role {role!r} is not a role from setup(): burst not run (it would be anonymous)")
                setup_failed += 1
                break
            headers = api.roles[role]
            results = race(req["method"], api.base + req["path"], n=scenario.get("n", 15),
                           headers=headers, body=req.get("body"), per_request_headers=req.get("per_request_headers"))
            codes = [c for c, _ in results]
            hit = False
            lost = sum(c == TRANSPORT_ERROR for c in codes)
            if lost:
                transport_lost += lost
                notes.append(f"{scenario['name']}: {lost} of {len(codes)} burst request(s) got no HTTP response (socket limit or crash); "
                             "the burst was weaker than asked")
            server_errors = sum(500 <= c < 600 and c != TRANSPORT_ERROR for c in codes)
            if server_errors:
                hit = True
                findings.append({"kind": "RACE-5XX", "severity": "medium", "endpoint": f"{req['method']} {req['path']}",
                                 "detail": f"{scenario['name']}: {server_errors} server errors", "codes": codes})
            try:
                problem = scenario["check"](api, results, ctx)
            except Exception as exc:       # reading the state back failed: after a race that usually means the state is corrupted
                problem = f"invariant check could not run ({type(exc).__name__}: {exc}); the app state is probably corrupted by the race"
            if problem:
                hit = True
                findings.append({"kind": "RACE-INVARIANT", "severity": "high", "endpoint": f"{req['method']} {req['path']}",
                                 "detail": f"{scenario['name']}: {problem}", "codes": codes})
            if hit:
                break
        else:
            notes.append(f"{scenario['name']}: no violation in {attempt + 1} burst(s) (timing-dependent: absence is not proof)")
    res = {"engine": "race", "findings": findings, "notes": notes}
    if not races:
        return trust.mark(res, trust.SKIPPED, "no RACES in qa-spec.py")
    if setup_failed >= len(races):
        return trust.mark(res, trust.ERRORED, f"setup failed for all {setup_failed} race scenario(s)")
    if setup_failed:
        return trust.mark(res, trust.DEGRADED, f"setup failed for {setup_failed} of {len(races)} race scenario(s)")
    if transport_lost:
        return trust.mark(res, trust.DEGRADED, f"{transport_lost} burst request(s) got no HTTP response: the race was weaker than configured")
    empty = [str(s.get("name", "?")) for s in races if trust.checks_nothing(s.get("check"))]
    if empty:
        notes.append(f"race check(s) with an empty body, they can never report a violation: {', '.join(empty)}")
        return trust.mark(res, trust.DEGRADED, f"empty race check(s) checked nothing: {', '.join(empty)}")
    return trust.mark(res, trust.RAN_OK)
