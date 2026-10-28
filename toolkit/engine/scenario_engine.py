"""Scenario engine: short scripted multi-step checks for things random search cannot reach by itself
(blocked user must lose access, single-use tokens, token of the wrong kind, permission revoked, ...).

qa-spec.py:
  SCENARIOS = [{"name": "blocked user loses access",
                "run": fn(api, ctx) -> None | "message"}]     # return a message (or raise AssertionError) when the rule is broken
`ctx = fresh_state(api)` per scenario. A crash that is not an AssertionError is reported as a note, not as a finding.
"""
import trust


def run(api, spec_doc, qa) -> dict:
    fresh = getattr(qa, "fresh_state", lambda api: {})
    findings, notes = [], []
    crashed = 0
    scenarios = getattr(qa, "SCENARIOS", [])
    if not scenarios:
        notes.append("no SCENARIOS in qa-spec.py (write one per access-control / lifecycle rule: blocked user, revoked token, single-use link)")
    for sc in scenarios:
        try:
            ctx = fresh(api) or {}
            problem = sc["run"](api, ctx)
        except AssertionError as exc:
            problem = str(exc) or "assertion failed"
        except Exception as exc:
            notes.append(f"{sc['name']}: scenario crashed ({type(exc).__name__}: {exc})")
            crashed += 1
            continue
        if problem:
            findings.append({"kind": "SCENARIO", "severity": "high", "endpoint": sc["name"], "detail": str(problem)[:400]})
    res = {"engine": "scenario", "findings": findings, "notes": notes}
    if not scenarios:
        return trust.mark(res, trust.SKIPPED, "no SCENARIOS in qa-spec.py")
    if crashed >= len(scenarios):
        return trust.mark(res, trust.ERRORED, f"all {crashed} scenario(s) crashed")
    if crashed:
        return trust.mark(res, trust.DEGRADED, f"{crashed} of {len(scenarios)} scenario(s) crashed")
    return trust.mark(res, trust.RAN_OK)
