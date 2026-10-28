"""Engine status contract: an empty finding list only means "clean" if the engine really ran.

Every engine result carries a terminal status, so a failed or skipped engine can never look like a clean one:

  ran_ok           the engine ran everything it was asked to run
  skipped_no_spec  nothing to do because qa-spec.py defines nothing for it (no RACES, no SCENARIOS, no DB_CHECKS, ...)
  degraded         ran, but part of its work was skipped or failed (a check errored, a body was rejected, only the built-in
                   oracle ran, ...). Findings are still valid; the ABSENCE of findings is weaker evidence
  setup_failed     the engine could not create the precondition it probes (a repeated create hit a unique-value conflict, a
                   409, ...): the probes behind it never ran. That is the spec's or the test data's fault, not a check that
                   errored. Findings are still valid; the ABSENCE of findings for those probes means nothing
  errored          crashed or could not do its job at all. The absence of findings means nothing

Results from engines that do not declare a status are treated as `degraded`, never as `ran_ok`.
`exit_code` keeps "engine broke" (2) apart from "findings present" (1, opt-in) and "all good" (0).
"""
RAN_OK, SKIPPED, DEGRADED, SETUP_FAILED, ERRORED = "ran_ok", "skipped_no_spec", "degraded", "setup_failed", "errored"
STATUSES = (RAN_OK, SKIPPED, DEGRADED, SETUP_FAILED, ERRORED)

EXIT_OK, EXIT_FINDINGS, EXIT_ENGINE_BROKE = 0, 1, 2


def mark(result: dict, status: str, reason: str = "") -> dict:
    """Set the terminal status on an engine result (and return it)."""
    if status not in STATUSES:
        raise ValueError(f"unknown engine status {status!r}")
    result["status"] = status
    result["status_reason"] = reason
    return result


def resolve(result: dict) -> tuple:
    """(status, reason) of one engine result. A crash always wins; a missing status is `degraded`."""
    if "engine-error" in result:
        first = [l for l in str(result["engine-error"]).strip().splitlines() if l.strip()]
        return ERRORED, (first[-1] if first else "engine crashed")[:200]
    status = result.get("status")
    if status in STATUSES:
        return status, result.get("status_reason", "")
    return DEGRADED, "engine did not report a status"


def summarize(results: list) -> dict:
    rows = []
    for r in results:
        status, reason = resolve(r)
        rows.append({"engine": r.get("engine", "?"), "status": status, "reason": reason,
                     "findings": len(r.get("findings", []))})
    by = lambda s: [row["engine"] for row in rows if row["status"] == s]
    return {"engines": rows, "errored": by(ERRORED), "degraded": by(DEGRADED), "setup_failed": by(SETUP_FAILED),
            "skipped": by(SKIPPED), "ran_ok": by(RAN_OK)}


def verdict(summary: dict) -> str:
    """One honest sentence. It never says 'clean': that word is for the reader to earn from the findings."""
    if summary["errored"]:
        return "NOT TRUSTED - engine(s) errored: " + ", ".join(summary["errored"]) + ". No finding from them does not mean no bug."
    parts = []
    if summary["degraded"]:
        parts.append("degraded: " + ", ".join(summary["degraded"]))
    if summary.get("setup_failed"):
        parts.append("setup failed (probes never ran): " + ", ".join(summary["setup_failed"]))
    if summary["skipped"]:
        parts.append("skipped (nothing in qa-spec.py): " + ", ".join(summary["skipped"]))
    if parts:
        return "PARTIAL - " + "; ".join(parts) + ". Absence of findings from these is weak evidence."
    return "ALL ENGINES RAN - absence of findings is real evidence for the checks the spec defines."


def header_lines(results: list) -> list:
    s = summarize(results)
    lines = ["## Coverage & Trust", "", "| engine | status | findings | reason |", "|---|---|---|---|"]
    for row in s["engines"]:
        lines.append(f"| {row['engine']} | {row['status'].upper()} | {row['findings']} | {row['reason'].replace('|', '/')} |")
    lines += ["", f"**{verdict(s)}**", ""]
    return lines


def exit_code(results: list, fail_on_findings: bool = False, strict: bool = False) -> int:
    """2 = an engine broke (or, with strict, ran degraded); 1 = findings present (only when asked); 0 otherwise."""
    s = summarize(results)
    if s["errored"] or (strict and (s["degraded"] or s["setup_failed"])):
        return EXIT_ENGINE_BROKE
    if fail_on_findings and any(f.get("severity") != "info" for r in results for f in r.get("findings", [])):
        return EXIT_FINDINGS
    return EXIT_OK


def cross_check(results: list, request_count: int = 0) -> list:
    """Independent trust downgrade (D1): an engine that claimed ran_ok but made no probes / saw no traffic is degraded.

    Status is otherwise self-reported; this is the only mechanical cross-check besides the canary.
    Mutates and returns `results`.
    """
    for r in results:
        status, _ = resolve(r)
        if status != RAN_OK:
            continue
        name = r.get("engine", "?")
        probes = r.get("probes")
        if probes is not None and probes == 0 and name in ("authz", "negative", "race", "scenario"):
            mark(r, DEGRADED, f"cross-check: claimed ran_ok with 0 probes ({name})")
            continue
        if name in ("authz", "negative", "stateful", "race", "scenario") and request_count == 0:
            mark(r, DEGRADED, "cross-check: claimed ran_ok but api.log has 0 requests")
    return results
