"""Outbound engine: turn sink.jsonl (what the app tried to send to the outside world) into findings.

  OUTBOUND-ATTEMPT  info    app opened a connection to an external host (blocked) - tells you which integrations exist and
                            that "blank key" did NOT stop the call
  OUTBOUND-EMAIL    info    mail captured by the fake SMTP server (count, subjects)
  OUTBOUND-LEAK     high    secrets / credentials / card numbers in an outbound request or email
  CANARY-IN-EMAIL   high    the negative engine's HTML canary (<i>qa-canary-html</i>) arrives unescaped in an outbound email
  CANARY-IN-PROMPT  info    the canary reaches an LLM / webhook / third-party API verbatim (user input inside a prompt:
                            check for prompt-injection hardening, delimiters, output use)
  SINK-RULE         high    qa-spec.py SINK_CHECKS = [fn(entry) -> None | "message"] returned a message

Built-in leak patterns apply to request headers, URL and body of every captured entry.
"""
import json
import re

from sink import read_log
import trust

LEAKS = [
    ("password in payload", re.compile(r'"(password|passwd|pwd)"\s*:\s*"[^"]{1,}"', re.I)),
    ("api key / token in payload or URL", re.compile(r"AIza[0-9A-Za-z_\-]{30,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|"
                                                      r"[?&](api_?key|access_?token|token|secret)=[^&\s]{8,}", re.I)),
    ("session JWT sent to third party", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("card number", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
]


def _is_email_api(e) -> bool:
    """HTTP mail APIs (Resend, SendGrid, Mailgun...) carry the message as JSON {to, subject, html|text}."""
    try:
        b = json.loads(e.get("body") or "")
    except ValueError:
        return False
    return isinstance(b, dict) and "subject" in b and "to" in b and any(k in b for k in ("html", "text", "content"))


def _mail_fields(e) -> tuple:
    if e["kind"] == "smtp":
        return e.get("to"), e.get("subject", "")
    b = json.loads(e["body"])
    return b.get("to"), str(b.get("subject", ""))


def run(sink_log: str, qa) -> dict:
    entries = read_log(sink_log) if sink_log else []
    findings, notes = [], []
    if not sink_log:
        return trust.mark({"engine": "outbound", "findings": [], "notes": ["no sink log (safe_run started with --no-sink or profile.sink=false)"]},
                          trust.SKIPPED, "no sink log: egress was not recorded")
    hosts: dict[str, int] = {}
    mails = []
    for e in entries:
        host = e.get("host") or ""
        if e["kind"] == "smtp":
            mails.append(e)
        elif host and e.get("via") != "direct":
            hosts[host] = hosts.get(host, 0) + 1
    for host, n in sorted(hosts.items()):
        findings.append({"kind": "OUTBOUND-ATTEMPT", "severity": "info", "endpoint": host,
                         "detail": f"app tried to reach {host} {n}x (blocked by sink). Integration exists; with blank keys it still calls out."})
    if mails:
        findings.append({"kind": "OUTBOUND-EMAIL", "severity": "info", "endpoint": "smtp",
                         "detail": f"{len(mails)} mail(s) captured: " + "; ".join(f"to {m['to']} '{m['subject'][:50]}'" for m in mails[:5])})
    canary = "<i>qa-canary-html</i>"
    for e in entries:
        if canary not in str(e.get("body", "")):
            continue
        mail_api = e["kind"] != "smtp" and _is_email_api(e)
        if mail_api and canary not in str(json.loads(e["body"]).get("html", "")):
            continue            # canary only in subject / plain text: not an HTML context
        if e["kind"] == "smtp" or mail_api:
            to, subject = _mail_fields(e)
            findings.append({"kind": "CANARY-IN-EMAIL", "severity": "high", "endpoint": f"mail to {to}",
                             "detail": f"user-controlled HTML reached an outbound email unescaped (subject {subject[:60]!r}): HTML/header injection"})
        else:
            dest = f"{e.get('host', '')}{str(e.get('path', ''))[:60]}"
            findings.append({"kind": "CANARY-IN-PROMPT", "severity": "info", "endpoint": dest,
                             "detail": "user input is embedded verbatim in the outbound payload (LLM prompt / webhook / API call); "
                                       "check the template for injection hardening and what the response is allowed to do"})
        break
    reported = set()
    for e in entries:
        blob = "\n".join([str(e.get("path", "")), str(e.get("headers", "")), str(e.get("body", ""))])
        for label, rx in LEAKS:
            m = rx.search(blob)
            if m and (label, e.get("host") or e["kind"]) not in reported:
                reported.add((label, e.get("host") or e["kind"]))
                # the secret itself is never copied into the report: show its context and its length only
                shown = blob[max(0, m.start() - 30):m.start()] + f"<redacted {len(m.group(0))} chars>" + blob[m.end():m.end() + 30]
                findings.append({"kind": "OUTBOUND-LEAK", "severity": "high", "endpoint": e.get("host") or e["kind"],
                                 "detail": f"{label}: ...{shown!r}"[:300]})
    for fn in getattr(qa, "SINK_CHECKS", []):
        for e in entries:
            try:
                msg = fn(e)
            except Exception as exc:
                notes.append(f"{getattr(fn, '__name__', 'check')} crashed: {exc}")
                break
            if msg:
                findings.append({"kind": "SINK-RULE", "severity": "high", "endpoint": getattr(fn, "__name__", "check"), "detail": str(msg)[:400]})
                break
    if not entries:
        notes.append("sink saw no outbound traffic (either the app makes none, or it ignores HTTP(S)_PROXY: check app.log / NODE_USE_ENV_PROXY)")
    res = {"engine": "outbound", "findings": findings, "notes": notes, "entries": len(entries)}
    if not entries:
        return trust.mark(res, trust.DEGRADED, "EGRESS UNVERIFIED: sink saw no traffic, which is not proof the app made none")
    if any("crashed" in n for n in notes):
        return trust.mark(res, trust.DEGRADED, "a SINK_CHECK crashed")
    return trust.mark(res, trust.RAN_OK)
