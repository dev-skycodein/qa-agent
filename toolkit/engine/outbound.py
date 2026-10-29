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
import base64
import binascii
import json
import quopri
import re

from sink import read_log, SECRET_PATTERNS as LEAKS
import trust

_B64_RUN = re.compile(r"[A-Za-z0-9+/=\r\n]{24,}")


def _decoded_variants(blob: str, body: str) -> list:
    """Text a MIME part may hide the secret in: quoted-printable and base64 runs (mail bodies). The sink stores the raw body,
    so a base64 "password" is only visible after this decode. Non-text decodes are dropped."""
    out = [blob]
    try:
        out.append(quopri.decodestring(body.encode("utf-8", "replace")).decode("utf-8", "replace"))
    except ValueError:
        pass
    runs = []
    for m in _B64_RUN.finditer(body):
        try:
            raw = base64.b64decode(re.sub(r"\s+", "", m.group(0)), validate=True)
        except (binascii.Error, ValueError):
            continue
        txt = raw.decode("utf-8", "replace")
        if txt and sum(c.isprintable() or c in "\r\n\t" for c in txt) / len(txt) > 0.9:
            runs.append(txt)
    if runs:
        out.append("\n".join(runs))
    return out


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
                         "detail": f"app tried to reach {host} {n}x via the proxy env vars (blocked by sink, or tunnelled if allow-listed). "
                                   "Integration exists; with blank keys it still calls out. Clients that ignore the proxy env are not seen."})
    if mails:
        findings.append({"kind": "OUTBOUND-EMAIL", "severity": "info", "endpoint": "smtp",
                         "detail": f"{len(mails)} mail(s) captured: " + "; ".join(f"to {m['to']} '{m['subject'][:50]}'" for m in mails[:5])})
    canary = "<i>qa-canary-html</i>"
    canary_reported = set()
    for e in entries:
        if canary not in str(e.get("body", "")):
            continue
        mail_api = e["kind"] != "smtp" and _is_email_api(e)
        if mail_api and canary not in str(json.loads(e["body"]).get("html", "")):
            continue            # canary only in subject / plain text: not an HTML context
        if e["kind"] == "smtp" or mail_api:
            to, subject = _mail_fields(e)
            key = ("email", str(to))
            if key not in canary_reported:          # one finding per recipient set, but every entry is looked at
                canary_reported.add(key)
                findings.append({"kind": "CANARY-IN-EMAIL", "severity": "high", "endpoint": f"mail to {to}",
                                 "detail": f"user-controlled HTML reached an outbound email unescaped (subject {subject[:60]!r}): HTML/header injection"})
        else:
            dest = f"{e.get('host', '')}{str(e.get('path', ''))[:60]}"
            key = ("prompt", dest)
            if key not in canary_reported:
                canary_reported.add(key)
                findings.append({"kind": "CANARY-IN-PROMPT", "severity": "info", "endpoint": dest,
                                 "detail": "user input is embedded verbatim in the outbound payload (LLM prompt / webhook / API call); "
                                           "check the template for injection hardening and what the response is allowed to do"})
    reported = set()
    for e in entries:
        # secrets found in the raw request headers by sink.py before it redacted them (the redacted copy cannot show them)
        for hit in e.get("header_leaks") or []:
            key = ("header", hit.get("label"), hit.get("header"), e.get("host") or e["kind"])
            if key not in reported:
                reported.add(key)
                findings.append({"kind": "OUTBOUND-LEAK", "severity": "high", "endpoint": e.get("host") or e["kind"],
                                 "detail": f"{hit.get('label')}: in request header '{hit.get('header')}' "
                                           f"<redacted {hit.get('chars')} chars>"[:300]})
        # secrets sink.py replaced in the URL / body / SMTP headers before storing them (the stored copy shows <redacted:...>)
        for hit in e.get("body_leaks") or []:
            key = ("body", hit.get("label"), hit.get("where"), e.get("host") or e["kind"])
            if key not in reported:
                reported.add(key)
                findings.append({"kind": "OUTBOUND-LEAK", "severity": "high", "endpoint": e.get("host") or e["kind"],
                                 "detail": f"{hit.get('label')}: in {hit.get('where')} <redacted {hit.get('chars')} chars>"[:300]})
    for e in entries:
        blob = "\n".join([str(e.get("path", "")), str(e.get("headers", "")), str(e.get("body", ""))])
        for text in _decoded_variants(blob, str(e.get("body", ""))):
            for label, rx in LEAKS:
                m = rx.search(text)
                if m and (label, e.get("host") or e["kind"]) not in reported:
                    reported.add((label, e.get("host") or e["kind"]))
                    # the secret itself is never copied into the report: show its context and its length only
                    shown = text[max(0, m.start() - 30):m.start()] + f"<redacted {len(m.group(0))} chars>" + text[m.end():m.end() + 30]
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
