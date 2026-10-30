"""Sensitive-field exposure: secrets that a response should never carry, found by reading the bodies the other engines already got.

It scans `api.log` (every response body the run saw), and it ALSO sends one GET per parameterless GET endpoint and configured role
(`_sweep`), so endpoints no other engine called are inspected too. Those sweep GETs are not verified read-only: a GET can change state on
the target (a logout, an export, a reset). Exclude such endpoints with `qa.SKIP`; the run notes say how many sweep GETs were sent.
A finding is a response field whose NAME says credential/secret (password, hash, secret, api_key, private_key, invite_code, ...) or
whose VALUE looks like one (bcrypt, PEM key, or a 64-hex digest under a secret-looking name), on an endpoint that is not itself the
place a credential is issued (login / token / refresh / session / password reset). On such an issuing endpoint only a password, hash or
secret field is reported (a token there is what the endpoint is for). A bare 64-hex value under an innocent name is NOT reported (it is
usually a content id). The value is never printed: only the first 3 characters and the length.

Design (tree of thoughts): (A) name-only match: cheap, noisy ("token" fields that are legitimately issued); (B) value-only match: misses
a plain-text secret; (C) name AND issuance-context filter, plus value shapes as a second, independent signal: chosen. False-positive
risks: a documented field such as `has_password: true` (boolean values are ignored), a public invite code meant to be shared (severity
low and 'verify'), a hash that is a content id (only 64-hex under a secret-looking name is reported).
Names are matched on whole words after camelCase/hyphen normalisation (`accessToken` -> `access_token`, `passenger` is not `pass`).
Bodies longer than the log cap are read from `full_body`. A 2xx body that was cut and has no `full_body` (the run's memory budget is used
up, or the app sent more than api.MAX_READ) cannot be parsed: it is counted, and the run is degraded rather than clean.
Status: ran_ok only when at least one JSON response body was inspected and no cut body was left unread; degraded when one was;
otherwise skipped_no_spec with the reason.
"""
import json
import re

import api as api_mod
import trust

# Names are normalised first (_norm): camelCase -> snake_case, '-' -> '_', lower case. Every pattern is anchored to whole words.
SECRET_NAME = re.compile(r"(^|_)(pass|passwd|password|pwd|secret|client_secret|private_?key|api_?key|access_?key|hash|hashed|sha\d*|"
                         r"digest|salt|invite_?code|ssn|card_?number|cvv|otp|totp|session_?id|sid)($|_)")
# the strongest names: a value under one of these on a response is reported as high (the rest are low, 'verify')
STRONG_NAME = re.compile(r"(^|_)(pass|passwd|password|pwd|secret|client_secret|private_?key|api_?key|hash|hashed|sha\d*|salt)($|_)")
TOKEN_NAME = re.compile(r"(^|_)(access_|refresh_|id_|auth_|bearer_|api_)?token$")
# no _url$ here: a reset URL carries the reset token, so a URL under a secret-looking name must still be inspected
SAFE_NAME = re.compile(r"(^has_|^is_|_count$|_at$|_policy$|_required$|_enabled$|^max_|^min_)")
# whole path segments only: '/authors' is not 'auth', '/tokenizer' is not 'token'; '/oauth2/token' and '/sessions' still match
ISSUE_PATH = re.compile(r"(?<![a-z])(login|signin|sign-in|logout|tokens?|refresh|sessions?|auth|oauth2?|password|reset|forgot|"
                        r"register|signup|sign-up|invites?)(?![a-z])", re.I)
BCRYPT = re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$", re.I)
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
ID_SEGMENT = re.compile(r"/[0-9a-fA-F-]{6,}|/\d+")          # path ids, normalised to /{id} (kept out of the f-string: py3.11)


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v, f"{path}[*]")
    else:
        yield path, node


def _norm(leaf: str) -> str:
    """'accessToken' -> 'access_token', 'Pass-Word' -> 'pass_word'. Lets the whole-word patterns see camelCase names."""
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", leaf).replace("-", "_").lower()


def _redact(v) -> str:
    s = str(v)
    return f"{s[:3]}... (len {len(s)})"


def _sweep(api, doc, qa, cap=40):
    """Send every parameterless GET once per configured role, so an endpoint no other engine called is still inspected.
    These are GETs, not verified read-only: a GET may change state (see the module docstring and qa.SKIP)."""
    skip = set(getattr(qa, "SKIP", ()) or ())
    n = 0
    for ep in api_mod.endpoints(doc):
        if ep["method"] != "GET" or ep["path_params"] or api_mod.key(ep) in skip or n >= cap:
            continue
        for role in api.roles:
            api.call(role, "GET", ep["path"])
            n += 1
    return n


def run(api, doc, qa=None) -> dict:
    allow = set(getattr(qa, "EXPOSURE_ALLOW", ()) or ())            # "METHOD path.field" the author says is fine
    swept = _sweep(api, doc, qa)
    seen, findings, inspected, unread = set(), [], 0, 0
    for e in api.log:
        if not (200 <= e["status"] < 300):
            continue
        try:
            body = json.loads(e.get("full_body") or e.get("body") or "")
        except ValueError:
            unread += 1 if e.get("truncated") else 0
            continue
        inspected += 1
        issuing = bool(ISSUE_PATH.search(e["path"])) and e["method"] in ("POST", "PUT")
        sent = e.get("request") if isinstance(e.get("request"), dict) else {}
        for fpath, value in _walk(body):
            leaf = _norm(fpath.rsplit(".", 1)[-1].replace("[*]", ""))
            if value is None or isinstance(value, bool) or value == "" or SAFE_NAME.search(leaf):
                continue
            by_name = bool(SECRET_NAME.search(leaf)) or (bool(TOKEN_NAME.search(leaf)) and not issuing)
            strong_name = bool(STRONG_NAME.search(leaf))
            by_value = isinstance(value, str) and (bool(BCRYPT.match(value)) or bool(PEM.search(value)) or (bool(HEX64.match(value)) and by_name))
            # an issuing endpoint legitimately returns tokens and session ids; a password, hash or secret field in its response is still a leak
            if issuing and not (by_value or strong_name):
                continue
            if not (by_name or by_value):
                continue
            raw_leaf = fpath.rsplit(".", 1)[-1].replace("[*]", "")
            if not (by_value or strong_name) and raw_leaf in sent and sent[raw_leaf] == value:
                continue    # a weak name echoing the caller's own value (e.g. the negative engine's mass-assign probe) is not a leak
            ep = e["method"] + " " + ID_SEGMENT.sub("/{id}", e["path"])
            key = (ep, fpath)
            if key in seen or f"{ep} {fpath}" in allow:
                continue
            seen.add(key)
            strong = by_value or strong_name
            # weak names (invite_code, session id, a token in a profile) are legitimate for the owner: low, 'who may see it' is the question
            findings.append({"kind": "EXPOSURE-SECRET-FIELD", "severity": "high" if strong else "low", "endpoint": ep,
                             "detail": f"response field {fpath!r} looks like a credential/secret ({_redact(value)}; role {e['role']}). "
                                       f"{'verify: legitimate for its owner, but confirm no other role receives it' if not strong else 'a response should not carry it'}"})
    notes = [f"{inspected} JSON response(s) inspected ({swept} GETs sent by this engine's sweep)"]
    if swept:
        notes.append("the sweep GETs are not verified read-only: a GET may have changed state on the target; exclude with qa.SKIP")
    res = {"engine": "exposure", "findings": findings, "notes": notes, "probes": inspected}
    if unread:
        notes.append(f"{unread} long response(s) were cut before this engine saw them: secrets in them were not checked")
        return trust.mark(res, trust.DEGRADED, f"{unread} long response(s) could not be read")
    if inspected == 0:
        return trust.mark(res, trust.SKIPPED, "no successful JSON response was logged: nothing to inspect")
    return trust.mark(res, trust.RAN_OK)
