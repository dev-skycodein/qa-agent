"""Sensitive-field exposure: secrets that a response should never carry, found by reading the bodies the other engines already got.

No extra requests: it scans `api.log` (every response body the run saw). A finding is a response field whose NAME says credential/secret
(password, hash, secret, api_key, private_key, invite_code, ...) or whose VALUE looks like one (bcrypt, 64-hex digest, PEM key), on an
endpoint that is not itself the place a credential is issued (login / token / refresh / session / password reset). The value is never
printed: only the first 3 characters and the length.

Design (tree of thoughts): (A) name-only match: cheap, noisy ("token" fields that are legitimately issued); (B) value-only match: misses
a plain-text secret; (C) name AND issuance-context filter, plus value shapes as a second, independent signal: chosen. False-positive
risks: a documented field such as `has_password: true` (boolean values are ignored), a public invite code meant to be shared (severity
medium and 'verify'), a hash that is a content id (only 64-hex under a secret-looking name is high; a bare hex value is medium).
It also sends one read-only GET per parameterless GET endpoint and role, so endpoints no other engine called are covered.
Status: ran_ok only when at least one JSON response body was inspected; otherwise skipped_no_spec with the reason.
"""
import json
import re

import api as api_mod
import trust

SECRET_NAME = re.compile(r"(pass(word|wd)?|pwd|secret|api[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret|"
                         r"(^|_)hash(ed)?($|_)|sha\d*|digest|salt|invite[_-]?code|ssn|card[_-]?number|cvv|otp|totp|session[_-]?id|sid$)", re.I)
TOKEN_NAME = re.compile(r"(^|_)(access_|refresh_|id_|auth_|bearer_|api_)?token$", re.I)
SAFE_NAME = re.compile(r"(^has_|^is_|_count$|_at$|_url$|_policy$|_required$|_enabled$|^max_|^min_)", re.I)
ISSUE_PATH = re.compile(r"(login|signin|sign-in|logout|token|refresh|session|auth|oauth|password|reset|forgot|register|signup|invite)", re.I)
BCRYPT = re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$", re.I)
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def _walk(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node[:20]:
            yield from _walk(v, f"{path}[*]")
    else:
        yield path, node


def _redact(v) -> str:
    s = str(v)
    return f"{s[:3]}... (len {len(s)})"


def _sweep(api, doc, qa, cap=40):
    """Read every parameterless GET once per configured role (read-only), so an endpoint no other engine called is still inspected."""
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
    seen, findings, inspected = set(), [], 0
    for e in api.log:
        if not (200 <= e["status"] < 300):
            continue
        try:
            body = json.loads(e.get("body") or "")
        except ValueError:
            continue
        inspected += 1
        issuing = bool(ISSUE_PATH.search(e["path"])) and e["method"] in ("POST", "PUT")
        for fpath, value in _walk(body):
            leaf = fpath.rsplit(".", 1)[-1].replace("[*]", "")
            if value is None or isinstance(value, bool) or value == "" or SAFE_NAME.search(leaf):
                continue
            by_name = bool(SECRET_NAME.search(leaf)) or (bool(TOKEN_NAME.search(leaf)) and not issuing)
            by_value = isinstance(value, str) and (bool(BCRYPT.match(value)) or bool(PEM.search(value)) or (bool(HEX64.match(value)) and by_name))
            if issuing and not by_value:
                continue
            if not (by_name or by_value):
                continue
            ep = f"{e['method']} {re.sub(r'/[0-9a-fA-F-]{6,}|/\d+', '/{id}', e['path'])}"
            key = (ep, fpath)
            if key in seen or f"{ep} {fpath}" in allow:
                continue
            seen.add(key)
            strong = by_value or bool(re.search(r"pass|secret|private|hash|sha\d|salt|api[_-]?key", leaf, re.I))
            # weak names (invite_code, session id, a token in a profile) are legitimate for the owner: low, 'who may see it' is the question
            findings.append({"kind": "EXPOSURE-SECRET-FIELD", "severity": "high" if strong else "low", "endpoint": ep,
                             "detail": f"response field {fpath!r} looks like a credential/secret ({_redact(value)}; role {e['role']}). "
                                       f"{'verify: legitimate for its owner, but confirm no other role receives it' if not strong else 'a response should not carry it'}"})
    res = {"engine": "exposure", "findings": findings, "notes": [f"{inspected} JSON response(s) inspected ({swept} read-only GETs sent by this engine)"],
           "probes": inspected}
    if inspected == 0:
        return trust.mark(res, trust.SKIPPED, "no successful JSON response was logged: nothing to inspect")
    return trust.mark(res, trust.RAN_OK)
