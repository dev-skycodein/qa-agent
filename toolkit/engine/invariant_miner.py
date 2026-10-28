"""Mine likely invariants from the traffic the other engines already produced, then look for the calls that break them.

Idea from AGORA / AGORA+ (Alonso, Ernst, Segura, Ruiz-Cortes; ISSTA 2023, TOSEM 2025): Daikon-style invariants over REST
request/response pairs. They reported ~80% precision, so this engine never claims a bug: its findings are `info` CANDIDATES for a
human or Claude to confirm, and the mined list is a starting point for writing the INVARIANTS of a new project's qa-spec.py.

Mined per (method, path template) over 2xx responses with a JSON object body:
  const      field always has the same value
  enum       string/bool field with <= 6 distinct values
  nonneg     numeric field never negative
  echo       response[field] == request[field] (the server stores what it was given)
  unique     POST ids never repeat
Invariants are learned on the first 70% of samples and checked on the rest (train/check split), needing >= MIN_SUPPORT samples.
Limits: needs complete JSON bodies (api.py keeps 8000 chars in log["body"]; longer ones are skipped and counted);
invariants that hold only because the test data was narrow are the usual false positive. One guard against that: a const/enum
over a field that only holds values this run itself sent under the same field name is not mined (measured false positive on the
demo: `GET /items/{id}` name in {qa, tee}, both sent by our own fuzzing).
"""
import json
import re
from collections import defaultdict

MIN_SUPPORT = 10
ENUM_MAX = 6
TRAIN_FRACTION = 0.7


def _template(path: str) -> str:
    path = path.split("?")[0]
    return re.sub(r"/(\d+|[0-9a-f]{24}|[0-9a-f-]{32,36})(?=/|$)", "/{id}", path)


def _scalar(v) -> bool:
    return isinstance(v, (str, int, float, bool)) and not isinstance(v, type(None))


def _samples(log: list):
    """Yield (group, request_body, response_object) for 2xx JSON-object responses; count what had to be skipped."""
    skipped = 0
    out = []
    for e in log:
        if not (200 <= e.get("status", 0) < 300):
            continue
        try:
            body = json.loads(e.get("body", e.get("response")) or "")      # "body" = api.py's long copy; "response" is cut at 300 chars
        except ValueError:
            skipped += 1                                       # truncated by api.py or not JSON
            continue
        if not isinstance(body, dict):
            continue
        req = e.get("request")
        out.append((f"{e['method']} {_template(e['path'])}", req if isinstance(req, dict) else {}, body))
    return out, skipped


def _sent_values(log: list) -> dict:
    """{field name: json-encoded scalars the engines themselves sent under that name} over every request body / query.
    A response field that only ever holds values we sent under the same name reflects OUR inputs (the generator's narrow
    vocabulary), not a rule of the server."""
    out = defaultdict(set)

    def walk(node, name=None):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, name)
        elif name is not None and _scalar(node):
            out[name].add(json.dumps(node))
    for e in log:
        walk(e.get("request"))
        walk(e.get("query"))
    return out


def mine(log: list) -> dict:
    """-> {"invariants": [...], "violations": [...], "skipped_bodies": n, "groups": n, "client_controlled": n}"""
    samples, skipped = _samples(log)
    sent = _sent_values(log)
    client_controlled = 0
    by_group = defaultdict(list)
    for g, req, body in samples:
        by_group[g].append((req, body))
    invariants, violations = [], []
    for group, rows in by_group.items():
        if len(rows) < MIN_SUPPORT:
            continue
        cut = max(MIN_SUPPORT - 3, int(len(rows) * TRAIN_FRACTION))
        train, check = rows[:cut], rows[cut:]
        fields = {k for _, b in train for k, v in b.items() if _scalar(v)}
        for f in sorted(fields):
            vals = [b[f] for _, b in train if f in b and _scalar(b[f])]
            if len(vals) < len(train) or len(vals) < MIN_SUPPORT - 3:      # field must be present in every training sample
                continue
            cands = []
            distinct = {json.dumps(v) for v in vals}
            vacuous = distinct <= sent.get(f, set()) and any(isinstance(v, (str, bool)) for v in vals)
            if vacuous:
                client_controlled += 1                      # const/enum over values the client itself sent under this name: skip
            elif len(distinct) == 1:
                cands.append(("const", f"{f} is always {vals[0]!r}", lambda b, f=f, c=vals[0]: b.get(f) == c))
            elif len(distinct) <= ENUM_MAX and all(isinstance(v, (str, bool)) for v in vals):
                allowed = {json.dumps(v) for v in vals}
                cands.append(("enum", f"{f} is one of {sorted(allowed)}", lambda b, f=f, a=allowed: json.dumps(b.get(f)) in a))
            if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals) and min(vals) >= 0:
                cands.append(("nonneg", f"{f} >= 0", lambda b, f=f: not isinstance(b.get(f), (int, float)) or b.get(f) >= 0))
            if all(f in r and _scalar(r[f]) for r, _ in train) and all(r[f] == b[f] for r, b in train):
                cands.append(("echo", f"response.{f} equals request.{f}",
                              lambda b, f=f, r=None: True))             # echo is checked pairwise below
            for kind, text, pred in cands:
                inv = {"group": group, "field": f, "kind": kind, "text": text, "support": len(train)}
                invariants.append(inv)
                for req, b in check:
                    if kind == "echo":
                        if f in req and _scalar(req[f]) and f in b and req[f] != b[f]:
                            violations.append({**inv, "example": {"request": req.get(f), "response": b.get(f)}})
                    elif not pred(b):
                        violations.append({**inv, "example": {"response": b.get(f)}})
        if group.startswith("POST ") and "id" in rows[0][1]:
            ids = [b.get("id") for _, b in rows if "id" in b]
            if len(ids) >= MIN_SUPPORT - 3:
                invariants.append({"group": group, "field": "id", "kind": "unique", "text": "created ids never repeat", "support": len(ids)})
                dup = [i for i in set(ids) if ids.count(i) > 1]
                if dup:
                    violations.append({"group": group, "field": "id", "kind": "unique", "text": "created ids never repeat",
                                       "support": len(ids), "example": {"duplicate_id": dup[0]}})
    return {"invariants": invariants, "violations": violations, "skipped_bodies": skipped, "client_controlled": client_controlled,
            "groups": sum(1 for rows in by_group.values() if len(rows) >= MIN_SUPPORT)}


def run(api, spec_doc=None, qa=None) -> dict:
    """Engine entry for run.py. Never produces more than `info` findings: these are candidates, not bugs."""
    import trust
    res = mine(api.log)
    findings, seen = [], set()
    for v in res["violations"]:
        key = (v["group"], v["kind"], v["field"])
        if key in seen:
            continue
        seen.add(key)
        findings.append({"kind": "INFERRED-INVARIANT", "severity": "info", "endpoint": v["group"],
                         "detail": f"mined '{v['text']}' ({v['support']} samples) then saw {v['example']}: CANDIDATE, confirm by hand"})
    notes = [f"mined {len(res['invariants'])} invariants over {res['groups']} endpoint group(s); "
             f"{res['skipped_bodies']} response bodies skipped (truncated or not JSON); "
             f"{res['client_controlled']} const/enum field(s) ignored because they only hold values this run sent itself"]
    notes += [f"suggested invariant: {i['group']}: {i['text']} (support {i['support']})" for i in res["invariants"][:25]]
    out = {"engine": "invariants", "findings": findings, "notes": notes, "mined": len(res["invariants"])}
    if res["groups"] == 0:
        return trust.mark(out, trust.DEGRADED, "no endpoint had enough complete JSON responses to mine (needs >= %d samples)" % MIN_SUPPORT)
    return trust.mark(out, trust.RAN_OK)
