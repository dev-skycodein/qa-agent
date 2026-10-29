"""Differential engine: send the SAME request sequence to two LOCAL versions of one API (A = old, B = new) and report what changed.

  python toolkit/engine/differential.py --a http://127.0.0.1:8001 --b http://127.0.0.1:8002 --openapi openapi.json \
         [--spec qa-spec.py] [--seed N] [--out dir] [--expect-changes allow.json] [--noise-runs 1] [--replay log.json]

The user starts both apps (separate data stores!). Everything goes through api.Api, so non-local hosts are refused.

DESIGN - tree of thoughts
-------------------------
Candidate 1, live dual-run: generate the sequence from the OpenAPI document, fire it at A and B, compare.
  + needs nothing but two running apps; any sequence the toolkit can generate; ids returned by creates can be mapped on the fly.
  - the two histories can diverge (a create that works on one side only), the apps must both be up at once.
Candidate 2, record/replay: record the traffic against A once (api.log), later replay it against B.
  + B can be started later; the recorded log is a regression artifact.
  - the recorded responses are stale and truncated, so they cannot serve as the oracle for noise.
Candidate 3, snapshot files: dump normalised responses of A to disk, diff against B's later.
  - the normalisation has to be decided before anyone knows what is volatile; every intended change invalidates it.
CHOSEN: live dual-run in LOCKSTEP (1: A and B get step i before step i+1 is sent), plus replay (2). The lockstep is what makes
  the equal-state tracking exact: after every write the two collection fingerprints are compared again.

ORACLES - chain of thought (a difference is a regression only if it is stable, deterministic and not intended)
-------------------------------------------------------------------------------------------------------------
1. Why not just diff A and B? Two runs of the very same code already differ: timestamps, uuids, counters. Those are noise.
2. NOISE LEARNING: the plan is run against A (run 0) and again against A (run 1, "A prime"). Whatever differs between those two
   runs of the SAME code is noise: (endpoint, status) / (endpoint, header) / (endpoint, json path). Only then is A compared with B.
3. FIXTURES: qa.setup creates records on each side, and the bodies it writes into qa.BODIES carry ids that differ per side.
   The engine pairs the two BODIES snapshots (parallel walk), so a plan literal A-id is sent to B as B's id, and both ids are
   tokenised (<FIX:n>) in responses. The fixtures are the ONLY id correspondence the engine assumes; every other id is per side.
4. Each create gets a per-side token <ID:step>; unique-ish body values (email, username, ...) are varied per run (A prime) so a
   repeated create does not 409. Only CREATES (a POST on a collection path) are varied: a login is not.
5. A probe id that means "does not exist" (999999, a fixed uuid) is sent unmapped and identically on both sides. A step that
   needs an item the create did not produce on THIS side is not sent at all (recorded as skipped): it never falls back to a
   fake id, so one side cannot be compared against a real item on the other.
6. Status: same code = fine. 2xx->5xx high (crash), 2xx->4xx medium, 4xx->5xx medium, 4xx->4xx medium, 4xx->2xx low, 5xx->non-5xx
   info. When status differs the bodies are NOT compared.
7. Body (same status, both JSON): field removed / type changed medium; field added info; scalar value low; arrays by position.
   A value that differs from the DOCUMENTED default of a field the request omitted is DIFF-DEFAULT (medium).
8. PAGING (collection reads): a page past the end that returns items on one side only (DIFF-PAGING, medium); a default page size
   that differs when the request sent no size (DIFF-PAGING, medium).
9. STATE, exact and lockstep: after each write whose outcome differs between A and B (or while the state is already diverged),
   the collection fingerprint (status, list length, total) is taken on both sides. Equal fingerprint = equal state again.
   While the state differs, collection reads are labelled DIVERGED and their body differences are info, never medium/low.
   Statuses are never downgraded by the state: a 500 on a list is still a 500.
10. Fixtures are created in phase 0 (copies of every collection create, with non-round numbers and cycling enum values, so that
   default page sizes and aggregates have something to show) and removed in phase 3, so the probe groups see the same data as
   before.

qa-spec.py knobs (all optional): DIFF_BASE_URL, DIFF_EXPECT (list), DIFF_SKIP (set of "METHOD /path"), DIFF_ROLE ({"METHOD /path": role}),
DIFF_NOISE_RUNS (default 1), DIFF_IGNORE (list, same syntax as DIFF_EXPECT, but means "volatile": not counted as an intended change),
DIFF_PROBES (default True: set False for the plain sequence only), setup_b(api_b) (roles for B; falls back to setup(api_b), then to
A's roles), BODIES (shared with the other engines), setup(api) (fixtures: its BODIES values are paired between A and B).
"""
import argparse
import copy
import importlib.util
import itertools
import json
import os
import random
import re
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trust  # noqa: E402
from api import (Api, WRITE_METHODS, endpoints, example, extract_id, key, load_openapi, prefix_of, resolve,  # noqa: E402
                 TRANSPORT_ERROR)

ENGINE = "differential"
MISSING_ID = "999999"          # path id of a probe step that means "does not exist": sent identically to both sides
LIST_CAP = 50                  # array elements compared by position
PROBE_BUDGET = 600             # probe steps per run, at most (a huge spec must not turn one run into hours)
VARIANT_CAP = 40               # body variants per operation
FIXTURE_COPIES = 25            # extra creates per collection in phase 0 (more than a default page, non-round values)
WALK_MAX = 6                   # repeated calls of a state-transition endpoint (POST /x/{id}/verb)
PAGE_FAR = 1_000_000           # a page number far past any real end
UNKNOWN_UUID = str(uuid.uuid5(uuid.NAMESPACE_URL, "differential-engine/unknown-id"))
UNKNOWN_IDS = (("uuid", UNKNOWN_UUID), ("numeric", MISSING_ID), ("malformed", "not-a-valid-id"))
WRONG_BY_TYPE = {"string": 12345, "integer": "not-a-number", "number": "not-a-number", "boolean": "yes",
                 "array": "not-a-list", "object": [1]}
MALFORMED_JSON = b'{"qa": '
ABSENT = "\x00absent"          # sentinel: a list item has no such field (cannot occur in JSON text)
UNIQUE_KEY = re.compile(r"e-?mail|user-?name|login|handle|slug|code|sku", re.I)
IDLIKE_KEY = re.compile(r"^(id|_id|uuid|pk)$|(_id|Id|ID)$")
# a code the API checks against a list (country, currency, language, postal, status, error ...): never varied by _vary
CLASSIFIER_KEY = re.compile(r"(country|currency|lang|language|locale|region|state|postal|zip|status|error|tax|gender|type|category)_?code$", re.I)
LIST_KEYS = ("items", "data", "results")        # the key a paginated list answer keeps its rows under
LIST_LEN = tuple(f"{k}.#len" for k in LIST_KEYS)
TIMELIKE_KEY = re.compile(r"(_at|At|time|Time|date|Date|expires|ts|timestamp)$")
VOLATILE_RX = [
    ("<uuid>", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("<ts>", re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:?\d\d)?")),
    ("<jwt>", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("<hex>", re.compile(r"\b[0-9a-fA-F]{24,}\b")),
]
IGNORED_HEADERS = {"date", "server", "content-length", "connection", "keep-alive", "transfer-encoding", "set-cookie", "etag",
                   "last-modified", "age", "x-request-id", "x-correlation-id", "x-trace-id", "x-response-time", "x-runtime",
                   "x-served-by", "via", "expires", "retry-after", "content-encoding", "vary"}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


# ---------------------------------------------------------------- normalisation

def _volatile(s: str) -> str:
    for token, rx in VOLATILE_RX:
        s = rx.sub(token, s)
    return s


def _norm_str(s: str, ids: dict, subs: dict, k=None) -> str:
    for val in sorted(subs, key=len, reverse=True):          # unique values this run injected
        if len(val) >= 4:
            s = s.replace(val, subs[val])
        elif s == val:
            s = subs[val]
    if s in ids and (not s.isdigit() or (k and IDLIKE_KEY.search(k))):      # a bare small number elsewhere ("version": "1") is not an id
        return ids[s]
    for rid, tok in ids.items():                              # an id embedded in a longer string (a URL, a message)
        if len(rid) >= 6 and rid in s:
            s = re.sub(r"(?<![\w-])" + re.escape(rid) + r"(?![\w-])", tok, s)
    return _volatile(s)


def _norm_json(v, ids, subs, k=None):
    if isinstance(v, str):
        return _norm_str(v, ids, subs, k)
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        if k and IDLIKE_KEY.search(k) and str(v) in ids:
            return ids[str(v)]
        if k and TIMELIKE_KEY.search(k) and isinstance(v, int) and 10 ** 9 <= v < 10 ** 13:
            return "<epoch>"
        return v
    if isinstance(v, list):
        return [_norm_json(x, ids, subs, k) for x in v]
    if isinstance(v, dict):
        return {kk: _norm_json(x, ids, subs, kk) for kk, x in v.items()}
    return v


def _norm_path(path: str, ids: dict) -> str:
    path, _, qs = path.partition("?")
    segs = [ids.get(s, _volatile(s)) for s in path.split("/")]
    return "/".join(segs)


def _subst(obj, mapping: dict, k=None):
    """Replace recorded ids by this run's ids inside a request body (ints only under id-like keys)."""
    if isinstance(obj, str):
        return mapping.get(obj, obj)
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if k and IDLIKE_KEY.search(k) and str(obj) in mapping:
            new = mapping[str(obj)]
            return int(new) if str(new).lstrip("-").isdigit() else new
        return obj
    if isinstance(obj, list):
        return [_subst(x, mapping, k) for x in obj]
    if isinstance(obj, dict):
        return {kk: _subst(x, mapping, kk) for kk, x in obj.items()}
    return obj


def _suffix(v: str, tag: str) -> str:
    local, at, domain = v.partition("@")
    return f"{local}+{tag}@{domain}" if at else f"{v}-{tag}"


def _skip_varying(k: str) -> bool:
    """Identifier-like and classifier fields are NOT made unique: a suffix on a reference (customer_id) or on a value the API
    validates against a list (country_code "US" -> "US-r1") is rejected or changes the answer, and that is noise, not a regression."""
    return bool(IDLIKE_KEY.search(k) or CLASSIFIER_KEY.search(k))


def _vary(obj, run_idx: int, subs: dict, k=None):
    """Make unique-ish body values (email / username / ...) distinct per run; remember every value -> token."""
    if isinstance(obj, dict):
        return {kk: _vary(x, run_idx, subs, kk) for kk, x in obj.items()}
    if isinstance(obj, list):
        return [_vary(x, run_idx, subs, k) for x in obj]
    if isinstance(obj, str) and k and UNIQUE_KEY.search(k) and not _skip_varying(k):
        token = f"<U:{k}>"
        subs[obj] = token
        if run_idx == 0:
            return obj
        new = _suffix(obj, f"r{run_idx}")
        subs[new] = token
        return new
    return obj


def _tname(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    return "array" if isinstance(v, list) else "object"


def _numeric(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_create(ep: dict) -> bool:
    """A POST on a collection path (the same path also has a GET): it creates one item. Only creates get unique-value variation
    (a repeated create would 409 otherwise). A login or an action (POST /auth/login, POST /x/{id}/advance) is never varied."""
    if ep["method"] != "POST" or ep["path_params"]:
        return False
    spec = ep.get("spec") or {}
    return "get" in ((spec.get("paths") or {}).get(ep["path"]) or {})


def _method(step: dict) -> str:
    return step["ep"]["method"] if "ep" in step else step["method"]


def _outcome(r: dict):
    """What one step did, as far as its write effect goes: (2xx?, created?). Skipped and transport steps have their own outcome."""
    if r.get("skipped"):
        return "skipped"
    if r.get("transport"):
        return "transport"
    return (200 <= r["status"] < 300, bool(r.get("created")))


# ---------------------------------------------------------------- fixtures (ids that setup() wrote into BODIES)

def fixture_pairs(bodies_a: dict, bodies_b: dict) -> list:
    """[(a_value, b_value)]: values at the same place of the two BODIES snapshots that differ (ids created by setup on each side)."""
    out = []

    def walk(x, y):
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) & set(y)):
                walk(x[k], y[k])
        elif isinstance(x, list) and isinstance(y, list):
            for p, q in zip(x, y):
                walk(p, q)
        elif type(x) in (str, int) and type(y) in (str, int) and x != y:
            out.append((str(x), str(y)))

    walk(bodies_a or {}, bodies_b or {})
    seen, uniq = set(), []
    for a_val, b_val in out:
        if a_val not in seen:
            seen.add(a_val)
            uniq.append((a_val, b_val))
    return uniq


def fixture_maps(pairs: list):
    """(tokens_a, tokens_b, xlate): both sides tokenise their fixture ids the same way; the plan's A literals become B's ids."""
    tokens_a = {a: f"<FIX:{n}>" for n, (a, _) in enumerate(pairs)}
    tokens_b = {b: f"<FIX:{n}>" for n, (_, b) in enumerate(pairs)}
    return tokens_a, tokens_b, {a: b for a, b in pairs}


# ---------------------------------------------------------------- execution of one run

def _record(resp, role, method, tpl, path, body, ids, subs, step) -> dict:
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    ctype = headers.get("content-type", "").split(";")[0].strip().lower()
    if resp.json is not None:
        norm = _norm_json(resp.json, ids, subs)
    else:
        norm = None
    return {"step": step, "role": role, "method": method, "tpl": tpl, "path": path, "req": body, "status": resp.status,
            "ctype": ctype, "hnames": sorted(h for h in headers if h not in IGNORED_HEADERS), "json": norm,
            "is_json": resp.json is not None, "text": _norm_str(resp.text, ids, subs) if resp.json is None else "",
            "raw": resp.text[:300], "transport": resp.status == TRANSPORT_ERROR, "resp_json": resp.json}


def _skipped(step: dict, i: int, why: str = "") -> dict:
    """Placeholder for a step that was not sent on this side (the item it needs was not created here). Never compared."""
    ep = step["ep"]
    return {"step": i, "role": "-", "method": ep["method"], "tpl": ep["path"], "path": ep["path"], "req": None, "status": 0,
            "ctype": "", "hnames": [], "json": None, "is_json": False, "text": "", "raw": "", "transport": False,
            "resp_json": None, "skipped": True, "created": False, "variant": step.get("variant", ""),
            "group": step.get("group", 0), "omitted": {}, "filter": None, "items": None, "query": None, "why": why}


def _list_key(js):
    """The LIST_KEYS entry that holds the rows of a list answer ('items', 'data' or 'results'), or None."""
    if not isinstance(js, dict):
        return None
    for k in LIST_KEYS:
        if isinstance(js.get(k), list):
            return k
    return None


def _items(js, flt, ids, subs):
    """For a filter probe: [{"id": token, "f": the filtered field as text or ABSENT}] of the returned items, else None."""
    key = _list_key(js)
    if not flt or key is None:
        return None
    out = []
    for it in js[key]:
        if not isinstance(it, dict):
            continue
        fv = it.get(flt["param"], ABSENT)
        out.append({"id": str(_norm_json(it.get("id"), ids, subs, "id")),
                    "f": ABSENT if fv is ABSENT else str(_norm_json(fv, ids, subs, flt["param"]))})
    return out


def _page_size_of(js):
    """(total, page_size) of a paginated list answer, or None. 'count' is taken as the total when there is no 'total'."""
    if not isinstance(js, dict):
        return None
    t, s = js.get("total", js.get("count")), js.get("page_size")
    if isinstance(t, (int, str)) and str(t).isdigit() and isinstance(s, int) and s > 0:
        return int(t), s
    return None


def _finalise(recs, ids, subs):
    """Normalise paths (and the label of each step) only after the whole run is known: ids become tokens."""
    for r in recs:
        r["tpl"] = _norm_path(r["tpl"], ids)
        r["npath"] = _norm_path(r["path"], ids)


class PlanRunner:
    """One side's execution of the plan, one step at a time. The lockstep driver alternates A and B."""

    def __init__(self, api, qa, run_idx: int, xlate=None, tokens=None):
        self.api, self.qa, self.run_idx = api, qa, run_idx
        self.xlate = xlate or {}                 # plan literals (A's fixture ids) -> this side's ids
        self.ids = dict(tokens or {})            # this side's raw id -> token
        self.subs, self.by_coll, self.pins, self.recs = {}, {}, {}, []
        self.lastlist = {}                       # collection path -> (total, page_size) of its last list answer

    def step(self, i: int, step: dict) -> dict:
        ep = step["ep"]
        path, missing = ep["path"], None
        for prm in ep["path_params"]:
            if step.get("fill"):
                value = step["fill"].get(prm, MISSING_ID)
            elif step.get("use"):
                if step["use"] not in self.pins:
                    missing = f"no item for pin {step['use']} on this side"
                    break
                value = self.pins[step["use"]]
            else:
                coll = prefix_of(ep["path"], prm)
                if coll not in self.by_coll:
                    missing = f"no {coll} item was created on this side"
                    break
                value = self.by_coll[coll]
            path = path.replace("{" + prm + "}", str(value))
        if missing is not None:
            rec = _skipped(step, i, missing)
            self.recs.append(rec)
            return rec
        query = step["query"]
        if step.get("past_end"):                 # one page past this side's own last page (or a far page if unknown)
            last = self.lastlist.get(ep["path"])
            if last and last[0] is not None:
                query = {**(query or {}), "page": str(max(1, -(-last[0] // last[1])) + 1)}
            else:
                query = {**(query or {}), "page": str(PAGE_FAR)}
        body = None
        if step["body"] is not None:
            body = _subst(step["body"], self.xlate) if self.xlate else step["body"]
            if _is_create(ep):
                body = _vary(body, self.run_idx, self.subs)
        role = _pick_role(self.api, self.qa, step)
        resp = self.api.call(role, ep["method"], path, body, query, raw=step.get("raw"))
        nid = extract_id(resp.json) if ep["method"] == "POST" and resp.ok else None
        if nid is not None:
            self.ids[str(nid)] = f"<ID:{i}>"
            if step.get("save"):
                self.pins[step["save"]] = nid
            if not ep["path_params"] and not step.get("variant"):
                self.by_coll[ep["path"].rstrip("/")] = nid
        if ep["method"] == "GET" and not ep["path_params"] and resp.ok:
            info = _page_size_of(resp.json)
            if info:
                self.lastlist[ep["path"]] = info
        rec = _record(resp, role, ep["method"], ep["path"], path, "<raw>" if step.get("raw") is not None else body,
                      self.ids, self.subs, i)
        rec.update(created=nid is not None, variant=step.get("variant", ""), group=step.get("group", 0),
                   omitted=step.get("omitted") or {}, filter=step.get("filter"), skipped=False,
                   items=_items(resp.json, step.get("filter"), self.ids, self.subs), query=query)
        self.recs.append(rec)
        return rec

    def finish(self) -> list:
        _finalise(self.recs, self.ids, self.subs)
        return self.recs


class ReplayRunner:
    """One side's replay of recorded api.log entries. Recorded ids (from the recorded create responses) are mapped to the ids
    this side got."""

    def __init__(self, api, run_idx: int):
        self.api, self.run_idx = api, run_idx
        self.ids, self.subs, self.mapping, self.recs = {}, {}, {}, []

    def step(self, i: int, e: dict) -> dict:
        path = "/".join(self.mapping.get(s, s) for s in e["path"].split("/"))
        try:
            rec_id = extract_id(json.loads(e.get("body") or "null"))
        except ValueError:
            rec_id = None
        body = _subst(e.get("request"), self.mapping) if isinstance(e.get("request"), (dict, list)) else None
        if body is not None and e["method"] == "POST" and rec_id is not None:
            body = _vary(body, self.run_idx, self.subs)
        role = e.get("role") if e.get("role") in self.api.roles else "anon"
        resp = self.api.call(role, e["method"], path, body, e.get("query"))
        nid = None
        if e["method"] == "POST" and resp.ok:
            nid = extract_id(resp.json)
            if nid is not None:
                self.ids[str(nid)] = f"<ID:{i}>"
                if rec_id is not None:
                    self.mapping[str(rec_id)] = str(nid)
        rec = _record(resp, role, e["method"], path, path, body, self.ids, self.subs, i)      # label = actual path, ids tokenised later
        rec.update(created=nid is not None, query=e.get("query"), skipped=False, variant="", group=0, omitted={}, filter=None,
                   items=None)
        self.recs.append(rec)
        return rec

    def finish(self) -> list:
        _finalise(self.recs, self.ids, self.subs)
        return self.recs


def _pick_role(api, qa, step) -> str:
    if step["role"] and step["role"] in api.roles:
        return step["role"]
    owner = getattr(qa, "OWNER", {}).get(step["key"], "user_a")
    if owner in api.roles:
        return owner
    return next((r for r in api.roles if r != "anon"), "anon")


def exec_plan(api, plan, qa, run_idx: int, tokens=None, xlate=None) -> list:
    """The whole plan on one side, sequentially (noise runs, pre-run fingerprint)."""
    runner = PlanRunner(api, qa, run_idx, xlate=xlate, tokens=tokens)
    for i, step in enumerate(plan):
        runner.step(i, step)
    return runner.finish()


def exec_replay(api, entries, run_idx: int) -> list:
    runner = ReplayRunner(api, run_idx)
    for i, e in enumerate(entries):
        runner.step(i, e)
    return runner.finish()


def lockstep(steps, runner_a, runner_b, fingerprint=None):
    """Send each step to A, then to B, before the next one. The state flag of every record says whether the two histories are still
    equal: a write whose outcome differs (or any write while the state is already diverged) re-checks the collection fingerprint
    through `fingerprint()` (True = equal again). Without a fingerprint the state stays diverged after the first differing write."""
    ok = True
    for i, s in enumerate(steps):
        a = runner_a.step(i, s)
        b = runner_b.step(i, s)
        write = _method(s) != "GET"
        differs = _outcome(a) != _outcome(b)
        if write and (differs or not ok):
            ok = fingerprint() if fingerprint is not None else (ok and not differs)
        a["state"] = b["state"] = "equal" if ok else "DIVERGED"
    return runner_a.finish(), runner_b.finish()


def _fp_value(resp):
    js = resp.json
    if not isinstance(js, dict):
        return (resp.status, None, None)
    length = next((len(v) for v in js.values() if isinstance(v, list)), None)
    total = js.get("total", js.get("count"))
    return (resp.status, length, None if total is None else str(total))


def _fingerprint(api, qa, steps) -> list:
    return [_fp_value(api.call(_pick_role(api, qa, s), "GET", s["ep"]["path"], None, None)) for s in steps]


# ---------------------------------------------------------------- probes (phase 4: after the main sequence)

def _json_schema(node):
    if not isinstance(node, dict):
        return None
    return ((node.get("content") or {}).get("application/json") or {}).get("schema")


def documented_defaults(doc: dict, ep: dict) -> dict:
    """{field: default} documented for one operation, in its request body or in a 2xx response schema."""
    op = ((doc.get("paths") or {}).get(ep["path"]) or {}).get(ep["method"].lower()) or {}
    schemas = [_json_schema(op.get("requestBody"))]
    for code, resp in (op.get("responses") or {}).items():
        if str(code).startswith("2"):
            schemas.append(_json_schema(resp))
    out = {}
    for sch in schemas:
        if not isinstance(sch, dict):
            continue
        for name, prop in (resolve(sch, doc).get("properties") or {}).items():
            p = resolve(prop, doc)
            if isinstance(p, dict) and "default" in p:
                out.setdefault(name, p["default"])
    return out


def _omit(doc, ep, body) -> dict:
    """Documented defaults of the fields a CREATE body leaves out (PATCH/PUT/DELETE do not default anything)."""
    if ep["method"] != "POST" or ep["path_params"] or not isinstance(body, dict):
        return {}
    return {k: v for k, v in documented_defaults(doc, ep).items() if k not in body}


def _ptype(prop: dict):
    t = prop.get("type")
    if isinstance(t, list):
        return next((x for x in t if x != "null"), None), "null" in t
    return t, bool(prop.get("nullable"))


def body_variants(schema, spec, base, cap=VARIANT_CAP) -> list:
    """[(name, body)]: `minimal` plus boundary, edge and wrong-type bodies, one property changed at a time from `base`."""
    s = resolve(schema, spec)
    props = {k: resolve(v, spec) for k, v in (s.get("properties") or {}).items()}
    if not props or not isinstance(base, dict):
        return []
    required = [r for r in (s.get("required") or []) if r in props]
    out = [("minimal", {k: base[k] for k in required if k in base})]

    def put(tag, name, val):
        out.append((f"{tag}:{name}", {**base, name: val}))

    for name, prop in props.items():
        if not isinstance(prop, dict):
            continue
        cur = base.get(name)
        t, nullable = _ptype(prop)
        if "enum" in prop:
            out += [(f"enum={v}:{name}", {**base, name: v}) for v in prop["enum"] if v != cur]
        if t == "array":
            put("empty", name, [])
        if t == "string":
            put("empty", name, "")
            if prop.get("minLength"):
                put("min", name, "x" * min(int(prop["minLength"]), 200))
            if "maxLength" in prop:
                put("max", name, "x" * min(int(prop["maxLength"]), 200))
            if prop.get("format") == "email":
                put("format", name, "not-an-email")
        if t in ("integer", "number"):
            if "minimum" in prop:
                put("min", name, prop["minimum"])
            if "maximum" in prop:
                put("max", name, prop["maximum"])
        if t == "boolean":
            put("flip", name, (not cur) if isinstance(cur, bool) else True)
        if nullable:
            put("null", name, None)
        if t in WRONG_BY_TYPE:
            put("type", name, WRONG_BY_TYPE[t])
    out += [(f"missing:{r}", {k: v for k, v in base.items() if k != r}) for r in required]
    return out[:cap]


def _copy_body(schema, spec, base, i: int) -> dict:
    """Fixture copy i of a create body: unique values get a suffix, enums cycle, integers get non-round values."""
    s = resolve(schema, spec)
    props = {k: resolve(v, spec) for k, v in (s.get("properties") or {}).items()}
    out = json.loads(json.dumps(base))
    for name, val in list(out.items()):
        prop = props.get(name) or {}
        if UNIQUE_KEY.search(name) and isinstance(val, str):
            out[name] = _suffix(val, f"c{i}")
        elif prop.get("enum") and not isinstance(val, bool):
            out[name] = prop["enum"][i % len(prop["enum"])]
        elif isinstance(val, int) and not isinstance(val, bool):
            new = val + 37 * i + 1
            if "maximum" in prop:
                new = min(new, int(prop["maximum"]))
            if "minimum" in prop:
                new = max(new, int(prop["minimum"]))
            out[name] = new
    return out


def _base_body(ep, bodies, doc):
    """A fresh copy of the body this operation is normally called with (qa BODIES, else an example), or None."""
    if ep.get("body_schema") is None:
        return None
    body = bodies.get(key(ep))
    if body is None:
        body = example(ep["body_schema"], doc)
    return json.loads(json.dumps(body)) if isinstance(body, dict) else None


def _props(ep) -> dict:
    return (ep.get("body_schema") or {}).get("properties") or {}


def _fixture_steps(doc, eps, bodies, skip, counter):
    """(creates, deletes): FIXTURE_COPIES more creates of every collection create, and their DELETEs (run after the main reads)."""
    creates, deletes = [], []
    if FIXTURE_COPIES <= 0:
        return creates, deletes
    item_delete = {}
    for e in eps:
        if e["method"] == "DELETE" and len(e["path_params"]) == 1:
            p = e["path_params"][0]
            if e["path"] == f"{prefix_of(e['path'], p)}/{{{p}}}":
                item_delete[prefix_of(e["path"], p)] = e
    for e in eps:
        if key(e) in skip or not _is_create(e) or e["body_schema"] is None:
            continue
        base = _base_body(e, bodies, doc)
        if base is None:
            continue
        d = item_delete.get(e["path"].rstrip("/"))
        for i in range(1, FIXTURE_COPIES + 1):
            pin = f"fx{next(counter)}"
            creates.append(_step(e, body=_copy_body(e["body_schema"], doc, base, i), variant=f"fixture:{i}", save=pin, phase=0))
            if d is not None:
                deletes.append(_step(d, use=pin, variant="fixture-undo", phase=3))
    return creates, deletes


def _filter_group(ctx, e, coll, name, values) -> list:
    """Filter probe for one enum query parameter: distinguishable items first (one per value), then GET ?name=value for every
    value and one unknown value, then the undo. Compared as id sets on both sides by compare()."""
    doc, bodies, item_ep, pin, undo = ctx["doc"], ctx["bodies"], ctx["item_ep"], ctx["pin"], ctx["undo"]
    create = ctx["coll_post"].get(coll)
    cbase = _base_body(create, bodies, doc) if create is not None else None
    patch = (item_ep.get(coll) or {}).get("PATCH") or (item_ep.get(coll) or {}).get("PUT")
    steps, made = [], []
    if create is not None and cbase is not None:
        if name in _props(create):
            for v in values:
                p = pin()
                made.append(p)
                steps.append(_step(create, body={**cbase, name: v}, variant=f"distinguish:{name}={v}", save=p))
        elif patch is not None and name in _props(patch):
            for v in values:
                p = pin()
                made.append(p)
                steps.append(_step(create, body=cbase, variant="probe-create", save=p))
                steps.append(_step(patch, use=p, body={name: v}, variant=f"distinguish:{name}={v}"))
    for v in values:
        steps.append(_step(e, query={name: str(v)}, filter={"param": name, "value": str(v)}, variant=f"filter:{name}={v}"))
    steps.append(_step(e, query={name: "not-a-real-value"}, variant=f"bad:{name}=not-a-real-value"))
    for p in made:
        steps += undo(coll, p)
    return steps


def probe_groups(doc, eps, bodies, skip, notes) -> list:
    """Probe groups (lists of steps), in order. A group creates what it needs and undoes what it created."""
    coll_post, item_ep = {}, {}
    for e in eps:
        if key(e) in skip:
            continue
        if e["method"] == "POST" and not e["path_params"]:
            coll_post[e["path"].rstrip("/")] = e
        elif len(e["path_params"]) == 1 and e["method"] in ("GET", "PATCH", "PUT", "DELETE"):
            p = e["path_params"][0]
            coll = prefix_of(e["path"], p)
            if e["path"] == f"{coll}/{{{p}}}":
                item_ep.setdefault(coll, {})[e["method"]] = e
    counter = itertools.count()
    groups, used, dropped = [], [0], [0]

    def pin():
        return f"p{next(counter)}"

    def undo(coll, p):
        d = (item_ep.get(coll) or {}).get("DELETE")
        return [_step(d, use=p, variant="undo")] if d is not None else []

    def add(group):
        if used[0] + len(group) > PROBE_BUDGET:
            dropped[0] += 1
            return
        used[0] += len(group)
        groups.append(group)

    ctx = {"doc": doc, "bodies": bodies, "coll_post": coll_post, "item_ep": item_ep, "pin": pin, "undo": undo}
    for e in eps:
        if key(e) in skip:
            continue
        body_schema = e["body_schema"] if e["method"] in WRITE_METHODS else None
        base = _base_body(e, bodies, doc) if body_schema is not None else None
        coll = prefix_of(e["path"], e["path_params"][0]) if e["path_params"] else e["path"].rstrip("/")
        if e["method"] == "POST" and not e["path_params"] and base is not None:
            for name, body in body_variants(body_schema, doc, base):
                p = pin()
                add([_step(e, body=body, variant=name, save=p, omitted=_omit(doc, e, body))] + undo(coll, p))
            p = pin()
            add([_step(e, raw=MALFORMED_JSON, variant="malformed-json", save=p)] + undo(coll, p))
        elif e["method"] in ("PATCH", "PUT") and e["path_params"] and base is not None and coll in coll_post:
            cbase = _base_body(coll_post[coll], bodies, doc)
            if cbase is not None:
                cases = body_variants(body_schema, doc, base) + [("malformed-json", None)]
                for name, body in cases:
                    p = pin()
                    raw = MALFORMED_JSON if name == "malformed-json" else None
                    add([_step(coll_post[coll], body=cbase, variant="probe-create", save=p),
                         _step(e, use=p, body=body, raw=raw, variant=name)] + undo(coll, p))
        if e["method"] == "POST" and len(e["path_params"]) == 1 and coll in coll_post and base is None:
            # a state-transition endpoint POST /x/{id}/verb: walk it WALK_MAX times on one created item, reading it in between
            tail = e["path"].split("{" + e["path_params"][0] + "}", 1)[1]
            cbase = _base_body(coll_post[coll], bodies, doc)
            get_item = (item_ep.get(coll) or {}).get("GET")
            if tail.startswith("/") and "{" not in tail and cbase is not None:
                p = pin()
                steps = [_step(coll_post[coll], body=cbase, variant="probe-create", save=p)]
                for k in range(1, WALK_MAX + 1):
                    steps.append(_step(e, use=p, variant=f"walk:{k}"))
                    if get_item is not None:
                        steps.append(_step(get_item, use=p, variant=f"walk-read:{k}"))
                add(steps + undo(coll, p))
        if e["path_params"] and e["method"] in ("GET", "PATCH", "PUT", "DELETE", "POST"):
            for label, lit in UNKNOWN_IDS:
                add([_step(e, fill={p: lit for p in e["path_params"]}, body=base, variant=f"unknown-id:{label}")])
        if e["method"] == "GET" and not e["path_params"]:
            for q in e["query_params"]:
                name, sch = q["name"], q["schema"]
                if sch.get("enum"):
                    add(_filter_group(ctx, e, coll, name, sch["enum"]))
                elif sch.get("type") in ("integer", "number"):
                    bad = ["abc"] + ([str(sch["minimum"] - 1)] if "minimum" in sch else []) \
                        + ([str(sch["maximum"] + 1)] if "maximum" in sch else [])
                    for v in bad:
                        add([_step(e, query={name: v}, variant=f"bad:{name}={v}")])
                    for v in [sch[k] for k in ("minimum", "maximum") if k in sch]:
                        add([_step(e, query={name: str(v)}, variant=f"bound:{name}={v}")])
                if name == "page" and sch.get("type") in ("integer", "number"):
                    add([_step(e, query={"page": "0"}, variant="bound:page=0")])
                    add([_step(e, query={"page": "-1"}, variant="bound:page=-1")])
                    add([_step(e, query={"page": str(PAGE_FAR)}, variant="past-end:far")])
                    add([_step(e, past_end=True, variant="past-end:page")])
    if dropped[0]:
        notes.append(f"probe budget ({PROBE_BUDGET} steps) reached: {dropped[0]} probe group(s) not run")
    return groups


def _step(ep, *, body=None, query=None, role=None, phase=4, group=0, variant="", **kw) -> dict:
    """One planned request. Keys: fill (path params by literal), use (path params from a pinned create), save (pin the id this
    create returns), raw (bytes sent as the body), filter ({param, value} of a filter probe), omitted ({field: documented default}),
    past_end (query page computed at run time from this side's last list answer)."""
    step = {"ep": ep, "key": key(ep), "body": body, "query": query, "role": role, "phase": phase, "group": group,
            "variant": variant, "omitted": {}, "fill": None, "use": None, "save": None, "raw": None, "filter": None,
            "past_end": False}
    step.update(kw)
    return step


def build_plan(doc: dict, qa, seed=None, notes=None, bodies=None) -> list:
    """Deterministic request plan: creators first (plus the fixture copies), then reads, then updates, deletes last (plus the
    fixture undo), then the probe groups (phase 4) unless DIFF_PROBES is False. The seed shuffles inside a phase."""
    eps = endpoints(doc)
    if bodies is None:
        bodies = getattr(qa, "BODIES", {}) or {}
    skip = set(getattr(qa, "SKIP", set())) | set(getattr(qa, "DIFF_SKIP", set()))
    roles_override = getattr(qa, "DIFF_ROLE", {})
    phases = {0: [], 1: [], 2: [], 3: []}
    for ep in eps:
        k = key(ep)
        if k in skip:
            continue
        if ep["method"] == "POST" and not ep["path_params"]:
            phase = 0
        elif ep["method"] == "DELETE":
            phase = 3
        elif ep["method"] == "GET" and not ep["path_params"]:
            phase = 1
        else:
            phase = 2
        body = None
        if k in bodies:
            body = json.loads(json.dumps(bodies[k]))
        elif ep["body_schema"] is not None and ep["method"] in WRITE_METHODS:
            body = example(ep["body_schema"], doc)
        query = {q["name"]: str(example(q["schema"], doc)) for q in ep.get("query_params", []) if q["required"]} or None
        phases[phase].append(_step(ep, body=body, query=query, role=roles_override.get(k), phase=phase,
                                   omitted=_omit(doc, ep, body)))
    rng = random.Random(seed) if seed is not None else None
    fx_creates, fx_deletes = _fixture_steps(doc, eps, bodies, skip, itertools.count())
    plan = []
    for p in sorted(phases):
        items = sorted(phases[p], key=lambda s: s["key"])
        if rng:
            rng.shuffle(items)
        plan += items
        if p == 0:
            plan += fx_creates
        if p == 3:
            plan += fx_deletes
    if getattr(qa, "DIFF_PROBES", True):
        for gi, group in enumerate(probe_groups(doc, eps, bodies, skip, notes), 1):
            for step in group:
                step["group"] = gi
                plan.append(step)
    if notes is not None and not plan:
        notes.append("OpenAPI document yielded no endpoints to exercise")
    return plan


def _pre_plan_reads(plan) -> list:
    """The collection reads of the main sequence: the state fingerprint (before the run and after writes)."""
    return [s for s in plan if s["phase"] == 1 and s["ep"]["method"] == "GET" and not s["ep"]["path_params"]]


def pre_state(api_a, api_b, plan, qa) -> dict:
    """GET fingerprint of the collection endpoints before any write: {equal: True|False|None, detail}.

    A is read twice (its own noise is excluded). A difference counts as UNEQUAL STATE when it is a status, an array length or a
    numeric value that is not a declared query parameter (so `limit: 20` vs `limit: 10` is not state)."""
    fp = _pre_plan_reads(plan)
    if not fp:
        return {"equal": None, "detail": "no collection GET in the plan"}
    a1 = exec_plan(api_a, fp, qa, 0)
    a2 = exec_plan(api_a, fp, qa, 1)
    b1 = exec_plan(api_b, fp, qa, 0)
    if any(r["transport"] for r in a1 + a2 + b1):
        return {"equal": None, "detail": "no HTTP answer to the pre-run GETs"}
    qnames = {q["name"] for s in plan for q in s["ep"]["query_params"]}
    noise = learn_noise(a1, [a2])
    diffs = []
    for ra, rb in zip(a1, b1):
        slot = noise.get(f"{ra['method']} {ra['tpl']}", {"status": False, "paths": set()})
        for change, jpath, av, bv in diff_records(ra, rb):
            if change != "status" and any(_under(jpath, n) for n in slot["paths"]):
                continue
            if change == "status" and slot["status"]:
                continue
            leaf = re.split(r"[.\[]", jpath)[-1]
            if change in ("status", "len") or (change == "value" and _numeric(av) and leaf not in qnames):
                diffs.append(f"{ra['method']} {ra['tpl']} {jpath}")
    if diffs:
        return {"equal": False, "detail": "; ".join(diffs[:3])}
    return {"equal": True, "detail": "pre-run GET fingerprint equal"}


def _pre_notes(pre: dict, notes: list) -> None:
    if pre["equal"] is True:
        notes.append("pre-run state: GET fingerprint equal on A and B, so both start from equal state; both then receive the "
                     "identical request sequence (same plan and seed)")
    elif pre["equal"] is False:
        notes.append(f"setup: pre-run state differs between A and B ({pre['detail']}): aggregate differences are reported as "
                     "UNEQUAL STATE, not as evidence of a code change")
    else:
        notes.append(f"setup: pre-run state could not be checked ({pre['detail']})")


# ---------------------------------------------------------------- comparison

def _walk(a, b, path, out):
    ta, tb = _tname(a), _tname(b)
    if ta != tb:
        out.append(("type", path or "$", a, b))
    elif ta == "object":
        for k in sorted(set(a) | set(b)):
            p = f"{path}.{k}" if path else k
            if k not in b:
                out.append(("removed", p, a[k], None))
            elif k not in a:
                out.append(("added", p, None, b[k]))
            else:
                _walk(a[k], b[k], p, out)
    elif ta == "array":
        if len(a) != len(b):
            out.append(("len", f"{path}.#len" if path else "#len", len(a), len(b)))
        for x, y in list(zip(a, b))[:LIST_CAP]:
            _walk(x, y, path + "[*]", out)
    elif a != b:
        out.append(("value", path or "$", a, b))


def diff_records(ra: dict, rb: dict) -> list:
    """[(change, jpath, a_value, b_value)] between two normalised records of the same step; each (change, jpath) once."""
    out = []
    if ra["status"] != rb["status"]:
        return [("status", "$status", ra["status"], rb["status"])]
    if ra["ctype"] != rb["ctype"]:
        out.append(("value", "$header.content-type", ra["ctype"], rb["ctype"]))
    for h in sorted(set(ra["hnames"]) - set(rb["hnames"])):
        out.append(("removed", f"$header.{h}", h, None))
    for h in sorted(set(rb["hnames"]) - set(ra["hnames"])):
        out.append(("added", f"$header.{h}", None, h))
    if ra["is_json"] and rb["is_json"]:
        _walk(ra["json"], rb["json"], "", out)
    elif ra["is_json"] != rb["is_json"]:
        out.append(("type", "$", "json" if ra["is_json"] else "non-json", "json" if rb["is_json"] else "non-json"))
    elif ra["text"] != rb["text"]:
        out.append(("value", "$text", ra["text"][:120], rb["text"][:120]))
    seen, uniq = set(), []
    for d in out:
        if (d[0], d[1]) not in seen:
            seen.add((d[0], d[1]))
            uniq.append(d)
    return uniq


def _under(path: str, noisy: str) -> bool:
    return path == noisy or path.startswith(noisy + ".") or path.startswith(noisy + "[")


def learn_noise(run_a, noise_runs) -> dict:
    """What differs between runs of the SAME code is noise: {label: {"status": bool, "paths": set(jpath)}}."""
    noise = {}
    for run_n in noise_runs:
        for ra, rn in zip(run_a, run_n):
            label = f"{ra['method']} {ra['tpl']}"
            slot = noise.setdefault(label, {"status": False, "paths": set()})
            if ra.get("skipped") or rn.get("skipped"):
                continue
            if ra["transport"] or rn["transport"]:
                slot["status"] = True
                continue
            for change, jpath, _, _ in diff_records(ra, rn):
                if change == "status":
                    slot["status"] = True
                else:
                    slot["paths"].add(jpath)
    return noise


def _glob(pat: str):
    """Shell-style '*' and '?' only. Unlike fnmatch, '[' and ']' are literal, so 'items[*].priority' names the path the diff prints."""
    return re.compile("".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pat) + r"\Z", re.S)


def _allowed(label: str, jpath: str, patterns: list) -> bool:
    for pat in patterns:
        parts = pat.split(None, 2)
        if len(parts) == 2 and _glob(pat.strip()).match(label):
            return True
        if len(parts) == 3 and _glob(pat.strip()).match(f"{label} {jpath}"):
            return True
    return False


def _status_sev(a: int, b: int) -> str:
    if 200 <= a < 300 and b >= 500:
        return "high"
    if 200 <= a < 300 and 400 <= b < 500:
        return "medium"
    if 400 <= a < 500 and b >= 500:
        return "medium"
    if 400 <= a < 500 and 400 <= b < 500:
        return "medium"          # the error code changed: a client that branches on it breaks
    if a >= 500 and b < 500:
        return "info"
    return "low"


def _sequence(ra, recs_a, recs_b) -> str:
    lo, hi = max(0, ra["step"] - 5), ra["step"] + 1
    return "\n".join(f"{r['method']} {r['path']} -> A:{r['status']} B:{b['status']}"
                     for r, b in zip(recs_a[lo:hi], recs_b[lo:hi]))


def _paging_kind(change, jpath, ra):
    """'past-end' / 'default' when a list answer differs in a way that is about paging, else None."""
    if ra["method"] != "GET" or "{" in ra["tpl"]:
        return None
    if (ra.get("variant") or "").startswith("past-end") and change == "len" and jpath in LIST_LEN:
        return "past-end"
    if ra.get("query") is None and change in ("len", "value") and jpath in LIST_LEN + ("page_size",):
        return "default"
    return None


def _finding(change, jpath, av, bv, ra, rb, recs_a, recs_b) -> dict:
    label = f"{ra['method']} {ra['tpl']}"
    omitted = ra.get("omitted") or {}
    probe = f" (probe {ra['variant']})" if ra.get("variant") else ""
    paging = _paging_kind(change, jpath, ra) if change in ("len", "value") else None
    if change == "status":
        kind, sev = "DIFF-STATUS", _status_sev(av, bv)
        what = f"status {av} -> {bv}"
        if ra["method"] == "POST":
            what += " (later steps that depend on this create may cascade)"
    elif jpath.startswith("$header."):
        kind, sev = "DIFF-HEADER", "info"
        what = {"removed": "header removed", "added": "header added"}.get(change, "header value changed") + f": {jpath[8:]}"
        if change == "value":
            what += f" {av!r} -> {bv!r}"
    elif paging == "past-end":
        kind, sev = "DIFF-PAGING", "medium"
        what = (f"a page past the end returns different items: A (old) returns {av} item(s), B (new) returns {bv} item(s) "
                "(past the last page, the list must be empty)")
    elif paging == "default":
        kind, sev = "DIFF-PAGING", "medium"
        what = (f"default page size changed: the request sent no page size, A (old) answers {jpath} {av!r}, "
                f"B (new) answers {bv!r}")
    elif change in ("removed", "added", "type"):
        kind = "DIFF-SHAPE"
        sev = {"removed": "medium", "type": "medium", "added": "info"}[change]
        what = {"removed": f"field removed: {jpath}", "added": f"field added: {jpath}",
                "type": f"type changed at {jpath}: {_tname(av)} -> {_tname(bv)}"}[change]
    elif change == "value" and "." not in jpath and "[" not in jpath and jpath in omitted and av == omitted[jpath]:
        kind, sev = "DIFF-DEFAULT", "medium"
        what = (f"documented default {av!r} of {jpath!r} changed: B (new) answers {bv!r} when the field is omitted")
    else:
        kind, sev = "DIFF-BODY", "low"
        what = f"{'array length' if change == 'len' else 'value'} changed at {jpath}: {str(av)[:80]!r} -> {str(bv)[:80]!r}"
    req = f"{ra['method']} {ra['path']}" + (f" body={json.dumps(ra['req'], default=str)[:150]}" if ra["req"] is not None else "")
    detail = (f"{what}{probe}. request: {req}. A (old) answered {ra['status']} {ra['raw'][:200]!r}; "
              f"B (new) answered {rb['status']} {rb['raw'][:200]!r}")
    return {"kind": kind, "severity": sev, "endpoint": label, "path": jpath, "detail": detail,
            "sequence": _sequence(ra, recs_a, recs_b), "count": 1}


def _filter_finding(ra, rb, param, value, recs_a, recs_b) -> dict:
    def wrong(items):
        return sum(1 for x in items if x["f"] not in (ABSENT, value))
    what = (f"filter {param}={value}: A (old) returned {len(ra['items'])} item(s) ({wrong(ra['items'])} with another {param}); "
            f"B (new) returned {len(rb['items'])} item(s) ({wrong(rb['items'])} with another {param})")
    req = f"{ra['method']} {ra['path']}"
    detail = (f"{what}{' (probe ' + ra['variant'] + ')' if ra.get('variant') else ''}. request: {req}. "
              f"A (old) answered {ra['status']}; B (new) answered {rb['status']}")
    return {"kind": "DIFF-FILTER", "severity": "medium", "endpoint": f"{ra['method']} {ra['tpl']}",
            "path": f"$filter.{param}={value}", "detail": detail, "sequence": _sequence(ra, recs_a, recs_b), "count": 1}


def _is_setup(rec) -> bool:
    return (rec.get("variant") or "").startswith(("distinguish:", "probe-create", "fixture:"))


def _filter_mismatch(ra, rb) -> bool:
    """A filter probe whose two answers hold different sets of items (both 2xx, both with items)."""
    if not ra.get("filter") or ra.get("skipped") or rb.get("skipped"):
        return False
    if not (200 <= ra["status"] < 300 and 200 <= rb["status"] < 300) or ra.get("items") is None or rb.get("items") is None:
        return False
    return sorted(x["id"] for x in ra["items"]) != sorted(x["id"] for x in rb["items"])


def _state_label(ra: dict, pre_bad: bool) -> str:
    if pre_bad:
        return "UNEQUAL STATE before the run"
    if ra.get("state") == "DIVERGED":
        return "DIVERGED after an earlier write"
    return "equal"


def compare(run_a, noise_runs, run_b, expect=(), ignore=(), pre=None) -> dict:
    """A (run 0) vs B, after excluding what differs between A and A prime. Returns findings + notes + counters."""
    noise = learn_noise(run_a, noise_runs)
    findings, index, notes = [], {}, []
    stats = {"compared": 0, "transport": 0, "status_noisy": set(), "suppressed": 0, "noise_excluded": 0, "skipped": 0,
             "diverged_from": None}
    pre_bad = bool(pre) and pre.get("equal") is False
    bad_groups = {ra.get("group") for ra, rb in zip(run_a, run_b)
                  if _is_setup(ra) and not ra.get("skipped") and not rb.get("skipped") and ra["status"] != rb["status"]}
    for ra, rb in zip(run_a, run_b):
        label = f"{ra['method']} {ra['tpl']}"
        if ra.get("skipped") or rb.get("skipped"):
            if ra.get("skipped") != rb.get("skipped"):
                stats["skipped"] += 1
            continue
        if ra["transport"] or rb["transport"]:
            stats["transport"] += 1
            continue
        slot = noise.get(label, {"status": False, "paths": set()})
        if slot["status"]:
            stats["status_noisy"].add(label)
            if ra["status"] != rb["status"]:
                continue                               # the status is noise here: no status claim, but the body is still compared
        stats["compared"] += 1
        if _filter_mismatch(ra, rb) and ra.get("group") not in bad_groups:
            continue                                   # reported once, as DIFF-FILTER below
        state = _state_label(ra, pre_bad)
        aggregate = ra["method"] == "GET" and "{" not in ra["tpl"]
        for change, jpath, av, bv in diff_records(ra, rb):
            if change != "status" and any(_under(jpath, n) for n in slot["paths"]):
                stats["noise_excluded"] += 1
                continue
            if _allowed(label, jpath, ignore):
                stats["noise_excluded"] += 1
                continue
            if _allowed(label, jpath, expect):
                stats["suppressed"] += 1
                continue
            k = (change, label, jpath)
            if k in index:
                index[k]["count"] += 1
                continue
            f = _finding(change, jpath, av, bv, ra, rb, run_a, run_b)
            if aggregate and state != "equal" and change != "status":
                f["severity"] = "info"
                f["detail"] = f"[{state}] " + f["detail"]
            index[k] = f
            findings.append(f)
    for ra, rb in zip(run_a, run_b):
        if not _filter_mismatch(ra, rb) or ra.get("group") in bad_groups:
            continue
        label = f"{ra['method']} {ra['tpl']}"
        jpath = f"$filter.{ra['filter']['param']}={ra['filter']['value']}"
        if _allowed(label, jpath, ignore):
            stats["noise_excluded"] += 1
            continue
        if _allowed(label, jpath, expect):
            stats["suppressed"] += 1
            continue
        k = ("filter", label, jpath)
        if k in index:
            index[k]["count"] += 1
            continue
        f = _filter_finding(ra, rb, ra["filter"]["param"], ra["filter"]["value"], run_a, run_b)
        state = _state_label(ra, pre_bad)
        if state != "equal":
            f["severity"] = "info"
            f["detail"] = f"[{state}] " + f["detail"]
        index[k] = f
        findings.append(f)
    for f in findings:
        if f["count"] > 1:
            f["detail"] += f" (seen {f['count']}x in the sequence; first shown)"
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    if stats["noise_excluded"]:
        notes.append(f"{stats['noise_excluded']} difference(s) excluded as noise (differ between two runs of A, or DIFF_IGNORE)")
    if stats["suppressed"]:
        notes.append(f"{stats['suppressed']} difference(s) suppressed by the expect-changes allow-list")
    if stats["skipped"]:
        notes.append(f"{stats['skipped']} step(s) not sent on one side because the item they needed was not created there "
                     "(not compared)")
    diverged = [r["step"] for r in run_a if r.get("state") == "DIVERGED" and not r.get("skipped")]
    if diverged:
        notes.append(f"the state differs between A and B after an earlier write, at {len(diverged)} step(s), first at step "
                     f"{diverged[0]} (the collection fingerprint differs): collection reads at those steps are labelled DIVERGED "
                     "and their body differences are info")
    stats["noise"] = {k: {"status": v["status"], "paths": sorted(v["paths"])} for k, v in noise.items() if v["status"] or v["paths"]}
    stats["diverged_from"] = diverged[0] if diverged else None
    return {"findings": findings, "notes": notes, "stats": stats}


# ---------------------------------------------------------------- engine entry points

def _finish(res, cmp, runs_total, n_steps, b_down, extra_notes) -> dict:
    res["findings"] = cmp["findings"]
    res["notes"] = extra_notes + cmp["notes"]
    res["noise_learned"] = cmp["stats"]["noise"]
    st = cmp["stats"]
    res["probes"] = runs_total
    reasons = []
    if b_down:
        return trust.mark(res, trust.ERRORED, "B returned no HTTP response for any step (is it running?)")
    if st["transport"]:
        reasons.append(f"{st['transport']} step(s) had no HTTP answer on A or B and were not compared")
    if st["status_noisy"]:
        reasons.append(f"{len(st['status_noisy'])} endpoint(s) answered differently in two runs of A (status unstable), status not "
                       "compared there: " + ", ".join(sorted(st["status_noisy"])[:4]))
    reasons += [n for n in extra_notes if n.startswith("setup:")]
    if n_steps == 0:
        reasons.append("nothing was compared (empty sequence)")
    elif st["compared"] == 0:
        reasons.append("no step could be compared")
    if reasons:
        return trust.mark(res, trust.DEGRADED, "; ".join(reasons)[:400])
    return trust.mark(res, trust.RAN_OK)


def _run_pair(api_a, api_b, pair_fn, noise_fn, noise_runs, expect, ignore, extra_notes, pre=None) -> dict:
    """pair_fn() -> (run_a, run_b) in lockstep; noise_fn(api, i) -> run i of A alone (noise learning)."""
    res = {"engine": ENGINE, "findings": [], "notes": [], "probes": 0}
    n_a = len(api_a.log)
    n_b = len(api_b.log)
    run_a, run_b = pair_fn()
    noise = [noise_fn(api_a, i) for i in range(1, max(0, noise_runs) + 1)]
    total = (len(api_a.log) - n_a) + (len(api_b.log) - n_b)
    answered = [r for r in run_b if not r.get("skipped")]
    b_down = bool(answered) and all(r["transport"] for r in answered)
    if noise_runs <= 0:
        extra_notes.append("setup: noise learning disabled (noise_runs=0): volatile fields will be reported")
    # Two 401s (or two anon answers) prove nothing about access control: when no step ever ran under a login on either side,
    # the run is DEGRADED through a "setup:" note (which _finish turns into a reason), never ran_ok.
    # Narrowed on purpose: a public API that answers 200 to anon is still compared (its refusals are not the issue); only the
    # case where nothing authenticated AND every answer was a refusal (401/403) is degraded.
    steps = [r for r in list(run_a) + list(run_b) if not r.get("skipped") and not r.get("transport")]
    authed = any(r.get("role", "anon") != "anon" and r.get("status") not in (401,) for r in steps)
    if steps and not authed and all(r.get("status") in (401, 403) for r in steps):
        extra_notes.append("setup: no step authenticated on either side and every answer was a refusal (401/403): the two "
                           "versions were not compared under a login, so no access-control result is shown")
    cmp = compare(run_a, noise, run_b, expect, ignore, pre)
    return _finish(res, cmp, total, len(run_a), b_down, extra_notes)


def _load_expect(src) -> list:
    if not src:
        return []
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise SystemExit(f"{src}: expected a JSON list of 'METHOD path json.path' strings")
    return data


def _roles_for_b(api, api_b, qa, notes):
    fn = getattr(qa, "setup_b", None) or getattr(qa, "setup", None)
    if fn:
        try:
            api_b.roles.update(fn(api_b) or {})
        except Exception as exc:
            notes.append(f"setup: roles for B could not be created ({type(exc).__name__}: {exc}); requests run with whatever roles exist")
    else:
        api_b.roles.update({k: v for k, v in api.roles.items() if k != "anon"})


def _execute(api_a, api_b, plan, qa, pairs, expect, ignore, notes, pre, noise_runs) -> dict:
    tok_a, tok_b, xlate = fixture_maps(pairs)
    fp_steps = _pre_plan_reads(plan)
    fingerprint = (lambda: _fingerprint(api_a, qa, fp_steps) == _fingerprint(api_b, qa, fp_steps)) if fp_steps else None
    pair_fn = lambda: lockstep(plan, PlanRunner(api_a, qa, 0, tokens=tok_a),
                               PlanRunner(api_b, qa, 0, xlate=xlate, tokens=tok_b), fingerprint)
    noise_fn = lambda client, i: exec_plan(client, plan, qa, i, tokens=tok_a)
    if pairs:
        notes.append(f"fixtures: {len(pairs)} id(s) created by setup on each side are paired (A's ids are sent to B as B's)")
    return _run_pair(api_a, api_b, pair_fn, noise_fn, noise_runs, expect, ignore, notes, pre=pre)


def run(api, doc, qa) -> dict:
    base_b = getattr(qa, "DIFF_BASE_URL", None) or os.environ.get("QA_DIFF_BASE_URL")
    res = {"engine": ENGINE, "findings": [], "notes": [], "probes": 0}
    if not base_b:
        return trust.mark(res, trust.SKIPPED, "no second version to compare: set DIFF_BASE_URL in qa-spec.py or QA_DIFF_BASE_URL")
    if base_b.rstrip("/") == api.base:
        return trust.mark(res, trust.ERRORED, "DIFF_BASE_URL equals the primary target: A and B must be two different running versions")
    try:
        api_b = Api(base_b)
    except SystemExit as exc:
        return trust.mark(res, trust.ERRORED, str(exc))
    if api_b.call("anon", "GET", "/").transport:                    # one refused connection costs ~2 s on Windows: fail before the plan
        return trust.mark(res, trust.ERRORED, "B returned no HTTP response (is it running?)")
    api_a = Api(api.base, {k: v for k, v in api.roles.items() if k != "anon"})      # own clients: the shared api.log stays untouched
    notes = []
    bodies_a = copy.deepcopy(getattr(qa, "BODIES", None) or {})     # A's setup has run (roles); its fixture ids are A's
    _roles_for_b(api, api_b, qa, notes)
    bodies_b = copy.deepcopy(getattr(qa, "BODIES", None) or {})     # setup on B wrote B's fixture ids
    if hasattr(qa, "BODIES") and isinstance(qa.BODIES, dict):
        qa.BODIES.clear()
        qa.BODIES.update(bodies_a)                                  # later engines see A's bodies, which run against A
    plan = build_plan(doc, qa, getattr(qa, "SEED", None), notes, bodies=bodies_a)
    pre = pre_state(api_a, api_b, plan, qa)
    _pre_notes(pre, notes)
    return _execute(api_a, api_b, plan, qa, fixture_pairs(bodies_a, bodies_b), list(getattr(qa, "DIFF_EXPECT", [])),
                    list(getattr(qa, "DIFF_IGNORE", [])), notes, pre, int(getattr(qa, "DIFF_NOISE_RUNS", 1)))


def replay_log(api_a, api_b, entries, noise_runs=1, expect=(), ignore=()) -> dict:
    """Replay recorded api.log entries against A (twice, for noise) and B, in lockstep. Entries need method, path, role, request,
    query and body (the recorded response, used only to map recorded ids to the ids of each replay)."""
    notes = ["pre-run state not checked in replay mode (the recorded log has no fingerprint): the state is tracked by write outcomes"]
    usable = [e for e in entries if e.get("method") in ("GET", "POST", "PUT", "PATCH", "DELETE") and e.get("status") != TRANSPORT_ERROR]
    if len(usable) != len(entries):
        notes.append(f"setup: {len(entries) - len(usable)} log entries skipped (unsupported method or no HTTP answer when recorded)")
    if not usable:
        return trust.mark({"engine": ENGINE, "findings": [], "notes": notes, "probes": 0}, trust.DEGRADED, "empty log: nothing replayed")
    for e in usable:
        if e["method"] == "POST" and 200 <= e.get("status", 0) < 300:
            try:
                if extract_id(json.loads(e.get("body") or "null")) is None:
                    notes.append(f"setup: recorded POST {e['path']} has no readable id (body truncated?): later steps keep the recorded id")
                    break
            except ValueError:
                notes.append(f"setup: recorded POST {e['path']} body is not complete JSON (log keeps 8000 chars): ids cannot be mapped")
                break
    pair_fn = lambda: lockstep(usable, ReplayRunner(api_a, 0), ReplayRunner(api_b, 0))
    noise_fn = lambda client, i: exec_replay(client, usable, i)
    return _run_pair(api_a, api_b, pair_fn, noise_fn, noise_runs, list(expect), list(ignore), notes)


# ---------------------------------------------------------------- CLI

def report_md(res: dict, a: str, b: str) -> str:
    status, reason = trust.resolve(res)
    lines = [f"# Differential: A={a} vs B={b}", "", f"status: **{status}** {reason}", "", f"findings: {len(res['findings'])}", ""]
    for f in res["findings"]:
        lines.append(f"- **{f['severity']} {f['kind']}** `{f['endpoint']}` {f.get('path', '')}: {f['detail']}")
        if f.get("sequence"):
            lines.append("  ```\n  " + f["sequence"].replace("\n", "\n  ") + "\n  ```")
    lines += [""] + [f"- note: {n}" for n in res["notes"]]
    if res.get("noise_learned"):
        lines += ["", "noise learned (excluded from comparison):"] + [f"- {k}: {v}" for k, v in res["noise_learned"].items()]
    return "\n".join(lines) + "\n"


def _load_spec(path):
    if not path:
        return SimpleNamespace()
    s = importlib.util.spec_from_file_location("qa_spec", path)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    p = argparse.ArgumentParser(description="differential test of two local versions of one API")
    p.add_argument("--a", required=True, help="old version base URL (local)")
    p.add_argument("--b", required=True, help="new version base URL (local)")
    p.add_argument("--openapi", help="OpenAPI file or local URL (default: A/openapi.json)")
    p.add_argument("--spec", help="qa-spec.py (roles, BODIES, DIFF_* knobs)")
    p.add_argument("--seed", type=int, help="shuffle the order of requests inside a phase, reproducibly")
    p.add_argument("--out", default="qa-report", help="output directory")
    p.add_argument("--expect-changes", help="JSON list of 'METHOD path json.path' for intended changes")
    p.add_argument("--noise-runs", type=int, help="extra runs of A used to learn noise (default 1)")
    p.add_argument("--replay", help="JSON file with api.log entries to replay instead of generating a sequence")
    a = p.parse_args(argv)
    api_a, api_b = Api(a.a), Api(a.b)
    qa = _load_spec(a.spec)
    fn_a = getattr(qa, "setup", None)
    if fn_a:
        api_a.roles.update(fn_a(api_a) or {})
    bodies_a = copy.deepcopy(getattr(qa, "BODIES", None) or {})     # A's fixture ids
    fn_b = getattr(qa, "setup_b", None) or fn_a
    if fn_b:
        api_b.roles.update(fn_b(api_b) or {})
    bodies_b = copy.deepcopy(getattr(qa, "BODIES", None) or {})     # B's fixture ids
    if isinstance(getattr(qa, "BODIES", None), dict):
        qa.BODIES.clear()
        qa.BODIES.update(bodies_a)
    expect = _load_expect(a.expect_changes) + list(getattr(qa, "DIFF_EXPECT", []))
    ignore = list(getattr(qa, "DIFF_IGNORE", []))
    noise_runs = a.noise_runs if a.noise_runs is not None else int(getattr(qa, "DIFF_NOISE_RUNS", 1))
    if a.replay:
        entries = json.loads(Path(a.replay).read_text(encoding="utf-8"))
        res = replay_log(api_a, api_b, entries, noise_runs, expect, ignore)
    else:
        doc = load_openapi(a.openapi or a.a.rstrip("/") + "/openapi.json")
        notes = []
        plan = build_plan(doc, qa, a.seed, notes, bodies=bodies_a)
        pre = pre_state(api_a, api_b, plan, qa)
        _pre_notes(pre, notes)
        res = _execute(api_a, api_b, plan, qa, fixture_pairs(bodies_a, bodies_b), expect, ignore, notes, pre, noise_runs)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "differential.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    md = report_md(res, a.a, a.b)
    (out / "differential.md").write_text(md, encoding="utf-8")
    print(md)
    code = trust.exit_code([res])
    if code == 0 and any(f["severity"] != "info" for f in res["findings"]):
        code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
