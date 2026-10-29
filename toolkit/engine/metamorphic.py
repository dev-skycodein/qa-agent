"""Metamorphic engine: find bugs WITHOUT knowing the correct answer, by checking relations between several responses.

Oracle problem: nobody here knows the "right" data, but related requests must answer in related ways (a page of 4 equals
two pages of 2; a filter only removes items; a PUT twice equals a PUT once). A broken relation is a bug in the app or a
wrong assumption of this engine, so every relation carries guards (below).

Candidate designs (tree of thoughts):
  A. Hard-coded relations per endpoint shape. Precise, few false positives, but every new API needs new code.
  B. OpenAPI-driven discovery (CHOSEN). The spec declares the parameters (limit/offset, page/per_page, sort/order, filter
     names that match response fields) and the CRUD siblings (POST /x, GET/PUT/DELETE /x/{id}, GET /x/{id}/y). The engine
     builds only the relations that the spec AND the live answers make applicable. Each relation is still a hand-written
     function. Cost: it relies on conventional names; a relation with no matching endpoint is reported "not applicable"
     and degrades the status.
  C. Property-based generation (Hypothesis draws random queries, checks every relation). Broadest input coverage, but a
     random sequence is hard to reproduce and the request budget hard to bound. The stateful engine already covers random
     sequences, so this engine stays deterministic.

Data: an empty or tiny collection is SEEDED first (POST with the spec's example body, varied per item, every body checked
by our own schema validator), and the seeded items are DELETEd again at the end when the spec has a DELETE. Enumeration
never asks for a page past the end when the listing says it is complete (total reached or a short page), so a paging bug
shows up as a finding, not as an unenumerable collection.

Guards used by every relation:
  - the baseline is read twice; if two identical reads differ, the check is INCONCLUSIVE (never a finding);
  - a violation must reproduce on a second full run of the relation, else it is only a note (flaky);
  - no expected values: only relations between this engine's own reads (and the spec's declared types);
  - volatile fields (timestamps, per-request counters) are learned from two identical reads and ignored by comparisons
    (qa.VOLATILE_FIELDS adds more; a counter that changes on EVERY read is learned too, so it is hidden: see limits).

Relations (kind: precondition -> violation; main false-positive risk):
  MR-PAGE-UNION      offset or page paging declared, >= 5 items. Every page of size k (walking up to 8 pages, including the
                     page after the end) must equal the full listing's slice at that position: no duplicate, no gap.
                     FP: unstable order (guarded by two full listings); a server that ignores the size (inconclusive).
  MR-PAGE-TOTAL      a top-level count field (total, count, ...) with enumerable paging: count == items reachable.
                     Limit sanity: limit 0 / -1 / 10^9 must not 5xx and must not return more items than exist.
                     FP: a count that means something else; limit=0 meaning "default page" is accepted (not flagged).
  MR-COUNT-AGREE     a GET without path params whose 2xx answer has an integer count field (total_books, count, ...) next to
                     a collection with POST and DELETE: before any write both counts agree (control), after one create
                     and one delete they must still agree. FP: a counter whose description says it is cumulative (skipped).
  MR-FILTER-SUBSET   a declared query param named like an item field; unfiltered (all pages) has >= 2 distinct values.
                     Filtered items must all satisfy the value (contains, when the spec says substring; equal otherwise),
                     filtered ids must be a subset of the unfiltered ids. For an exact filter (spec silent about substring
                     matching): nothing equal to the value may be dropped, and a strict substring of a seeded value must
                     match nothing. FP: a search/LIKE param whose spec does not say so.
  MR-SORT-ORDER      declared sort param; field takes >= 3 distinct values. A field the spec declares numeric must hold no
                     strings. sort=f must be monotone (asc or desc; casefold accepted for strings). With a declared order
                     param, the opposite order must reverse the key sequence, and when keys are distinct the item order too.
                     FP: DB collation (guarded by casefold), sort params that mean something else.
  MR-PARAM-ORDER     a list GET with >= 2 settable declared params. The same params in reverse order: same status and body.
                     FP: order-sensitive APIs (rare, and then a real finding).
  MR-UNKNOWN-PARAM   any GET without required query params. Adding qa_unknown_param must not 5xx and must not change
                     a 2xx body (a 4xx is a clean refusal). FP: low; the body compare ignores volatile fields.
  MR-HEAD-GET        any GET. HEAD must answer the same status as GET (Content-Type differs = low). 405/501 on HEAD = not
                     applicable (the framework does not route HEAD), recorded as a note, not a finding.
  MR-READ-IDEMPOTENT two identical GETs have the same body (volatile ignored). Same items in another order = low.
                     FP: per-read data the engine could not tell apart from volatile (hidden, not reported).
  MR-WRITE-ROUNDTRIP POST /coll body -> GET /coll/{id}: every body field the GET returns must equal what was sent.
                     Whitespace-only difference = low. FP: server-side normalisation (trim, upper-case, hashing) = medium.
  MR-PUT-IDEMPOTENT  POST a fresh item, PUT body, GET, PUT same body again, GET: both states must be equal.
                     FP: fields the server bumps on every write (updated_at, version): add them to qa.VOLATILE_FIELDS.
  MR-DELETE-GONE     POST a fresh item (and one item of each documented child collection /x/{id}/y that has a POST),
                     DELETE it: GET must answer 404/410 (re-read once); a second DELETE must not 5xx; each child collection
                     must answer 404 or an empty list afterwards (medium when it still lists items).
                     FP: soft delete (200 with a deleted flag) looks like a leftover resource.
  MR-FILTER-PARTITION  OPTIONAL. A boolean query param x: ?x=true and ?x=false must be disjoint and together equal the listing,
                     also under one other filter (composition). Inclusion flags (include_*, with_*, show_*) are skipped:
                     ?include_archived=true adds rows, so it is not a split. FP: a flag whose meaning is not a split.
  MR-SEARCH-CASE     OPTIONAL. A text-search param (q, search, ...) with a word in its original, lower and upper case must find the
                     same items. Medium only when the spec says case-insensitive; otherwise a low "verify". FP: undocumented
                     collation or a search that is deliberately case-sensitive.
  MR-BULK-ATOMIC     OPTIONAL. A bulk POST (array body) with one valid and one invalid item must be rejected AND leave the
                     collection unchanged. Medium when the spec promises all-or-nothing, low "verify" otherwise. FP: APIs that apply
                     partial batches by design.

Trust: no relation applicable at all -> SKIPPED (skipped_no_spec). A relation with no applicable endpoint, an
inconclusive check or an engine error -> DEGRADED. Write relations create data (POST) and run after the read relations,
so the read checks see the seeded state. Engine traffic goes only through api.Api.
Roles: a write goes to the first role that gets it accepted (401/403 -> the next role), and later writes to that
collection reuse that role.

qa knobs (all optional): SKIP (global, endpoints never touched), METAMORPHIC_SKIP {"MR-SORT-ORDER GET /x", "GET /x",
"MR-HEAD-GET"}, VOLATILE_FIELDS {"updated_at"}, BODIES {"POST /x": {...}}, METAMORPHIC_ROLE ("user_a" by default).
"""
import json
import math
import re
import time
import urllib.parse
from collections import Counter

import api
import schema_fuzz
import trust
from api import endpoints, example, extract_id, fill, key, prefix_of, resolve

RELATIONS = ("MR-PAGE-UNION", "MR-PAGE-TOTAL", "MR-FILTER-SUBSET", "MR-SORT-ORDER", "MR-PARAM-ORDER",
             "MR-UNKNOWN-PARAM", "MR-HEAD-GET", "MR-READ-IDEMPOTENT", "MR-WRITE-ROUNDTRIP", "MR-PUT-IDEMPOTENT",
             "MR-DELETE-GONE", "MR-COUNT-AGREE", "MR-FILTER-PARTITION", "MR-SEARCH-CASE", "MR-BULK-ATOMIC")          # read-only relations first; write relations create data and run last
OPTIONAL = {"MR-FILTER-PARTITION", "MR-SEARCH-CASE", "MR-BULK-ATOMIC"}      # silently absent when the API has no boolean filter / text-search parameter (not a degradation)
NA_REASON = {
    "MR-PAGE-UNION": "needs a list endpoint with paging (limit+offset, or per_page+page) declared in the OpenAPI",
    "MR-PAGE-TOTAL": "needs a list endpoint with a size parameter (limit, per_page, ...) declared in the OpenAPI",
    "MR-FILTER-SUBSET": "needs a declared query parameter whose name matches a field of the list items (e.g. category)",
    "MR-SORT-ORDER": "needs a declared sort parameter (sort, sort_by, order_by) and scalar item fields to sort by",
    "MR-PARAM-ORDER": "needs a list GET with at least 2 declared query parameters the engine can set",
    "MR-UNKNOWN-PARAM": "needs at least one GET endpoint without required query parameters",
    "MR-HEAD-GET": "needs at least one GET endpoint",
    "MR-READ-IDEMPOTENT": "needs at least one GET endpoint with no required query parameters (and a usable id for /{id})",
    "MR-WRITE-ROUNDTRIP": "needs POST /collection with a body and GET /collection/{id}",
    "MR-PUT-IDEMPOTENT": "needs POST /collection, PUT /collection/{id} with a body, and GET /collection/{id}",
    "MR-DELETE-GONE": "needs POST /collection, DELETE /collection/{id} and GET /collection/{id}",
    "MR-FILTER-PARTITION": "needs a list endpoint with a boolean query parameter (in_stock, active, ...)",
    "MR-SEARCH-CASE": "needs a list endpoint with a text-search parameter (q, search, query, term, ...)",
    "MR-BULK-ATOMIC": "needs POST /collection/<verb> taking an array of items (bulk create) next to a listable /collection",
    "MR-COUNT-AGREE": "needs a GET without path params that answers an integer count field (total, count, total_books, ...) "
                      "next to a collection with POST and DELETE /collection/{id}",
}
SIZE_NAMES = ("limit", "page_size", "per_page", "pageSize", "perPage", "size")
OFFSET_NAMES = ("offset", "skip")
PAGE_NAMES = ("page", "page_number", "pageNumber")
SORT_NAMES = ("sort", "sort_by", "sortBy", "order_by", "orderBy")
ORDER_NAMES = ("order", "direction", "sort_order", "sortOrder", "dir")
SEARCH_NAMES = ("q", "query", "search", "term", "keyword", "keywords", "text")
CASE_INSENSITIVE = re.compile(r"case[- ]?insensitive|ignor\w* case|regardless of case|any case", re.I)
CASE_SENSITIVE = re.compile(r"case[- ]?sensitive", re.I)
CONTROL = set(SIZE_NAMES + OFFSET_NAMES + PAGE_NAMES + SORT_NAMES + ORDER_NAMES)
TOTAL_NAMES = ("total", "count", "total_count", "totalCount", "total_items", "totalItems", "total_results", "totalResults")
SHAPE_NAMES = ("items", "data", "results", "records", "rows", "list")
NUMERIC_TEXT = re.compile(r"^-?\d+(\.\d+)?$")
INCLUSION_FLAG = re.compile(r"^(include|with|show)(_|-|[A-Z]|$)")   # include_archived, includeDeleted: true ADDS rows to the default listing, so it is not a partition
COUNT_NAME = re.compile(r"total|count", re.I)                       # a count field of a stats-like answer
COUNT_EXCLUDE = re.compile(r"\b(ever|cumulative|since|historical|created|added)\b", re.I)   # counts that never go down
SUBSTRING_WORDS = re.compile(r"substring|contain|partial|search|\blike\b|fuzzy|prefix", re.I)
K = 2                       # MR-PAGE-UNION: pages of size K
PAGE_SIZE = 50              # size used when the engine enumerates a collection (capped by the spec's maximum)
MAX_PAGES = 20
MAX_WALK = 8                # MR-PAGE-UNION walks at most this many pages
FILTER_VALUES = 3           # MR-FILTER-SUBSET tries this many distinct values of the field
SEED_MIN = 6                # collections with fewer items get seeded up to this many
UNKNOWN_PARAM = "qa_unknown_param"


class Inconclusive(Exception):
    """The check could not give an answer (unstable baseline, paging not driveable, ...). Not a finding; degrades status."""


class NotApplicable(Exception):
    """The endpoint does not support what the relation needs (HEAD answers 405). Not a finding, not a degradation."""


# ---------- small helpers ----------

def body_of(r):
    return r.json if r.json is not None else r.text


def strip(obj, vol):
    if isinstance(obj, dict):
        return {k: strip(v, vol) for k, v in obj.items() if k not in vol}
    if isinstance(obj, list):
        return [strip(v, vol) for v in obj]
    return obj


def _unordered(obj, vol):
    if isinstance(obj, dict):
        return {k: _unordered(v, vol) for k, v in obj.items() if k not in vol}
    if isinstance(obj, list):
        return sorted((_unordered(v, vol) for v in obj), key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return obj


def ident(x):
    """Identity of a list item: its id when it has one, else its canonical JSON."""
    if isinstance(x, dict) and isinstance(x.get("id"), (int, str)) and not isinstance(x.get("id"), bool):
        return x["id"]
    return json.dumps(x, sort_keys=True, default=str)


def ids_of(items):
    return [str(ident(x)) for x in items]


def norm(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def list_of(body, shape):
    if shape == "":
        return body if isinstance(body, list) else None
    if isinstance(body, dict) and isinstance(body.get(shape), list):
        return body[shape]
    return None


def detect_shape(body):
    """'' when the body is a bare list, the key of the item list in an object, or None when it is not a list response."""
    if isinstance(body, list):
        return ""
    if isinstance(body, dict):
        for k in SHAPE_NAMES:
            if isinstance(body.get(k), list):
                return k
        lists = [k for k, v in body.items() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
    return None


def total_key(body):
    if isinstance(body, dict):
        for k in TOTAL_NAMES:
            v = body.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                return k
    return None


def scalar_fields(sample):
    if not sample or not isinstance(sample[0], dict):
        return []
    return [k for k, v in sample[0].items() if k != "id" and isinstance(v, (str, int, float, bool))]


def first_diff(a, b, path="$"):
    """Human-readable location of the first difference between two (already stripped) JSON values."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                return f"{path}.{k} present in only one response"
            if a[k] != b[k]:
                return first_diff(a[k], b[k], f"{path}.{k}")
        return path
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return first_diff(x, y, f"{path}[{i}]")
        return path
    return f"{path}: {str(a)[:60]!r} vs {str(b)[:60]!r}"


def _learn(a, b, out):
    """Collect scalar keys whose value differs between two identical reads. Structural changes (length, order, ids) are
    not learned: a shuffled or dropped item must stay visible to the relations."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in set(a) & set(b):
            va, vb = a[k], b[k]
            if isinstance(va, (dict, list)) and isinstance(vb, (dict, list)):
                _learn(va, vb, out)
            elif not isinstance(va, (dict, list)) and not isinstance(vb, (dict, list)) and va != vb:
                out.add(k)
    elif isinstance(a, list) and isinstance(b, list):
        if [ident(x) for x in a] != [ident(x) for x in b]:
            return
        for x, y in zip(a, b):
            _learn(x, y, out)


def _monotone(keys):
    """(non-decreasing, non-increasing) under Python order, or under casefold for strings (DB collations differ)."""
    def mono(seq):
        pairs = list(zip(seq, seq[1:]))
        return all(a <= b for a, b in pairs), all(a >= b for a, b in pairs)
    exact = mono(keys)
    if exact[0] or exact[1]:
        return exact
    if all(isinstance(k, str) for k in keys):
        return mono([k.casefold() for k in keys])
    return exact


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _valid(value, schema, spec):
    try:
        return not schema_fuzz.check(value, schema, spec)
    except schema_fuzz.Unresolvable:
        return False


# ---------- spec helpers (what the OpenAPI declares) ----------

def _path_node(spec, path, method):
    return ((spec.get("paths") or {}).get(path) or {}).get(method.lower()) or {}


def response_schema(op):
    """The resolved 200 JSON schema of an operation ({} when none is declared)."""
    spec = op.get("spec") or {}
    resp = (_path_node(spec, op["path"], op["method"]).get("responses") or {}).get("200") or {}
    media = ((resp.get("content") or {}).get("application/json") or {}).get("schema")
    return resolve(media, spec) if media else {}


def item_field_type(op, shape, field):
    """The JSON type the spec declares for one field of the list items, or None."""
    spec = op.get("spec") or {}
    s = response_schema(op)
    if shape:
        s = resolve((s.get("properties") or {}).get(shape, {}), spec)
    items = resolve(s.get("items", {}), spec) if isinstance(s, dict) else {}
    prop = resolve((items.get("properties") or {}).get(field, {}), spec)
    t = prop.get("type") if isinstance(prop, dict) else None
    return t if isinstance(t, str) else None


def declared_text(op, name):
    """Summary, description and the text of the parameter `name` (params and description fields), joined."""
    spec = op.get("spec") or {}
    node = _path_node(spec, op["path"], op["method"])
    texts = [node.get("summary", ""), node.get("description", "")]
    params = list(node.get("parameters") or []) + list(((spec.get("paths") or {}).get(op["path"]) or {}).get("parameters") or [])
    for p in params:
        if isinstance(p, dict) and p.get("name") == name:
            texts += [p.get("description", ""), (p.get("schema") or {}).get("description", "")]
    return " ".join(t for t in texts if isinstance(t, str))


def item_tpl(ops, P):
    """(GET /P/{param} path, param) for the collection P, or (None, None)."""
    for o in ops:
        if o["method"] == "GET" and len(o["path_params"]) == 1 and o["path"] == P + "/{" + o["path_params"][0] + "}":
            return o["path"], o["path_params"][0]
    return None, None


def writable(col, by, ops):
    """A collection that has POST and an item DELETE (so the engine can create and remove its own items)."""
    tpl, _ = item_tpl(ops, col["path"])
    return f"POST {col['path']}" in by and tpl is not None and f"DELETE {tpl}" in by


# ---------- request context ----------

class Ctx:
    def __init__(self, api, spec, qa):
        self.api, self.spec = api, spec
        self.skip = set(getattr(qa, "METAMORPHIC_SKIP", set()) or set())
        self.volatile = set(getattr(qa, "VOLATILE_FIELDS", set()) or set())
        self.learned = set()
        self.bodies = getattr(qa, "BODIES", {}) or {}
        names = [r for r in api.roles if r != "anon"]
        explicit = getattr(qa, "METAMORPHIC_ROLE", None)
        self.explicit_role = bool(explicit)
        self.role = explicit or ("user_a" if "user_a" in names else (names[0] if names else "anon"))
        self.role_names = [self.role] if self.explicit_role else [self.role] + [n for n in names if n != self.role]
        self.write_role = {}          # collection path -> role that the app accepted a create with
        self.created = []             # (concrete collection path, id) of every item this engine created
        self.count_start = {}         # (stats path, collection path) -> (agree, list total, stat value) before any write
        self.findings, self.notes, self.trace = [], [], []
        self.stats = {k: dict.fromkeys(("instances", "clean", "violations", "inconclusive", "errors", "skipped",
                                        "not_applicable"), 0) for k in RELATIONS}
        self.na_relations = {}
        self.log0 = len(api.log)

    def rq(self, method, path, query=None, body=None, role=None):
        r = self.api.call(role or self.role, method, path, body, query=query)
        qs = ("?" + urllib.parse.urlencode(query)) if query else ""
        extra = f" body={json.dumps(body, default=str)[:90]}" if body is not None else ""
        self.trace.append(f"{method} {path}{qs}{extra} -> {r.status} {r.text[:110]!r}")
        return r

    def role_for(self, path):
        return self.write_role.get(path, self.role)

    def writers(self, path):
        """Roles to try for a create under `path`: the one that worked before first, then the others."""
        if self.explicit_role:
            return [self.role]
        pref = self.write_role.get(path)
        if pref is None:
            return list(self.role_names)
        return [pref] + [r for r in self.role_names if r != pref]

    def canon(self, r):
        return json.dumps(strip(body_of(r), self.volatile), sort_keys=True, default=str)

    def unordered(self, r):
        return json.dumps(_unordered(body_of(r), self.volatile), sort_keys=True, default=str)

    def diff(self, a, b):
        return first_diff(strip(body_of(a), self.volatile), strip(body_of(b), self.volatile))

    def skipped(self, kind, label, base):
        return any(x in self.skip for x in (f"{kind} {label}", f"{kind} {base}", base, kind))


# ---------- discovery ----------

def discover(ctx, ops):
    """Collections: GET endpoints without path params that answer a list. Paging style comes from the declared params."""
    cols = []
    for op in ops:
        if op["method"] != "GET" or op["path_params"] or op["query_required"]:
            continue
        r = ctx.rq("GET", op["path"])
        shape = detect_shape(r.json) if r.ok else None
        if shape is None:
            continue
        declared = [p["name"] for p in op["query_params"]]
        size = next((n for n in SIZE_NAMES if n in declared), None)
        off = next((n for n in OFFSET_NAMES if n in declared), None)
        pg = next((n for n in PAGE_NAMES if n in declared), None)
        if size and off:
            style = "offset"
        elif size and pg:
            style = "page"
        else:
            style = "limit-only" if size else "none"
        sample = list_of(r.json, shape) or []
        total = total_key(r.json)
        cap = None
        if size:
            schema = next((p["schema"] for p in op["query_params"] if p["name"] == size), {}) or {}
            cap = schema.get("maximum") if _num(schema.get("maximum")) else None
        col = {"op": op, "path": op["path"], "ek": key(op), "shape": shape, "declared": declared,
               "sample": sample, "total": total, "style": style, "size": size, "offset": off, "page": pg, "base": 1,
               "paged": bool(size or off or pg), "count": r.json[total] if total else len(sample),
               "fetch": min(PAGE_SIZE, int(cap)) if cap and cap >= 1 else PAGE_SIZE}
        if style == "page":
            col["base"] = detect_base(ctx, col)
        cols.append(col)
    return cols


def discover_counts(ctx, ops):
    """(stats path, count field) for GET endpoints without path params that answer a non-list object with an integer count
    field whose description does not say the count only grows."""
    out = []
    for op in ops:
        if op["method"] != "GET" or op["path_params"] or op["query_required"]:
            continue
        r = ctx.rq("GET", op["path"])
        if not r.ok or not isinstance(r.json, dict) or detect_shape(r.json) is not None:
            continue
        props = response_schema(op).get("properties") or {}
        for k, v in r.json.items():
            if not isinstance(v, int) or isinstance(v, bool) or not COUNT_NAME.search(k):
                continue
            desc = str(resolve(props.get(k, {}), ctx.spec).get("description", ""))
            if COUNT_EXCLUDE.search(desc):
                continue
            out.append((op["path"], k))
    return out


def detect_base(ctx, col):
    """1-based or 0-based page numbers. 0-based only when page 0 answers items that differ from page 1."""
    r0 = ctx.rq("GET", col["path"], {col["size"]: 5, col["page"]: 0})
    r1 = ctx.rq("GET", col["path"], {col["size"]: 5, col["page"]: 1})
    if r0.ok and r1.ok:
        a = list_of(r0.json, col["shape"]) or []
        b = list_of(r1.json, col["shape"]) or []
        if a and ids_of(a) != ids_of(b):
            return 0
    return 1


def concrete_path(op, cols):
    """The GET path with its id filled from the sample of the matching collection, or None when no id is known."""
    if not op["path_params"]:
        return op["path"]
    if len(op["path_params"]) != 1:
        return None
    p = op["path_params"][0]
    col = next((c for c in cols if c["path"] == prefix_of(op["path"], p)), None)
    if col is None or not col["sample"] or not isinstance(col["sample"][0], dict) or "id" not in col["sample"][0]:
        return None
    return fill(op["path"], {p: col["sample"][0]["id"]})


VOLATILE_READS = 3        # reads per path
VOLATILE_GAP_S = 0.05     # 50 ms apart: longer than the 15.6 ms Windows clock tick, so a timestamp can change between reads


def learn_volatile(ctx, paths):
    """Learn the fields that change between re-reads of the same GET (timestamps, counters, tokens). Two back-to-back reads can
    fall in the same clock tick and miss a timestamp, so VOLATILE_READS reads are taken VOLATILE_GAP_S apart and every later
    read is compared with the first one: a field that differs in any of them is volatile."""
    for path in paths:
        reads = []
        for i in range(VOLATILE_READS):
            if i:
                time.sleep(VOLATILE_GAP_S)
            reads.append(ctx.rq("GET", path))
        ok = [r for r in reads if r.ok]
        for other in ok[1:]:
            _learn(body_of(ok[0]), body_of(other), ctx.learned)
    ctx.volatile |= ctx.learned


# ---------- seeding and cleanup ----------

def body_for(ctx, op):
    if op is None:
        return None
    if key(op) in ctx.bodies:
        return ctx.bodies[key(op)]
    if op["body_schema"] is None:
        return None
    return example(op["body_schema"], ctx.spec)


def _vary(value, ps, k):
    """Value number k of a field: the next enum member, a shifted number, or the same text with a suffix (bounds kept)."""
    enum = ps.get("enum") if isinstance(ps, dict) else None
    if isinstance(enum, list) and enum:
        return enum[k % len(enum)]
    if isinstance(value, bool):
        return value
    if _num(value):
        nv = value + k
        if _num(ps.get("maximum")):
            nv = min(nv, ps["maximum"])
        if _num(ps.get("minimum")):
            nv = max(nv, ps["minimum"])
        return int(nv) if isinstance(value, int) else round(float(nv), 2)
    if isinstance(value, str):
        cands = [f"{value}-{k}", f"{value}{k}"] if ps.get("pattern") else [f"{value} {k}"]
        for cand in cands:
            if isinstance(ps.get("maxLength"), int) and len(cand) > ps["maxLength"]:
                continue
            if ps.get("pattern"):
                try:
                    if not re.search(ps["pattern"], cand):
                        continue
                except re.error:
                    continue
            return cand
        return value
    return value


def seed_variant(body0, schema, spec, k):
    """Item number k built from the example body (every value varied, the result checked by our validator)."""
    if not isinstance(body0, dict) or not isinstance(schema, dict):
        return body0
    props = resolve(schema, spec).get("properties") or {}
    out = {}
    for name, value in body0.items():
        ps = resolve(props.get(name), spec) if isinstance(props.get(name), dict) else {}
        out[name] = _vary(value, ps, k)
    return out if _valid(out, schema, spec) else body0


def seed(ctx, cols, ops):
    """Create items in collections that are empty or too small for the relations. Returns [(collection, id)]."""
    by = {key(o): o for o in ops}
    created = []
    for col in cols:
        post = by.get(f"POST {col['path']}")
        have = col["count"]
        if post is None or have >= SEED_MIN:
            continue
        body0 = body_for(ctx, post)
        if body0 is None:
            ctx.notes.append(f"seeding skipped for {col['path']}: no request body example")
            continue
        if post["body_schema"] is not None and not _valid(body0, post["body_schema"], ctx.spec):
            ctx.notes.append(f"seeding skipped for {col['path']}: the example body fails our schema validator "
                             f"(qa.BODIES can supply a valid one)")
            continue
        n = 0
        for k in range(1, SEED_MIN - have + 1):
            body = seed_variant(body0, post["body_schema"], ctx.spec, k)
            try:
                rid = create(ctx, col["path"], body)
            except Inconclusive as exc:
                ctx.notes.append(f"seeding {col['path']} stopped: {exc}"[:300])
                break
            created.append((col["path"], rid))
            n += 1
        if n:
            ctx.notes.append(f"seeded {n} item(s) into {col['path']} (it held {have}) from the spec's example body")
    return created


def _delete_for(ops, by, coll):
    """The item DELETE path that belongs to the concrete collection path `coll`, or None."""
    for o in ops:
        if o["method"] != "GET" or not o["path_params"]:
            continue
        last = "/{" + o["path_params"][-1] + "}"
        if not o["path"].endswith(last):
            continue
        parts = re.split(r"\{\w+\}", o["path"][: -len(last)])
        if re.fullmatch("[^/]+".join(re.escape(p) for p in parts), coll) and f"DELETE {o['path']}" in by:
            return o["path"]
    return None


def cleanup(ctx, ops):
    """DELETE every item this engine created (seeds and the write relations' items), where the spec has a DELETE."""
    if not ctx.created:
        return
    by = {key(o): o for o in ops}
    gone, left = 0, 0
    for coll, rid in reversed(ctx.created):
        if _delete_for(ops, by, coll) is None:
            left += 1
            continue
        r = ctx.rq("DELETE", f"{coll}/{rid}", role=ctx.role_for(coll))
        if r.ok or r.status in (404, 410):          # 404: already removed by the relation itself (its own delete)
            gone += 1
        else:
            left += 1
    ctx.notes.append(f"created items cleaned up: {gone} deleted, {left} left in place (no DELETE, or the DELETE failed)")


# ---------- enumeration helpers used by several relations ----------

def window(ctx, col, start, size):
    """Items [start, start+size) through the endpoint's own paging parameters. start is a multiple of size for pages."""
    if col["style"] == "offset":
        q = {col["size"]: size, col["offset"]: start}
    else:
        q = {col["size"]: size, col["page"]: col["base"] + start // size}
    r = ctx.rq("GET", col["path"], q)
    items = list_of(r.json, col["shape"]) if r.ok else None
    if items is None:
        raise Inconclusive(f"GET {col['path']} {q} -> {r.status} (no item list)")
    return items, r, q


def fetch_all(ctx, col, extra=None):
    """Every item reachable by paging (with extra query params). Returns (items, complete, reason).

    Stops when the listing says it is finished: the total is reached, or a page is shorter than the size asked for.
    It never asks for a page past that point, so a paging bug answers as a repeat (inconclusive) only where it is real."""
    extra = dict(extra or {})
    if col["style"] not in ("offset", "page"):
        r = ctx.rq("GET", col["path"], extra or None)
        items = list_of(r.json, col["shape"]) if r.ok else None
        if items is None:
            raise Inconclusive(f"GET {col['path']} -> {r.status} (no item list)")
        if col["paged"]:
            return items, False, "only a limit/offset/page parameter is declared: cannot page through"
        return items, True, ""
    items, seen = [], set()
    pos, pg = 0, col["base"]
    size = col["fetch"]
    total = None
    for _ in range(MAX_PAGES):
        q = dict(extra)
        q[col["size"]] = size
        if col["style"] == "offset":
            q[col["offset"]] = pos
        else:
            q[col["page"]] = pg
        r = ctx.rq("GET", col["path"], q)
        page = list_of(r.json, col["shape"]) if r.ok else None
        if page is None:
            raise Inconclusive(f"GET {col['path']} {q} -> {r.status}")
        if isinstance(r.json, dict) and isinstance(r.json.get(col["total"] or "-"), int):
            total = r.json[col["total"]]
        if not page:
            return items, True, ""
        ids = [ident(x) for x in page]
        if any(i in seen for i in ids):
            return items, False, f"paging repeats items at {q}"
        seen.update(ids)
        items.extend(page)
        pos += len(page)
        pg += 1
        if total is not None and len(items) >= total:
            return items, True, ""
        if len(page) < size:
            return items, True, ""
    return items, False, f"more than {MAX_PAGES} pages"


def list_total(ctx, col):
    """The number of items the collection holds: its total field, or a complete enumeration."""
    if col["total"]:
        r = ctx.rq("GET", col["path"])
        t = r.json.get(col["total"]) if r.ok and isinstance(r.json, dict) else None
        if isinstance(t, int):
            return t
    full, complete, why = fetch_all(ctx, col)
    if not complete:
        raise Inconclusive(f"cannot count {col['path']} ({why})")
    return len(full)


def stat_value(ctx, path, key_name):
    r = ctx.rq("GET", path)
    v = r.json.get(key_name) if r.ok and isinstance(r.json, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) else None


UNIQUE_FIELD = re.compile(r"(^|_)(sku|code|slug|username|handle|email|key|ref|reference|number|uuid|id)$", re.I)
CONFLICT_TEXT = re.compile(r"exist|unique|duplicate|conflict|already|taken|in use", re.I)


def _unique_variant(body, k):
    """The same body with its identifier-like string fields made different (sku-3, a3@x.com), for a create that hit a uniqueness rule."""
    if not isinstance(body, dict):
        return body
    out = dict(body)
    for name, v in body.items():
        if isinstance(v, str) and UNIQUE_FIELD.search(name):
            out[name] = (v.split("@", 1)[0] + f"{k}@" + v.split("@", 1)[1]) if "@" in v else f"{v}-{k}"
    return out


def create(ctx, path, body):
    """POST a new item under `path` with the first role that is accepted; returns its id. A 409 / uniqueness answer is retried
    with identifier-like fields (sku, code, email, ...) made distinct: our own earlier creates are the usual cause."""
    last = None
    for role in ctx.writers(path):
        r = ctx.rq("POST", path, body=body, role=role)
        for attempt in range(1, 4):
            if r.ok or not (r.status in (409, 422, 400) and CONFLICT_TEXT.search(r.text or "")):
                break
            ctx.nonce = getattr(ctx, "nonce", 0) + 1
            r = ctx.rq("POST", path, body=_unique_variant(body, f"{ctx.nonce}{attempt}"), role=role)
        if r.ok:
            ctx.write_role[path] = role
            rid = extract_id(r.json)
            if rid is None:
                raise Inconclusive(f"create POST {path} answered {r.status} without an id")
            ctx.created.append((path, rid))
            return rid
        last = r
        if r.status not in (401, 403):
            break
    raise Inconclusive(f"create POST {path} -> {last.status if last else '?'}: {last.text[:80] if last else ''}")


# ---------- relations: each builder returns fn() -> None (clean) | (severity, detail) (violation) ----------

def union_fn(ctx, col):
    def fn():
        full, complete, why = fetch_all(ctx, col)
        if not complete:
            raise Inconclusive(f"cannot enumerate every item ({why})")
        if len(full) < 2 * K + 1:
            raise Inconclusive(f"needs more than {2 * K} items, the collection has {len(full)}")
        again, c2, why2 = fetch_all(ctx, col)
        if not c2 or ids_of(again) != ids_of(full):
            raise Inconclusive("unstable order: two full listings of the same collection differ")
        want = ids_of(full)
        seen = []
        for i in range(min(MAX_WALK, math.ceil(len(want) / K) + 1)):
            pos = i * K
            page, _, q = window(ctx, col, pos, K)
            if len(page) > K:
                raise Inconclusive(f"server returned {len(page)} items for size={K}")
            got, exp = ids_of(page), want[pos:pos + K]
            if got != exp:
                dup = sorted({g for g in got if g in seen})
                missing = [e for e in exp if e not in got]
                return ("medium", f"{q} -> ids {got}, but the full listing has {exp} at positions {pos}-{pos + K - 1}: "
                                  f"duplicates {dup or 'none'}, missing {missing or 'none'}")
            seen.extend(got)
        return None
    return fn


def total_fn(ctx, col):
    def fn():
        full, complete, why = fetch_all(ctx, col)
        if not complete:
            raise Inconclusive(f"cannot enumerate every item ({why})")
        _, r, q = window(ctx, col, 0, PAGE_SIZE)
        t = r.json.get(col["total"]) if isinstance(r.json, dict) else None
        if not isinstance(t, int):
            raise Inconclusive(f"'{col['total']}' missing in the first page")
        if t == len(full):
            return None
        return ("medium", f"{col['total']}={t} in {q} but paging reaches {len(full)} items")
    return fn


def limit_fn(ctx, col, v):
    def fn():
        q = {col["size"]: v}
        if col["style"] == "offset":
            q[col["offset"]] = 0
        elif col["style"] == "page":
            q[col["page"]] = col["base"]
        r = ctx.rq("GET", col["path"], q)
        if r.server_error or r.transport:
            return ("medium", f"{q} -> {r.status}: {r.text[:120]}")
        if not r.ok:
            return None                                   # a clean refusal is a sane answer
        items = list_of(r.json, col["shape"])
        if items is None or col["style"] not in ("offset", "page"):
            return None
        full, complete, _ = fetch_all(ctx, col)
        if complete and len(items) > len(full):
            return ("medium", f"{q} returned {len(items)} items but only {len(full)} exist")
        return None
    return fn


def _step_mismatch(ctx, sp, sk, col, before, label):
    """Compare how far the list total and the stats count moved in one write. Returns a detail string or None."""
    l0, s0 = before
    l1 = list_total(ctx, col)
    s1 = stat_value(ctx, sp, sk)
    if s1 is None:
        raise Inconclusive(f"{sp} {sk} is not readable")
    if (l1 - l0) == (s1 - s0):
        return None
    s1b = stat_value(ctx, sp, sk)                          # eventual consistency is not a leftover: one re-read
    if s1b is not None and (l1 - l0) == (s1b - s0):
        return None
    return (f"after {label}: {col['path']} total moved {l1 - l0:+d} ({l0} -> {l1}) but {sp} {sk} moved "
            f"{(s1b if s1b is not None else s1) - s0:+d} ({s0} -> {s1b if s1b is not None else s1})")


def count_fn(ctx, sp, sk, col, body, tpl, param):
    """A create moves the list total and the stats count by the same amount, and so does a delete. The check compares the
    MOVES, so it needs no agreement before the writes (a stale counter disagrees from the first delete on)."""
    def fn():
        l0 = list_total(ctx, col)
        s0 = stat_value(ctx, sp, sk)
        if s0 is None:
            raise Inconclusive(f"{sp} {sk} is not readable")
        rid = create(ctx, col["path"], body)
        bad = _step_mismatch(ctx, sp, sk, col, (l0, s0), "one create")
        if bad:
            return ("medium", bad)
        l1 = list_total(ctx, col)
        s1 = stat_value(ctx, sp, sk)
        d = ctx.rq("DELETE", fill(tpl, {param: rid}), role=ctx.role_for(col["path"]))
        if not d.ok:
            raise Inconclusive(f"DELETE -> {d.status}")
        bad = _step_mismatch(ctx, sp, sk, col, (l1, s1), "one delete")
        return ("medium", bad) if bad else None
    return fn


def filter_fn(ctx, col, field, contains):
    """Up to FILTER_VALUES distinct values of the field (most frequent first) are tried: one value can be too short or too
    common to show a fallback, so a single probe is not enough."""
    def fn():
        unf, complete, why = fetch_all(ctx, col)
        if not complete:
            raise Inconclusive(f"cannot enumerate every item ({why})")
        counts = Counter(norm(x[field]) for x in unf if isinstance(x, dict) and field in x)
        if len(counts) < 2:
            raise Inconclusive(f"'{field}' takes {len(counts)} distinct value(s): the filter cannot be tested")
        order = sorted(counts, key=lambda v: (-counts[v], -len(v)))
        for sv in order[:FILTER_VALUES]:
            found = _check_value(ctx, col, unf, field, sv, contains, set(counts))
            if found:
                return found
        return None
    return fn


def boolean_partition_params(query_params):
    """Boolean query params that can split a listing: control names and inclusion flags (include_*, with_*, show_*) are left out."""
    return [q["name"] for q in (query_params or [])
            if (q.get("schema") or {}).get("type") == "boolean" and q["name"] not in CONTROL and not INCLUSION_FLAG.match(q["name"])]


def partition_fn(ctx, col, name, base):
    """A boolean filter splits a listing in two: ?x=true and ?x=false must be disjoint and together equal the listing they filter
    (also under another filter: a bug that only shows when two filters are combined is the usual one)."""
    def fn():
        whole, c0, w0 = fetch_all(ctx, col, base or None)
        yes, c1, w1 = fetch_all(ctx, col, {**base, name: "true"})
        no, c2, w2 = fetch_all(ctx, col, {**base, name: "false"})
        if not (c0 and c1 and c2):
            raise Inconclusive(f"cannot enumerate every item ({w0 or w1 or w2})")
        W, T, F = ({ident(x) for x in L} for L in (whole, yes, no))
        if not W:
            raise Inconclusive("the listing is empty")
        under = f" (with {', '.join(f'{k}={v}' for k, v in base.items())})" if base else ""
        if T & F:
            return ("medium", f"?{name}=true and ?{name}=false both returned ids {sorted(T & F)[:5]}{under}: the filter does not split the listing")
        lost, extra = sorted(W - (T | F)), sorted((T | F) - W)
        if lost or extra:
            return ("medium", f"?{name}=true plus ?{name}=false do not add up to the listing{under}: missing ids {lost[:5]}, ids not in it {extra[:5]}")
        if base:                                        # composition: R(flag=v and base) must equal R(flag=v) intersected with R(base)
            for label, combined, v in (("true", T, "true"), ("false", F, "false")):
                alone, ca, wa = fetch_all(ctx, col, {name: v})
                if not ca:
                    raise Inconclusive(f"cannot enumerate ?{name}={v} alone ({wa})")
                expect = {ident(x) for x in alone} & W
                if combined != expect:
                    return ("medium", f"?{name}={v}{under} returned ids {sorted(combined - expect)[:5]} that ?{name}={v} alone does not, "
                                      f"and missed {sorted(expect - combined)[:5]}: combining the filters changes what {name} means")
        return None
    return fn


def search_fn(ctx, col, name, documented):
    """Text search: the same word in its original, lower and upper case must find the same items when the search is documented as
    case-insensitive (medium); when the document says nothing the difference is only reported as low 'verify'."""
    def fn():
        words = [w for x in col["sample"] if isinstance(x, dict) for v in x.values() if isinstance(v, str)
                 for w in re.findall(r"[A-Za-z]{4,}", v)]
        word = next((w for w in words if w != w.lower() and w != w.upper()), None) or (words[0] if words else None)
        if word is None:
            raise Inconclusive("no alphabetic word of 4+ letters in the sample to search for")
        found = {}
        for label, q in (("exact", word), ("lower", word.lower()), ("upper", word.upper())):
            items, complete, why = fetch_all(ctx, col, {name: q})
            if not complete:
                raise Inconclusive(f"search results cannot be enumerated ({why})")
            found[label] = {ident(x) for x in items}
        if not found["exact"]:
            raise Inconclusive(f"?{name}={word!r} returned nothing: no baseline to compare the other cases with")
        if found["exact"] == found["lower"] == found["upper"]:
            return None
        counts = ", ".join(f"{k}={len(v)}" for k, v in found.items())
        if documented:
            return ("medium", f"?{name}={word!r}: the OpenAPI describes the search as case-insensitive but the answers differ by case ({counts})")
        return ("low", f"?{name}={word!r}: answers differ by case ({counts}); verify whether the search is meant to be case-insensitive")
    return fn


def _check_value(ctx, col, unf, field, sv, contains, values):
    filt, c2, why2 = fetch_all(ctx, col, {field: sv})
    if not c2:
        raise Inconclusive(f"filtered listing cannot be enumerated ({why2})")
    bad = [x for x in filt if not _satisfies(x, field, sv, contains)]
    if bad:
        return ("medium", f"?{field}={sv} returned {len(bad)} item(s) not matching it "
                          f"({'contains' if contains else 'equal'}), e.g. id={ident(bad[0])} "
                          f"{field}={bad[0].get(field) if isinstance(bad[0], dict) else bad[0]!r}")
    ukeys = {ident(x) for x in unf}
    outside = [ident(x) for x in filt if ident(x) not in ukeys]
    if outside:
        return ("medium", f"?{field}={sv} returned ids not present in the unfiltered listing: {outside[:5]}")
    if contains:
        return None
    fkeys = {ident(x) for x in filt}
    dropped = [ident(x) for x in unf if norm(x.get(field) if isinstance(x, dict) else None) == sv and ident(x) not in fkeys]
    if dropped:
        return ("medium", f"?{field}={sv} dropped items that carry exactly that value: ids {dropped[:5]}")
    probe = _strict_probe(sv, values)
    if probe is not None:
        pf, c3, _ = fetch_all(ctx, col, {field: probe})
        if c3 and any(norm(x.get(field) if isinstance(x, dict) else None) != probe for x in pf):
            wrong = [x for x in pf if norm(x.get(field) if isinstance(x, dict) else None) != probe]
            return ("medium", f"exact filter {field}={probe!r} (a strict substring of {sv!r}) returned "
                              f"{len(wrong)} item(s) whose value is not {probe!r}, e.g. {field}="
                              f"{wrong[0].get(field) if isinstance(wrong[0], dict) else wrong[0]!r}")
    return None


def _satisfies(x, field, sv, contains):
    if not isinstance(x, dict) or field not in x:
        return False
    v = x[field]
    if contains and isinstance(v, str):
        return sv.casefold() in v.casefold()
    return norm(v) == sv


def _strict_probe(sv, values):
    """A strict substring of `sv` (3+ chars) that equals none of the seeded values, or None."""
    low = {v.casefold() for v in values}
    for n in range(len(sv) - 1, 2, -1):
        if sv[:n].casefold() not in low:
            return sv[:n]
    return None


def sort_fn(ctx, col, sort_name, field, order_name):
    def fn():
        r1, c1, why = fetch_all(ctx, col, {sort_name: field})
        if not c1:
            raise Inconclusive(f"sorted listing cannot be enumerated ({why})")
        keys = [x.get(field) if isinstance(x, dict) else None for x in r1]
        if not keys or any(k is None for k in keys):
            raise Inconclusive(f"'{field}' missing in some items")
        declared = item_field_type(col["op"], col["shape"], field)
        if declared in ("integer", "number"):
            strs = [k for k in keys if isinstance(k, str)]
            if strs:
                return ("medium", f"{sort_name}={field}: the spec declares {declared} but {len(strs)} of {len(keys)} "
                                  f"item(s) carry a string, e.g. {strs[0]!r}: they sort as text, not as numbers")
        try:
            sorted(keys)
        except TypeError:
            raise Inconclusive(f"'{field}' has mixed types")
        if len(set(map(str, keys))) < 3:
            raise Inconclusive(f"'{field}' has fewer than 3 distinct values")
        asc, desc = _monotone(keys)                      # text order first: a database that sorts numeric-looking strings as text is right
        if not asc and not desc and all(isinstance(k, str) and NUMERIC_TEXT.match(k) for k in keys):
            asc, desc = _monotone([float(k) for k in keys])   # numeric text with no declared type: numeric order is accepted too
        if not asc and not desc:
            return ("medium", f"{sort_name}={field} is not monotone: first keys {keys[:12]}")
        if asc and desc:
            raise Inconclusive(f"all '{field}' keys are equal")
        if order_name is None:
            return None
        opp = "desc" if asc else "asc"
        r2, c2, why2 = fetch_all(ctx, col, {sort_name: field, order_name: opp})
        if not c2:
            raise Inconclusive(f"reversed listing cannot be enumerated ({why2})")
        keys2 = [x.get(field) if isinstance(x, dict) else None for x in r2]
        if keys2 != list(reversed(keys)):
            return ("medium", f"{order_name}={opp} did not reverse {sort_name}={field}: asc keys {keys[:8]}, "
                              f"reversed request keys {keys2[:8]}")
        if len(set(map(str, keys))) == len(keys) and ids_of(r2) != list(reversed(ids_of(r1))):
            return ("medium", f"{order_name}={opp} reverses the keys of {sort_name}={field} but not the items, "
                              f"and the keys are distinct: asc ids {ids_of(r1)[:8]}, {opp} ids {ids_of(r2)[:8]}")
        return None
    return fn


def param_order_fn(ctx, path, pairs):
    def fn():
        a = ctx.rq("GET", path, dict(pairs))
        a2 = ctx.rq("GET", path, dict(pairs))
        if ctx.canon(a) != ctx.canon(a2):
            raise Inconclusive("unstable: the same request twice answered differently")
        b = ctx.rq("GET", path, dict(reversed(pairs)))
        if a.status == b.status and ctx.canon(a) == ctx.canon(b):
            return None
        return ("medium", f"same parameters in another order: {[k for k, _ in pairs]} -> {a.status}, "
                          f"reversed -> {b.status}; body diff: {ctx.diff(a, b)}")
    return fn


def unknown_fn(ctx, path):
    def fn():
        base, base2 = ctx.rq("GET", path), ctx.rq("GET", path)
        if not base.ok:
            raise Inconclusive(f"baseline GET -> {base.status}")
        if ctx.canon(base) != ctx.canon(base2):
            raise Inconclusive("unstable baseline")
        r = ctx.rq("GET", path, {UNKNOWN_PARAM: "qa-probe"})
        if r.server_error or r.transport:
            return ("medium", f"unknown query parameter -> {r.status}: {r.text[:120]}")
        if r.ok and ctx.canon(r) != ctx.canon(base):
            return ("medium", f"unknown query parameter changed the answer: {ctx.diff(base, r)}")
        return None
    return fn


def _ctype(r):
    for k, v in r.headers.items():
        if k.lower() == "content-type":
            return v.split(";")[0].strip().lower()
    return ""


def head_fn(ctx, path):
    def fn():
        g = ctx.rq("GET", path)
        if not g.ok:
            raise Inconclusive(f"GET -> {g.status}")
        h = ctx.rq("HEAD", path)
        if h.status in (405, 501):
            raise NotApplicable(f"HEAD answers {h.status}")
        if h.server_error or h.transport:
            return ("medium", f"HEAD -> {h.status} while GET -> {g.status}")
        if h.status != g.status:
            return ("medium", f"HEAD -> {h.status} but GET -> {g.status}")
        if _ctype(g) and _ctype(h) and _ctype(g) != _ctype(h):
            return ("low", f"Content-Type differs: GET {_ctype(g)}, HEAD {_ctype(h)}")
        return None
    return fn


def read_fn(ctx, path):
    def fn():
        a, b = ctx.rq("GET", path), ctx.rq("GET", path)
        if not a.ok:
            raise Inconclusive(f"GET -> {a.status}")
        if b.status != a.status:
            return ("medium", f"two identical GETs answered {a.status} then {b.status}")
        if ctx.canon(a) == ctx.canon(b):
            return None
        if ctx.unordered(a) == ctx.unordered(b):
            return ("low", "same items in a different order on two identical reads (default order unspecified?)")
        return ("medium", f"two identical GETs differ: {ctx.diff(a, b)}")
    return fn


def roundtrip_fn(ctx, path, body, tpl, param):
    def fn():
        rid = create(ctx, path, body)
        g = ctx.rq("GET", fill(tpl, {param: rid}), role=ctx.role_for(path))
        if not g.ok:
            return ("medium", f"created id={rid} but GET -> {g.status}: {g.text[:100]}")
        if not isinstance(g.json, dict) or not isinstance(body, dict):
            raise Inconclusive("create or read body is not a JSON object")
        mism, weak = [], True
        for k, v in body.items():
            if k in g.json and g.json[k] != v:
                mism.append(f"{k}: sent {v!r}, read back {g.json[k]!r}")
                if not (isinstance(v, str) and isinstance(g.json[k], str) and v.strip() == g.json[k].strip()):
                    weak = False
        if not mism:
            return None
        return ("low" if weak else "medium", f"id={rid}: " + "; ".join(mism))
    return fn


def put_fn(ctx, path, create_body, put_body, tpl, param):
    def fn():
        rid = create(ctx, path, create_body)
        target = fill(tpl, {param: rid})
        role = ctx.role_for(path)
        p1 = ctx.rq("PUT", target, body=put_body, role=role)
        if not p1.ok:
            raise Inconclusive(f"first PUT -> {p1.status}")
        s1 = ctx.rq("GET", target, role=role)
        p2 = ctx.rq("PUT", target, body=put_body, role=role)
        if p2.server_error or p2.transport:
            return ("medium", f"second identical PUT {target} -> {p2.status}: {p2.text[:100]}")
        if not p2.ok:
            raise Inconclusive(f"second PUT -> {p2.status}")
        s2 = ctx.rq("GET", target, role=role)
        if not (s1.ok and s2.ok):
            raise Inconclusive("GET after PUT failed")
        if ctx.canon(s1) == ctx.canon(s2):
            return None
        return ("medium", f"state after PUT #1 != state after PUT #2 (same body): {ctx.diff(s1, s2)}")
    return fn


def _child_state(ctx, path, role=None):
    """(status, number of items) of a child collection read, as `role` (default: the default role)."""
    r = ctx.rq("GET", path, role=role)
    if r.server_error or r.transport:
        return r.status, None
    if not r.ok:
        return r.status, 0
    items = list_of(r.json, detect_shape(r.json))
    return r.status, (len(items) if items is not None else 0)


SOFT_FLAG = re.compile(r"^(is_)?(deleted|removed|archived)(_at|_on)?$", re.I)
SOFT_OFF = re.compile(r"^(is_)?(active|enabled|available)$", re.I)
SOFT_STATE = {"deleted", "removed", "archived", "inactive", "trashed"}


def soft_deleted(body) -> bool:
    """The resource answers 200 after DELETE but says itself that it is deleted (deleted:true, deleted_at set, active:false,
    status:'archived'): a documented soft delete, not a leftover. Anything else answering 200 stays a finding."""
    if not isinstance(body, dict):
        return False
    for k, v in body.items():
        if SOFT_FLAG.match(k) and v not in (None, False, 0, "", "false"):
            return True
        if SOFT_OFF.match(k) and v in (False, 0, "false"):
            return True
        if k.lower() in ("status", "state") and isinstance(v, str) and v.lower() in SOFT_STATE:
            return True
    return False


GONE_STATUS = (403, 404, 410)     # after a DELETE: 404/410 is gone; 403 means this role cannot see it, which is not a leftover either


def delete_fn(ctx, path, create_body, tpl, param, children):
    """Create an item (and one child under each documented child collection), DELETE it as its owner, then read it back as its
    owner. A 200 that still shows the item is a finding (unless it says it is soft-deleted). Reads by the default role are not
    used: a 403 from another role is not evidence that the resource remains."""
    def fn():
        rid = create(ctx, path, create_body)
        target = fill(tpl, {param: rid})
        role = ctx.role_for(path)                        # the role that created the item (create() records it)
        kids = []
        for ctpl, cbody in children:                     # one item under each documented child collection
            cpath = fill(ctpl, {param: rid})
            try:
                create(ctx, cpath, cbody)
                kids.append((cpath, ctx.role_for(cpath)))
            except Inconclusive:
                pass
        before = {c: _child_state(ctx, c, crole) for c, crole in kids}
        d1 = ctx.rq("DELETE", target, role=role)
        if not d1.ok:
            raise Inconclusive(f"DELETE -> {d1.status}")
        g = ctx.rq("GET", target, role=role)
        if g.status not in GONE_STATUS:
            g = ctx.rq("GET", target, role=role)         # one re-read: eventual consistency is not a leftover
            if g.status not in GONE_STATUS and not (g.ok and soft_deleted(g.json)):
                return ("high", f"DELETE answered {d1.status} but GET {target} still answers {g.status}: the resource remains")
        for c, crole in kids:
            n0 = before[c][1]
            if not n0:
                continue
            status, n = _child_state(ctx, c, crole)
            if n is None:
                return ("medium", f"after DELETE {target}, GET {c} -> {status}: a server error for the children of a deleted item")
            if n:
                return ("medium", f"after DELETE {target} (answered {d1.status}) the child collection {c} still lists "
                                  f"{n} item(s) of the deleted item (it listed {n0} before): expected 404 or an empty list")
        d2 = ctx.rq("DELETE", target, role=role)
        if d2.server_error or d2.transport:
            return ("medium", f"second DELETE {target} -> {d2.status}: {d2.text[:100]}")
        return None
    return fn


ATOMIC_WORDS = re.compile(r"all[- ]or[- ]nothing|atomic|transaction|rolled? back|either all|none (of them )?(is|are) (created|saved)", re.I)


def bulk_atomic_fn(ctx, col, bulk):
    """POST a bulk body of one valid item plus one item missing a required field: the request must be rejected AND leave the collection
    unchanged. Rejected-but-partly-applied is the classic commit-while-validating bug (medium when the document promises all-or-nothing,
    low 'verify' otherwise: some APIs apply partial batches by design and say so)."""
    def fn():
        sch, spec = bulk["body_schema"], ctx.spec
        base = example(sch, spec) if isinstance(sch, dict) else None
        field, isch = None, None
        if isinstance(sch, dict) and sch.get("type") == "array":
            isch = resolve(sch.get("items", {}), spec)
        elif isinstance(sch, dict):
            for n, p in (sch.get("properties") or {}).items():
                p = resolve(p, spec)
                if p.get("type") == "array":
                    field, isch = n, resolve(p.get("items", {}), spec)
                    break
        if not isinstance(isch, dict) or not isinstance(example(isch, spec), dict):
            raise NotApplicable("the bulk body does not hold an array of objects")
        required = [k for k in (isch.get("required") or []) if k in example(isch, spec)]
        if not required:
            raise NotApplicable("the bulk item has no required field to break")
        ctx.nonce = getattr(ctx, "nonce", 0) + 1
        good = _unique_variant(example(isch, spec), f"g{ctx.nonce}")
        bad = _unique_variant({k: v for k, v in example(isch, spec).items() if k != required[0]}, f"h{ctx.nonce}")
        body = [good, bad] if field is None else {**(base if isinstance(base, dict) else {}), field: [good, bad]}
        before = list_total(ctx, col)
        resp = None
        for role in ctx.writers(bulk["path"]):
            resp = ctx.rq("POST", bulk["path"], body=body, role=role)
            if resp.status not in (401, 403):
                break
        if resp is None or resp.status in (401, 403):
            raise Inconclusive("no configured role may call the bulk endpoint")
        if resp.ok or not (400 <= resp.status < 500):
            raise Inconclusive(f"the bulk request with a broken item answered {resp.status}: no clean rejection to test atomicity on")
        after = list_total(ctx, col)
        if after > before:
            documented = bool(ATOMIC_WORDS.search(declared_text(bulk, "")))
            return ("medium" if documented else "low",
                    f"POST {bulk['path']} was rejected ({resp.status}) because one item lacks '{required[0]}', yet {after - before} item(s) "
                    f"were created ({before} -> {after})" + ("; the OpenAPI promises all-or-nothing" if documented else "; verify whether partial batches are intended"))
        return None
    return fn


def child_specs(ctx, ops, tpl, param, by):
    """(child collection template, example body) for each direct sub-collection of `tpl` that has a POST."""
    out = []
    if not tpl:
        return out
    for o in ops:
        if o["method"] != "GET" or not o["path"].startswith(tpl + "/"):
            continue
        rest = o["path"][len(tpl) + 1:]
        if "{" in rest or "/" in rest or re.findall(r"\{(\w+)\}", o["path"]) != [param]:
            continue
        post = by.get(f"POST {o['path']}")
        body = body_for(ctx, post)
        if body is not None:
            out.append((o["path"], body))
    return out


# ---------- execution ----------

def run_instance(ctx, kind, label, base, fn):
    """Run one relation instance. A violation counts only when the second, independent run reproduces it."""
    st = ctx.stats[kind]
    if ctx.skipped(kind, label, base):
        st["skipped"] += 1
        return
    st["instances"] += 1
    ctx.trace = []
    try:
        first = fn()
        if first is None:
            st["clean"] += 1
            return
        first_trace = ctx.trace
        ctx.trace = []
        second = fn()
        if second is None:
            st["inconclusive"] += 1
            ctx.notes.append(f"{kind} {label}: NOT reported, the violation did not reproduce on the second run "
                             f"(flaky): {first[1][:160]}")
            return
        sev, detail = first
        ctx.findings.append({"kind": kind, "severity": sev, "endpoint": base, "detail": f"{label}: {detail}"[:1200],
                             "sequence": "\n".join(first_trace)[-1800:]})
        st["violations"] += 1
    except NotApplicable as exc:
        st["instances"] -= 1
        st["not_applicable"] += 1
        ctx.notes.append(f"{kind} {label}: not applicable: {exc}")
    except Inconclusive as exc:
        st["inconclusive"] += 1
        ctx.notes.append(f"{kind} {label}: inconclusive: {exc}"[:300])
    except Exception as exc:                  # odd app answers must not kill the engine: record and degrade
        st["errors"] += 1
        ctx.notes.append(f"{kind} {label}: engine error: {type(exc).__name__}: {exc}"[:300])


def finish(ctx, cols):
    total = sum(s["instances"] for s in ctx.stats.values())
    na = sorted(ctx.na_relations)
    inc = sum(s["inconclusive"] for s in ctx.stats.values())
    errs = sum(s["errors"] for s in ctx.stats.values())
    skipped = sum(s["skipped"] for s in ctx.stats.values())
    if skipped:
        ctx.notes.append(f"{skipped} relation check(s) skipped by METAMORPHIC_SKIP (explicit choice, not a degradation)")
    ctx.notes.append("collections: " + (", ".join(f"{c['path']} ({c['style'] + ' paging' if c['style'] != 'none' else 'no paging'})"
                                                  for c in cols) or "none found"))
    res = {"engine": "metamorphic", "findings": ctx.findings, "notes": ctx.notes, "probes": total,
           "requests": len(ctx.api.log) - ctx.log0, "relations": ctx.stats, "volatile_learned": sorted(ctx.learned)}
    if total == 0:
        return trust.mark(res, trust.SKIPPED, "skipped_no_spec: no metamorphic relation applies to this OpenAPI ("
                                              + "; ".join(f"{k}: {NA_REASON[k]}" for k in na[:3]) + " ...)")
    if na or inc or errs:
        reasons = []
        if na:
            reasons.append("relation not applicable: " + ", ".join(na))
        if inc:
            reasons.append(f"{inc} check(s) inconclusive")
        if errs:
            reasons.append(f"{errs} check(s) errored")
        return trust.mark(res, trust.DEGRADED, "; ".join(reasons))
    return trust.mark(res, trust.RAN_OK, f"all applicable relations ran ({total} checks)")


def build_plan(ctx, ops, cols, reads, stat_fields):
    by = {key(o): o for o in ops}
    plan = {k: [] for k in RELATIONS}
    for col in cols:
        ek, P, sample = col["ek"], col["path"], col["sample"]
        post = by.get(f"POST {P}")
        tpl, param = item_tpl(ops, P)
        get_i, put_i, del_i = (by.get(f"{m} {tpl}") if tpl else None for m in ("GET", "PUT", "DELETE"))
        fields = scalar_fields(sample)
        filt_names = [n for n in col["declared"] if n not in CONTROL and n in fields]
        if col["style"] in ("offset", "page"):
            plan["MR-PAGE-UNION"].append((ek, ek, union_fn(ctx, col)))
            if col["total"]:
                plan["MR-PAGE-TOTAL"].append((f"{ek} total={col['total']}", ek, total_fn(ctx, col)))
        if col["size"]:
            for v in (0, -1, 10 ** 9):
                plan["MR-PAGE-TOTAL"].append((f"{ek} {col['size']}={v}", ek, limit_fn(ctx, col, v)))
        for n in filt_names:
            contains = bool(SUBSTRING_WORDS.search(declared_text(col["op"], n)))
            plan["MR-FILTER-SUBSET"].append((f"{ek} ?{n}=", ek, filter_fn(ctx, col, n, contains)))
        bools = boolean_partition_params(col["op"].get("query_params"))
        base_filters = [{}]
        if sample and filt_names and sample[0].get(filt_names[0]) is not None:
            base_filters.append({filt_names[0]: norm(sample[0].get(filt_names[0]))})
        for n in bools:
            for b in base_filters:
                plan["MR-FILTER-PARTITION"].append((f"{ek} ?{n}=" + (f" + {next(iter(b))}" if b else ""), ek, partition_fn(ctx, col, n, b)))
        for n in col["declared"]:
            if n in SEARCH_NAMES and n not in CONTROL:
                txt = declared_text(col["op"], n)
                if CASE_SENSITIVE.search(txt) and not CASE_INSENSITIVE.search(txt):
                    continue                                   # documented as case-sensitive: a difference is the contract
                plan["MR-SEARCH-CASE"].append((f"{ek} ?{n}=", ek, search_fn(ctx, col, n, bool(CASE_INSENSITIVE.search(txt)))))
        for bulk in ops:
            if (bulk["method"] == "POST" and not bulk["path_params"] and bulk["path"].startswith(P.rstrip("/") + "/")
                    and "/" not in bulk["path"][len(P.rstrip("/")) + 1:] and bulk.get("body_schema") and col["op"]):
                plan["MR-BULK-ATOMIC"].append((key(bulk), key(bulk), bulk_atomic_fn(ctx, col, bulk)))
        sort_name = next((n for n in col["declared"] if n in SORT_NAMES), None)
        order_name = next((n for n in col["declared"] if n in ORDER_NAMES), None)
        sort_fields = []
        if sort_name and fields:
            enum = sort_enum(col["op"], sort_name)
            sort_fields = [f for f in enum if f in fields] if enum else fields
            for f in sort_fields[:3]:
                plan["MR-SORT-ORDER"].append((f"{ek} {sort_name}={f}", ek,
                                              sort_fn(ctx, col, sort_name, f, order_name)))
        if sample:
            filt = (filt_names[0], norm(sample[0].get(filt_names[0]))) if filt_names else None
            pairs = settable_pairs(col, sort_fields[0] if sort_fields else None, filt)
            if len(pairs) >= 2:
                plan["MR-PARAM-ORDER"].append((ek, ek, param_order_fn(ctx, P, pairs)))
        body_c = body_for(ctx, post)
        body_p = body_for(ctx, put_i)
        if post and get_i and body_c is not None:
            plan["MR-WRITE-ROUNDTRIP"].append((key(post), key(post), roundtrip_fn(ctx, P, body_c, tpl, param)))
            if put_i and body_p is not None:
                plan["MR-PUT-IDEMPOTENT"].append((key(post), key(post), put_fn(ctx, P, body_c, body_p, tpl, param)))
            if del_i:
                children = child_specs(ctx, ops, tpl, param, by)
                plan["MR-DELETE-GONE"].append((key(post), key(post), delete_fn(ctx, P, body_c, tpl, param, children)))
        if post and del_i and body_c is not None:
            for sp, sk in stat_fields:
                start = ctx.count_start.get((sp, P))
                if start is None:
                    continue
                if not (start[0] or _mentions(col, sp, sk)):
                    ctx.notes.append(f"{sp} {sk} is not paired with {P}: the totals differ before any write and the names "
                                     f"do not mention the collection")
                    continue
                plan["MR-COUNT-AGREE"].append((f"{sp} {sk} vs {P}", ek,
                                               count_fn(ctx, sp, sk, col, body_c, tpl, param)))
    for op, path in reads:
        ek = key(op)
        label = f"{op['method']} {path}"
        plan["MR-READ-IDEMPOTENT"].append((label, ek, read_fn(ctx, path)))
        plan["MR-UNKNOWN-PARAM"].append((label, ek, unknown_fn(ctx, path)))
        plan["MR-HEAD-GET"].append((label, ek, head_fn(ctx, path)))
    return plan


def sort_enum(op, name):
    p = next((p for p in op["query_params"] if p["name"] == name), None)
    return list(((p or {}).get("schema") or {}).get("enum") or [])


def settable_pairs(col, sort_field, filt):
    """Ordered (name, value) pairs for the declared params the engine can set to a valid value."""
    out = []
    for n in col["declared"]:
        if n == col["size"]:
            out.append((n, 3))
        elif n == col["offset"]:
            out.append((n, 0))
        elif n == col["page"]:
            out.append((n, col["base"]))
        elif n in SORT_NAMES and sort_field:
            out.append((n, sort_field))
        elif n in ORDER_NAMES:
            out.append((n, "asc"))
        elif filt and n == filt[0]:
            out.append((n, filt[1]))
    return out


def _mentions(col, sp, sk) -> bool:
    """The stats field names the collection: its last path segment (singular stem) occurs in the stats path or field."""
    seg = col["path"].rstrip("/").split("/")[-1].lower()
    stem = seg[:-1] if seg.endswith("s") else seg
    return bool(stem) and stem in f"{sp} {sk}".lower()


def snapshot_counts(ctx, ops, cols, stat_fields):
    """Before any write: does each stats count agree with each writable collection's total? Agreement, or a name that
    mentions the collection, pairs them for MR-COUNT-AGREE."""
    by = {key(o): o for o in ops}
    for sp, sk in stat_fields:
        for col in cols:
            if not writable(col, by, ops):
                continue
            try:
                l0, s0 = list_total(ctx, col), stat_value(ctx, sp, sk)
            except Inconclusive:
                l0 = s0 = None
            ctx.count_start[(sp, col["path"])] = (l0 is not None and l0 == s0, l0, s0)


# ---------- entry point ----------

def run(api, spec_doc, qa) -> dict:
    global_skip = set(getattr(qa, "SKIP", set()) or set())
    ops = [o for o in endpoints(spec_doc) if key(o) not in global_skip]
    ctx = Ctx(api, spec_doc, qa)
    try:
        cols = discover(ctx, ops)
        stat_fields = discover_counts(ctx, ops)
        if seed(ctx, cols, ops):
            cols = discover(ctx, ops)                    # the samples now include the seeded items
        reads = [(op, concrete_path(op, cols)) for op in ops if op["method"] == "GET" and not op["query_required"]]
        reads = [(op, p) for op, p in reads if p is not None]
        learn_volatile(ctx, [p for _, p in reads])
        if ctx.learned:
            ctx.notes.append("volatile fields learned from re-reads of the same GET (ignored by every comparison; "
                             f"override with qa.VOLATILE_FIELDS): {sorted(ctx.learned)}")
        snapshot_counts(ctx, ops, cols, stat_fields)
        plan = build_plan(ctx, ops, cols, reads, stat_fields)
        for kind in RELATIONS:
            if not plan[kind] and kind in OPTIONAL:
                continue
            if not plan[kind]:
                ctx.na_relations[kind] = NA_REASON[kind]
                ctx.notes.append(f"relation not applicable: {kind} ({NA_REASON[kind]})")
                continue
            for label, base, fn in plan[kind]:
                run_instance(ctx, kind, label, base, fn)
    finally:
        cleanup(ctx, ops)
    return finish(ctx, cols)
