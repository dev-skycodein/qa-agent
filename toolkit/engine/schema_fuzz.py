"""Schema-branch and response-conformance fuzzing: the `schema` engine.

WHY: api.resolve() keeps only the FIRST anyOf/oneOf branch, so the other branches and the boundaries of every field are
never sent. Nothing checks that the app's responses match the response schemas the spec declares either.

DESIGN CANDIDATES (tree of thoughts) and the choice:
  A. Enumerate only: send every branch / enum / nullable / boundary once. Deterministic and cheap, but blind to
     combinations and has no principled stop rule.
  B. Pure random generation from the schema (Hypothesis-style) under a budget. Broad, but a generator bug yields
     schema-INVALID bodies, so a 4xx becomes a false "valid input rejected" and a 5xx a false "valid input crashed".
  C. CHOSEN, hybrid. (1) Deterministic enumeration from a 2xx baseline, ONE change per candidate (branches, enum values,
     nullable null, boundaries). (2) Seeded random VALID bodies, spent only while NEW (status, response key-shape)
     signatures keep appearing (stop after STALE_LIMIT consecutive repeats), under a per-endpoint and a global hard cap.
     Every body is checked by our own validator BEFORE it is sent, so nothing we send is schema-invalid by our own
     reading and an error answer means something.

ORACLES (each finding carries request + response evidence in `detail`):
  SCHEMA-VALID-5XX      a schema-valid input (or the qa.BODIES baseline, when it passes our validator) got a 5xx. Reported
                        only when one identical resend is 5xx too; a flake is a note, not a finding. medium.
  SCHEMA-REJECTS-VALID  a DETERMINISTIC schema-valid variant got 400/422 while the baseline (or another 2xx sibling on the
                        same endpoint and role) got 2xx. Needs that control. A resend must also be 400/422. Bodies that
                        look like conflicts ("already exists", "unique", ...) are not reported. medium.
                        Only values the SCHEMA DECLARES may back it: a declared bound (minimum, maximum, exclusive forms,
                        minLength, maxLength, minItems, maxItems), an enum member, example, default, a pattern or format
                        sample, a boolean, a nullable null. Invented values (natural 1, zero, "qa", the untyped "qa", an
                        array length with no declared bounds) are still SENT, for 5xx and drift, but a 4xx on them is
                        only a note: the schema does not say they are valid boundaries.
                        Random multi-field inputs never feed this oracle (too many confounders).
  SCHEMA-ACCEPTS-INVALID  a PUT or PATCH whose body breaks one declared enum or pattern of one field answered 2xx (twice).
                        Control: the same write with a valid value answered 2xx. The item's original value is written back
                        afterwards (best effort). medium. False-positive risk: an app that normalises the value
                        (trim, case) before checking it; the detail names the rule it broke.
  SCHEMA-DRIFT          a 2xx, or a documented 4xx/default, JSON body violates its declared response schema. Path and the
                        offending value are given. low (a contract mismatch, not an exploit by itself).

FALSE-POSITIVE RISKS (details in docs/design/engine-schema-fuzz.md): cross-field business rules the schema does not state
(REJECTS), a 5xx caused by a downstream outage (SCHEMA-VALID-5XX), oneOf overlap (we accept a value that matches at least
one branch, so drift is missed rather than invented), pattern/format checks only as strict as the regexes below.

qa-spec knobs (all optional, read with getattr): SKIP, BODIES (valid baseline body), PUBLIC (sent as anon), IDS (path
params; an unlisted param is probed with '1' and reported as a gap), OWNER (role per endpoint, default user_a),
SCHEMA_MAX (global probe cap, default 600), SCHEMA_PER_ENDPOINT (default 40), SCHEMA_SEED (default 1).
DELETE is never sent (destructive, nothing to fuzz body-wise).

Usage: run(client, spec_doc, qa, seed=None, max_probes=None, per_endpoint=None) -> engine result dict (see trust.py).
"""
import datetime
import json
import math
import random
import re
import urllib.parse
import uuid

import api
import trust

# Keywords the validator does NOT check. A schema that uses one cannot be judged by it, so the operation is DEGRADED and no
# SCHEMA-DRIFT / SCHEMA-REJECTS-VALID is reported for it (the validator would otherwise call a value valid that the schema forbids,
# or the reverse: e.g. a writeOnly field the app rightly omits from a response is "required" to our validator).
UNSUPPORTED = ("multipleOf", "uniqueItems", "patternProperties", "minProperties", "not", "if", "then", "else", "readOnly", "writeOnly")

KIND_SEVERITY = {"SCHEMA-VALID-5XX": "medium", "SCHEMA-REJECTS-VALID": "medium", "SCHEMA-DRIFT": "low",
                 "SCHEMA-ACCEPTS-INVALID": "medium"}
REJECT_STATUSES = (400, 422)
CONFLICT_WORDS = ("already exists", "already registered", "duplicate", "unique", "conflict", "taken", "in use")
WRITE = ("POST", "PUT", "PATCH")
DEFAULT_SEED, DEFAULT_MAX_PROBES, DEFAULT_PER_ENDPOINT = 1, 600, 40
DET_LIMIT, STALE_LIMIT = 30, 12
ACCEPT_PROBES = 6           # PUT/PATCH body fields probed with an out-of-contract value (enum or pattern)
ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.éß漢"
SAMPLE = {"email": "qa@example.com", "date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z",
          "uuid": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"}
FORMATS = {
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "date": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
    "date-time": re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", re.I),
    "uuid": re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
}


try:                                  # Python 3.11+ moved the regex parser into re._parser / re._constants
    from re import _constants as _C
    from re import _parser as _P
except ImportError:                      # pragma: no cover - Python < 3.11
    import sre_constants as _C
    import sre_parse as _P

_CAT_RE = {_C.CATEGORY_DIGIT: r"\d", _C.CATEGORY_NOT_DIGIT: r"\D", _C.CATEGORY_SPACE: r"\s",
           _C.CATEGORY_NOT_SPACE: r"\S", _C.CATEGORY_WORD: r"\w", _C.CATEGORY_NOT_WORD: r"\W"}


class _NoSample(Exception):
    """A regex construct the sampler does not generate (lookaround, backreference, ...)."""


def _in_member(ch, items) -> bool:
    negate = any(op == _C.NEGATE for op, _ in items)
    hit = False
    for op, av in items:
        if op == _C.LITERAL and ord(ch) == av:
            hit = True
        elif op == _C.RANGE and av[0] <= ord(ch) <= av[1]:
            hit = True
        elif op == _C.CATEGORY and re.fullmatch(_CAT_RE.get(av, "(?!)"), ch):
            hit = True
    return hit != negate


def _in_sample(items, rng):
    pool = []
    for op, av in items:
        if op == _C.LITERAL:
            pool.append(chr(av))
        elif op == _C.RANGE:
            pool += [chr(av[0]), chr(av[1])]
        elif op == _C.CATEGORY:
            pool += [c for c in ("0", "a", " ", "_") if re.fullmatch(_CAT_RE.get(av, "(?!)"), c)]
    pool += list("aA0_ -.x9")
    ok = [c for c in dict.fromkeys(pool) if _in_member(c, items)]
    if not ok:
        raise _NoSample("character class with no sampled member")
    return rng.choice(ok) if rng else ok[0]


def _regex_gen(seq, rng, out):
    for op, av in seq:
        if op == _C.LITERAL:
            out.append(chr(av))
        elif op == _C.NOT_LITERAL:
            out.append("a" if av != ord("a") else "b")
        elif op == _C.ANY:
            out.append("a")
        elif op in (_C.IN, _C.CATEGORY):
            out.append(_in_sample(av if op == _C.IN else [(op, av)], rng))
        elif op in (_C.MAX_REPEAT, _C.MIN_REPEAT) or op == getattr(_C, "POSSESSIVE_REPEAT", None):
            lo, hi, sub = av
            cap = lo + 3 if hi >= _C.MAXREPEAT else max(lo, min(hi, lo + 3))
            for _ in range(lo if rng is None else rng.randint(lo, cap)):
                _regex_gen(sub, rng, out)
        elif op == _C.SUBPATTERN:
            _regex_gen(av[-1], rng, out)
        elif op == _C.BRANCH:
            alts = av[1]
            _regex_gen(alts[rng.randrange(len(alts)) if rng else 0], rng, out)
        elif op == _C.AT:
            continue
        else:
            raise _NoSample(str(op))


def regex_sample(pattern, rng=None):
    """A string the regex matches: the first alternative and the fewest repeats (rng=None), or a random one. None when the
    pattern uses a construct this sampler does not generate. Every result is checked with re.search before it is returned."""
    try:
        out: list = []
        _regex_gen(_P.parse(pattern), rng, out)
        s = "".join(out)
        return s if re.search(pattern, s) else None
    except (_NoSample, re.error, RecursionError, ValueError, TypeError, IndexError):
        return None


class Unresolvable(Exception):
    """An external, dangling or cyclic $ref: the schema cannot be checked, so the operation is not fuzzed."""


class _Gap(Exception):
    """Coverage could not be built for an operation (no valid baseline, ...)."""


class _Budget(Exception):
    """The per-endpoint or the global probe cap was reached."""


# ---------- JSON-schema helpers (local $ref only) ----------

def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _intval(x, default):
    return int(x) if _num(x) else default


def _lookup(ref, spec):
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise Unresolvable(f"external or non-local $ref {ref!r}")
    node = spec
    for part in ref[2:].split("/"):
        part = urllib.parse.unquote(part).replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise Unresolvable(f"$ref {ref!r} does not resolve")
        node = node[part]
    return node


def deref(schema, spec):
    """Follow local $ref chains. The schema's own keywords (allOf, anyOf, ...) are left for the caller."""
    if schema is True:
        return {}
    if not isinstance(schema, dict):
        raise Unresolvable(f"schema is not an object: {str(schema)[:80]}")
    for _ in range(17):
        if "$ref" not in schema:
            return schema
        schema = _lookup(schema["$ref"], spec)
        if not isinstance(schema, dict):
            raise Unresolvable(f"$ref target is not an object: {str(schema)[:80]}")
    raise Unresolvable("$ref chain longer than 16")


def merged(schema, spec, depth=0):
    """The schema with allOf folded in (properties and required merged, other keys: the outer schema wins)."""
    s = deref(schema, spec)
    if "allOf" not in s:
        return s
    if depth > 10:
        raise Unresolvable("allOf nested deeper than 10")
    out, props, required = {}, {}, []
    for sub in s["allOf"]:
        m = merged(sub, spec, depth + 1)
        out.update({k: v for k, v in m.items() if k not in ("properties", "required")})
        props.update(m.get("properties") or {})
        required += [r for r in (m.get("required") or []) if r not in required]
    out.update({k: v for k, v in s.items() if k not in ("allOf", "properties", "required")})
    props.update(s.get("properties") or {})
    required += [r for r in (s.get("required") or []) if r not in required]
    if props:
        out["properties"] = props
    if required:
        out["required"] = required
    return out


def _types(s) -> list:
    t = s.get("type")
    if t is None:
        return []
    return list(t) if isinstance(t, list) else [t]


def _nullable(s) -> bool:
    return s.get("nullable") is True or "null" in _types(s)


def _kind(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _is_type(value, t) -> bool:
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, float) and value.is_integer())
    if t == "number":
        return _num(value)
    if t == "boolean":
        return isinstance(value, bool)
    if t == "object":
        return isinstance(value, dict)
    if t == "array":
        return isinstance(value, list)
    if t == "null":
        return value is None
    return True                                    # unknown type keyword: never invent a failure


def _same(a, b) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _j(v) -> str:
    return json.dumps(v, sort_keys=True, default=str)


class _Lbl(str):
    """A candidate label that also records whether the schema itself designates the value. Plain str labels count as
    designated; the producers of invented values (natural 1, zero, 'qa', untyped, unbounded array lengths) mark theirs False."""
    designated = True


def _lab(text, designated=True):
    out = _Lbl(text)
    out.designated = bool(designated)
    return out


def _des(lbl) -> bool:
    return getattr(lbl, "designated", True)


# ---------- validator (JSON-schema subset, stdlib only) ----------

def _real_datetime(value: str, fmt: str) -> bool:
    """The text already matches the format's shape (FORMATS); this checks the calendar and clock values it cannot express:
    2026-13-45, 2026-02-30 and 25:00:00 are shaped right and still not dates or times."""
    try:
        datetime.date(int(value[0:4]), int(value[5:7]), int(value[8:10]))
        if fmt == "date-time":
            hh, mm, ss = int(value[11:13]), int(value[14:16]), int(value[17:19])
            if hh > 23 or mm > 59 or ss > 60:
                return False
    except ValueError:
        return False
    return True


def check(value, schema, spec) -> list:
    """Validate `value` against `schema`. Returns [(path, message, offending value)]; [] means valid.

    Supported: $ref (local), type (incl. list and nullable / 3.0 nullable), enum, const, required, properties,
    additionalProperties (false or a schema), items, minItems/maxItems, minLength/maxLength, pattern, format (email,
    date, date-time, uuid), minimum/maximum with both the 3.0 boolean and the 3.1 numeric exclusive forms, allOf (all),
    anyOf and oneOf (at least one branch matches: the lenient reading, so overlap cannot create a false drift).
    Unknown keywords are ignored, and the keywords in UNSUPPORTED are not checked at all: an operation whose schema uses one is
    DEGRADED by _probe_op, so this validator's verdict on it is never reported as drift or rejection.
    Raises Unresolvable for an external or broken $ref."""
    errs: list = []
    _check(value, schema, spec, "$", 0, errs)
    return errs


def _check(value, schema, spec, path, depth, errs):
    if depth > 12:
        return                                       # deeper recursion than we follow: accept, never invent a failure
    s = deref(schema, spec)
    for sub in s.get("allOf") or []:
        _check(value, sub, spec, path, depth + 1, errs)
    for kw in ("anyOf", "oneOf"):
        if kw in s:
            ok = False
            for branch in s[kw] or []:
                sub_errs: list = []
                _check(value, branch, spec, path, depth + 1, sub_errs)
                if not sub_errs:
                    ok = True
                    break
            if not ok:
                errs.append((path, f"matches none of the {kw} branches", value))
    types = _types(s)
    if "enum" in s and isinstance(s["enum"], list) and not any(_same(value, e) for e in s["enum"]):
        errs.append((path, f"not one of the enum values {_j(s['enum'])[:120]}", value))
    if "const" in s and not _same(value, s["const"]):
        errs.append((path, f"must equal {_j(s['const'])}", value))
    if value is None:
        if types and not _nullable(s):
            errs.append((path, f"expected {'/'.join(types)}, got null", value))
        return
    if types and not any(_is_type(value, t) for t in types):
        errs.append((path, f"expected {'/'.join(types)}, got {_kind(value)}", value))
        return
    if isinstance(value, dict) and ("properties" in s or "required" in s or "additionalProperties" in s or "object" in types):
        props = s.get("properties") or {}
        for r in s.get("required") or []:
            if r not in value:
                errs.append((f"{path}.{r}", "required property missing", value))
        ap = s.get("additionalProperties", True)
        for k, v in value.items():
            p = f"{path}.{k}"
            if k in props:
                _check(v, props[k], spec, p, depth + 1, errs)
            elif ap is False:
                errs.append((p, "additional property not allowed", v))
            elif isinstance(ap, dict):
                _check(v, ap, spec, p, depth + 1, errs)
    if isinstance(value, list):
        if _num(s.get("minItems")) and len(value) < s["minItems"]:
            errs.append((path, f"fewer than {s['minItems']} item(s)", value))
        if _num(s.get("maxItems")) and len(value) > s["maxItems"]:
            errs.append((path, f"more than {s['maxItems']} item(s)", value))
        if isinstance(s.get("items"), dict):
            for i, v in enumerate(value):
                _check(v, s["items"], spec, f"{path}[{i}]", depth + 1, errs)
    if isinstance(value, str):
        if _num(s.get("minLength")) and len(value) < s["minLength"]:
            errs.append((path, f"shorter than {s['minLength']}", value))
        if _num(s.get("maxLength")) and len(value) > s["maxLength"]:
            errs.append((path, f"longer than {s['maxLength']}", value))
        if isinstance(s.get("pattern"), str):
            try:
                if not re.search(s["pattern"], value):
                    errs.append((path, f"does not match pattern {s['pattern']!r}", value))
            except re.error:
                pass                                 # an invalid pattern in the spec is not the app's failure
        fmt = s.get("format")
        if fmt in FORMATS and not FORMATS[fmt].match(value):
            errs.append((path, f"not a valid {fmt}", value))
        elif fmt in ("date", "date-time") and not _real_datetime(value, fmt):
            errs.append((path, f"not a real {fmt} (month, day or time out of range)", value))
    if _num(value):
        _bounds(value, s, path, errs)


def _bounds(v, s, path, errs):
    lo, hi = s.get("minimum"), s.get("maximum")
    exlo, exhi = s.get("exclusiveMinimum"), s.get("exclusiveMaximum")
    if _num(lo):
        if exlo is True and v <= lo:
            errs.append((path, f"must be > {lo}", v))
        elif v < lo:
            errs.append((path, f"must be >= {lo}", v))
    if _num(exlo) and v <= exlo:
        errs.append((path, f"must be > {exlo}", v))
    if _num(hi):
        if exhi is True and v >= hi:
            errs.append((path, f"must be < {hi}", v))
        elif v > hi:
            errs.append((path, f"must be <= {hi}", v))
    if _num(exhi) and v >= exhi:
        errs.append((path, f"must be < {exhi}", v))


# ---------- valid examples (deterministic enumeration) ----------

def _examples(schema, spec, depth=0) -> list:
    """Candidate values for one schema as [(label, value)]. Not yet validated: callers filter with check()."""
    if depth > 6:
        return []
    s = merged(schema, spec)
    out: list = []
    if "example" in s:
        out.append((_lab("example"), s["example"]))
    if "default" in s:
        out.append((_lab("default"), s["default"]))
    if isinstance(s.get("enum"), list):
        out += [(_lab(f"enum[{i}]"), v) for i, v in enumerate(s["enum"])]
    for kw in ("anyOf", "oneOf"):
        for i, branch in enumerate(s.get(kw) or []):
            out += [(_lab(f"{kw}[{i}]>{lbl}", _des(lbl)), v) for lbl, v in _valid_examples(branch, spec, depth + 1)[:4]]
    types = _types(s)
    if _nullable(s):
        out.append((_lab("null"), None))
    if "object" in types or "properties" in s:
        out += _object_examples(s, spec, depth)
    if "array" in types or "items" in s:
        out += _array_examples(s, spec, depth)
    if "integer" in types or "number" in types:
        out += _number_examples(s, "integer" in types and "number" not in types)
    if "string" in types or (not types and any(k in s for k in ("format", "minLength", "maxLength", "pattern"))):
        out += _string_examples(s)
    if "boolean" in types:
        out += [("true", True), ("false", False)]
    if not types and not any(k in s for k in ("enum", "anyOf", "oneOf", "properties", "items", "example", "default", "format")):
        out.append((_lab("untyped", False), "qa"))
    return out[:60]


def _valid_examples(schema, spec, depth=0) -> list:
    return [(lbl, v) for lbl, v in _examples(schema, spec, depth) if not check(v, schema, spec)]


def _number_examples(s, integer) -> list:
    step = 1 if integer else 0.5
    lo, hi = s.get("minimum"), s.get("maximum")
    exlo, exhi = s.get("exclusiveMinimum"), s.get("exclusiveMaximum")
    out = [(_lab("natural", False), 1)]
    if _num(lo):
        out.append(("minimum", lo))
    if _num(exlo):
        out.append(("exclusiveMinimum+step", exlo + step))
    if exlo is True and _num(lo):
        out.append(("exclusiveMinimum+step", lo + step))
    if _num(hi):
        out.append(("maximum", hi))
    if _num(exhi):
        out.append(("exclusiveMaximum-step", exhi - step))
    if exhi is True and _num(hi):
        out.append(("exclusiveMaximum-step", hi - step))
    out.append((_lab("zero", False), 0))
    if _num(lo) and _num(hi):
        out.append(("midpoint", (lo + hi) // 2 if integer else (lo + hi) / 2))
    return out


def _string_examples(s) -> list:
    out = []
    fmt = s.get("format")
    if fmt in SAMPLE:
        out.append((f"format={fmt}", SAMPLE[fmt]))
    out.append((_lab("qa", False), "qa"))
    if isinstance(s.get("pattern"), str):
        smp = regex_sample(s["pattern"])
        if smp is not None:
            out.append(("pattern", smp))
    mn, mx = s.get("minLength"), s.get("maxLength")
    if _num(mn) and 0 < mn <= 2000:
        out.append((f"minLength={mn}", "x" * int(mn)))
    if _num(mx) and 0 <= mx <= 2000:
        out.append((f"maxLength={mx}", "x" * int(mx)))
    return out


def _object_examples(s, spec, depth) -> list:
    """Baseline = required fields at their first valid example; then ONE field varied at a time."""
    props = s.get("properties") or {}
    base: dict = {}
    base_des = True
    for name in s.get("required") or []:
        ex = _valid_examples(props.get(name, {}), spec, depth + 1)
        if not ex:
            return []
        picks = [(lbl, v) for lbl, v in ex if v is not None]
        base[name] = picks[0][1] if picks else None
        base_des = base_des and (_des(picks[0][0]) if picks else True)
    out = [(_lab("object", base_des), dict(base))]
    opt_vals, opt_des = {}, True
    for name in props:
        if name in base:
            continue
        ex = _valid_examples(props[name], spec, depth + 1)
        if ex:
            opt_vals[name] = ex[0][1]
            opt_des = opt_des and _des(ex[0][0])
    if opt_vals:
        out.append((_lab("all-optional", opt_des), {**base, **opt_vals}))
    for name, ps in props.items():
        for lbl, v in _valid_examples(ps, spec, depth + 1)[:16]:
            out.append((_lab(f"{name}={lbl}", _des(lbl)), {**base, name: v}))
    return out


def _array_examples(s, spec, depth) -> list:
    items = s.get("items")
    ex = _valid_examples(items, spec, depth + 1) if isinstance(items, dict) else []
    mn, mx = _intval(s.get("minItems"), 0), s.get("maxItems")
    bounded = "minItems" in s or "maxItems" in s          # a length the schema declares; otherwise length 1 or 0 is invented
    if not ex:
        return [(_lab("array(empty)", "minItems" in s), [])] if mn == 0 else []
    v = ex[0][1]
    n = min(max(mn, 1), 64)
    out = [(_lab(f"array(len={n})", bounded and _des(ex[0][0])), [v] * n)]
    if mn == 0:
        out.append((_lab("array(empty)", "minItems" in s), []))
    if _num(mx) and 0 < mx <= 16 and mx != n:
        out.append((f"array(maxItems={int(mx)})", [v] * int(mx)))
    out += [(_lab(f"array[{lbl}]", bounded and _des(lbl)), [x]) for lbl, x in ex[:6]]
    return out


def uncovered_branches(schema, spec) -> list:
    """anyOf/oneOf branches (top level of `schema`) for which no schema-valid example could be built."""
    s = merged(schema, spec)
    return [f"{kw}[{i}]" for kw in ("anyOf", "oneOf") for i, b in enumerate(s.get(kw) or []) if not _valid_examples(b, spec)]


def branch_examples(schema, spec, limit=40) -> list:
    """Valid-per-branch request bodies for one schema: [{"label": str, "value": any}], at most `limit`.

    Order: the first valid example of EVERY top-level anyOf/oneOf branch first (branch coverage), then everything else
    (enum values, nullable null, one-field boundaries). Every value is accepted by check() and duplicates are removed.
    The first entry is the natural baseline. Raises Unresolvable for a bad $ref."""
    s = merged(schema, spec)
    ordered: list = []
    for kw in ("anyOf", "oneOf"):
        for i, branch in enumerate(s.get(kw) or []):
            ex = _valid_examples(branch, spec)
            if ex:
                ordered.append((_lab(f"{kw}[{i}]>{ex[0][0]}", _des(ex[0][0])), ex[0][1]))
    ordered += _valid_examples(schema, spec)
    out, index = [], {}
    for lbl, v in ordered:
        sig = _j(v)
        if sig in index:
            if _des(lbl) and not out[index[sig]]["designated"]:
                out[index[sig]]["designated"] = True        # the same value is also a declared one (e.g. minimum = 1)
            continue
        index[sig] = len(out)
        out.append({"label": lbl, "value": v, "designated": _des(lbl)})
        if len(out) >= limit:
            break
    return out


# ---------- valid random generation (seeded) ----------

def _random_value(schema, spec, rng, depth=0):
    if depth > 6:
        return "qa"
    s = merged(schema, spec)
    if s.get("nullable") is True and rng.random() < 0.1:
        return None
    for kw in ("anyOf", "oneOf"):
        if s.get(kw):
            return _random_value(rng.choice(s[kw]), spec, rng, depth + 1)
    if isinstance(s.get("enum"), list) and s["enum"]:
        return rng.choice(s["enum"])
    types = [t for t in _types(s) if t != "null"]
    if types:
        t = rng.choice(types)
    elif "properties" in s:
        t = "object"
    elif "items" in s:
        t = "array"
    else:
        return "qa"
    if t == "object":
        req = s.get("required") or []
        return {n: _random_value(p, spec, rng, depth + 1) for n, p in (s.get("properties") or {}).items()
                if n in req or rng.random() < 0.5}
    if t == "array":
        lo = min(_intval(s.get("minItems"), 0), 64)
        hi = max(lo, min(_intval(s.get("maxItems"), lo + 3), lo + 3))
        return [_random_value(s.get("items") or {}, spec, rng, depth + 1) for _ in range(rng.randint(lo, hi))]
    if t == "string":
        return _random_string(s, rng)
    if t in ("integer", "number"):
        return _random_number(s, t == "integer", rng)
    if t == "boolean":
        return rng.random() < 0.5
    return "qa"


def _random_string(s, rng):
    fmt = s.get("format")
    if fmt == "email":
        return f"qa{rng.randint(0, 9999)}@example.com"
    if fmt == "date":
        return "2026-03-14"
    if fmt == "date-time":
        return "2026-03-14T10:20:30Z"
    if fmt == "uuid":
        return str(uuid.UUID(int=rng.getrandbits(128), version=4))
    if isinstance(s.get("pattern"), str):
        smp = regex_sample(s["pattern"], rng)
        if smp is not None:
            return smp
    lo = min(_intval(s.get("minLength"), 0), 2000)
    hi = max(lo, min(_intval(s.get("maxLength"), lo + 12), lo + 40))
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(lo, hi)))


def _num_range(s):
    lo = s.get("minimum") if _num(s.get("minimum")) else None
    hi = s.get("maximum") if _num(s.get("maximum")) else None
    if _num(s.get("exclusiveMinimum")):
        lo = s["exclusiveMinimum"] if lo is None else max(lo, s["exclusiveMinimum"])
    if _num(s.get("exclusiveMaximum")):
        hi = s["exclusiveMaximum"] if hi is None else min(hi, s["exclusiveMaximum"])
    lo = 0 if lo is None else lo
    hi = lo + 1000 if hi is None else hi
    return lo, max(lo, hi)


def _random_number(s, integer, rng):
    lo, hi = _num_range(s)
    if integer:
        a, b = math.ceil(lo), math.floor(hi)
        return rng.randint(a, b) if a <= b else a
    return round(rng.uniform(lo, hi), 3)


def _valid_random(schema, spec, rng):
    """(True, value) for the first random draw our validator accepts (6 tries), else (False, None)."""
    for _ in range(6):
        v = _random_value(schema, spec, rng)
        if not check(v, schema, spec):
            return True, v
    return False, None


def _qs(v):
    """A JSON value as a query-string value. None -> None (omit), booleans lower-case, lists kept for repeated keys."""
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return [x for x in (_qs(i) for i in v) if x is not None]
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    return str(v)


# ---------- operations ----------

def _query_params(item, op, spec) -> list:
    pmap: dict = {}
    for p in list(item.get("parameters") or []) + list(op.get("parameters") or []):
        p = deref(p, spec)
        if p.get("in") == "query" and "name" in p:
            pmap[p["name"]] = {"name": p["name"], "schema": p.get("schema") or {}, "required": bool(p.get("required"))}
    return list(pmap.values())


def _unsupported(schema, spec, seen=None, depth=0) -> set:
    """The UNSUPPORTED keywords used anywhere in a schema tree (local $refs followed, each target walked once)."""
    found: set = set()
    if seen is None:
        seen = set()
    if not isinstance(schema, dict) or depth > 30:
        return found
    if "$ref" in schema:
        try:
            schema = deref(schema, spec)
        except Unresolvable:
            return found
        if id(schema) in seen:
            return found
        seen.add(id(schema))
    found |= {kw for kw in UNSUPPORTED if kw in schema}
    subs = []
    if isinstance(schema.get("properties"), dict):
        subs += list(schema["properties"].values())
    for kw in ("allOf", "anyOf", "oneOf"):
        if isinstance(schema.get(kw), list):
            subs += schema[kw]
    for kw in ("items", "additionalProperties", "not", "if", "then", "else"):
        if isinstance(schema.get(kw), dict):
            subs.append(schema[kw])
    for sub in subs:
        found |= _unsupported(sub, spec, seen, depth + 1)
    return found


def _op_unsupported(op, spec) -> set:
    """UNSUPPORTED keywords in this operation's request body, query parameters and JSON responses."""
    found: set = set()
    if op["body"] is not None:
        found |= _unsupported(op["body"], spec)
    for q in op["query"]:
        found |= _unsupported(q.get("schema") or {}, spec)
    for r in op["responses"].values():
        if not isinstance(r, dict):
            continue
        try:
            media = (deref(r, spec).get("content") or {}).get("application/json")
        except Unresolvable:
            continue
        if isinstance(media, dict):
            found |= _unsupported(media.get("schema") or {}, spec)
    return found


def _operations(spec) -> list:
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in api.METHODS:
            op = item.get(method.lower())
            if not isinstance(op, dict):
                continue
            d = {"method": method, "path": path, "body": None, "query": [], "responses": op.get("responses") or {},
                 "error": None}
            try:
                d["query"] = _query_params(item, op, spec)
                rb = op.get("requestBody")
                if rb is not None:
                    media = (deref(rb, spec).get("content") or {}).get("application/json")
                    if media is not None:
                        d["body"] = media.get("schema") or {}
            except Unresolvable as e:
                d["error"] = str(e)
            ops.append(d)
    return ops


def _has_json_response(responses, spec) -> bool:
    """True when some response declares application/json, directly or through a local $ref (_documented follows the same refs)."""
    for r in responses.values():
        try:
            if isinstance(r, dict) and "$ref" in r:
                r = deref(r, spec)
            if isinstance(r, dict) and "application/json" in (r.get("content") or {}):
                return True
        except (AttributeError, Unresolvable):
            continue
    return False


def _documented(responses, status, spec):
    """The JSON schema declared for this status: exact code, then NXX, then default (error statuses only). None = nothing declared."""
    keys = [str(status), f"{status // 100}XX"] + (["default"] if status >= 400 else [])
    for k in keys:
        if k in responses:
            media = (deref(responses[k], spec).get("content") or {}).get("application/json")
            return None if media is None else (media.get("schema") or {})
    return None


def _shape(v, depth=0) -> str:
    if depth > 3:
        return "..."
    if isinstance(v, dict):
        return "{" + ",".join(f"{k}:{_shape(x, depth + 1)}" for k, x in sorted(v.items())) + "}"
    if isinstance(v, list):
        return "[" + (_shape(v[0], depth + 1) if v else "") + "]"
    return _kind(v)


def _sig(resp):
    try:
        return (resp.status, _shape(json.loads(resp.text)))
    except (ValueError, RecursionError):
        return (resp.status, "text")


def _req(body, query) -> str:
    return f"request body {_j(body)[:200]}" + (f", query {_j(query)[:120]}" if query else "")


# ---------- run state ----------

class _Run:
    def __init__(self, client, spec, qa, seed, max_probes, per_endpoint):
        self.client, self.spec, self.seed = client, spec, seed
        self.max_probes, self.per_endpoint = max_probes, per_endpoint
        self.skip = set(getattr(qa, "SKIP", set()) or set())
        self.public = set(getattr(qa, "PUBLIC", set()) or set())
        self.bodies = dict(getattr(qa, "BODIES", {}) or {})
        self.ids = dict(getattr(qa, "IDS", {}) or {})
        self.owner = dict(getattr(qa, "OWNER", {}) or {})
        self.probes = 0
        self.ep_probes = 0
        self.transport = 0
        self.findings: list = []
        self.index: dict = {}
        self.notes: list = []
        self.gaps: list = []
        self.sigs: dict = {}
        self.per_endpoint_probes: dict = {}
        self.all_ops: dict = {}          # "METHOD /path" -> operation, for id discovery
        self.role_cache: dict = {}       # operation key -> candidate roles, the first one tried first
        self.id_cache: dict = {}         # collection path -> an id the app itself handed out (or None)
        self.unsupported: set = set()    # operation keys whose schema uses an UNSUPPORTED keyword (DRIFT/REJECTS suppressed)

    def note(self, msg):
        self.notes.append(msg)

    def gap(self, msg):
        self.gaps.append(msg)

    def send(self, role, method, path, body, query):
        if self.probes >= self.max_probes:
            raise _Budget(f"global probe cap {self.max_probes} reached")
        if self.ep_probes >= self.per_endpoint:
            raise _Budget(f"per-endpoint cap {self.per_endpoint} reached")
        self.probes += 1
        self.ep_probes += 1
        resp = self.client.call(role, method, path, body, query=query or None)
        if resp.transport:
            self.transport += 1
        return resp

    def observe(self, k, resp) -> bool:
        """True when this (status, response key-shape) signature is new for the endpoint."""
        seen = self.sigs.setdefault(k, set())
        sig = _sig(resp)
        if sig in seen:
            return False
        seen.add(sig)
        return True

    def add(self, kind, k, detail, dedupe, **extra):
        if dedupe in self.index:
            self.index[dedupe]["hits"] += 1
            return
        f = {"kind": kind, "severity": KIND_SEVERITY[kind], "endpoint": k, "detail": detail, "hits": 1, **extra}
        self.index[dedupe] = f
        self.findings.append(f)


def _role(st, k) -> str:
    """The role an operation is sent with. A configured owner is used alone; an owner that is not configured (the default
    'user_a' is often absent) makes every configured role a candidate, tried in order by _first_ok, then anon."""
    if k in st.role_cache:
        return st.role_cache[k][0]
    if k in st.public:
        cands = ["anon"]
    else:
        owner = st.owner.get(k, api.default_owner(st.client.roles))
        if owner in st.client.roles:
            cands = [owner]
        else:
            cands = [r for r in st.client.roles if r != "anon"] + ["anon"]
            st.note(f"{k}: role '{owner}' not configured; trying {', '.join(cands)} in order, keeping the first that gets 2xx")
    st.role_cache[k] = cands
    return cands[0]


def _first_ok(st, k, role, method, path, body, query):
    """(role, response) of the first candidate role the app accepts. Only 401/403 make it try the next role."""
    order = [role] + [c for c in st.role_cache.get(k, [role]) if c != role]
    first = None
    for r in order:
        resp = st.send(r, method, path, body, query)
        if first is None:
            first = (r, resp)
        if resp.ok:
            return r, resp
        if resp.status not in (401, 403):
            break
    return first


def _items_of(body) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for v in body.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
    return []


def _discover_id(st, path_t, p):
    """An id for path param `p` taken from the app's own answers: the first item of the collection above it, else the id
    of a fresh item created with the collection's example body. None when neither answers one."""
    coll = api.prefix_of(path_t, p)
    if coll in st.id_cache:
        return st.id_cache[coll]
    found = None
    get = st.all_ops.get(f"GET {coll}")
    if get is not None and coll and "{" not in coll and not any(q["required"] for q in get["query"]):
        role = _role(st, api.key(get))
        _, r = _first_ok(st, api.key(get), role, "GET", coll, None, None)
        if r.ok:
            for item in _items_of(r.json):
                found = api.extract_id(item)
                if found is not None:
                    break
    if found is None:
        post = st.all_ops.get(f"POST {coll}")
        if post is not None and coll and post["body"] is not None:
            try:
                cands = branch_examples(post["body"], st.spec, 1)
            except Unresolvable:
                cands = []
            if cands:
                role = _role(st, api.key(post))
                _, r = _first_ok(st, api.key(post), role, "POST", coll, cands[0]["value"], None)
                if r.ok:
                    found = api.extract_id(r.json)
    st.id_cache[coll] = found
    if found is not None:
        st.note(f"{coll}: '{p}' taken from the app's own answers (id {found!r})")
    return found


def _query_baseline(op, spec) -> dict:
    base = {}
    for p in op["query"]:
        if not p["required"]:
            continue
        vals = [v for _, v in _valid_examples(p["schema"], spec) if v is not None]
        s = _qs(vals[0]) if vals else None
        if s is None:
            raise _Gap(f"required query '{p['name']}' has no valid example")
        base[p["name"]] = s
    return base


def _det_candidates(op, spec, body_list, body_base, query_base) -> list:
    """(label, body, query, designated) per deterministic candidate. designated: the schema declares the value (see _Lbl)."""
    out = []
    if op["body"] is not None:
        out += [(f"body {c['label']}", c["value"], query_base, c["designated"]) for c in body_list]
    for p in op["query"]:
        for lbl, v in _valid_examples(p["schema"], spec)[:12]:
            s = _qs(v)
            if s is not None:
                out.append((f"query {p['name']} {lbl}", body_base, {**query_base, p["name"]: s}, _des(lbl)))
    return out


def _random_candidate(op, spec, rng):
    body = None
    if op["body"] is not None:
        ok, body = _valid_random(op["body"], spec, rng)
        if not ok:
            return None
    query: dict = {}
    for p in op["query"]:
        if not p["required"] and rng.random() < 0.4:
            continue
        ok, v = _valid_random(p["schema"], spec, rng)
        if not ok:
            if p["required"]:
                return None
            continue
        s = _qs(v)
        if s is not None:
            query[p["name"]] = s
    return body, query


def _drift(st, op, resp, body, query, path, msg, bad):
    k = api.key(op)
    if k in st.unsupported:
        return                                        # DEGRADED by _probe_op: our validator cannot judge this schema
    norm = re.sub(r"\[\d+\]", "[*]", path)
    st.add("SCHEMA-DRIFT", k,
           f"{path}: {msg}; value {_j(bad)[:100]}; response {resp.status}. {_req(body, query)}; response body: {resp.text[:200]}",
           ("drift", k, resp.status, norm, msg), status=resp.status, path=path, value=bad,
           request=body, query=query, response=resp.text[:200])


def _conform(st, op, resp, body, query):
    if resp.status == 204 or resp.transport:
        return
    schema = _documented(op["responses"], resp.status, st.spec)
    if schema is None:
        return
    if not resp.text.strip():
        t = _types(merged(schema, st.spec))
        if t and "null" not in t:
            _drift(st, op, resp, body, query, "$", "empty response body where the response schema declares a value", None)
        return
    try:
        value = json.loads(resp.text)
    except (ValueError, RecursionError):
        _drift(st, op, resp, body, query, "$", "response body is not JSON but the schema declares application/json",
               resp.text[:80])
        return
    for path, msg, bad in check(value, schema, st.spec)[:5]:
        _drift(st, op, resp, body, query, path, msg, bad)


def _handle(st, op, role, path, label, body, query, resp, ctx) -> bool:
    """Conformance + the 5xx oracle for one response. Returns True when its signature is new (novelty)."""
    k = api.key(op)
    new = st.observe(k, resp)
    _conform(st, op, resp, body, query)
    if resp.server_error:
        if not ctx["valid"]:
            st.note(f"{k}: 5xx on '{label}' comes from a BODIES entry our validator rejects; not reported as SCHEMA-VALID-5XX")
        else:
            again = st.send(role, op["method"], path, body, query)
            if again.server_error:
                st.add("SCHEMA-VALID-5XX", k,
                       f"schema-valid input ({label}) -> {resp.status}; identical resend -> {again.status}. "
                       f"{_req(body, query)}; response: {resp.text[:200]}",
                       ("5xx", k, resp.status), status=resp.status, request=body, query=query, response=resp.text[:200])
            else:
                st.note(f"{k}: 5xx on '{label}' ({resp.status}) not reproduced on resend ({again.status}); not reported")
    return new


def _rejects(st, op, role, path, rejected, control):
    """rejected: [(label, body, query, resp)] deterministic 400/422 answers. control: (label, resp) of a 2xx sibling or None."""
    k = api.key(op)
    if not rejected or k in st.unsupported:
        return
    if control is None:
        st.gap(f"{k}: {len(rejected)} schema-valid variant(s) answered 4xx and no 2xx control exists on this endpoint; "
               f"SCHEMA-REJECTS-VALID not evaluated")
        return
    ctl_label, ctl = control
    for label, body, query, resp, designated in rejected:
        if not designated:
            st.note(f"{k}: '{label}' -> {resp.status} is not reported: the schema does not declare that value, so it is "
                    f"not a boundary of the contract")
            continue
        if any(w in resp.text.lower() for w in CONFLICT_WORDS):
            st.note(f"{k}: '{label}' -> {resp.status} looks like a conflict answer; not reported as REJECTS")
            continue
        again = st.send(role, op["method"], path, body, query)
        if again.status not in REJECT_STATUSES:
            st.note(f"{k}: '{label}' 4xx not reproduced on resend ({again.status}); not reported")
            continue
        st.add("SCHEMA-REJECTS-VALID", k,
               f"'{label}' is schema-valid but answered {resp.status} (resend {again.status}), while '{ctl_label}' answered "
               f"{ctl.status} on the same endpoint and role. {_req(body, query)}; response: {resp.text[:200]}. "
               f"Verify that no cross-field rule outside the schema rejects this.",
               ("rej", k, label), status=resp.status, request=body, query=query, response=resp.text[:200],
               control=ctl_label)


def _invalid_for(prop, spec):
    """(label, value, message) for a value the property's declared enum or pattern rejects, or None. Candidates: a text of the
    same length as an enum member ('zzz' for 'USD' catches a length-only check), then generic texts. The validator confirms
    each one, so the value is schema-invalid by construction."""
    p = merged(prop, spec)
    cands = []
    if isinstance(p.get("enum"), list) and p["enum"]:
        first = p["enum"][0]
        if isinstance(first, str) and first:
            cands.append(("same-length", "z" * len(first)))
        cands.append(("not-in-enum", "qa-not-in-enum"))
        if all(_num(e) for e in p["enum"]):
            cands.append(("not-in-enum", max(p["enum"]) + 1000))
    if isinstance(p.get("pattern"), str):
        cands += [("empty", ""), ("pattern", "!!! ?")]
    for lbl, v in cands:
        errs = check(v, prop, spec)
        if errs:
            return lbl, v, errs[0][1]
    return None


def _accepts_invalid(st, op, role, path, body_base, method):
    """SCHEMA-ACCEPTS-INVALID: a PUT or PATCH whose body breaks one declared enum or pattern of one field must be refused.
    Control: the same write with a valid value answers 2xx. The invalid write is resent once; only a second 2xx is a finding.
    The item's original value is written back afterwards (best effort: the other fields keep the baseline values sent)."""
    k = api.key(op)
    spec = st.spec
    try:
        props = merged(op["body"], spec).get("properties") or {}
    except Unresolvable as e:
        st.gap(f"{k}: request schema does not resolve for the invalid-write probes: {e}")
        return
    if not isinstance(body_base, dict):
        return
    targets = []
    for name, ps in props.items():
        try:
            if _invalid_for(ps, spec) is not None:
                targets.append(name)
        except Unresolvable:
            continue
    if not targets:
        return
    before = st.send(role, "GET", path, None, None)
    if not before.ok or not isinstance(before.json, dict):
        st.gap(f"{k}: the item cannot be read before the invalid writes: SCHEMA-ACCEPTS-INVALID not evaluated")
        return
    for name in targets[:ACCEPT_PROBES]:
        bad_lbl, bad_val, why = _invalid_for(props[name], spec)
        if name in body_base:
            valid = body_base[name]
        else:
            ex = [v for _, v in _valid_examples(props[name], spec) if v is not None]
            if not ex:
                st.note(f"{k}: '{name}' has no valid example, so SCHEMA-ACCEPTS-INVALID is not evaluated for it")
                continue
            valid = ex[0]
        ctl = st.send(role, method, path, {**body_base, name: valid}, None)
        if not ctl.ok:
            st.gap(f"{k}: '{name}': the valid control write answered {ctl.status}; invalid writes to that field are not evaluated")
            continue
        bad_body = {**body_base, name: bad_val}
        first = st.send(role, method, path, bad_body, None)
        if not first.ok:
            continue
        again = st.send(role, method, path, bad_body, None)
        if again.ok:
            st.add("SCHEMA-ACCEPTS-INVALID", k,
                   f"'{name}'={bad_val!r} breaks the schema ({why}) but the {method} answered {first.status} (resend "
                   f"{again.status}); the valid control answered {ctl.status}. {_req(bad_body, None)}; "
                   f"response: {first.text[:200]}",
                   ("accept", k, name), status=first.status, request=bad_body, response=first.text[:200], field=name)
        if name in before.json:                       # best-effort restore of the value the item had
            restore = {**body_base, name: before.json[name]} if method == "PUT" else {name: before.json[name]}
            st.send(role, method, path, restore, None)


def _probe_op(st, op, rng):
    k = api.key(op)
    kws = _op_unsupported(op, st.spec)
    if kws:
        st.unsupported.add(k)
        st.gap(f"{k}: schema uses {', '.join(sorted(kws))}, which this validator does not check: no SCHEMA-DRIFT or "
               f"SCHEMA-REJECTS-VALID is reported for this operation (5xx checks still run)")
    method, path_t = op["method"], op["path"]
    role = _role(st, k)
    try:
        # Everything that can fail on a bad $ref is built BEFORE the first request.
        body_list, body_base, body_valid = [], None, True
        if op["body"] is not None:
            body_list = branch_examples(op["body"], st.spec, DET_LIMIT)
            for lbl in uncovered_branches(op["body"], st.spec):
                st.gap(f"{k}: {lbl} has no schema-valid example, so that branch is not tested")
            if k in st.bodies and check(st.bodies[k], op["body"], st.spec):
                # A rejected BODIES entry is not a valid baseline. It is not used, the operation is DEGRADED (a gap), and the
                # spec-derived schema-valid examples are fuzzed instead, so their 5xx are still reported.
                st.note(f"{k}: qa.BODIES entry fails our schema validator; it is not used as the baseline, and the spec example is")
                st.gap(f"{k}: qa.BODIES entry rejected by our schema validator (not used as baseline)")
                if not body_list:
                    raise _Gap("qa.BODIES entry rejected and no schema-valid example exists; the body is not fuzzed")
                body_base = body_list[0]["value"]
            elif k in st.bodies:
                body_base = st.bodies[k]
            elif body_list:
                body_base = body_list[0]["value"]
            else:
                raise _Gap("no schema-valid body example at all; the body is not fuzzed")
        query_base = _query_baseline(op, st.spec)
        values, guessed = {}, []
        for p in re.findall(r"\{(\w+)\}", path_t):
            if p in st.ids:
                values[p] = st.ids[p]
                continue
            found = _discover_id(st, path_t, p)
            if found is None:
                values[p] = "1"
                guessed.append(p)
            else:
                values[p] = found
        path = api.fill(path_t, values)
        if guessed:
            st.gap(f"{k}: path param(s) {guessed} have no id: no list or create endpoint answered one, and there is no "
                   f"qa.IDS entry; probed with '1' (controls may answer 404)")
    except (Unresolvable, _Gap) as e:
        st.gap(f"{k}: {e}")
        return
    except _Budget as e:
        st.gap(f"{k}: id discovery cut short: {e}")
        return

    ctx = {"valid": body_valid}
    try:
        role, base = _first_ok(st, k, role, method, path, body_base, query_base)
        _handle(st, op, role, path, "baseline", body_base, query_base, base, ctx)
        control = ("baseline", base) if base.ok else None
        base_sig = _j([body_base, query_base])
        rejected = []
        for label, cb, cq, des in _det_candidates(op, st.spec, body_list, body_base, query_base):
            if _j([cb, cq]) == base_sig:
                continue
            resp = st.send(role, method, path, cb, cq)
            _handle(st, op, role, path, label, cb, cq, resp, ctx)
            if resp.ok and control is None:
                control = (label, resp)
            if resp.status in REJECT_STATUSES:
                rejected.append((label, cb, cq, resp, des))
        _rejects(st, op, role, path, rejected, control)
        if method in ("PUT", "PATCH") and op["body"] is not None and not guessed and body_base is not None:
            _accepts_invalid(st, op, role, path, body_base, method)
    except _Budget as e:
        st.gap(f"{k}: deterministic phase cut short: {e}")
        return
    except Unresolvable as e:
        st.gap(f"{k}: response or branch schema does not resolve: {e}")
        return

    if op["body"] is None and not op["query"]:
        return                                        # GET with no inputs: the baseline was the whole job
    stale = 0
    try:
        while stale < STALE_LIMIT:
            cand = _random_candidate(op, st.spec, rng)
            if cand is None:
                stale += 1
                continue
            cb, cq = cand
            resp = st.send(role, method, path, cb, cq)
            new = _handle(st, op, role, path, "random", cb, cq, resp, ctx)
            stale = 0 if new else stale + 1
    except _Budget as e:
        st.note(f"{k}: random phase stopped: {e}")
    except Unresolvable as e:
        st.gap(f"{k}: schema does not resolve during random generation: {e}")


def run(client, spec_doc, qa, seed=None, max_probes=None, per_endpoint=None) -> dict:
    """Schema-branch enumeration, seeded valid random bodies, and response conformance. See the module docstring."""
    seed = getattr(qa, "SCHEMA_SEED", DEFAULT_SEED) if seed is None else seed
    st = _Run(client, spec_doc, qa, seed, max_probes or getattr(qa, "SCHEMA_MAX", DEFAULT_MAX_PROBES),
              per_endpoint or getattr(qa, "SCHEMA_PER_ENDPOINT", DEFAULT_PER_ENDPOINT))
    todo = []
    all_ops = _operations(spec_doc)
    st.all_ops = {api.key(o): o for o in all_ops}
    for op in all_ops:
        k = api.key(op)
        if op["error"]:
            st.gap(f"{k}: {op['error']}")
            continue
        if k in st.skip:
            st.note(f"{k}: listed in qa.SKIP")
            continue
        if op["method"] == "DELETE":
            st.note(f"{k}: DELETE is never fuzzed (destructive)")
            continue
        if op["method"] in WRITE and op["body"] is None:
            st.note(f"{k}: no application/json request schema; not fuzzed")
            continue
        if op["method"] == "GET" and not op["query"] and not _has_json_response(op["responses"], spec_doc):
            st.note(f"{k}: nothing to check (no query parameters and no inline JSON response schema)")
            continue
        todo.append(op)
    for op in todo:
        st.ep_probes = 0
        try:
            _probe_op(st, op, random.Random(f"{seed}|{api.key(op)}"))
        finally:
            st.per_endpoint_probes[api.key(op)] = st.ep_probes
    if st.transport:
        st.gap(f"{st.transport} probe(s) got no HTTP response (refused, reset or timeout): those answers are unknown")
    endpoints = {k: {"probes": n, "signatures": len(st.sigs.get(k, ()))} for k, n in st.per_endpoint_probes.items()}
    res = {"engine": "schema", "findings": st.findings,
           "notes": [f"GAP: {g}" for g in st.gaps] + st.notes,
           "probes": st.probes, "seed": seed, "endpoints": endpoints}
    if st.gaps:
        return trust.mark(res, trust.DEGRADED, f"{len(st.gaps)} gap(s); first: {st.gaps[0]}"[:200])
    if not todo:
        return trust.mark(res, trust.SKIPPED, "no request or response schema to fuzz in the spec")
    if st.probes == 0:
        return trust.mark(res, trust.DEGRADED, "operations were selected but no probe was sent")
    return trust.mark(res, trust.RAN_OK, f"{len(todo)} operation(s), {st.probes} probe(s), seed {seed}")
