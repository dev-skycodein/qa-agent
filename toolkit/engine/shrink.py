#!/usr/bin/env python3
"""Shrink a failing API request sequence to a minimal one and emit a standalone proof of concept.

Input: a sequence of requests (steps) that ends in a failure: a 5xx / no-HTTP-answer, a marker in a response body,
or a QA invariant that breaks. Output: a shorter, simpler sequence that fails with THE SAME failure, proven to
reproduce on fresh state (k of n runs, Wilson interval), plus poc_<kind>_<hash>.py (stdlib only) and a short .md.

Candidate designs (tree of thoughts):
  A. Greedy one-at-a-time removal: drop each step, keep the drop if the failure survives, repeat until a pass changes
     nothing. Simple and 1-minimal, but it always pays about n trials per pass, and it has no coarse moves: when the
     needed steps are few and the noise is large, it spends most of its budget on steps that are obviously needed.
  B. Hypothesis-style structural shrinking: excellent for values, but it needs the generator's draw sequence to replay
     the example. A recorded HTTP trace has no draw sequence, so this would mean re-implementing the generator.
     Rejected for this tool (stateful.py already gets Hypothesis's own shrinking for generated sequences).
  C. Binary search on the failing prefix: finds the shortest failing prefix in log(n) trials. Cheap first cut, but a
     bug that needs steps 3, 9 and 14 keeps all the noise between them, so it is only a pre-pass at most.
  D. Zeller's ddmin (CHOSEN for steps): test contiguous partitions and their complements, halve granularity until the
     sequence is 1-minimal (removing any single step makes the failure disappear). Deterministic (fixed partitions,
     fixed order), cacheable (each subset is tested once), budgeted (max_trials), and it usually needs far fewer trials
     than A on long sequences with few needed steps.
  Field-level shrinking (chosen, after steps): greedy, on the surviving steps' JSON bodies: drop keys and array items,
  shorten strings, move numbers toward 0/1, set booleans to False. Strings holding {{step_N.id}} are never edited.

Signature-slippage guard: a candidate counts as "still failing" only if its FIRST failure has the same signature as
the original failure, so shrinking cannot silently slide to a different (easier) bug:
  5xx        "5xx METHOD /normalised/path"            (ids in the path become {id}; 599 = no HTTP answer, as in stateful.py)
  body       "body:<marker> METHOD /normalised/path"  (the marker must appear in that step's response)
  invariant  "invariant:<name>:<message with digits -> N>"
The target signature is the one OBSERVED on the original sequence, not the one written in the finding text.

Reproducibility: the minimal sequence is replayed R times (default 5) on fresh state. k/n and the Wilson 95% lower
bound are reported. 0 < k < n -> reported as FLAKY (degraded), never as confirmed. k = 0 -> setup_failed, no PoC.

Fresh state: every trial calls the user-supplied reset() first (wire it to safe_run's reset_cmd, see the CLI and
docs/design/engine-shrink.md). Without reset() the status is degraded: trials share app state.

Limits: see docs/design/engine-shrink.md (reset dependence, flaky bugs, id substitution gaps, budget).

Module use:
    from shrink import shrink_finding, five_xx, parse_sequence_text
    result = shrink_finding(steps, base_url, five_xx, reset=my_reset, roles=roles, out_dir="out")
CLI:
    python toolkit/engine/shrink.py --engines-json engines.json --finding 0 --base-url http://127.0.0.1:8000 \
        --reset-cmd "python reset_db.py" --app-dir demo --runs 5 --out out
Exit codes: 0 = confirmed PoC written (ran_ok); 1 = degraded (flaky / budget) or setup_failed; 2 = usage or engine error.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from api import TRANSPORT_ERROR, Api, assert_local, extract_id  # noqa: E402
from stats import wilson  # noqa: E402
import trust  # noqa: E402

PLACEHOLDER_RE = re.compile(r"\{\{step_(\d+)\.id\}\}")
_ID_SEG = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|\{\{step_\d+\.id\}\})$")


class BudgetExhausted(Exception):
    """Raised by a counting oracle when the trial budget is spent. ddmin / shrink_fields catch it and return best-so-far."""


class Unresolved(ValueError):
    """A step refers to {{step_N.id}} but step N produced no id in this trial (usually: N was removed by ddmin)."""


# ---------------------------------------------------------------- signatures

def norm_path(path: str) -> str:
    """'/items/12/export?x=1' -> '/items/{id}/export'. Same rule in the generated PoC."""
    segs = path.split("?", 1)[0].split("/")
    return "/".join("{id}" if _ID_SEG.match(seg) else seg for seg in segs)


def five_xx(log, api=None, ctx=None):
    """Failure = the last request got a 5xx or no HTTP answer (599)."""
    e = log[-1]
    if e["status"] >= 500:
        return f"5xx {e['method']} {norm_path(e['path'])}"
    return None


five_xx.kind, five_xx.marker = "5xx", None


def body_marker(marker: str):
    """Failure = the last response body contains `marker`."""
    def detect(log, api=None, ctx=None):
        e = log[-1]
        if marker in (e.get("body") or ""):
            return f"body:{marker} {e['method']} {norm_path(e['path'])}"
        return None
    detect.kind, detect.marker = "body", marker
    return detect


def invariant(fn, name: str):
    """Failure = a QA invariant `fn(api, log, ctx)` raised AssertionError. Digits in the message are normalised."""
    def detect(log, api=None, ctx=None):
        try:
            fn(api, log, ctx)
        except AssertionError as exc:
            return f"invariant:{name}:{re.sub(r'[0-9]+', 'N', str(exc))[:200]}"
        return None
    detect.kind, detect.marker = "invariant", None
    detect.name = name
    return detect


def kind_of(signature: str) -> str:
    if signature.startswith("5xx "):
        return "5xx"
    if signature.startswith("body:"):
        return "body"
    return "invariant"


# ---------------------------------------------------------------- ddmin (pure)

def _split(seq, n):
    """Partition seq into n contiguous, nearly equal, non-empty chunks (deterministic)."""
    k, m = divmod(len(seq), n)
    out, start = [], 0
    for i in range(n):
        size = k + (1 if i < m else 0)
        if size:
            out.append(seq[start:start + size])
        start += size
    return out


class _Stop(Exception):
    pass


def ddmin(items, still_fails, max_trials=None) -> dict:
    """Zeller's delta debugging. `still_fails(subset_list) -> bool` must hold for `items` itself (the caller checks).

    Returns {"items": minimal list (original order), "trials", "cache_hits", "exhausted", "one_minimal"}.
    one_minimal is True when the loop ended on its own: removing any single item makes still_fails False.
    exhausted is True when max_trials (or a BudgetExhausted raised by still_fails) stopped it first; the returned
    items still fail (only verified subsets are ever adopted), they are just not proven minimal.
    """
    items = list(items)
    cache: dict = {}
    st = {"trials": 0, "cache_hits": 0, "exhausted": False}

    def test(idxs):
        key = tuple(idxs)
        if key in cache:
            st["cache_hits"] += 1
            return cache[key]
        if max_trials is not None and st["trials"] >= max_trials:
            raise _Stop()
        st["trials"] += 1
        verdict = bool(still_fails([items[i] for i in idxs]))
        cache[key] = verdict
        return verdict

    c = list(range(len(items)))
    n = 2
    try:
        while len(c) >= 2:
            subsets = _split(c, n)
            moved = False
            for s in subsets:                                   # reduce to a subset that still fails
                if test(s):
                    c, n, moved = s, 2, True
                    break
            if not moved:                                       # reduce to a complement that still fails
                for s in subsets:
                    gone = set(s)
                    comp = [i for i in c if i not in gone]
                    if comp and test(comp):
                        c, n, moved = comp, max(n - 1, 2), True
                        break
            if not moved:
                if n >= len(c):                                 # singletons tested, none removable: 1-minimal
                    break
                n = min(len(c), 2 * n)                          # finer partition
        if len(c) == 1 and test([]):                            # the empty sequence fails: minimal is empty
            c = []
    except (_Stop, BudgetExhausted):
        st["exhausted"] = True
    return {"items": [items[i] for i in c], "trials": st["trials"], "cache_hits": st["cache_hits"],
            "exhausted": st["exhausted"], "one_minimal": not st["exhausted"]}


# ---------------------------------------------------------------- field-level shrinking

def _candidates(v):
    """Smaller variants of one JSON value, deterministic order: drop before edit, one change per candidate."""
    if isinstance(v, dict):
        for k in sorted(v):
            yield {kk: vv for kk, vv in v.items() if kk != k}
        for k in sorted(v):
            for c in _candidates(v[k]):
                yield {**v, k: c}
    elif isinstance(v, list):
        for i in range(len(v)):
            yield v[:i] + v[i + 1:]
        for i in range(len(v)):
            for c in _candidates(v[i]):
                yield v[:i] + [c] + v[i + 1:]
    elif isinstance(v, bool):
        if v:
            yield False
    elif isinstance(v, int):
        if v != 0:
            yield 0
        if v > 1:
            yield 1
        if v > 2:
            yield v // 2
        if v > 1:
            yield v - 1                                         # one step at a time near a threshold (qty >= 5)
    elif isinstance(v, float):
        if v != 0.0:
            yield 0.0
        if v > 1.0:
            yield 1.0
    elif isinstance(v, str):
        if "{{" in v:
            return                                              # placeholders are never edited
        if v:
            yield ""
        if len(v) > 1:
            yield v[: len(v) // 2]


def greedy_steps(items, still_fails, max_trials=None) -> dict:
    """Linear greedy removal (the cheaper alternative, measured in test_shrink.py): one scan that drops each item
    whose removal keeps the failure, repeated until a full scan removes nothing (=> 1-minimal). Same result contract as ddmin."""
    cur = list(items)
    st = {"trials": 0, "exhausted": False}
    try:
        progressed = True
        while progressed:
            progressed = False
            i = 0
            while i < len(cur):
                if max_trials is not None and st["trials"] >= max_trials:
                    raise _Stop()
                st["trials"] += 1
                trial = cur[:i] + cur[i + 1:]
                if still_fails(trial):
                    cur, progressed = trial, True
                else:
                    i += 1
    except (_Stop, BudgetExhausted):
        st["exhausted"] = True
    return {"items": cur, "trials": st["trials"], "cache_hits": 0, "exhausted": st["exhausted"],
            "one_minimal": not st["exhausted"]}


def shrink_fields(steps, still_fails) -> dict:
    """Greedy field-level shrinking of step bodies. Stops at a fixpoint (a full pass adopts nothing) or when still_fails
    raises BudgetExhausted. Returns {"steps", "exhausted", "fixpoint", "accepted"}."""
    cur = json.loads(json.dumps(steps, default=str))
    st = {"exhausted": False, "accepted": 0}
    try:
        changed = True
        while changed:
            changed = False
            for i in range(len(cur)):
                if cur[i].get("body") is None:
                    continue
                for cand in _candidates(cur[i]["body"]):
                    trial = [dict(s) for s in cur]
                    trial[i] = {**cur[i], "body": cand}
                    if still_fails(trial):
                        cur = trial
                        changed = True
                        st["accepted"] += 1
                        break
    except BudgetExhausted:
        st["exhausted"] = True
    return {"steps": cur, "exhausted": st["exhausted"], "fixpoint": not st["exhausted"], "accepted": st["accepted"]}


# ---------------------------------------------------------------- replay

def _canon(steps) -> str:
    return json.dumps(steps, sort_keys=True, default=str)


def _subst(value, ids: dict):
    if isinstance(value, str):
        def rep(m):
            n = int(m.group(1))
            if n not in ids:
                raise Unresolved(f"step {n} produced no id in this trial")
            return str(ids[n])
        return PLACEHOLDER_RE.sub(rep, value)
    if isinstance(value, dict):
        return {k: _subst(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, ids) for v in value]
    return value


class Replayer:
    """Runs a step list against FRESH state per trial: reset() (if given), then one api.Api client (local hosts only).

    step = {"idx": int, "role": str, "method": str, "path": str (may hold {{step_N.id}}), "body": any|None, "query": dict|None}
    idx is the step's ORIGINAL position; {{step_N.id}} refers to idx N, so removing steps never renumbers references.
    """

    def __init__(self, base_url: str, reset=None, roles: dict | None = None, ctx_factory=None):
        assert_local(base_url)
        self.base_url = base_url
        self.reset = reset
        self.roles = roles or {}
        self.ctx_factory = ctx_factory
        self.trials = 0
        self.last_seed_log: list = []     # the requests ctx_factory (fresh_state) made in the last trial: the PoC must replay them

    def run(self, steps, detector) -> dict:
        """outcome: 'fail' (sig = the first failure's signature), 'pass', or 'invalid' (a reference could not resolve)."""
        self.trials += 1
        if self.reset is not None:
            self.reset()
        api = Api(self.base_url, roles=self.roles)
        ctx = self.ctx_factory(api) if self.ctx_factory else {}
        self.last_seed_log = list(api.log)
        ids: dict = {}
        for n, s in enumerate(steps):
            try:
                path = _subst(s["path"], ids)
                body = _subst(s.get("body"), ids)
            except Unresolved:
                return {"outcome": "invalid", "sig": None, "steps_run": n, "log": api.log}
            resp = api.call(s["role"], s["method"], path, body, query=s.get("query"))
            if resp.ok:
                new_id = extract_id(resp.json)
                if new_id is not None:
                    ids[s["idx"]] = new_id
            sig = detector(api.log, api, ctx)
            if sig:
                return {"outcome": "fail", "sig": sig, "steps_run": n + 1, "log": api.log}
        return {"outcome": "pass", "sig": None, "steps_run": len(steps), "log": api.log}


def make_oracle(replayer: Replayer, detector, target: str):
    """still_fails(steps): True only when the FIRST failure of the replay has exactly the target signature."""
    def still_fails(steps):
        try:
            t = replayer.run(steps, detector)
        except Unresolved:
            return False
        return t["outcome"] == "fail" and t["sig"] == target
    return still_fails


class _Counter:
    """Memoises the oracle and enforces the trial budget (every real oracle call is one trial)."""

    def __init__(self, fn, max_calls=None):
        self.fn, self.max_calls, self.calls, self.cache = fn, max_calls, 0, {}

    def __call__(self, steps):
        key = _canon(steps)
        if key in self.cache:
            return self.cache[key]
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise BudgetExhausted()
        self.calls += 1
        verdict = bool(self.fn(steps))
        self.cache[key] = verdict
        return verdict


# ---------------------------------------------------------------- input: sequence text / api.log

_LINE = re.compile(r"^(\S+) (GET|POST|PUT|PATCH|DELETE) (\S+) -> (\d{3}) ?(.*)$")


def parse_sequence_text(text: str):
    """Parse the `sequence` text of a stateful finding ('role METHOD path -> status request' lines).
    Returns (steps, statuses). Only the lines after 'last steps before failure:' are used when that header exists.
    The request column is a Python repr (stateful.py prints {e['request']}); it is read with ast.literal_eval."""
    parts = text.split("last steps before failure:", 1)
    scope = parts[-1]
    steps, statuses = [], []
    for line in scope.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        role, method, path, status, req = m.groups()
        try:
            body = None if req.strip() == "None" else ast.literal_eval(req.strip())
        except (ValueError, SyntaxError):
            raise ValueError(f"cannot read the request of step {len(steps)}: {req[:80]!r}")
        steps.append({"idx": len(steps), "role": role, "method": method, "path": path, "body": body, "query": None})
        statuses.append(int(status))
    return guess_id_refs(steps, statuses), statuses


def guess_id_refs(steps, statuses):
    """Heuristic for text input (no response bodies): a numeric path segment is taken to be the id made by the most
    recent earlier successful POST to the same collection. Wrong guesses are harmless: the oracle must still reproduce
    the failure, or the result is setup_failed."""
    for i, s in enumerate(steps):
        segs = s["path"].split("?", 1)[0].split("/")
        for j, seg in enumerate(segs):
            if not seg.isdigit():
                continue
            coll = "/".join(segs[:j])
            for k in range(i - 1, -1, -1):
                prev = steps[k]
                if prev["method"] == "POST" and statuses[k] in (200, 201) and prev["path"].split("?", 1)[0].rstrip("/") == coll:
                    segs[j] = "{{step_%d.id}}" % prev["idx"]
                    break
        s["path"] = "/".join(segs)
    return steps


def steps_from_log(entries):
    """api.log entries (one fresh run) -> steps up to and including the first 5xx / 599. Ids are substituted exactly:
    a path segment equal to an id returned by an earlier 2xx response becomes {{step_N.id}}."""
    cut = next((i for i, e in enumerate(entries) if e["status"] >= 500), None)
    if cut is None:
        raise ValueError("no 5xx / no-HTTP-answer entry in the log: nothing to shrink")
    return _entries_to_steps(entries[: cut + 1])


def _with_seed(seed_steps, steps):
    """The PoC's step list: the fresh_state seed requests first, then the shrunk steps with their {{step_N.id}} references
    moved past the seed (the seed's own steps keep idx 0..m-1)."""
    m = len(seed_steps)
    if not m:
        return list(steps)

    def shift(value):
        if isinstance(value, str):
            return PLACEHOLDER_RE.sub(lambda mt: "{{step_%d.id}}" % (int(mt.group(1)) + m), value)
        if isinstance(value, dict):
            return {k: shift(v) for k, v in value.items()}
        if isinstance(value, list):
            return [shift(v) for v in value]
        return value

    return list(seed_steps) + [{**s, "idx": s["idx"] + m, "path": shift(s["path"]), "body": shift(s.get("body"))} for s in steps]


def _entries_to_steps(entries):
    """api.log entries -> steps (no cut). Shared by steps_from_log and the seed replay."""
    steps, ids_by_value = [], {}
    for i, e in enumerate(entries):
        if e.get("request") == "<raw>":
            raise ValueError(f"step {i} sent a raw body: it cannot be replayed")
        segs = e["path"].split("?", 1)[0].split("/")
        segs = [("{{step_%d.id}}" % ids_by_value[seg]) if seg in ids_by_value else seg for seg in segs]
        steps.append({"idx": i, "role": e["role"], "method": e["method"], "path": "/".join(segs),
                      "body": e.get("request"), "query": e.get("query")})
        if 200 <= e["status"] < 300:
            try:
                new_id = extract_id(json.loads(e.get("body") or "null"))
            except ValueError:
                new_id = None                                  # body was cut at BODY_CAP: no id, no substitution
            if new_id is not None:
                ids_by_value.setdefault(str(new_id), i)
    return steps


# ---------------------------------------------------------------- proof of concept

_POC_TEMPLATE = '''#!/usr/bin/env python3
"""Proof of concept generated by toolkit/engine/shrink.py. Stdlib only, no toolkit imports.

Replays __N__ request(s) against a LOCAL app. Reset the app to a fresh state first: this script does not reset it.
  python __FILE__ http://127.0.0.1:8000 [--roles roles.json]
Exit 1: FAIL, bug reproduced (the same failure as recorded). Exit 0: PASS, not reproduced.
Exit 2: refused (usage, non-local host, bad step). Exit 3: invariant bug, cannot be checked standalone.
roles.json maps role name -> headers, e.g. {"user_a": {"Authorization": "Bearer <token>"}}. No token is stored here.
"""
import http.client
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

KIND = __KIND__
SIGNATURE = __SIG__
MARKER = __MARKER__
STEPS = json.loads(__STEPS__)
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
PLACEHOLDER = re.compile(r"\\{\\{step_(\\d+)\\.id\\}\\}")
ID_SEG = re.compile(r"^(\\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}|\\{\\{step_\\d+\\.id\\}\\})$")


class _LocalRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to a local host, as the replayer does; any other redirect comes back as the 3xx."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).hostname not in LOCAL_HOSTS:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _LocalRedirect)


def norm_path(path):
    segs = path.split("?", 1)[0].split("/")
    return "/".join("{id}" if ID_SEG.match(seg) else seg for seg in segs)


def subst(value, ids):
    if isinstance(value, str):
        def rep(m):
            n = int(m.group(1))
            if n not in ids:
                raise LookupError(f"step {n} produced no id")
            return str(ids[n])
        return PLACEHOLDER.sub(rep, value)
    if isinstance(value, dict):
        return {k: subst(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [subst(v, ids) for v in value]
    return value


def extract_id(body):
    if isinstance(body, dict):
        for k in ("id", "_id", "uuid", "pk"):
            if k in body and isinstance(body[k], (str, int)):
                return body[k]
        for k, v in body.items():
            if k.endswith("_id") and isinstance(v, (str, int)):
                return v
        for k in ("data", "result", "item"):
            if isinstance(body.get(k), dict):
                return extract_id(body[k])
    return None


def send(base, step, path, body, roles):
    url = base + path
    if step.get("query"):
        url += "?" + urllib.parse.urlencode(step["query"], doseq=True)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", **roles.get(step["role"], {})}
    req = urllib.request.Request(url, data=data, method=step["method"], headers=headers)
    try:
        with OPENER.open(req, timeout=30) as r:
            return r.status, r.read(4_000_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4_000_000).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, http.client.HTTPException) as exc:
        return 599, f"connection error: {exc}"


def main(argv):
    args = list(argv[1:])
    roles = {}
    if "--roles" in args:
        i = args.index("--roles")
        with open(args[i + 1], encoding="utf-8") as fh:
            roles = json.load(fh)
        del args[i:i + 2]
    base = args[0] if args else os.environ.get("QA_BASE_URL", "")
    if not base:
        print("usage: python " + os.path.basename(argv[0]) + " http://127.0.0.1:8000 [--roles roles.json]", file=sys.stderr)
        return 2
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in LOCAL_HOSTS:
        print(f"REFUSED: non-local target {base!r}", file=sys.stderr)
        return 2
    base = base.rstrip("/")
    print(f"replaying {len(STEPS)} step(s) against {base} (run it against a freshly reset app)")
    if KIND == "invariant":
        print("UNVERIFIED: this failure is a QA invariant; it cannot be checked standalone. Replay only, no verdict.")
    ids = {}
    for i, s in enumerate(STEPS):
        try:
            path = subst(s["path"], ids)
            body = subst(s.get("body"), ids)
        except LookupError as exc:
            print(f"SETUP: {exc} at step {i}; the reproduction cannot run")
            return 2
        if not path.startswith("/") or path.startswith("//"):
            print(f"REFUSED: step {i} path is not a plain absolute path: {path!r}", file=sys.stderr)
            return 2
        status, text = send(base, s, path, body, roles)
        print(f"[{i}] {s['role']} {s['method']} {path} -> {status}")
        if 200 <= status < 300:
            try:
                new_id = extract_id(json.loads(text))
            except ValueError:
                new_id = None
            if new_id is not None:
                ids[s["idx"]] = new_id                         # keyed by the ORIGINAL step index, like the Replayer
        sig = None
        if KIND == "5xx" and status >= 500:
            sig = f"5xx {s['method']} {norm_path(path)}"
        elif KIND == "body" and MARKER and MARKER in text:
            sig = f"body:{MARKER} {s['method']} {norm_path(path)}"
        if sig:
            if sig == SIGNATURE:
                print(f"FAIL: bug reproduced at step {i}: {sig}")
                return 1
            print(f"PASS: recorded bug not reproduced; a different failure came first at step {i}: {sig}")
            return 0
    if KIND == "invariant":
        return 3
    print("PASS: bug not reproduced (no failure with the recorded signature)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


def write_poc(out_dir, steps, signature, detector, result) -> tuple:
    """Write poc_<kind>_<hash>.py and .md. Only called for a sequence that reproduced at least once."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    kind = kind_of(signature)
    digest = hashlib.sha256(_canon({"steps": steps, "sig": signature}).encode("utf-8")).hexdigest()[:10]
    stem = f"poc_{kind}_{digest}"
    py, md = out / f"{stem}.py", out / f"{stem}.md"
    src = (_POC_TEMPLATE.replace("__FILE__", py.name).replace("__N__", str(len(steps)))
           .replace("__KIND__", repr(kind)).replace("__SIG__", repr(signature))
           .replace("__MARKER__", repr(getattr(detector, "marker", None)))
           .replace("__STEPS__", repr(json.dumps(steps, sort_keys=True, default=str))))
    py.write_text(src, encoding="utf-8")
    rp = result["repro"]
    lines = [f"# Proof of concept: {signature}", "",
             f"- Status: **{result['status'].upper()}** - {result['status_reason']}",
             f"- Repro on fresh state: {rp['k']}/{rp['n']} runs (95% CI {rp['wilson_low']:.0%}-{rp['wilson_high']:.0%})",
             f"- Steps: {result['steps_before']} before shrinking, {result['steps_after']} after "
             f"(oracle trials used: {result['trials']} of budget {result['budget']})", "",
             "## Run", "", "Reset the app to a fresh state first (the script does not reset it), then:", "",
             f"    python {py.name} http://127.0.0.1:8000 [--roles roles.json]", "",
             "Exit 1 = FAIL, bug reproduced. Exit 0 = PASS, not reproduced. Exit 3 = invariant bug (replay only).", "",
             "## Minimal sequence", ""]
    for i, s in enumerate(steps, 1):
        tail = f" with body `{json.dumps(s['body'], ensure_ascii=True)}`" if s.get("body") is not None else ""
        lines.append(f"{i}. `{s['role']} {s['method']} {s['path']}`{tail}")
    lines.append("")
    md.write_text("\n".join(lines), encoding="utf-8")
    return str(py), str(md)


# ---------------------------------------------------------------- the pipeline

def shrink_finding(steps, base_url, detector, reset=None, roles=None, ctx_factory=None, runs=5,
                   max_trials=400, out_dir=None, expected_sig=None, method="ddmin") -> dict:
    """Shrink `steps` to a minimal sequence that fails with the same signature as the original, then prove it.

    detector: five_xx, body_marker(...), invariant(...) or any callable (log, api, ctx) -> signature | None.
    method: "ddmin" (default, Zeller) or "greedy" (linear removal; cheaper on the planted test, see docs).
    Budget: max_trials counts oracle trials (the original run included). The k repro runs are extra, reported separately.
    """
    if method not in ("ddmin", "greedy"):
        raise ValueError(f"unknown method {method!r}")
    assert_local(base_url)
    result = {"engine": "shrink", "findings": [], "kind": None, "signature": None, "steps_before": len(steps),
              "steps_after": len(steps), "trials": 0, "budget": max_trials, "budget_exhausted": False,
              "fixpoint": False, "repro": {"k": 0, "n": runs, "wilson_low": 0.0, "wilson_high": 1.0},
              "flaky": False, "poc_path": None, "poc_md_path": None, "minimal_steps": steps}
    notes = [] if reset is not None else ["no reset(): trials share app state"]
    try:
        rep = Replayer(base_url, reset=reset, roles=roles, ctx_factory=ctx_factory)
        if not steps:
            return trust.mark(result, trust.SETUP_FAILED, "no steps to shrink")
        first = rep.run(steps, detector)
        if first["outcome"] != "fail":
            why = "a reference could not resolve" if first["outcome"] == "invalid" else "the failure did not occur"
            return trust.mark(result, trust.SETUP_FAILED,
                              f"the original sequence did not reproduce on fresh state ({why}); "
                              "a truncated tail misses setup steps, or the bug is not deterministic")
        target = first["sig"]
        result.update(signature=target, kind=kind_of(target), trials=1)
        seed_steps = []
        if ctx_factory is not None:
            try:
                seed_steps = _entries_to_steps(rep.last_seed_log)
            except ValueError as exc:
                notes.append(f"fresh_state() requests cannot be replayed in the PoC ({exc})")
            if not seed_steps and not notes:
                notes.append("fresh_state() made no logged request: the PoC has no seed steps (it may not run on the app's own client)")
        if expected_sig and expected_sig != target:
            return trust.mark(result, trust.SETUP_FAILED,
                              f"the original failed with a different signature: got {target}, expected {expected_sig}")

        counter = _Counter(make_oracle(rep, detector, target), max_calls=max_trials)
        counter.calls = 1
        counter.cache[_canon(steps)] = True
        dd = (ddmin if method == "ddmin" else greedy_steps)(steps, counter)
        minimal = dd["items"]
        fields = shrink_fields(minimal, counter)
        final = fields["steps"]
        exhausted = dd["exhausted"] or fields["exhausted"]
        result.update(steps_after=len(final), trials=counter.calls, budget_exhausted=exhausted,
                      fixpoint=not exhausted, minimal_steps=final)

        k = 0
        for _ in range(runs):
            t = rep.run(final, detector)
            if t["outcome"] == "fail" and t["sig"] == target:
                k += 1
        lo, hi = wilson(k, runs)
        result["repro"] = {"k": k, "n": runs, "wilson_low": lo, "wilson_high": hi}
        result["flaky"] = 0 < k < runs

        m = len(final)
        poc_steps = _with_seed(seed_steps, final)
        if k == 0:
            status, reason = trust.SETUP_FAILED, (f"the minimal sequence did not reproduce in {runs} re-runs (the oracle "
                                                  "run was a fluke or the bug is flaky): no PoC written")
        elif k < runs:
            status, reason = trust.DEGRADED, (f"FLAKY: {k}/{runs} fresh-state re-runs reproduced "
                                              f"(95% CI {lo:.0%}-{hi:.0%}); {m} step(s), not confirmed")
        elif exhausted:
            status, reason = trust.DEGRADED, (f"budget exhausted before a 1-minimal fixpoint ({counter.calls} of "
                                              f"{max_trials} trials): {m} step(s) reproduce {k}/{runs}")
        else:
            status, reason = trust.RAN_OK, f"1-minimal: {m} step(s) reproduce {k}/{runs} on fresh state"
        if notes:
            reason = reason + "; " + "; ".join(notes)
            if status == trust.RAN_OK:                          # no reset(): the repro is not on fresh state, so not confirmed
                status = trust.DEGRADED
        trust.mark(result, status, reason)                      # status first: write_poc quotes it in the .md
        result["poc_steps"] = poc_steps
        if k >= 1 and out_dir is not None:
            result["poc_path"], result["poc_md_path"] = write_poc(out_dir, poc_steps, target, detector, result)
        return result
    except Exception as exc:                                    # reset / app / detector crash: never a fake result
        return trust.mark(result, trust.ERRORED, f"{type(exc).__name__}: {str(exc)[:200]}")


# ---------------------------------------------------------------- CLI

def make_reset_cmd(cmd: str, app_dir: str | None):
    """reset() that runs `cmd` as an argv list (shell=False) in app_dir before every trial. Use a script for complex work.
    It must restore FRESH state that the running app sees (and restart the app if the app caches state in memory)."""
    argv = [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t
            for t in shlex.split(cmd, posix=sys.platform != "win32")]

    def reset():
        p = subprocess.run(argv, cwd=app_dir or None, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            raise RuntimeError(f"reset_cmd failed ({p.returncode}): {(p.stdout + p.stderr)[-400:]}")
    return reset


def _load_qa(path: str):
    spec = importlib.util.spec_from_file_location("qa_spec_for_shrink", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _input_from_engines(a, qa):
    results = json.loads(Path(a.engines_json).read_text(encoding="utf-8"))
    flat = [f for r in results for f in r.get("findings", [])]
    if a.finding is None or not 0 <= a.finding < len(flat):
        raise ValueError(f"--finding must be 0..{len(flat) - 1} ({len(flat)} finding(s) in the file)")
    f = flat[a.finding]
    if not f.get("sequence"):
        raise ValueError("this finding has no 'sequence' text: only stateful sequences can be shrunk (or use --log)")
    steps, statuses = parse_sequence_text(f["sequence"])
    if not steps:
        raise ValueError("no request lines found in the finding's sequence text")
    last = steps[-1]
    if a.marker:
        return steps, body_marker(a.marker), None
    if statuses[-1] >= 500:
        return steps, five_xx, five_xx(
            [{"method": last["method"], "path": last["path"], "status": statuses[-1]}])
    name = f.get("detail", "").split(":", 1)[0]
    for fn in getattr(qa, "INVARIANTS", []) if qa else []:
        if getattr(fn, "__name__", "") == name:
            return steps, invariant(fn, name), None
    raise ValueError("finding is not a 5xx; pass --qa-spec (for its INVARIANTS) or --marker")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Shrink a failing request sequence and emit a standalone PoC.")
    p.add_argument("--engines-json", help="engines.json from a run; use with --finding")
    p.add_argument("--finding", type=int, help="0-based index over all findings in --engines-json (file order)")
    p.add_argument("--log", help="an api.log JSON list from one fresh run (exact id substitution; preferred)")
    p.add_argument("--base-url", required=True)
    p.add_argument("--reset-cmd", help="run before every trial (argv, no shell); must give fresh state")
    p.add_argument("--app-dir", help="working directory for --reset-cmd")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--max-trials", type=int, default=400)
    p.add_argument("--out", default="shrink-out")
    p.add_argument("--roles-json", help="JSON map role -> headers (tokens stay in this local file, never in the PoC)")
    p.add_argument("--qa-spec", help="qa-spec.py, for INVARIANTS of invariant findings and fresh_state()")
    p.add_argument("--marker", help="treat a body containing this text as the failure instead of a 5xx")
    p.add_argument("--method", default="ddmin", choices=("ddmin", "greedy"))
    a = p.parse_args(argv)
    try:
        assert_local(a.base_url)
        qa = _load_qa(a.qa_spec) if a.qa_spec else None
        ctx_factory = (lambda api: qa.fresh_state(api) or {}) if qa is not None and hasattr(qa, "fresh_state") else None
        roles = json.loads(Path(a.roles_json).read_text(encoding="utf-8")) if a.roles_json else None
        if a.log:
            entries = json.loads(Path(a.log).read_text(encoding="utf-8"))
            steps = steps_from_log(entries)
            detector, expected = (body_marker(a.marker) if a.marker else five_xx), None
        elif a.engines_json:
            steps, detector, expected = _input_from_engines(a, qa)
        else:
            raise ValueError("give --engines-json with --finding, or --log")
        reset = make_reset_cmd(a.reset_cmd, a.app_dir) if a.reset_cmd else None
        res = shrink_finding(steps, a.base_url, detector, reset=reset, roles=roles, ctx_factory=ctx_factory,
                             runs=a.runs, max_trials=a.max_trials, out_dir=a.out, expected_sig=expected,
                             method=a.method)
    except (ValueError, SystemExit, OSError) as exc:
        print(f"[shrink] {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: v for k, v in res.items() if k != "findings"}, indent=2, default=str))
    if res["status"] == trust.ERRORED:
        return 2
    return 0 if res["status"] == trust.RAN_OK else 1


if __name__ == "__main__":
    sys.exit(main())
