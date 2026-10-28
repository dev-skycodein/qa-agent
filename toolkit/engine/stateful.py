"""Generic stateful engine: random sequences of API write calls, invariants checked after every step.

Actions come from the OpenAPI write endpoints (bodies from Hypothesis strategies built from the
schemas, ids from earlier responses). Built-in invariant: no 5xx. Project invariants come from
qa-spec.py:

  fresh_state(api) -> ctx        called once per example; seed data. ctx["ids"] = {"/products": [pid]}
                                 pre-fills the id pools (key = collection path of the id parameter).
  INVARIANTS = [fn(api, log, ctx)]   raise AssertionError with a clear message when broken
  ACTORS = ["user_a", "user_b", "admin"]   roles that act (default: every configured non-anon role)
  ADMIN_ONLY / ADMIN_ROLE ("admin"): those endpoints are mostly called as the admin role so the search reaches deep states.
  STATEFUL_SKIP = {"POST /auth/login"}   endpoints never used as random actions (SKIP also applies, to every engine)
  Built-in actions: one rule per write endpoint (random role/body/id) plus `repeat` (replay an earlier request).
  STATEFUL_BODIES = {"POST /orders/": {...}}  fixed body instead of generated ones (rarely wanted; BODIES is for authz only) (e.g. real ids from ctx are better set via BODY_HOOKS)
  BODY_HOOKS = {"POST /orders/": fn(body, ctx) -> body}   patch generated body with real ids
"""
import json
import os
import re
import sys
import time

from api import WRITE_METHODS, endpoints, extract_id, fill, key, prefix_of, strategy
import trust


def _is_engine_error(exc, first) -> bool:
    """True when `exc` is Hypothesis' own error (flaky data generation, failed health check) and no app failure was recorded for it:
    that is a problem of the search, not a finding about the app."""
    if first:
        return False
    return type(exc).__module__.split(".")[0] == "hypothesis"     # by module name: no import needed to decide


def run(api, spec_doc, qa, max_examples=25, steps=12, time_budget=240, rounds=4, seed=None, attempts=3) -> dict:
    from hypothesis import HealthCheck, settings
    from hypothesis import strategies as st
    from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

    skip = set(getattr(qa, "STATEFUL_SKIP", set())) | set(getattr(qa, "SKIP", set()))
    eps = [e for e in endpoints(spec_doc) if e["method"] in WRITE_METHODS and key(e) not in skip]
    actors = list(getattr(qa, "ACTORS", [r for r in api.roles if r != "anon"]))
    invariants = list(getattr(qa, "INVARIANTS", []))
    admin_only = set(getattr(qa, "ADMIN_ONLY", set())) | {key(e) for e in eps if "/admin" in e["path"]}
    admin_role = getattr(qa, "ADMIN_ROLE", "admin")
    fresh = getattr(qa, "fresh_state", lambda api: {})
    hooks = getattr(qa, "BODY_HOOKS", {})
    fixed = getattr(qa, "STATEFUL_BODIES", {})       # NOT BODIES: those are single valid samples for authz and would hide random values
    engine_error = None                # set when Hypothesis itself fails (see _is_engine_error)
    started = [time.time()]            # reset every round: shrinking in round 1 must not starve round 2
    stats = {"steps": 0}

    def guarded(method):
        """Record the first failure with its traceback (Hypothesis can report 'flaky' when a replay cannot reproduce it)."""
        import functools
        import traceback

        @functools.wraps(method)
        def wrapper(self, *a, **kw):
            try:
                return method(self, *a, **kw)
            except BaseException as exc:
                # StopTest / Frozen / UnsatisfiedAssumption are Hypothesis control flow (data exhausted), not app failures
                internal = type(exc).__name__ in ("StopTest", "Frozen", "UnsatisfiedAssumption", "DataExhausted")
                if not internal and not isinstance(exc, (KeyboardInterrupt, SystemExit)) and "first" not in stats:
                    stats["first"] = {"message": f"{method.__name__}: {type(exc).__name__}: {exc}"[:400],
                                      "tail": [f"{e['role']} {e['method']} {e['path']} -> {e['status']} {e['request']}" for e in self.log[-10:]]
                                              + ["traceback: " + traceback.format_exc()[-600:]]}
                raise
        return wrapper

    class Machine(RuleBasedStateMachine):
        def __init__(self):
            super().__init__()
            try:
                self.ctx = fresh(api) or {}
            except Exception as exc:                      # seed/setup failure: say so instead of a confusing replay error
                stats.setdefault("first", {"message": f"fresh_state() failed: {type(exc).__name__}: {exc}",
                                           "tail": [str(e) for e in api.log[-5:]]})
                raise
            self.pools = {k: list(v) for k, v in self.ctx.get("ids", {}).items()}
            self.log = []

        @rule(data=st.data())
        @guarded
        def act(self, data):
            if time.time() - started[0] > time_budget:
                return
            ep = data.draw(st.sampled_from(eps), label="endpoint")
            if key(ep) in admin_only and admin_role in actors and data.draw(st.integers(0, 6), label="bias") > 0:
                role = admin_role                          # admin-only endpoint: mostly act as admin, else every call is a 403
            else:
                role = data.draw(st.sampled_from(actors), label="actor")
            values = {}
            for param in ep["path_params"]:
                pool = self.pools.get(prefix_of(ep["path"], param)) or []
                if not pool:
                    return
                values[param] = data.draw(st.sampled_from(pool), label=param)
            body = None
            if key(ep) in fixed:
                body = fixed[key(ep)]
            elif ep["body_schema"] is not None:
                body = data.draw(strategy(ep["body_schema"], spec_doc), label="body")
            if key(ep) in hooks and body is not None:
                body = hooks[key(ep)](body, self.ctx)
            self._perform(role, ep["method"], fill(ep["path"], values), body,
                          pool=ep["path"].rstrip("/") if ep["method"] == "POST" and not ep["path_params"] else None)

        @rule(data=st.data())
        @guarded
        def repeat(self, data):
            """Replay an earlier request verbatim: double-submit / double-process bugs (double refund, restock, charge)."""
            if not self.log or time.time() - started[0] > time_budget:
                return
            e = self.log[data.draw(st.integers(0, len(self.log) - 1), label="replayed step")]
            self._perform(e["role"], e["method"], e["path"], e["request"], pool=e.get("pool"))

        def _perform(self, role, method, path, body, pool):
            resp = api.call(role, method, path, body)
            stats["steps"] += 1
            if os.environ.get("QA_TRACE"):
                print(f"[trace] {role} {method} {path} -> {resp.status} {json.dumps(body)[:160] if body else ''}", file=sys.stderr)
            self.log.append({"role": role, "method": method, "path": path, "status": resp.status,
                             "request": body, "response": resp.text[:1500], "pool": pool})
            if resp.ok and pool:
                new_id = extract_id(resp.json)
                if new_id is not None:
                    self.pools.setdefault(pool, []).append(new_id)
            if resp.server_error:
                self._fail(f"server error {resp.status} on {method} {path}: {resp.text[:150]}", name=f"5xx {method} {path}")
            elif resp.transport:           # no HTTP answer: the app crashed, hung or dropped the connection (name keeps the 5xx prefix: same handling)
                self._fail(f"no HTTP response on {method} {path}: {resp.text[:150]}", name=f"5xx {method} {path}")

        def _fail(self, message, name="step"):
            # remember the first real failure: Hypothesis may report "flaky" if a replay cannot reproduce it
            stats.setdefault("first", {"message": message, "name": name, "tail": [f"{e['role']} {e['method']} {e['path']} -> {e['status']} {e['request']}"
                                                                    for e in self.log[-10:]]})
            raise AssertionError(message)

        @invariant()
        @guarded
        def project_invariants(self):
            for fn in invariants:
                try:
                    fn(api, self.log, self.ctx)
                except AssertionError as exc:
                    self._fail(f"{fn.__name__}: {exc}", name=fn.__name__)

    if not eps:
        return trust.mark({"engine": "stateful", "findings": [], "notes": ["no write endpoints found"], "steps": 0},
                          trust.SKIPPED, "no write endpoints in the OpenAPI")
    cfg = settings(max_examples=max_examples, stateful_step_count=steps, deadline=None,
                   suppress_health_check=list(HealthCheck), database=None, print_blob=False)
    Machine.TestCase.settings = cfg
    findings = []
    clean_tries = 0
    for round_no in range(max(rounds, attempts)):
        stats.pop("first", None)
        started[0] = time.time()
        try:
            case = Machine.TestCase("runTest")
            if seed is not None:                                # reproducible search: same seed + same app state = same sequences
                from hypothesis import seed as hyp_seed
                hyp_seed(seed + round_no)(type(case).runTest)(case)      # seed the plain function, not the bound method
            else:
                case.runTest()
            if findings or clean_tries >= attempts - 1:
                break                                      # clean round after a finding, or enough independent clean tries
            clean_tries += 1                               # one clean random search is weak evidence: try again with a new seed
            continue
        except BaseException as exc:  # hypothesis re-raises the original failure with the falsifying steps in __notes__
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            import traceback
            notes = "\n".join(getattr(exc, "__notes__", []))
            first = stats.get("first")
            if _is_engine_error(exc, first):
                engine_error = f"{type(exc).__name__}: {str(exc)[:300]}"
                break
            if first:        # the real failure, even if Hypothesis could only report "flaky" on replay
                detail = first["message"][:400]
                sequence = (notes + "\n" if notes else "") + "last steps before failure:\n" + "\n".join(first["tail"])
            else:
                detail = f"{type(exc).__name__}: {str(exc)[:300]}"
                sequence = notes + "\n" + "".join(traceback.format_exception(exc))[-1500:]
            findings.append({"kind": "STATEFUL-INVARIANT", "severity": "high", "endpoint": "(sequence)",
                             "detail": detail, "sequence": sequence[-1800:]})
            if not first:
                break
            # switch the failing check off so the next round can find a different bug class
            name = first.get("name", "")
            invariants[:] = [fn for fn in invariants if fn.__name__ != name]
            if name.startswith("5xx "):
                _, bad_method, bad_path = name.split(" ", 2)
                eps[:] = [e for e in eps if not (e["method"] == bad_method and
                                                 re.fullmatch(re.sub(r"\{[^/]+\}", "[^/]+", e["path"]), bad_path))]
            elif not invariants:
                break
    res = {"engine": "stateful", "findings": findings, "steps": stats["steps"], "rounds": round_no + 1,
           "notes": [f"no failure found in {clean_tries + 1} independent search attempts (random search: absence is not proof)"] if not findings else []}
    if engine_error:
        res["notes"] = res["notes"] + [f"search stopped by an error of Hypothesis itself (not an app finding): {engine_error}"]
        return trust.mark(res, trust.DEGRADED if findings else trust.ERRORED, f"Hypothesis error: {engine_error}"[:400])
    if not getattr(qa, "INVARIANTS", []):
        return trust.mark(res, trust.DEGRADED, "no INVARIANTS in qa-spec.py: only the built-in no-5xx oracle ran")
    return trust.mark(res, trust.RAN_OK)
