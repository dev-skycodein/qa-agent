"""Workflow chains (engine name 'workflow'): create a resource, then apply every action the API offers on it, and check invariants that
need the whole chain, not one request. Built on logic_engine.Ctx (account read-back, role ranking, body building).

Design (tree of thoughts):
  (A) a hand-written scenario per domain: precise, but it is exactly the circularity this toolkit tries to leave;
  (B) random sequences of operations (stateful.py already does that, with the spec's own invariants);
  (C) chain discovery from the OpenAPI + fixed, domain-free invariants: chosen. A POST whose response carries `x_id` (or `id` of x)
      is a producer of x; a write operation under `/xs/{x_id}/<verb>` is an action on x. Each action is applied to a fresh x.
Oracles (each needs a read-back; none is a bare 2xx):
  LOGIC-NEGATIVE-BALANCE   after an action the owner's balance is below zero although the account object says it has no overdraft
                           (flag present and false: medium; no flag at all: low, 'verify').
  LOGIC-CONSERVATION       a response field that names an amount taken from the balance (credit_applied_cents, balance_used, ...)
                           differs from the observed change of the owner's balance.
  LOGIC-CROSS-OWNER-ACTION a second ordinary role performs the action on a resource that the readable object ties to the first role
                           (customer_id == owner id). High when the owner's balance changed, medium otherwise.
  LOGIC-STATE-REGRESSION   after a terminal action (cancel, close, void, archive, ...) another action on the same resource still succeeds.
  LOGIC-BOUND-VIOLATION    an action with an amount, repeated with 60% of the paid/total amount, succeeds more often than the amount allows
                           (refund cap) or the resource reads back refunded > paid.
  LOGIC-IDEMPOTENCY        an operation that declares an Idempotency-Key header answers the same stored response for a reused key with a
                           DIFFERENT body.
False-positive risks: an app that legitimately lets a cancelled resource be changed (reactivate-like names are excluded), a shared
resource that several customers may pay (needs an owner field to claim), debt accounts without an overdraft flag (low only).
Status: skipped_no_spec when the API has no create->action chain; degraded when an oracle could not read back; ran_ok otherwise.
"""
import re

import api as api_mod
import logic_engine as L
import trust
from api import key

TERMINAL = re.compile(r"cancel|close|void|terminate|archive|deactivate|revoke", re.I)
FOLLOWUP_OK = re.compile(r"refund|reimburs|credit|return|chargeback|receipt|notify|resend|export|print|download", re.I)    # normal after a cancel
REVIVE = re.compile(r"reactivat|restor|undo|reopen|resume|uncancel|reviv", re.I)
PREREQ = re.compile(r"pay|confirm|activate|complete|approve|submit|checkout|capture|settle", re.I)
IDEM = re.compile(r"idempoten", re.I)
OWNER_KEY = re.compile(r"(^|_)(customer|owner|user|account|member)(_id)?$", re.I)
OVERDRAFT_KEY = re.compile(r"overdraft|credit_line|allow_negative|negative_ok", re.I)
TAKEN_TOKENS = ("applied", "used", "deducted", "debited", "spent", "redeemed", "drawn")
SPEND_ROUNDS = 6                  # create + action rounds per action while the balance keeps falling
SHARE = 0.6                      # share of the paid amount asked for by each repeated amount-bearing action


def singular(seg):
    if seg.endswith("ies"):
        return seg[:-3] + "y"
    return seg[:-1] if seg.endswith("s") and not seg.endswith("ss") else seg


def param_base(param, path):
    if param.endswith("_id") and len(param) > 3:
        return param[:-3]
    before = path.split("{" + param + "}")[0].rstrip("/").split("/")[-1]
    return singular(before) if before else None


def refs_of(obj, produced_base):
    """{base: id} found in a producer's response: its own id, every `x_id`, every nested object with an id."""
    out = {}
    if not isinstance(obj, dict):
        return out
    if isinstance(obj.get("id"), (int, str)) and produced_base:
        out[produced_base] = obj["id"]
    for k, v in obj.items():
        if k.endswith("_id") and len(k) > 3 and isinstance(v, (int, str)) and not isinstance(v, bool):
            out.setdefault(k[:-3], v)
        elif isinstance(v, dict) and isinstance(v.get("id"), (int, str)):
            out.setdefault(singular(k), v["id"])
    return out


class Chains:
    def __init__(self, api, spec, qa):
        self.ctx = L.Ctx(api, spec, qa)
        self.api, self.spec = api, spec
        self.producers = [e for e in self.ctx.all if e["method"] == "POST" and not e["path_params"]
                          and key(e) not in getattr(qa, "SKIP", set())]
        self.actions = {}          # base -> [(ep, param)]
        self.coll = {}             # base -> the collection path the action hangs under (/subs for /subs/{subscription_id}/cancel)
        for e in self.ctx.writes:
            if len(e["path_params"]) == 1 and e["method"] in ("POST", "PATCH", "PUT"):
                p = e["path_params"][0]
                if e["path"].rstrip("/").endswith("{" + p + "}"):
                    continue              # PATCH /x/{id} is an update, not a verb on x; chains use /x/{id}/<verb>
                base = param_base(p, e["path"])
                if base:
                    self.actions.setdefault(base, []).append((e, p))
                    self.coll.setdefault(base, e["path"].split("{" + p + "}")[0].rstrip("/"))
        self.prod_for = {}
        self.notes, self.unchecked = [], set()

    # ---------- fresh resources ----------

    def fresh(self, base):
        """(ref, producer response object, role) of a newly created `base`, or None."""
        def produced(e):
            return base if e["path"].rstrip("/") == self.coll.get(base) else singular(e["path"].rstrip("/").split("/")[-1])
        order = sorted(self.producers, key=lambda e: (produced(e) != base, key(e) != self.prod_for.get(base)))
        for ep in order:
            for role in self.ctx.roles_by_privilege()[:2] or [self.ctx.role]:
                try:
                    body = self.ctx.build(ep, {})
                except Exception:           # a body that cannot be built is not a finding
                    break
                resp = self.ctx.send(ep, {}, body, role)
                if resp.ok and isinstance(resp.json, dict):
                    refs = refs_of(resp.json, produced(ep))
                    if base in refs:
                        self.prod_for[base] = key(ep)
                        return refs[base], resp.json, role
                if resp.status in (401, 403):
                    continue
                break
        return None

    def reader(self, action):
        path = action["path"].rsplit("/", 1)[0]
        return next((e for e in self.ctx.all if e["method"] == "GET" and e["path"] == path), None)

    def read(self, action, p, ref, role):
        rd = self.reader(action)
        if rd is None:
            return None
        resp = self.api.call(role, "GET", L.fill_strict(rd["path"], {p: ref}))
        return resp.json if resp.ok and isinstance(resp.json, dict) else None

    # ---------- one action with whatever it needs first ----------

    def apply(self, base, ep, p, ref, role, body=None, retry_roles=True):
        """Send the action; on 400/409/422 first try the other actions that look like prerequisites (pay, confirm, ...).
        Returns (response, role that was accepted)."""
        ctx = self.ctx
        body = ctx.build(ep, {}) if body is None else body
        roles = [role] + ([r for r in ctx.roles_by_privilege() if r != role] if retry_roles else [])
        resp = None
        for r in roles:
            resp = ctx.send(ep, {p: ref}, body, r)
            if resp.status in (401, 403):
                continue
            if not resp.ok and resp.status in (400, 409, 422):
                for q, qp in self.actions.get(base, []):
                    if q is not ep and PREREQ.search(q["path"].rsplit("/", 1)[-1]):
                        ctx.send(q, {qp: ref}, ctx.build(q, {}), r)
                resp = ctx.send(ep, {p: ref}, body, r)
            return resp, r
        return resp, role

    # ---------- oracles ----------

    def variants(self, ep):
        """The default body, then the same body with each other enum value of its first enum field (a 'change to the same value' answer
        of 4xx says nothing about the action)."""
        ctx = self.ctx
        base = ctx.build(ep, {})
        out = [base]
        props = L.props_of(ep)
        for name, sch in props.items():
            enum = sch.get("enum") if isinstance(sch, dict) else None
            if isinstance(enum, list) and len(enum) > 1 and isinstance(base, dict) and name in base:
                out += [{**base, name: v} for v in enum if v != base[name]][:4]
                break
        return out

    def balance_checks(self, base, ep, p):
        """Spend-down: repeat create + action while the owner's balance keeps falling, so the credit eventually runs smaller than the
        charge (the case where 'subtract the full amount instead of what was applied' goes below zero)."""
        for _ in range(SPEND_ROUNDS):
            if not self.balance_round(base, ep, p):
                break

    def balance_round(self, base, ep, p) -> bool:
        ctx = self.ctx
        got = self.fresh(base)
        if got is None:
            self.notes.append(f"no producer for {base}: {key(ep)} not exercised")
            return False
        ref, _, owner = got
        ctx.trail = []
        before = ctx.snap(owner)
        resp, acting = self.apply(base, ep, p, ref, owner)
        if not resp.ok:
            return False
        after = ctx.snap(owner)
        if not (before and after and L.is_num(before["bal"]) and L.is_num(after["bal"])):
            self.unchecked.add(f"{key(ep)} balance read-back")
            return False
        raw = after["raw"]
        flags = [v for k, v in raw.items() if isinstance(v, bool) and OVERDRAFT_KEY.search(k)]
        if after["bal"] < 0 and before["bal"] >= 0 and ctx.privileged(owner) is not True and not any(flags):
            ctx.add("LOGIC-NEGATIVE-BALANCE", "medium" if flags else "low", key(ep),
                    f"after {key(ep)} the owner's balance is {after['bal']} (was {before['bal']}) and the account "
                    f"{'says overdraft is off' if flags else 'has no overdraft flag'}", list(ctx.trail), "neg")
        objs = [resp.json] + [v for v in (resp.json or {}).values() if isinstance(v, dict)] if isinstance(resp.json, dict) else []
        for obj in objs:
            for k, v in obj.items():
                tk = L.tokens(k)
                if L.is_num(v) and any(t in L.BALANCE_TOKENS for t in tk) and any(t in TAKEN_TOKENS for t in tk):
                    moved = before["bal"] - after["bal"]
                    if abs(moved - v) > L.TOL:
                        ctx.add("LOGIC-CONSERVATION", "medium", key(ep),
                                f"the response says {k}={v} but the owner's balance moved by {moved:+} ({before['bal']} -> {after['bal']})",
                                list(ctx.trail), k)
        return after["bal"] < before["bal"] and after["bal"] >= 0           # keep spending only while the credit is falling and not yet below zero

    def cross_owner(self, base, ep, p):
        ctx = self.ctx
        attackers = [r for r in ctx.roles if ctx.privileged(r) is False]
        got = self.fresh(base)
        if got is None or len(attackers) < 2:
            if len(attackers) < 2:
                self.unchecked.add(f"{key(ep)} cross-owner (needs two ordinary roles)")
            return
        ref, obj, owner = got
        mine = ctx.snap(owner)
        if mine is None:
            self.unchecked.add(f"{key(ep)} cross-owner (no account endpoint to learn the owner's id)")
            return
        res = self.read(ep, p, ref, owner) or obj
        tied = any(OWNER_KEY.search(k) and v == mine["id"] for k, v in res.items())
        if not tied:
            self.unchecked.add(f"{key(ep)} cross-owner (the {base} does not show whose it is)")
            return
        other = next(r for r in attackers if r != owner)
        ctx.trail = []
        before = ctx.snap(owner)
        resp = ctx.send(ep, {p: ref}, ctx.build(ep, {}), other)
        if resp.ok:
            after = ctx.snap(owner)
            moved = bool(before and after and L.is_num(before["bal"]) and L.is_num(after["bal"]) and before["bal"] != after["bal"])
            ctx.add("LOGIC-CROSS-OWNER-ACTION", "high" if moved else "medium", key(ep),
                    f"{other} performed {key(ep)} on a {base} that belongs to {owner} (answer {resp.status})"
                    + (f"; the owner's balance changed {before['bal']} -> {after['bal']}" if moved else ""), list(ctx.trail), other)

    def terminal(self, base, ep, p):
        ctx = self.ctx
        if not TERMINAL.search(ep["path"].rsplit("/", 1)[-1]):
            return
        others = [(q, qp) for q, qp in self.actions.get(base, []) if q is not ep and not TERMINAL.search(q["path"].rsplit("/", 1)[-1])
                  and not REVIVE.search(q["path"].rsplit("/", 1)[-1]) and not FOLLOWUP_OK.search(q["path"].rsplit("/", 1)[-1])]
        if not others:
            return
        got = self.fresh(base)
        if got is None:
            return
        ref, _, owner = got
        ctx.trail = []
        resp, acting = self.apply(base, ep, p, ref, owner, retry_roles=False)
        if not resp.ok:
            self.unchecked.add(f"{key(ep)} terminal state (the {base} could not be taken to it)")
            return
        for q, qp in others:
            for body in self.variants(q):
                r = ctx.send(q, {qp: ref}, body, acting)
                if r.ok:
                    ctx.add("LOGIC-STATE-REGRESSION", "medium", key(q),
                            f"{key(q)} was accepted ({r.status}) on a {base} after {key(ep)}: a finished {base} should refuse it",
                            list(ctx.trail), key(q))
                    break

    def repeat_cap(self, base, ep, p):
        ctx = self.ctx
        amount = next((n for n in L.props_of(ep) if L.has_token(n, ("amount",))), None)
        if amount is None:
            return
        got = self.fresh(base)
        if got is None:
            return
        ref, obj, owner = got
        ctx.trail = []
        for q, qp in self.actions.get(base, []):               # get the resource ready (pay, confirm, ...) WITHOUT using the amount action
            if q is not ep and PREREQ.search(q["path"].rsplit("/", 1)[-1]):
                ctx.send(q, {qp: ref}, ctx.build(q, {}), owner)
        acting = owner
        for r in ctx.roles_by_privilege():                      # the role that may call the amount action (a refund may be staff-only)
            probe = ctx.send(ep, {p: ref}, ctx.build(ep, {amount: 0}), r)
            if probe.status not in (401, 403):
                acting = r
                break
        res = self.read(ep, p, ref, acting) or self.read(ep, p, ref, owner)
        if res is None:
            self.unchecked.add(f"{key(ep)} repeat cap (no GET of the {base} to read the paid amount)")
            return
        basis = next((v for k, v in res.items() if L.is_num(v) and "paid" in L.tokens(k) and not any("refund" in t for t in L.tokens(k))), None)
        if not basis or basis <= 1:
            self.unchecked.add(f"{key(ep)} repeat cap (the {base} shows no paid amount)")
            return
        amt = max(1, int(basis * SHARE))
        done = 0
        for _ in range(3):
            r = ctx.send(ep, {p: ref}, ctx.build(ep, {amount: amt}), acting)
            if r.ok:
                done += 1
        res2 = self.read(ep, p, ref, acting) or {}
        refunded = next((v for k, v in res2.items() if L.is_num(v) and any("refund" in t for t in L.tokens(k))), None)
        if done * amt > basis or (refunded is not None and refunded > basis):
            ctx.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                    f"{done} requests of {amt} (60% of the {basis} paid) were all accepted"
                    + (f" and the {base} reads back {refunded} refunded" if refunded is not None else "")
                    + f": more than the {basis} that was paid", list(ctx.trail), amount)

    def idempotency(self, ep):
        ctx = self.ctx
        node = ((self.spec.get("paths") or {}).get(ep["path"]) or {}).get(ep["method"].lower()) or {}
        hdr = next((x.get("name") for x in (node.get("parameters") or []) if isinstance(x, dict) and x.get("in") == "header"
                    and IDEM.search(x.get("name", ""))), None)
        if not hdr:
            return
        role = ctx.role
        body1 = ctx.build(ep, {})
        body2 = dict(body1) if isinstance(body1, dict) else body1
        if isinstance(body2, dict):
            tweak = next((n for n, v in body2.items() if L.is_num(v) and not isinstance(v, bool)), None)
            if tweak is None:
                tweak = next((n for n, v in body2.items() if isinstance(v, str)), None)
                if tweak:
                    body2[tweak] = body2[tweak] + "x"
            else:
                body2[tweak] = body2[tweak] + 1
            if tweak is None:
                return
        ctx.bump()
        ctx.bump()
        token = f"qa-idem-{ctx.probes}"
        a = self.api.call(role, ep["method"], ep["path"], body1, None, None, {hdr: token})
        b = self.api.call(role, ep["method"], ep["path"], body2, None, None, {hdr: token})
        ctx.trail = [{"method": ep["method"], "path": ep["path"], "body": body1, "status": a.status, "readback": None},
                     {"method": ep["method"], "path": ep["path"], "body": body2, "status": b.status, "readback": None}]
        if a.ok and b.ok and a.json is not None and a.json == b.json:
            ctx.add("LOGIC-IDEMPOTENCY", "medium", key(ep),
                    f"{hdr} reused with a different body answered {b.status} with the first response: a reused key with another request "
                    f"should be rejected (422/409)", list(ctx.trail), hdr)


def run(api, spec_doc, qa) -> dict:
    ch = Chains(api, spec_doc, qa)
    ctx = ch.ctx
    res = {"engine": "workflow", "findings": ctx.findings, "notes": ch.notes, "probes": 0}
    budget_hit = False
    try:
        if ch.actions:
            if ctx.account() is None:
                ch.unchecked.add("account balance checks (no parameterless GET returning the caller's id and a balance)")
            for base, acts in ch.actions.items():
                for ep, p in acts:
                    for check in (ch.balance_checks, ch.cross_owner, ch.terminal, ch.repeat_cap):
                        try:
                            if check is ch.balance_checks and ctx.account() is None:
                                continue
                            check(base, ep, p)
                        except L.Budget:
                            raise
                        except Exception as exc:       # an odd answer must not kill the engine: record, degrade
                            ctx.errors += 1
                            ch.notes.append(f"{check.__name__} {key(ep)}: {type(exc).__name__}: {exc}"[:240])
        for ep in ch.producers:
            try:
                ch.idempotency(ep)
            except L.Budget:
                raise
            except Exception as exc:
                ctx.errors += 1
                ch.notes.append(f"idempotency {key(ep)}: {type(exc).__name__}: {exc}"[:240])
    except L.Budget:
        budget_hit = True
        ch.notes.append(f"write budget ({ctx.max}) spent: the remaining chains were not exercised")
    res["probes"] = ctx.probes
    res["chains"] = {b: [key(e) for e, _ in a] for b, a in ch.actions.items()}
    res["account_endpoint"] = ctx.account_path
    if ch.unchecked:
        ch.notes.append("could not check: " + ", ".join(sorted(ch.unchecked)[:8]))
    if not ch.actions and not ctx.probes:
        return trust.mark(res, trust.SKIPPED, "no create->action chain: no POST /x/{x_id}/<verb> style operation")
    if ctx.probes == 0:
        return trust.mark(res, trust.DEGRADED, "no request was sent: nothing was checked")
    if not ch.actions:   # only the idempotency probe ran: the chain oracles (balance, owner, terminal, repeat) never ran
        return trust.mark(res, trust.DEGRADED, "no create->action chain: only the idempotency probe ran; chain oracles not run")
    reasons = []
    if budget_hit:
        reasons.append("write budget spent")
    if ctx.errors:
        reasons.append(f"{ctx.errors} check(s) crashed")
    if ch.unchecked:
        reasons.append(f"{len(ch.unchecked)} check(s) could not read back")
    if reasons:
        return trust.mark(res, trust.DEGRADED, "; ".join(reasons))
    return trust.mark(res, trust.RAN_OK, "every chain oracle ran with read-back")
