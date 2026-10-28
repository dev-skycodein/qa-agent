"""Business-logic engine: money and quantity abuse, confirmed by read-back (never by a 2xx alone).

  Run through run.py with --engines ...,logic   (the engine is called run(api, doc, qa) like the others)

DESIGN - tree of thoughts
-------------------------
Candidate 1, pure declarative: the project lists every invariant (LOGIC_RULES) and the engine only executes them.
  + zero false positives by construction (the spec owns the rule); precise messages.
  - finds nothing the author did not already think of; every project pays the authoring cost first.
Candidate 2, pure heuristic: guess money fields by name, fire abuse values, look at what the server stored.
  + works on any OpenAPI document with no spec at all.
  - name guesses are noisy (a negative balance can be a legal credit, "amount" in a payment is client input), so most
    of its findings must be labelled "verify".
Candidate 3, hybrid (CHOSEN): LAYER A runs declared rules (confirmed violations, severity high); LAYER B runs name-based
  heuristics whose every finding is read-back proven but still a candidate (severity medium, detail starts with "verify:").
  LAYER C (added in this revision) discovers the state the API exposes (a GET of the created resource, a parameterless GET
  that returns the caller's id and balance, e.g. GET /me) and checks invariants across write sequences.
  Heuristics only claim what the server stored; a rule only claims what a rule's author declared.

State isolation per probe - two options:
  (a) qa-spec fresh_state(api) hook before every probe. Exact, but the project must write it, and shared stock makes
      probes interact unless it is reset each time.
  (b) unique resources per probe: every probe creates its own item / order / coupon through the spec's own create
      endpoints and reads back that resource. CHOSEN for the heuristics: no hook needed, and a probe's read-back can
      only see its own writes. Declared rules use a `setup` list for the same purpose.

Roles - a write endpoint is probed as the first role the server does not refuse (401/403) for it (role_for). An empty-body
  request is sent to find out (a validation error still proves the role may reach the endpoint; nothing is created).
  Privilege is read from the caller's account object (role/type/is_admin); an unknown privilege never yields a claim.

ORACLES - chain of thought (each: the precise violation, how it can be a false positive, how read-back confirms it)
  VALUE probes (create endpoints and actions on a fresh resource). Abuse values -1, 2**31, 2**53+1, 1e308 (+1.5 for integer
    fields; 150 for discount fields). Control = the same create with no abuse value; a read-back equal to the control means
    the server IGNORED the field, which is not a claim.
      NEGATIVE-VALUE  sent < 0 and read back < 0.           FP: a legal credit / negative balance. -> medium, verify.
      OVERFLOW        |sent| >= 2**31, read back != sent and != control (wrapped, clamped, inf). FP: JS-style float
                      precision loss on a client that re-reads the value as a double. -> medium, verify.
      ROUNDING        fractional value into an integer field, accepted (stored as sent or silently changed). FP: a
                      server that rounds by design and documents it. -> medium, verify.
      BOUND-VIOLATION discount read back above 100 (percent scale). FP: an API that uses a 0..1 scale and happens to
                      accept 150 as a different unit. -> medium, verify.
      ECHO            a request field with no same-named read-back field is matched to the read-back number that carries
                      its base name (price_override -> unit_price). One candidate only; otherwise it is not checked.
  TAMPER (create endpoints that reference a catalogue item and carry price / total / subtotal, declared OR present only in
      the read-back, e.g. a `total` the spec does not document). Control value c; client sends c+7; read back == c+7 and
      != c means the server trusted the client amount. FP: an API where the client legitimately sets the price.
      -> PRICE-TAMPER medium, verify.
  BOUNDS (LAYER C, schema check): a numeric field whose OpenAPI schema declares minimum/maximum is sent the first value
      outside it (min-1, -1, max+1, or the bound itself for exclusive). Accepted AND echoed back == sent means the server
      stored a value its own contract forbids. FP: a contract that is wrong, not the server. -> BOUND-VIOLATION medium, verify.
  UNIT (any read-back order-like object): total == unit price * quantity to the cent, when no discount / coupon / tax / fee
      is set. FP: a server that adds a fee the read-back does not show. Used for fractional prices (qty 10 of 2.99) and for
      32-bit wrap (qty chosen so price*qty crosses 2**31). -> SUM-MISMATCH medium, verify.
  STOCK (create endpoints with a quantity field and a reference to a parent with a stock field):
      negative quantity on a fresh parent -> stock rose = NEGATIVE-VALUE; stock below zero -> BOUND-VIOLATION.
      SELL-OUT: parent stock 2, order 2 (accepted), order 1 more: must be refused; a further accepted order, or stock < 0,
      is a BOUND-VIOLATION. FP: a backorder feature (documented) - verify.
  DOUBLE-APPLY (action endpoints with a money field, on a fresh resource). The identical request is sent twice (the amount
      field, when present, is set to the order total). A money field read back changed by d1 the first time and by d2 == d1
      the second time means the action applied twice. FP: a legitimately additive action (add points, top up). verify.
      Also: a read-back `refunded`-like field above the order `total` -> BOUND-VIOLATION (refunds exceed what was paid).
  CONSERVATION (LAYER C, account read-back, GET /me-like endpoint):
      purchase: buyer balance change == -order total (else CONSERVATION).
      refund: buyer balance change == +refund amount.
      transfer to self: caller balance change == 0 (else CONSERVATION).
      transfer to another user: sender -amount and recipient +amount.
      top-up: caller +amount.
      negative amount accepted and the caller's balance rose -> NEGATIVE-VALUE (only for a NON-privileged caller).
      A non-privileged caller's balance below zero after a purchase -> NEGATIVE-VALUE. Admin / unknown privilege: no claim
      (credit lines are documented, see the decoys in the tests).
  SINGLE-USE / LIMIT (LAYER C): a consumer request references a parent created with a single-use flag or a max-uses 1 limit
      (found by name in the parent's create body). The parent is created once; the consumer is sent as two different roles;
      both 2xx and the reference echoed back -> DOUBLE-APPLY medium, verify.
  SEQUENCE (LAYER C): place -> refund in full -> refund again (double refund, see DOUBLE-APPLY); place -> cancel -> partial
      refund: status must stay terminal (STATE-REGRESSION).
  SUM (any read-back object with lines and total): sum(line.price * line.qty) must equal total within a tolerance.
      FP: rounding on discounts with many lines (tolerance grows with the number of lines). medium, verify.
  STATE-REGRESSION (cancel-like action, then every other POST action on the same resource): status read back after the
      other action is non-terminal while it was terminal after cancel. FP: a status word that is terminal in our list but
      not in the app. verify.
  Declared rules (LAYER A) report high severity because the author declared the invariant:
      conservation     accepted act changes `field` by -|delta_field| (decrease) or +|delta_field| (increase); rejected act
                       must change nothing.                                    -> LOGIC-SUM-MISMATCH
      non_negative     read-back `field` below `min` (default 0) after the acts -> LOGIC-NEGATIVE-VALUE
      sum_of_parts    read-back total != sum(lines price*qty) within tolerance  -> LOGIC-SUM-MISMATCH
      bounded_by       read-back `field` above `bound_field` (or bound_value)    -> LOGIC-BOUND-VIOLATION
      monotone_state   status moves out of a terminal state, or backwards in `order`  -> LOGIC-STATE-REGRESSION
      unique_use       counter read back above max_field (or max_value)          -> LOGIC-DOUBLE-APPLY

qa-spec.py knobs (all optional):
  LOGIC_RULES        [rule dict, ...] (see kinds above). Each rule: name, kind, setup [{call, body, save}], acts
                     [{call, body}] or act (single), repeat (default 1), read "/path/{name}", kind-specific keys.
                     `call` is "METHOD /path" with {name} placeholders filled from `save`d ids; a body string "{name}"
                     becomes the saved id. A setup step saves the response `id`, or the field named by `save_from`
                     (e.g. {"call": "POST /subscriptions", "body": {...}, "save": "inv", "save_from": "invoice_id"}).
  LOGIC_HEURISTICS   True (default): run LAYER B and C.
  LOGIC_ROLE         role that sends the probes by default (default: first non-anon role, else anon)
  LOGIC_SKIP         endpoints the heuristics must not write to (SKIP applies too)
  LOGIC_MAX_PROBES   write-request budget (default 400); the engine stops and reports degraded when it is spent
  BODIES             valid baseline bodies, as in authz / stateful
Status: skipped_no_spec when there are no rules and no candidate field; degraded when rules ran but no heuristic candidate
  existed, when a read-back was missing, or when the budget ran out; errored when every check crashed; ran_ok otherwise.
`probes` counts the write requests really sent. A finding always carries `sequence`: the requests and read-backs.
`gated` lists fields the server refuses to the caller's role (not checked further: role-gated, not a bypass).
"""
import math
import re
import uuid

import trust
from api import endpoints, example, extract_id, key, prefix_of, resolve

KINDS = ("conservation", "non_negative", "sum_of_parts", "bounded_by", "monotone_state", "unique_use")
RULE_FINDING = {"conservation": "LOGIC-SUM-MISMATCH", "non_negative": "LOGIC-NEGATIVE-VALUE", "sum_of_parts": "LOGIC-SUM-MISMATCH",
                "bounded_by": "LOGIC-BOUND-VIOLATION", "monotone_state": "LOGIC-STATE-REGRESSION", "unique_use": "LOGIC-DOUBLE-APPLY"}
MONEY_TOKENS = ("price", "amount", "total", "balance", "quantity", "qty", "stock", "discount", "refund", "points", "credit")
STOCK_TOKENS = ("stock", "inventory", "available")
QTY_TOKENS = ("quantity", "qty")
PRICE_TOKENS = ("price", "unit")
TAMPER_TOKENS = ("price", "total", "subtotal")
DEFAULTS = (("price", 10), ("stock", 1000), ("discount", 0), ("quantity", 1), ("qty", 1))      # valid values for required fields
TERMINAL = ("cancelled", "canceled", "refunded", "void", "voided", "closed", "deleted", "expired")
WRITE = ("POST", "PUT", "PATCH")
TOL = 0.01
MAX_PROBES = 400
ABUSE_NUM = (-1, 2 ** 31, 2 ** 53 + 1, 1e308)
ABUSE_FRACTION = 1.5
ABUSE_DISCOUNT = (-1, 150)
TAMPER_DELTA = 7
GATED = (401, 403)                                     # refused to this role: not a bypass, a gate
ADJUST_TOKENS = ("discount", "coupon", "tax", "fee", "shipping", "percent", "promo")
BALANCE_TOKENS = ("balance", "wallet", "funds", "credit", "credits", "cash")
PRIV_KEYS = ("role", "roles", "type", "kind", "is_admin", "admin")
PRIV_WORDS = ("admin", "administrator", "root", "superuser", "staff", "owner")
RECIPIENT_WORDS = ("recipient", "payee", "receiver", "target", "dest", "destination", "to")
QUALIFIER_TOKENS = ("override", "input", "requested", "custom", "new", "set", "client")
LIMIT_INT_TOKENS = ("max", "limit", "uses", "quota")
LIMIT_BOOL_TOKENS = ("single", "once")
IDENT_TOKENS = ("code", "key", "token", "slug", "sku", "name")
SELL_STOCK = 2
FRACTION_PRICE = 2.99
FRACTION_QTY = 10
FUND_AMOUNT = 10000                                    # top-up before a money step (only via the API's own top-up endpoint)
MEASURABLE = 1e12                                      # a balance beyond this cannot be compared to the cent (float absorbs it)
INT32 = 2 ** 31
HUGE_STOCK = 2 ** 40


class Budget(Exception):
    """The write budget (LOGIC_MAX_PROBES) is spent: stop, keep what was found, report degraded."""


def tokens(name: str) -> list:
    """'unitPrice' -> ['unit', 'price'], 'item_id' -> ['item', 'id'], 'refunded' -> ['refunded']."""
    return [t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", name)]


def has_token(name: str, words) -> bool:
    """Substring per token, so 'subtotal' matches 'total' and 'refunded' matches 'refund'."""
    return any(w in t for t in tokens(name) for w in words)


def is_money(name: str) -> bool:
    return has_token(name, MONEY_TOKENS)


def is_num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and not (isinstance(v, float) and not math.isfinite(v))


def is_num_schema(s) -> bool:
    return isinstance(s, dict) and s.get("type") in ("integer", "number")


def is_recipient(name: str) -> bool:
    """'to_user_id', 'recipientId' -> a reference to the party that receives: an id field with a recipient word."""
    toks = tokens(name)
    return len(toks) >= 2 and toks[-1] == "id" and any(t in RECIPIENT_WORDS for t in toks[:-1])


def fk_base(name: str):
    """'item_id' / 'itemId' -> 'item' (a reference to another resource), else None."""
    toks = tokens(name)
    return "".join(toks[:-1]) if len(toks) >= 2 and toks[-1] == "id" else None


def fill_strict(tpl: str, values: dict) -> str:
    """Fill {name} placeholders; a missing one raises KeyError (never sends a half-built path, unlike api.fill)."""
    def sub(m):
        if m.group(1) not in values:
            raise KeyError(m.group(1))
        return str(values[m.group(1)])
    return re.sub(r"\{(\w+)\}", sub, tpl)


def subst(v, saved: dict):
    """A body value '{name}' becomes the saved id (keeps its type); nested dicts and lists are walked."""
    if isinstance(v, str):
        m = re.fullmatch(r"\{(\w+)\}", v)
        return saved[m.group(1)] if m and m.group(1) in saved else v
    if isinstance(v, dict):
        return {k: subst(x, saved) for k, x in v.items()}
    if isinstance(v, list):
        return [subst(x, saved) for x in v]
    return v


def props_of(ep: dict) -> dict:
    schema = ep.get("body_schema") or {}
    return {k: resolve(v, ep["spec"]) for k, v in (schema.get("properties") or {}).items()}


def required_of(ep: dict) -> set:
    return set((ep.get("body_schema") or {}).get("required") or [])


def resource_prefix(ep: dict):
    """('/orders', 'order_id') for POST /orders/{order_id}/refund; ('/orders', None) for POST /orders."""
    params = re.findall(r"\{(\w+)\}", ep["path"])
    if not params:
        return ep["path"].rstrip("/"), None
    return prefix_of(ep["path"], params[-1]), params[-1]


def echo_key(name: str, obj: dict):
    """The read-back field that carries a request field: the same name, else the one number whose tokens contain the
    request field's base tokens ('price_override' -> 'unit_price'). None when there is no single candidate."""
    if not isinstance(obj, dict):
        return None
    if name in obj:
        return name
    base = [t for t in tokens(name) if t not in QUALIFIER_TOKENS]
    if not base or base == tokens(name):
        return None
    cands = [k for k in obj if is_num(obj[k]) and all(b in tokens(k) for b in base)]
    return cands[0] if len(cands) == 1 else None


def sum_problem(obj: dict):
    """(total, sum) when a read-back object's lines do not add up to its total, else None."""
    lines, total = obj.get("lines"), obj.get("total")
    if not isinstance(lines, list) or not lines or not is_num(total):
        return None
    s = 0.0
    for line in lines:
        if not isinstance(line, dict):
            return None
        p = next((line[k] for k in line if is_num(line[k]) and has_token(k, PRICE_TOKENS)), None)
        q = next((line[k] for k in line if is_num(line[k]) and has_token(k, QTY_TOKENS)), None)
        if p is None or q is None:
            return None
        s += p * q
    return (total, s) if abs(total - s) > TOL * (1 + len(lines)) else None


def unit_problem(obj):
    """(total, expected) when a read-back order's total is not its unit price times its quantity. Skipped when the object
    carries an adjustment (discount, coupon, tax, fee): then the total is not that product by design."""
    if not isinstance(obj, dict) or not is_num(obj.get("total")):
        return None
    for k, v in obj.items():
        if has_token(k, ADJUST_TOKENS) and v not in (None, 0, False, "", []):
            return None
    price = next((obj[k] for k in obj if is_num(obj[k]) and has_token(k, PRICE_TOKENS) and not has_token(k, ("total",))), None)
    qty = next((obj[k] for k in obj if is_num(obj[k]) and has_token(k, QTY_TOKENS)), None)
    if price is None or qty is None:
        return None
    expected = round(price * qty, 2)
    total = obj["total"]
    return (total, expected) if abs(total - expected) > TOL + 1e-9 * abs(expected) else None


def parent_price_name(parent):
    return next((n for n, s in props_of(parent).items()
                 if is_num_schema(s) and has_token(n, PRICE_TOKENS) and not has_token(n, ("total",))), None)


def parent_stock_name(parent):
    return next((n for n, s in props_of(parent).items() if is_num_schema(s) and has_token(n, STOCK_TOKENS)), None)


def limit_overrides(parent: dict):
    """{field: value} that makes a parent single-use / max 1 use (a boolean single_use, an integer max_uses), else None."""
    out = {}
    for n, s in props_of(parent).items():
        toks = tokens(n)
        if s.get("type") == "boolean" and any(t in LIMIT_BOOL_TOKENS for t in toks):
            out[n] = True
        elif s.get("type") == "integer" and any(t in LIMIT_INT_TOKENS for t in toks):
            out[n] = 1
    return out or None


class Ctx:
    def __init__(self, api, spec, qa):
        self.api, self.spec, self.qa = api, spec, qa
        named = [r for r in api.roles if r != "anon"]
        self.role = getattr(qa, "LOGIC_ROLE", None) or (named[0] if named else "anon")
        self.roles = ([self.role] + [r for r in named if r != self.role]) if named else []
        self.max = int(getattr(qa, "LOGIC_MAX_PROBES", MAX_PROBES))
        self.bodies = getattr(qa, "BODIES", None) or {}
        skip = set(getattr(qa, "LOGIC_SKIP", set())) | set(getattr(qa, "SKIP", set()))
        self.all = endpoints(spec)
        self.writes = [e for e in self.all if e["method"] in WRITE and key(e) not in skip]
        self.candidate_keys = [key(e) for e in self.writes if self.money(e)]
        self.probes = 0
        self.trail = []
        self.findings = []
        self.seen = set()
        self.notes = []
        self.unchecked = set()
        self.gated = []
        self.errors = 0
        self.role_cache = {}
        self.account_path = None
        self.account_checked = False
        self.topup = None
        self._ranked = None
        self._gate_seen = set()

    # ---------- plumbing (every request goes through api.Api) ----------

    def bump(self):
        if self.probes >= self.max:
            raise Budget()
        self.probes += 1

    def send(self, ep, values, body, role=None):
        self.bump()
        path = fill_strict(ep["path"], values)
        resp = self.api.call(role or self.role, ep["method"], path, body=body)
        self.trail.append({"method": ep["method"], "path": path, "body": body, "status": resp.status, "readback": None})
        return resp

    def read(self, reader, rid, role=None):
        """GET of one resource: the read-back. Not counted as a probe (it changes nothing)."""
        if reader is None or rid is None:
            return None
        param = re.findall(r"\{(\w+)\}", reader["path"])[-1]
        path = fill_strict(reader["path"], {param: rid})
        resp = self.api.call(role or self.role, "GET", path)
        obj = resp.json if resp.ok and isinstance(resp.json, dict) else None
        self.trail.append({"method": "GET", "path": path, "body": None, "status": resp.status, "readback": obj})
        return obj

    def reader_for(self, prefix):
        for e in self.all:
            if e["method"] == "GET" and re.fullmatch(re.escape(prefix) + r"/\{\w+\}", e["path"]):
                return e
        return None

    def creator_for(self, prefix):
        return next((e for e in self.writes if e["method"] == "POST" and e["path"].rstrip("/") == prefix), None)

    def parent_for(self, base):
        for e in self.writes:
            seg = e["path"].rstrip("/").rsplit("/", 1)[-1]
            if e["method"] == "POST" and "{" not in e["path"] and seg.lower().startswith(base) and self.reader_for(e["path"]):
                return e
        return None

    def money(self, ep):
        return [(n, p) for n, p in props_of(ep).items() if is_num_schema(p) and is_money(n)]

    def fk_parent(self, ep):
        for name in props_of(ep):
            base = fk_base(name)
            if base:
                parent = self.parent_for(base)
                if parent is not None:
                    return name, parent
        return None

    def roles_by_privilege(self):
        """Non-privileged roles first (probes should look like a normal user), then unknown, then privileged. Stable."""
        if self._ranked is None:
            rank = {False: 0, None: 1, True: 2}
            self._ranked = sorted(self.roles, key=lambda r: rank[self.privileged(r)])
        return self._ranked

    def role_for(self, ep):
        """The first role (normal users first) the server does not refuse (401/403) for this create endpoint.
        Sent with an empty body: a validation error still proves the role may reach it, and nothing is written."""
        if "{" in ep["path"] or len(self.roles) < 2:
            return self.role
        k = key(ep)
        if k not in self.role_cache:
            chosen = self.roles_by_privilege()[0]
            for r in self.roles_by_privilege():
                self.bump()
                if self.api.call(r, ep["method"], ep["path"], body={}).status not in GATED:
                    chosen = r
                    break
            self.role_cache[k] = chosen
        return self.role_cache[k]

    def build(self, ep, overrides, depth=0):
        """A valid body: the BODIES entry or the required fields of the schema example, DEFAULTS for money fields,
        a fresh parent for each reference (item_id), then the explicit overrides."""
        schema = ep.get("body_schema") or {}
        base = self.bodies.get(key(ep))
        if base is None:
            base = example(schema, ep["spec"]) if schema else {}
            req = required_of(ep)
            base = {k: v for k, v in base.items() if k in req} if isinstance(base, dict) else {}
        body = dict(base)
        props = props_of(ep)
        for name in body:
            if name in overrides:
                continue
            for word, default in DEFAULTS:
                if word in tokens(name) and is_num_schema(props.get(name)):
                    body[name] = default
                    break
        for name in list(body):
            base_name = fk_base(name)
            if name in overrides or not base_name or depth >= 2:
                continue
            parent = self.parent_for(base_name)
            if parent is not None:
                pid = self.make_parent(parent, depth + 1)
                if pid is not None:
                    body[name] = pid
        body.update(overrides)
        return body

    def new_resource(self, creator, role=None):
        resp = self.send(creator, {}, self.build(creator, {}), role)
        return extract_id(resp.json) if resp.ok else None

    def make_parent(self, parent, depth, overrides=None):
        resp = self.send(parent, {}, self.build(parent, overrides or {}, depth), self.role_for(parent))
        return extract_id(resp.json) if resp.ok else None

    def add(self, kind, severity, endpoint, detail, trail, tag=""):
        marker = (kind, endpoint, tag)
        if marker in self.seen:
            return
        self.seen.add(marker)
        text = detail if severity == "high" else "verify: " + detail
        self.findings.append({"kind": kind, "severity": severity, "endpoint": endpoint, "detail": text[:500], "sequence": trail})

    def gate(self, ep, name, status):
        """Record that the server refuses `name` to this caller's role (once per field): a gate, not a bypass."""
        k = f"{key(ep)} {name}"
        if k not in self._gate_seen:
            self._gate_seen.add(k)
            self.gated.append(k)
            self.notes.append(f"{k}: refused ({status}) for role {self.role_for(ep)}: role-gated, not checked further")

    def attempt(self, ep, overrides, role=None):
        """One abuse attempt: create the resource (or a fresh one for an action), send ep with overrides, read it back.
        `role` overrides the caller (used to check a privileged-only acceptance as a normal user).
        None when there is no read path (no GET /{id} for the resource): the caller records that as unchecked."""
        prefix, param = resource_prefix(ep)
        reader = self.reader_for(prefix)
        if reader is None:
            self.unchecked.add(key(ep))
            return None
        self.trail = []
        before = None
        if param is None:
            role = role or self.role_for(ep)
            body = self.build(ep, overrides)
            resp = self.send(ep, {}, body, role)
            rid = extract_id(resp.json) if resp.ok else None
            after = self.read(reader, rid, role) if rid is not None else None
        else:
            creator = self.creator_for(prefix)
            if creator is None:
                self.unchecked.add(key(ep))
                return None
            role = role or self.role_for(creator)
            rid = self.new_resource(creator, role)
            if rid is None:
                return None
            before = self.read(reader, rid, role)
            body = self.build(ep, overrides)
            resp = self.send(ep, {param: rid}, body, role)
            after = self.read(reader, rid, role)
        if resp.ok and after is None:
            self.unchecked.add(key(ep))
        if after is not None:
            sp = sum_problem(after)
            if sp:
                self.add("LOGIC-SUM-MISMATCH", "medium", key(ep), f"read back total {sp[0]} != sum of read back lines {sp[1]}",
                         list(self.trail), "sum")
            up = unit_problem(after)
            if up:
                self.add("LOGIC-SUM-MISMATCH", "medium", key(ep),
                         f"read back total {up[0]} != unit price x quantity {up[1]}", list(self.trail), "unit")
        return {"resp": resp, "rid": rid, "before": before, "after": after, "trail": list(self.trail)}

    # ---------- account state (LAYER C): a parameterless GET that returns the caller's id and balance ----------

    def account(self):
        if not self.account_checked:
            self.account_checked = True
            for e in self.all:
                if e["method"] != "GET" or "{" in e["path"]:
                    continue
                resp = self.api.call(self.role, "GET", e["path"])
                obj = resp.json if resp.ok and isinstance(resp.json, dict) else None
                if obj and "id" in obj and any(is_num(v) and has_token(k, BALANCE_TOKENS) for k, v in obj.items()):
                    self.account_path = e["path"]
                    break
        return self.account_path

    def snap(self, role):
        path = self.account()
        if path is None:
            return None
        resp = self.api.call(role, "GET", path)
        obj = resp.json if resp.ok and isinstance(resp.json, dict) else None
        self.trail.append({"method": "GET", "path": path, "body": None, "status": resp.status, "readback": obj})
        if obj is None or "id" not in obj:
            return None
        bal = next((obj[k] for k in obj if is_num(obj[k]) and has_token(k, BALANCE_TOKENS)), None)
        if bal is not None and abs(bal) > MEASURABLE:
            bal = None          # a balance this large (a probe drove it there) cannot be compared to the cent: no claim
        return {"id": obj["id"], "bal": bal, "raw": obj}

    def privileged(self, role):
        """True / False from the account object's role field; None when the object does not say (no claim then)."""
        s = self.snap(role)
        if s is None:
            return None
        marks = [k for k in s["raw"] if k in PRIV_KEYS]
        if not marks:
            return None
        return any(str(s["raw"][k]).lower() in PRIV_WORDS or s["raw"][k] is True for k in marks)

    # ---------- LAYER A: declared rules ----------

    def rule_send(self, step, saved):
        method, tpl = step["call"].split(" ", 1)
        path = fill_strict(tpl, saved)
        body = subst(step["body"], saved) if "body" in step else None
        self.bump()
        resp = self.api.call(self.role, method, path, body=body)
        self.trail.append({"method": method, "path": path, "body": body, "status": resp.status, "readback": None})
        return resp, (body if isinstance(body, dict) else {})

    def run_rules(self, rules, out):
        for i, rule in enumerate(rules):
            name = rule.get("name", f"rule-{i}") if isinstance(rule, dict) else f"rule-{i}"
            try:
                self.rule(rule, name, out)
            except Budget:
                raise
            except Exception as exc:
                out["errors"] += 1
                self.notes.append(f"rule {name!r}: crashed ({type(exc).__name__}: {exc})")

    def rule(self, rule, name, out):
        kind = rule.get("kind")
        if kind not in KINDS:
            out["errors"] += 1
            self.notes.append(f"rule {name!r}: unknown kind {kind!r} (one of {', '.join(KINDS)})")
            return
        read_tpl = rule.get("read")
        if not read_tpl:
            out["errors"] += 1
            self.notes.append(f"rule {name!r}: no 'read' path, so nothing can be confirmed by read-back")
            return
        self.trail = []
        saved = {}
        for step in rule.get("setup", []):
            resp, _ = self.rule_send(step, saved)
            rid = extract_id(resp.json) if resp.ok else None
            if step.get("save_from") and resp.ok and isinstance(resp.json, dict):       # the id of a RELATED resource (invoice_id), not of this one
                rid = resp.json.get(step["save_from"])
            if rid is None:
                out["setup_failed"] += 1
                self.notes.append(f"rule {name!r}: setup {step.get('call')} failed ({resp.status}); its probes never ran")
                return
            if step.get("save"):
                saved[step["save"]] = rid
        out["ran"] += 1
        acts = rule.get("acts") or ([rule["act"]] if rule.get("act") else [])
        repeat = max(1, int(rule.get("repeat", 1)))

        def read_obj():
            resp = self.api.call(self.role, "GET", fill_strict(read_tpl, saved))
            obj = resp.json if resp.ok and isinstance(resp.json, dict) else None
            self.trail.append({"method": "GET", "path": fill_strict(read_tpl, saved), "body": None, "status": resp.status,
                               "readback": obj})
            return obj

        def run_acts():
            for _ in range(repeat):
                for step in acts:
                    self.rule_send(step, saved)

        def add_rule(detail):
            self.add(RULE_FINDING[kind], "high", f"rule: {name}", detail, list(self.trail), name)

        def missing(field):
            self.notes.append(f"rule {name!r}: '{field}' not readable as a number (check the read path)")

        if kind == "conservation":
            act, field, dfield = rule["act"], rule["field"], rule["delta_field"]
            before = read_obj()
            resp, sent = self.rule_send(act, saved)
            after = read_obj()
            if not (before and after and is_num(before.get(field)) and is_num(after.get(field))):
                return missing(field)
            amount = sent.get(dfield)
            if not is_num(amount):
                self.notes.append(f"rule {name!r}: act body has no numeric '{dfield}'")
                return
            amount = abs(amount)
            delta = after[field] - before[field]
            direction = rule.get("direction", "decrease")
            expected = ((-amount if direction == "decrease" else amount) if resp.ok else 0)
            if delta != expected:
                add_rule(f"{field} changed by {delta} (before {before[field]}, after {after[field]}); the act was "
                         f"{'accepted' if resp.ok else 'rejected'} with |{dfield}|={amount}, so {field} should change by {expected}")
        elif kind == "non_negative":
            run_acts()
            after = read_obj()
            v = (after or {}).get(rule["field"])
            if not is_num(v):
                return missing(rule["field"])
            lo = rule.get("min", 0)
            if v < lo:
                add_rule(f"{rule['field']} read back as {v} (minimum {lo}) after the acts")
        elif kind == "bounded_by":
            run_acts()
            after = read_obj() or {}
            v = after.get(rule["field"])
            bound = after.get(rule["bound_field"]) if rule.get("bound_field") else rule.get("bound_value")
            if not (is_num(v) and is_num(bound)):
                return missing(rule["field"])
            if v > bound:
                add_rule(f"{rule['field']} read back as {v}, above its bound {bound}")
        elif kind == "sum_of_parts":
            run_acts()
            obj = read_obj() or {}
            tf, lf = rule.get("total_field", "total"), rule.get("lines_field", "lines")
            pf, qf = rule.get("price_field", "price"), rule.get("qty_field", "qty")
            total, lines = obj.get(tf), obj.get(lf)
            if not (is_num(total) and isinstance(lines, list) and lines):
                return missing(tf)
            s = 0.0
            for line in lines:
                if not (isinstance(line, dict) and is_num(line.get(pf)) and is_num(line.get(qf))):
                    return missing(f"{lf}[].{pf}/{qf}")
                s += line[pf] * line[qf]
            if abs(total - s) > rule.get("tolerance", TOL):
                add_rule(f"{tf} read back as {total}, but {lf} add up to {s}")
        elif kind == "monotone_state":
            field = rule["field"]
            order = list(rule.get("order") or [])
            terminal = [str(t) for t in rule.get("terminal", [])]
            prev_obj = read_obj()
            prev = (prev_obj or {}).get(field)
            for step in acts:
                self.rule_send(step, saved)
                cur_obj = read_obj()
                cur = (cur_obj or {}).get(field)
                if prev is None or cur is None:
                    return missing(field)
                backwards = (str(prev) in terminal and cur != prev) or (
                    prev in order and cur in order and order.index(cur) < order.index(prev))
                if backwards:
                    add_rule(f"{field} went {prev} -> {cur} after {step['call']}")
                prev = cur
        elif kind == "unique_use":
            accepted = 0
            for _ in range(repeat):
                for step in acts:
                    resp, _ = self.rule_send(step, saved)
                    accepted += 1 if resp.ok else 0
            after = read_obj() or {}
            counter = after.get(rule["field"])
            cap = after.get(rule["max_field"]) if rule.get("max_field") else rule.get("max_value")
            if not (is_num(counter) and is_num(cap)):
                return missing(rule["field"])
            if counter > cap:
                add_rule(f"{rule['field']} reached {counter} (cap {cap}) after {accepted} accepted use(s)")

    # ---------- LAYER B: heuristics (candidates; every finding is read-back proven) ----------

    def value_probes(self, ep, name, sch):
        is_int = sch.get("type") == "integer"
        discount = has_token(name, ("discount",))
        ctrl = self.attempt(ep, {})
        if ctrl is None:
            return
        echo = echo_key(name, ctrl["after"]) if ctrl["after"] else None
        if echo is None:
            probe = self.attempt(ep, {name: (ABUSE_DISCOUNT if discount else ABUSE_NUM)[0]})
            if probe is not None and probe["resp"].status in GATED:
                self.gate(ep, name, probe["resp"].status)
            else:
                self.unchecked.add(f"{key(ep)} {name}")
            return
        control = ctrl["after"][echo]
        values = ABUSE_DISCOUNT if discount else ABUSE_NUM + ((ABUSE_FRACTION,) if is_int else ())
        for sent in values:
            att = self.attempt(ep, {name: sent})
            if att is None:
                return
            if att["after"] is None or echo not in att["after"]:
                if att["resp"].ok:
                    self.unchecked.add(f"{key(ep)} {name}")
                continue
            if not att["resp"].ok:
                if att["resp"].status in GATED:
                    self.gate(ep, name, att["resp"].status)
                continue
            stored = att["after"][echo]
            if stored == control or not is_num(stored):
                continue          # the server ignored the field (or stored something we cannot compare): no claim
            self.classify(ep, name, sent, stored, is_int, discount, att["trail"])

    def classify(self, ep, name, sent, stored, is_int, discount, trail):
        ek = key(ep)
        if discount and stored > 100:
            return self.add("LOGIC-BOUND-VIOLATION", "medium", ek,
                            f"{name}: sent {sent!r}, read back {stored!r} (above 100 on a percent scale)", trail, name)
        if sent < 0 and stored < 0:
            return self.add("LOGIC-NEGATIVE-VALUE", "medium", ek,
                            f"{name}: sent {sent!r}, read back {stored!r} (a negative amount was stored)", trail, name)
        if is_int and isinstance(sent, float) and sent != int(sent):
            return self.add("LOGIC-ROUNDING", "medium", ek,
                            f"{name}: fractional {sent!r} accepted for an integer field, read back {stored!r}", trail, name)
        if abs(sent) >= 2 ** 31 and (not math.isfinite(stored) or stored != sent):
            self.add("LOGIC-OVERFLOW", "medium", ek,
                     f"{name}: sent {sent!r}, read back {stored!r} (the server changed a very large value)", trail, name)

    def tamper(self, ep, name):
        ctrl = self.attempt(ep, {})
        if ctrl is None or not ctrl["after"]:
            return
        echo = echo_key(name, ctrl["after"])
        if echo is None or not is_num(ctrl["after"][echo]):
            return
        c = ctrl["after"][echo]
        t = c + TAMPER_DELTA
        att = self.attempt(ep, {name: t})
        if att is None:
            return
        if not att["resp"].ok:
            if att["resp"].status in GATED:
                self.gate(ep, name, att["resp"].status)
            return
        if att["after"] is None or att["after"].get(echo) != t or c == t:
            return
        if self.privileged(self.role_for(ep)) is True:
            # an admin's acceptance is a bypass only if a normal user may send the same value too
            normal = [r for r in self.roles_by_privilege() if self.privileged(r) is False]
            if not normal:
                self.gate(ep, name, "accepted for a privileged role only; no normal role to compare")
                return
            again = self.attempt(ep, {name: t}, role=normal[0])
            if again is None or not again["resp"].ok:
                if again is not None and again["resp"].status in GATED:
                    self.gate(ep, name, again["resp"].status)
                return
            att = again
        self.add("LOGIC-PRICE-TAMPER", "medium", key(ep),
                 f"{name}: client sent {t}, read back {t}; the server's own value was {c}", att["trail"], name)

    def catalogue_probes(self, ep, money, fk):
        """Create endpoints that reference a catalogue item (fk): tamper, purchase conservation, quantity boundaries."""
        self.ensure_funds(self.role_for(ep))
        ctrl = self.attempt(ep, {})
        if ctrl is None:
            return
        props = props_of(ep)
        names = [n for n, _ in money if has_token(n, TAMPER_TOKENS)]
        if ctrl["after"]:
            names += [n for n, v in ctrl["after"].items() if is_num(v) and has_token(n, TAMPER_TOKENS)
                      and n not in props and n not in names]
        for name in names:
            self.tamper(ep, name)
        qty = next((n for n, _ in money if has_token(n, QTY_TOKENS)), None)
        if qty is None:
            return
        self.purchase(ep, qty, fk)
        self.stock_coupled(ep, qty, fk)
        self.fraction_probe(ep, qty, fk)
        self.overflow_probe(ep, qty, fk)
        self.sellout_probe(ep, qty, fk)

    def topup_ep(self):
        """The wallet's own funding endpoint, found by shape: parameterless POST with an amount and no recipient."""
        if self.topup is None:
            self.topup = False
            if self.account() is not None:
                for ep in self.writes:
                    prefix, param = resource_prefix(ep)
                    if ep["method"] != "POST" or param is not None or self.reader_for(prefix) is not None:
                        continue
                    amt = next((n for n, _ in self.money(ep) if has_token(n, ("amount",))), None)
                    if amt and not any(is_recipient(n) for n in props_of(ep)):
                        self.topup = (ep, amt)
                        break
        return self.topup or None

    def ensure_funds(self, role):
        """Fund the probe caller before a money step, so a drained balance does not refuse (402) every later probe.
        Done outside the balance measurement windows. Only through the API's own top-up endpoint, if it has one."""
        found = self.topup_ep()
        if found is not None:
            ep, amt = found
            self.send(ep, {}, self.build(ep, {amt: FUND_AMOUNT}), role)

    def purchase(self, ep, qty_name, fk):
        """Buyer balance change must equal -(order total); a non-privileged buyer must not go below zero."""
        if self.account() is None:
            self.unchecked.add(f"{key(ep)} buyer balance (no account endpoint such as GET /me)")
            return
        prefix, _ = resource_prefix(ep)
        role = self.role_for(ep)
        body = self.build(ep, {qty_name: 1})
        self.ensure_funds(role)
        self.trail = []
        before = self.snap(role)
        resp = self.send(ep, {}, body, role)
        after = self.snap(role)
        if not resp.ok or before is None or after is None or not is_num(before["bal"]) or not is_num(after["bal"]):
            return
        obj = self.read(self.reader_for(prefix), extract_id(resp.json), role) or \
            (resp.json if isinstance(resp.json, dict) else None)
        total = (obj or {}).get("total")
        if not is_num(total):
            self.unchecked.add(f"{key(ep)} total (not in the read-back)")
            return
        delta = after["bal"] - before["bal"]
        if abs(delta + total) > TOL:
            self.add("LOGIC-CONSERVATION", "medium", key(ep),
                     f"the buyer's balance changed by {delta:+} but the order total is {total}; the debit must equal the charge",
                     list(self.trail), "purchase")
        if after["bal"] < 0 and self.privileged(role) is False:
            self.add("LOGIC-NEGATIVE-VALUE", "medium", key(ep),
                     f"a non-privileged buyer's balance went to {after['bal']} after a purchase", list(self.trail), "balance")
        self.overspend(ep, qty_name, fk, role)

    def overspend(self, ep, qty_name, fk, role):
        """A non-privileged buyer ordering more than the balance must be refused (402). Accepted = the balance went negative.
        Privileged accounts (documented credit line) and accounts whose privilege is unknown are never claimed."""
        fkname, parent = fk
        price, stock = parent_price_name(parent), parent_stock_name(parent)
        if price is None or stock is None or self.privileged(role) is not False:
            return
        s0 = self.snap(role)
        if s0 is None or not is_num(s0["bal"]) or s0["bal"] < 0:
            return
        pid = self.make_parent(parent, 1, {stock: HUGE_STOCK})
        unit = (self.read(self.reader_for(parent["path"]), pid) or {}).get(price) if pid is not None else None
        if not is_num(unit) or unit <= 0:
            return
        qty = int(s0["bal"] // unit) + 1
        self.trail = []
        resp = self.send(ep, {}, self.build(ep, {qty_name: qty, fkname: pid}), role)
        s1 = self.snap(role)
        if resp.ok and s1 and is_num(s1["bal"]) and s1["bal"] < -TOL:
            self.add("LOGIC-NEGATIVE-VALUE", "medium", key(ep),
                     f"a non-privileged buyer ordered {qty} at {unit} with a balance of {s0['bal']}: accepted, and the "
                     f"balance went to {s1['bal']}", list(self.trail), "overspend")

    def stock_coupled(self, ep, qty_name, fk):
        fkname, parent = fk
        preader = self.reader_for(parent["path"])
        role = self.role_for(ep)
        for v in (-5, 2000):
            self.trail = []
            pid = self.make_parent(parent, 1)
            p0 = self.read(preader, pid) if pid is not None else None
            stock = next((n for n, x in (p0 or {}).items() if is_num(x) and has_token(n, STOCK_TOKENS)), None)
            if stock is None:
                self.unchecked.add(f"{key(ep)} stock")
                return
            resp = self.send(ep, {}, self.build(ep, {qty_name: v, fkname: pid}), role)
            if not resp.ok:
                continue
            p1 = self.read(preader, pid) or {}
            if not is_num(p1.get(stock)):
                continue
            s0, s1 = p0[stock], p1[stock]
            if v < 0 and s1 > s0:
                self.add("LOGIC-NEGATIVE-VALUE", "medium", key(ep),
                         f"{stock} rose {s0} -> {s1} after an accepted order with {qty_name}={v}", list(self.trail), qty_name)
            if s1 < 0:
                self.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                         f"{stock} fell {s0} -> {s1} (below zero) after an accepted order with {qty_name}={v}",
                         list(self.trail), qty_name)

    def fraction_probe(self, ep, qty_name, fk):
        """A decimal unit price in bulk: total must be price x quantity to the cent (bulk truncation shows here)."""
        fkname, parent = fk
        price = parent_price_name(parent)
        if price is None or props_of(parent)[price].get("type") != "number":
            return
        role = self.role_for(ep)
        pid = self.make_parent(parent, 1, {price: FRACTION_PRICE})
        if pid is None:
            self.notes.append(f"{key(ep)}: fraction probe skipped (the parent refused a price of {FRACTION_PRICE})")
            return
        self.trail = []
        resp = self.send(ep, {}, self.build(ep, {qty_name: FRACTION_QTY, fkname: pid}), role)
        if not resp.ok:
            return
        prefix, _ = resource_prefix(ep)
        obj = self.read(self.reader_for(prefix), extract_id(resp.json), role) or \
            (resp.json if isinstance(resp.json, dict) else None)
        up = unit_problem(obj)
        if up:
            self.add("LOGIC-SUM-MISMATCH", "medium", key(ep),
                     f"unit price {FRACTION_PRICE} x quantity {FRACTION_QTY}: total read back as {up[0]}, expected {up[1]} "
                     f"(a decimal price truncated for bulk orders?)", list(self.trail), "fraction")

    def overflow_probe(self, ep, qty_name, fk):
        """A quantity that makes price x quantity cross 2**31: the total must not wrap."""
        fkname, parent = fk
        price, stock = parent_price_name(parent), parent_stock_name(parent)
        if price is None or stock is None:
            return
        role = self.role_for(ep)
        pid = self.make_parent(parent, 1, {stock: HUGE_STOCK})
        if pid is None:
            return
        p0 = self.read(self.reader_for(parent["path"]), pid) or {}
        unit = p0.get(price)
        if not is_num(unit) or unit <= 0 or unit != int(unit):
            return
        qty = INT32 // int(unit) + 1
        self.trail = []
        resp = self.send(ep, {}, self.build(ep, {qty_name: qty, fkname: pid}), role)
        if not resp.ok:
            return
        prefix, _ = resource_prefix(ep)
        obj = self.read(self.reader_for(prefix), extract_id(resp.json), role) or \
            (resp.json if isinstance(resp.json, dict) else None)
        up = unit_problem(obj)
        if up:
            self.add("LOGIC-SUM-MISMATCH", "medium", key(ep),
                     f"unit price {unit} x quantity {qty}: total read back as {up[0]}, expected {up[1]} "
                     f"(a total past 2**31 wrapped?)", list(self.trail), "overflow")

    def sellout_probe(self, ep, qty_name, fk):
        """Sell the stock out, then order one more: the second order must be refused and stock must not go negative."""
        fkname, parent = fk
        stock = parent_stock_name(parent)
        if stock is None:
            return
        role = self.role_for(ep)
        pid = self.make_parent(parent, 1, {stock: SELL_STOCK})
        if pid is None:
            return
        preader = self.reader_for(parent["path"])
        self.trail = []
        first = self.send(ep, {}, self.build(ep, {qty_name: SELL_STOCK, fkname: pid}), role)
        if not first.ok:
            self.notes.append(f"{key(ep)}: sell-out probe skipped (the first order of {SELL_STOCK} was refused, {first.status})")
            return
        second = self.send(ep, {}, self.build(ep, {qty_name: 1, fkname: pid}), role)
        left = (self.read(preader, pid) or {}).get(stock)
        if is_num(left) and left < 0:
            self.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                     f"{stock} fell to {left} after selling out ({SELL_STOCK}) and a further order of 1 was accepted "
                     f"({second.status})", list(self.trail), "sellout")
        elif second.ok:
            self.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                     f"an order of 1 was accepted after the stock sold out (stock now {left}); expected a refusal",
                     list(self.trail), "sellout")

    def double_apply(self, ep, money):
        prefix, param = resource_prefix(ep)
        if not money or param is None:
            return
        reader, creator = self.reader_for(prefix), self.creator_for(prefix)
        if reader is None or creator is None:
            self.unchecked.add(key(ep))
            return
        role = self.role_for(creator)
        self.trail = []
        rid = self.new_resource(creator, role)
        if rid is None:
            return
        o0 = self.read(reader, rid, role)
        if not o0:
            return
        props = props_of(ep)
        total = o0.get("total") if is_num(o0.get("total")) else None
        body = self.build(ep, {})
        amount_names = [n for n, _ in money if has_token(n, ("amount", "refund")) and n in props]
        if total is not None:
            for n in amount_names:
                body[n] = total
        sent = next((body[n] for n in amount_names if is_num(body.get(n))), None)
        a0 = self.snap(role)
        r1 = self.send(ep, {param: rid}, body, role)
        o1 = self.read(reader, rid, role)
        a1 = self.snap(role)
        r2 = self.send(ep, {param: rid}, body, role)
        o2 = self.read(reader, rid, role)
        a2 = self.snap(role)
        if r1.ok and a0 and a1 and is_num(a0["bal"]) and is_num(a1["bal"]) and sent is not None:
            credit = a1["bal"] - a0["bal"]
            if abs(credit - sent) > TOL:
                self.add("LOGIC-CONSERVATION", "medium", key(ep),
                         f"a refund of {sent} credited the buyer {credit:+}; a refund must credit exactly what it refunds",
                         list(self.trail), "refund-credit")
        if o2 and total is not None:
            for f, v in o2.items():
                if is_num(v) and has_token(f, ("refund",)) and v > o2.get("total", math.inf) + TOL:
                    self.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                             f"{f} read back as {v}, above the order total {o2['total']} (refunded more than was paid)",
                             list(self.trail), f + "-paid")
        if not (r1.ok and r2.ok and o0 and o1 and o2):
            return
        for f, v1 in o1.items():
            if not (is_num(v1) and is_money(f) and is_num(o0.get(f)) and is_num(o2.get(f))):
                continue
            d1, d2 = v1 - o0[f], o2[f] - v1
            if d1 != 0 and d2 == d1:
                self.add("LOGIC-DOUBLE-APPLY", "medium", key(ep),
                         f"the identical request changed {f} by {d1} both times ({o0[f]} -> {v1} -> {o2[f]}); "
                         f"verify it is not an intended additive action", list(self.trail), f)
        if r2.ok and a1 and a2 and is_num(a1["bal"]) and is_num(a2["bal"]) and sent is not None and a2["bal"] - a1["bal"] > TOL:
            self.add("LOGIC-DOUBLE-APPLY", "medium", key(ep),
                     f"the second identical request credited the buyer {a2['bal'] - a1['bal']:+} again (refund of {sent})",
                     list(self.trail), "credit-twice")

    def account_probes(self, ep, money):
        """Account-level actions (a transfer, a top-up): no resource to read back, so the caller's balance is the state."""
        if self.account() is None:
            self.unchecked.add(f"{key(ep)} balance (no account endpoint such as GET /me)")
            return
        amt = next((n for n, _ in money if has_token(n, ("amount",))), None) or money[0][0]
        role = self.role_for(ep)
        rec = next((n for n in props_of(ep) if is_recipient(n)), None)
        self.ensure_funds(role)
        self.trail = []
        before = self.snap(role)
        if before is None or not is_num(before["bal"]):
            self.unchecked.add(f"{key(ep)} balance")
            return
        other = next((r for r in self.roles_by_privilege() if r != role), None)
        other_snap = self.snap(other) if other else None
        # 1. a negative amount must never credit the caller (sent to another user when there is one: a refused
        #    self-transfer would say nothing about the amount)
        target = other_snap["id"] if (rec and other_snap) else before["id"]
        self.trail = []
        b0 = self.snap(role)
        resp = self.send(ep, {}, self.build(ep, {amt: -1, **({rec: target} if rec else {})}), role)
        b1 = self.snap(role)
        if resp.ok and b0 and b1 and is_num(b1["bal"]) and b1["bal"] - b0["bal"] > TOL and self.privileged(role) is False:
            self.add("LOGIC-NEGATIVE-VALUE", "medium", key(ep),
                     f"{amt}=-1 was accepted and the caller's balance rose {b0['bal']} -> {b1['bal']}",
                     list(self.trail), amt)
        amount = 1
        if rec is None:
            self.trail = []
            b0 = self.snap(role)
            resp = self.send(ep, {}, self.build(ep, {amt: amount}), role)
            b1 = self.snap(role)
            if resp.ok and b0 and b1 and is_num(b0["bal"]) and is_num(b1["bal"]) and abs(b1["bal"] - b0["bal"] - amount) > TOL:
                self.add("LOGIC-CONSERVATION", "medium", key(ep),
                         f"{amt}={amount} changed the caller's balance by {b1['bal'] - b0['bal']:+}", list(self.trail), "credit")
            return
        # 2. transfer to self: the caller's balance must not change
        self.trail = []
        b0 = self.snap(role)
        resp = self.send(ep, {}, self.build(ep, {amt: amount, rec: before["id"]}), role)
        b1 = self.snap(role)
        if resp.ok and b0 and b1 and is_num(b0["bal"]) and is_num(b1["bal"]) and abs(b1["bal"] - b0["bal"]) > TOL:
            self.add("LOGIC-CONSERVATION", "medium", key(ep),
                     f"a transfer of {amount} to yourself (id {before['id']}) changed your balance by "
                     f"{b1['bal'] - b0['bal']:+}; it must change nothing", list(self.trail), "self")
        # 3. transfer to another user: sender -amount, recipient +amount
        if other_snap is None or not is_num(other_snap["bal"]):
            return
        self.trail = []
        s0, r0 = self.snap(role), self.snap(other)
        resp = self.send(ep, {}, self.build(ep, {amt: amount, rec: other_snap["id"]}), role)
        s1, r1 = self.snap(role), self.snap(other)
        if resp.ok and all(x and is_num(x["bal"]) for x in (s0, s1, r0, r1)):
            ds, dr = s1["bal"] - s0["bal"], r1["bal"] - r0["bal"]
            if abs(ds + amount) > TOL or abs(dr - amount) > TOL:
                self.add("LOGIC-CONSERVATION", "medium", key(ep),
                         f"a transfer of {amount}: sender changed {ds:+}, recipient changed {dr:+}; money must move exactly",
                         list(self.trail), "other")

    def shared_limit(self, consumer):
        """A single-use or max-1 parent (a coupon) redeemed by two different principals through the consumer request."""
        if consumer["method"] != "POST" or "{" in consumer["path"]:
            return
        for ref_name, sch in props_of(consumer).items():
            if sch.get("type") not in ("string", "integer"):
                continue
            ref_toks = tokens(ref_name)
            for parent in self.writes:
                if parent["method"] != "POST" or "{" in parent["path"] or parent is consumer:
                    continue
                base = parent["path"].rstrip("/").rsplit("/", 1)[-1].lower()
                single = base[:-1] if base.endswith("s") else base
                if single not in ref_toks:
                    continue
                limit = limit_overrides(parent)
                if limit:
                    self.single_use_probe(consumer, ref_name, parent, limit)
                    return

    def single_use_probe(self, consumer, ref_name, parent, limit):
        ident_name = next((n for n, s in props_of(parent).items()
                           if s.get("type") == "string" and any(t in IDENT_TOKENS for t in tokens(n))), None)
        overrides = dict(limit)
        if ident_name:
            overrides[ident_name] = f"qa-{uuid.uuid4().hex[:10]}"
        role_a = self.role_for(consumer)
        others = [r for r in self.roles_by_privilege() if r != role_a]
        if not others:
            self.notes.append(f"{key(consumer)}: single-use probe needs a second role; none configured")
            return
        role_b = others[0]          # others is ordered normal users first
        presp = self.send(parent, {}, self.build(parent, overrides), self.role_for(parent))
        if not presp.ok:
            self.notes.append(f"{key(parent)}: single-use setup refused ({presp.status}); its probe never ran")
            return
        ident = overrides[ident_name] if ident_name else extract_id(presp.json)
        if ident is None:
            return
        self.trail = []
        a = self.send(consumer, {}, self.build(consumer, {ref_name: ident}), role_a)
        b = self.send(consumer, {}, self.build(consumer, {ref_name: ident}), role_b)
        if not (a.ok and b.ok):
            return
        echo = b.json.get(ref_name) if isinstance(b.json, dict) else None
        if echo is None or str(echo) != str(ident):
            self.unchecked.add(f"{key(consumer)} {ref_name} (the second use is not echoed)")
            return
        self.add("LOGIC-DOUBLE-APPLY", "medium", key(consumer),
                 f"single-use {key(parent)} {ident!r} was redeemed by {role_a} ({a.status}) and then by {role_b} "
                 f"({b.status}); the second redemption should be refused", list(self.trail), "shared")

    def bounds(self, ep):
        """A value outside the schema's own minimum / maximum must be refused; if it is accepted and echoed, it is a finding."""
        for name, sch in props_of(ep).items():
            if not is_num_schema(sch):
                continue
            lo, hi = sch.get("minimum"), sch.get("maximum")
            bads = []
            if is_num(lo):
                if sch.get("exclusiveMinimum") is True:
                    bads.append(lo)
                else:
                    bads += [lo - 1] + ([-1] if lo - 1 > -1 else [])
            if is_num(hi):
                bads.append(hi if sch.get("exclusiveMaximum") is True else hi + 1)
            for bad in bads[:3]:
                self.bound_probe(ep, name, bad, lo, hi)

    def bound_probe(self, ep, name, bad, lo, hi):
        prefix, param = resource_prefix(ep)
        bound_text = f"minimum {lo}" if (is_num(lo) and (bad < lo or bad == lo)) else f"maximum {hi}"
        if param is None:
            role = self.role_for(ep)
            self.trail = []
            resp = self.send(ep, {}, self.build(ep, {name: bad}), role)
            if not resp.ok:
                return
            rid = extract_id(resp.json)
            obj = self.read(self.reader_for(prefix), rid, role) if self.reader_for(prefix) and rid is not None else None
            src = obj if obj is not None else (resp.json if isinstance(resp.json, dict) else None)
            trail = list(self.trail)
        else:
            att = self.attempt(ep, {name: bad})
            if att is None or not att["resp"].ok:
                return
            src = att["after"] if att["after"] is not None else (att["resp"].json if isinstance(att["resp"].json, dict) else None)
            trail = att["trail"]
        if not isinstance(src, dict) or name not in src:
            self.unchecked.add(f"{key(ep)} {name} (bound probe: not echoed)")
            return
        stored = src[name]
        if is_num(stored) and abs(stored - bad) < 1e-9:
            self.add("LOGIC-BOUND-VIOLATION", "medium", key(ep),
                     f"{name}: the schema declares {bound_text} but the server accepted {bad!r} and stored {stored!r}",
                     trail, name + " bound")

    def state_regression(self, cancel):
        prefix, param = resource_prefix(cancel)
        reader, creator = self.reader_for(prefix), self.creator_for(prefix)
        if reader is None or creator is None:
            self.unchecked.add(key(cancel))
            return
        others = [e for e in self.writes if e["method"] == "POST" and resource_prefix(e)[1]
                  and resource_prefix(e)[0] == prefix and "cancel" not in e["path"]]
        for other in others:
            self.trail = []
            role = self.role_for(creator)
            rid = self.new_resource(creator, role)
            if rid is None:
                return
            self.send(cancel, {param: rid}, {}, role)
            obj1 = self.read(reader, rid, role) or {}
            s1 = obj1.get("status")
            if str(s1).lower() not in TERMINAL:
                continue
            body = self.build(other, {})
            total = obj1.get("total")
            if is_num(total) and total > 0:      # a PARTIAL amount: a full refund legitimately ends in a terminal state
                for n, _ in self.money(other):
                    if has_token(n, ("amount", "refund")) and n in props_of(other):
                        body[n] = round(total / 2, 2)
            _, opar = resource_prefix(other)
            self.send(other, {opar: rid}, body, role)
            s2 = (self.read(reader, rid, role) or {}).get("status")
            if s2 is not None and s2 != s1 and str(s2).lower() not in TERMINAL:
                self.add("LOGIC-STATE-REGRESSION", "medium", key(other),
                         f"status {s1} -> {s2} after {key(other)} on a resource that {key(cancel)} had made {s1}; "
                         f"verify the transition is not allowed by the app", list(self.trail), key(other))

    def heuristics(self):
        for ep in self.writes:
            try:
                money = self.money(ep)
                prefix, param = resource_prefix(ep)
                if money and param is None and self.reader_for(prefix) is None and ep["method"] == "POST":
                    self.account_probes(ep, money)
                else:
                    for name, sch in money:
                        self.value_probes(ep, name, sch)
                    if param is None:
                        fk = self.fk_parent(ep)
                        if fk is not None:
                            self.catalogue_probes(ep, money, fk)
                        self.shared_limit(ep)
                    else:
                        self.double_apply(ep, money)
                self.bounds(ep)
                if ep["method"] == "POST" and ep["path"].endswith("/cancel") and param:
                    self.state_regression(ep)
            except Budget:
                raise
            except Exception as exc:
                self.errors += 1
                self.notes.append(f"{key(ep)}: heuristic crashed ({type(exc).__name__}: {exc})")


def run(api, spec_doc, qa) -> dict:
    rules = list(getattr(qa, "LOGIC_RULES", None) or [])
    heuristics_on = bool(getattr(qa, "LOGIC_HEURISTICS", True))
    ctx = Ctx(api, spec_doc, qa)
    out = {"ran": 0, "errors": 0, "setup_failed": 0}
    budget_hit = False
    try:
        if rules:
            ctx.run_rules(rules, out)
        if heuristics_on and ctx.writes:
            ctx.heuristics()
    except Budget:
        budget_hit = True
        ctx.notes.append(f"write budget ({ctx.max}) spent: the remaining checks did not run (raise LOGIC_MAX_PROBES)")
    if ctx.unchecked:
        ctx.notes.append(f"{len(ctx.unchecked)} field/endpoint check(s) had no read-back (no GET /{{id}}, field not echoed, "
                         f"or no account endpoint): " + ", ".join(sorted(ctx.unchecked)[:8]))
    res = {"engine": "logic", "findings": ctx.findings, "notes": ctx.notes, "probes": ctx.probes,
           "rules": {"declared": len(rules), "ran": out["ran"], "errors": out["errors"], "setup_failed": out["setup_failed"]},
           "candidates": ctx.candidate_keys, "heuristics": heuristics_on and bool(ctx.candidate_keys),
           "gated": ctx.gated, "account_endpoint": ctx.account_path}
    if not rules and not heuristics_on:
        return trust.mark(res, trust.SKIPPED, "no LOGIC_RULES and LOGIC_HEURISTICS is off")
    if not rules and not ctx.candidate_keys and ctx.probes == 0:
        return trust.mark(res, trust.SKIPPED, "no LOGIC_RULES, no money/quantity field and no bounded or single-use field in any write body")
    if ctx.errors + out["errors"] and ctx.probes == 0:
        return trust.mark(res, trust.ERRORED, "every logic check crashed before a probe was sent")
    if ctx.probes == 0:
        if out["setup_failed"] and not out["ran"]:
            return trust.mark(res, trust.SETUP_FAILED, f"{out['setup_failed']} rule setup(s) failed: probes never ran")
        return trust.mark(res, trust.DEGRADED, "no write request was sent: nothing was checked")
    reasons = []
    if rules and heuristics_on and not ctx.candidate_keys:
        reasons.append("heuristics found no candidate money/quantity field; only LOGIC_RULES ran")
    if budget_hit:
        reasons.append("write budget spent")
    if out["setup_failed"]:
        reasons.append(f"{out['setup_failed']} rule setup(s) failed")
    if out["errors"] + ctx.errors:
        reasons.append(f"{out['errors'] + ctx.errors} check(s) crashed")
    if ctx.unchecked:
        reasons.append(f"{len(ctx.unchecked)} check(s) had no read-back")
    if reasons:
        return trust.mark(res, trust.DEGRADED, "; ".join(reasons))
    return trust.mark(res, trust.RAN_OK, "declared rules and heuristic probes ran with read-back")
