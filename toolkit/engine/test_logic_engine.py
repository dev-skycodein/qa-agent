"""Tests for logic_engine.py against our own stdlib shop server (ephemeral ports, loopback only).

  python toolkit/engine/test_logic_engine.py        (also collectable by pytest)

The shop has one FIXED behaviour and one buggy behaviour per variant. Every buggy variant must produce its expected finding
(with declared rules, with heuristics only, or both); the FIXED variant must produce ZERO findings with everything switched on.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import logic_engine  # noqa: E402
import trust  # noqa: E402
from api import Api  # noqa: E402

INT, NUM, STR = {"type": "integer"}, {"type": "number"}, {"type": "string"}


def _body(props, required):
    return {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": props, "required": required}}}},
            "responses": {"200": {"description": "ok"}, "201": {"description": "ok"}}}


def _param(name):
    return [{"name": name, "in": "path", "required": True, "schema": INT}]


OK = {"responses": {"200": {"description": "ok"}}}
DOC = {"openapi": "3.0.0", "info": {"title": "shop", "version": "1"}, "paths": {
    "/items": {"post": _body({"name": STR, "price": INT, "stock": INT}, ["name", "price", "stock"])},
    "/items/{item_id}": {"get": {"parameters": _param("item_id"), **OK}},
    "/orders": {"post": _body({"item_id": INT, "quantity": INT, "discount": INT, "price": NUM, "total": NUM}, ["item_id", "quantity"])},
    "/orders/{order_id}": {"get": {"parameters": _param("order_id"), **OK}},
    "/orders/{order_id}/refund": {"post": {"parameters": _param("order_id"), **_body({"amount": NUM}, [])}},
    "/orders/{order_id}/cancel": {"post": {"parameters": _param("order_id"), **OK}},
    "/orders/{order_id}/reopen": {"post": {"parameters": _param("order_id"), **OK}},
    "/coupons": {"post": _body({"code": STR, "max_uses": INT}, ["code", "max_uses"])},
    "/coupons/{coupon_id}": {"get": {"parameters": _param("coupon_id"), **OK}},
    "/coupons/{coupon_id}/redeem": {"post": {"parameters": _param("coupon_id"), **OK}},
}}

BUGGY = {
    "neg_qty": "accepts quantity <= 0 and raises stock",
    "no_stock_check": "accepts quantity above stock",
    "client_price": "trusts the client price",
    "no_overflow": "stores an item price wrapped to int32",
    "discount_unbounded": "accepts discounts above 100",
    "total_mismatch": "total = sum of lines + 3",
    "refund_twice": "every refund call refunds the whole total again",
    "replace_cancelled": "reopen works on a cancelled order",
    "coupon_reuse": "coupon redeem ignores max_uses",
}


def _isint(x):
    return isinstance(x, int) and not isinstance(x, bool)


class Shop:
    def __init__(self, variant):
        self.v = variant
        self.lock = threading.Lock()
        self.items, self.orders, self.coupons = {}, {}, {}
        self.n = 0

    def nid(self):
        self.n += 1
        return self.n

    def handle(self, method, path, body):
        parts = [p for p in path.split("?")[0].split("/") if p]
        if method == "POST" and parts == ["items"]:
            return self.create_item(body)
        if method == "POST" and parts == ["orders"]:
            return self.create_order(body)
        if method == "POST" and parts == ["coupons"]:
            return self.create_coupon(body)
        if method == "GET" and len(parts) == 2 and parts[0] in ("items", "orders", "coupons"):
            table = {"items": self.items, "orders": self.orders, "coupons": self.coupons}[parts[0]]
            obj = table.get(int(parts[1])) if parts[1].isdigit() else None
            return (200, dict(obj)) if obj else (404, {"error": "not found"})
        if method == "POST" and len(parts) == 3 and parts[0] == "orders" and parts[1].isdigit():
            return self.order_action(int(parts[1]), parts[2])
        if method == "POST" and len(parts) == 3 and parts[0] == "coupons" and parts[2] == "redeem" and parts[1].isdigit():
            return self.redeem(int(parts[1]))
        return 404, {"error": "no route"}

    def create_item(self, body):
        name, price, stock = body.get("name"), body.get("price"), body.get("stock")
        if not isinstance(name, str) or not _isint(price) or price < 0 or not _isint(stock) or stock < 0:
            return 422, {"error": "invalid item"}
        if self.v == "no_overflow":
            price = ((price + 2 ** 31) % 2 ** 32) - 2 ** 31
        item = {"id": self.nid(), "name": name, "price": price, "stock": stock}
        self.items[item["id"]] = item
        return 201, dict(item)

    def create_order(self, body):
        iid, qty = body.get("item_id"), body.get("quantity")
        item = self.items.get(iid) if _isint(iid) else None
        if item is None or not _isint(qty):
            return 422, {"error": "invalid order"}
        d = body.get("discount", 0)
        if not _isint(d) or (self.v != "discount_unbounded" and not 0 <= d <= 100):
            return 422, {"error": "invalid discount"}
        if self.v == "neg_qty":
            if qty > item["stock"]:
                return 422, {"error": "insufficient stock"}
        elif self.v == "no_stock_check":
            if qty < 1:
                return 422, {"error": "quantity must be positive"}
        elif qty < 1 or qty > item["stock"]:
            return 422, {"error": "insufficient stock"}
        base = body["price"] if self.v == "client_price" and is_num(body.get("price")) else item["price"]
        unit = base if d == 0 else round(base * (100 - d) / 100, 2)
        total = unit * qty + (3 if self.v == "total_mismatch" else 0)
        item["stock"] -= qty
        oid = self.nid()
        order = {"id": oid, "item_id": iid, "quantity": qty, "price": unit, "discount": d, "total": total, "status": "placed",
                 "refunded": 0, "lines": [{"item_id": iid, "qty": qty, "price": unit}]}
        self.orders[oid] = order
        return 201, dict(order)

    def order_action(self, oid, action):
        o = self.orders.get(oid)
        if o is None:
            return 404, {"error": "not found"}
        if action == "refund":
            if self.v == "refund_twice":
                o["refunded"] += o["total"]
                o["status"] = "refunded"
                return 200, dict(o)
            if o["status"] != "placed":
                return 409, {"error": "not refundable"}
            o["refunded"], o["status"] = o["total"], "refunded"
            return 200, dict(o)
        if action == "cancel":
            if o["status"] != "placed":
                return 409, {"error": "not cancellable"}
            o["status"] = "cancelled"
            return 200, dict(o)
        if action == "reopen":
            if self.v == "replace_cancelled" and o["status"] == "cancelled":
                o["status"] = "placed"
                return 200, dict(o)
            return 409, {"error": "cannot reopen"}
        return 404, {"error": "no route"}

    def create_coupon(self, body):
        code, mx = body.get("code"), body.get("max_uses")
        if not isinstance(code, str) or not _isint(mx) or mx < 1:
            return 422, {"error": "invalid coupon"}
        c = {"id": self.nid(), "code": code, "max_uses": mx, "uses": 0}
        self.coupons[c["id"]] = c
        return 201, dict(c)

    def redeem(self, cid):
        c = self.coupons.get(cid)
        if c is None:
            return 404, {"error": "not found"}
        if self.v != "coupon_reuse" and c["uses"] >= c["max_uses"]:
            return 409, {"error": "already used"}
        c["uses"] += 1
        return 200, dict(c)


def is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def serve(variant):
    shop = Shop(variant)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                body = None
            if body is None:
                code, obj = 400, {"error": "bad json"}
            else:
                with shop.lock:
                    code, obj = shop.handle(method, self.path, body)
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


ITEM = {"name": "c", "price": 10, "stock": 10}
RULES = [
    {"name": "stock conservation on order", "kind": "conservation",
     "setup": [{"call": "POST /items", "body": ITEM, "save": "item"}],
     "act": {"call": "POST /orders", "body": {"item_id": "{item}", "quantity": -3}},
     "read": "/items/{item}", "field": "stock", "delta_field": "quantity", "direction": "decrease"},
    {"name": "stock never negative", "kind": "non_negative",
     "setup": [{"call": "POST /items", "body": {"name": "n", "price": 10, "stock": 1}, "save": "item"}],
     "acts": [{"call": "POST /orders", "body": {"item_id": "{item}", "quantity": 5}}],
     "read": "/items/{item}", "field": "stock", "min": 0},
    {"name": "order total equals its lines", "kind": "sum_of_parts",
     "setup": [{"call": "POST /items", "body": {"name": "s", "price": 10, "stock": 1000}, "save": "item"},
               {"call": "POST /orders", "body": {"item_id": "{item}", "quantity": 3}, "save": "order"}],
     "read": "/orders/{order}", "total_field": "total", "lines_field": "lines", "price_field": "price", "qty_field": "qty"},
    {"name": "refund cannot exceed the order total", "kind": "bounded_by",
     "setup": [{"call": "POST /items", "body": {"name": "r", "price": 10, "stock": 1000}, "save": "item"},
               {"call": "POST /orders", "body": {"item_id": "{item}", "quantity": 1}, "save": "order"}],
     "acts": [{"call": "POST /orders/{order}/refund", "body": {"amount": 1}}], "repeat": 2,
     "read": "/orders/{order}", "field": "refunded", "bound_field": "total"},
    {"name": "cancelled order stays cancelled", "kind": "monotone_state",
     "setup": [{"call": "POST /items", "body": {"name": "m", "price": 10, "stock": 1000}, "save": "item"},
               {"call": "POST /orders", "body": {"item_id": "{item}", "quantity": 1}, "save": "order"}],
     "acts": [{"call": "POST /orders/{order}/cancel"}, {"call": "POST /orders/{order}/reopen"}],
     "read": "/orders/{order}", "field": "status", "terminal": ["cancelled"]},
    {"name": "coupon is single use", "kind": "unique_use",
     "setup": [{"call": "POST /coupons", "body": {"code": "c1", "max_uses": 1}, "save": "coupon"}],
     "acts": [{"call": "POST /coupons/{coupon}/redeem"}], "repeat": 2,
     "read": "/coupons/{coupon}", "field": "uses", "max_field": "max_uses"},
]

EXPECT_DECLARED = {"neg_qty": "LOGIC-SUM-MISMATCH", "no_stock_check": "LOGIC-NEGATIVE-VALUE", "total_mismatch": "LOGIC-SUM-MISMATCH",
                   "refund_twice": "LOGIC-BOUND-VIOLATION", "replace_cancelled": "LOGIC-STATE-REGRESSION",
                   "coupon_reuse": "LOGIC-DOUBLE-APPLY"}
EXPECT_HEURISTIC = {"neg_qty": "LOGIC-NEGATIVE-VALUE", "no_stock_check": "LOGIC-BOUND-VIOLATION", "client_price": "LOGIC-PRICE-TAMPER",
                    "no_overflow": "LOGIC-OVERFLOW", "discount_unbounded": "LOGIC-BOUND-VIOLATION", "total_mismatch": "LOGIC-SUM-MISMATCH",
                    "refund_twice": "LOGIC-DOUBLE-APPLY", "replace_cancelled": "LOGIC-STATE-REGRESSION"}


def run_variant(variant, rules, heuristics):
    srv, base = serve(variant)
    try:
        api = Api(base)
        qa = SimpleNamespace(LOGIC_RULES=rules, LOGIC_HEURISTICS=heuristics, LOGIC_MAX_PROBES=1500)
        res = logic_engine.run(api, DOC, qa)
        for f in res["findings"]:
            assert f.get("sequence"), f"finding without read-back evidence: {f['kind']}"
        return res
    finally:
        srv.shutdown()
        srv.server_close()


def kinds(res):
    return {f["kind"] for f in res["findings"]}


def test_declared_rules_detect_each_bug():
    for variant, expected in EXPECT_DECLARED.items():
        res = run_variant(variant, RULES, heuristics=False)
        assert expected in kinds(res), f"{variant}: expected {expected}, got {sorted(kinds(res))} {res['notes']}"
        assert all(f["severity"] == "high" for f in res["findings"]), f"{variant}: declared rules must be high"


def test_heuristics_detect_each_bug():
    for variant, expected in EXPECT_HEURISTIC.items():
        res = run_variant(variant, [], heuristics=True)
        assert expected in kinds(res), f"{variant}: expected {expected}, got {sorted(kinds(res))} {res['notes']}"
        assert all(f["severity"] == "medium" and f["detail"].startswith("verify:") for f in res["findings"]), \
            f"{variant}: heuristic findings must be medium and say verify"


def test_fixed_shop_has_zero_findings():
    res = run_variant("fixed", RULES, heuristics=True)
    assert res["findings"] == [], f"fixed shop must be clean, got {[(f['kind'], f['endpoint'], f['detail']) for f in res['findings']]}"
    assert res["probes"] > 0, "probes counter must be real"
    assert trust.resolve(res)[0] != trust.ERRORED, res.get("notes")


def test_probes_are_real_and_status_honest():
    res = run_variant("fixed", RULES, heuristics=True)
    assert res["probes"] > 20, res["probes"]
    assert trust.resolve(res)[0] in (trust.RAN_OK, trust.DEGRADED), trust.resolve(res)


def test_no_spec_no_money_is_skipped():
    doc = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/notes": {"post": _body({"text": STR}, ["text"])}}}
    srv, base = serve("fixed")
    try:
        res = logic_engine.run(Api(base), doc, SimpleNamespace())
    finally:
        srv.shutdown()
        srv.server_close()
    assert trust.resolve(res)[0] == trust.SKIPPED, trust.resolve(res)
    assert res["probes"] == 0 and res["findings"] == []


def test_rules_without_candidate_fields_are_degraded():
    doc = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/notes": {"post": _body({"text": STR}, ["text"])}}}
    srv, base = serve("fixed")
    try:
        rule = {"name": "x", "kind": "bounded_by", "setup": [{"call": "POST /notes", "body": {"text": "x"}}],
                "read": "/notes", "field": "a", "bound_value": 1}
        res = logic_engine.run(Api(base), doc, SimpleNamespace(LOGIC_RULES=[rule]))
    finally:
        srv.shutdown()
        srv.server_close()
    status, reason = trust.resolve(res)
    assert status == trust.DEGRADED and "no candidate" in reason, (status, reason)


def test_unknown_rule_kind_is_reported_not_silent():
    res = run_variant("fixed", [{"name": "bad", "kind": "magic", "read": "/items/{x}"}], heuristics=False)
    assert res["findings"] == [] and any("unknown kind" in n for n in res["notes"]), res["notes"]
    assert trust.resolve(res)[0] != trust.RAN_OK


# ---------------------------------------------------------------- LAYER C: a marketplace with account state (GET /me)
# One buggy variant per new capability; "fixed" is the clean control (ZERO findings expected).

MARKET_ROLES = {"user_a": {"Authorization": "Bearer tok-a"}, "user_b": {"Authorization": "Bearer tok-b"},
                "admin": {"Authorization": "Bearer tok-admin"}}
ADMIN_FIRST_ROLES = {"admin": MARKET_ROLES["admin"], "user_a": MARKET_ROLES["user_a"], "user_b": MARKET_ROLES["user_b"]}


def _rb(props, required=()):
    return {"requestBody": {"required": True, "content": {"application/json": {
        "schema": {"type": "object", "properties": props, "required": list(required)}}}},
        "responses": {"200": {"description": "ok"}, "201": {"description": "ok"}}}


_NUM_POS = {"type": "number", "minimum": 0, "exclusiveMinimum": True}
MARKET_DOC = {"openapi": "3.0.3", "info": {"title": "market", "version": "1"}, "paths": {
    "/me": {"get": {"responses": {"200": {"description": "me"}}}},
    "/wallet/topup": {"post": _rb({"amount": _NUM_POS}, ["amount"])},
    "/transfers": {"post": _rb({"to_user_id": INT, "amount": _NUM_POS}, ["to_user_id", "amount"])},
    "/products": {"post": _rb({"name": STR, "price": {"type": "number", "minimum": 0},
                               "stock": {"type": "integer", "minimum": 0}}, ["name", "price", "stock"])},
    "/products/{product_id}": {"get": {"parameters": _param("product_id"), **OK}},
    "/orders": {"post": _rb({"product_id": INT, "quantity": {"type": "integer", "minimum": 1}, "coupon": STR,
                             "price_override": {"type": "number", "minimum": 0}}, ["product_id", "quantity"])},
    "/orders/{order_id}": {"get": {"parameters": _param("order_id"), **OK}},
    "/orders/{order_id}/refund": {"post": {"parameters": _param("order_id"), "requestBody": {"content": {"application/json": {
        "schema": {"type": "object", "properties": {"amount": {"type": "number", "minimum": 0}}}}}}, **OK}},
    "/orders/{order_id}/cancel": {"post": {"parameters": _param("order_id"), **OK}},
    "/coupons": {"post": _rb({"code": STR, "percent": {"type": "integer", "minimum": 1, "maximum": 100},
                              "single_use": {"type": "boolean"}}, ["code", "percent"])},
}}


class Market:
    """Marketplace with one bug switch per new capability. Variants: fixed (clean) or one of the bug names below."""

    def __init__(self, variant):
        self.v = variant
        self.lock = threading.Lock()
        self.users = {1: {"id": 1, "role": "user", "balance": 100}, 2: {"id": 2, "role": "user", "balance": 100},
                      3: {"id": 3, "role": "admin", "balance": 0}}
        self.tokens = {"tok-a": 1, "tok-b": 2, "tok-admin": 3}
        self.products, self.orders, self.coupons = {}, {}, {}
        self.n = 100

    def nid(self):
        self.n += 1
        return self.n

    def who(self, headers):
        tok = (headers.get("Authorization") or "").replace("Bearer ", "", 1).strip()
        uid = self.tokens.get(tok)
        return self.users[uid] if uid else None

    def pub(self, u):
        return {"id": u["id"], "role": u["role"], "balance": u["balance"]}

    def handle(self, method, path, body, headers):
        parts = [p for p in path.split("?")[0].split("/") if p]
        if method == "GET" and len(parts) == 2 and parts[0] == "products":
            p = self.products.get(int(parts[1])) if parts[1].isdigit() else None
            return (200, dict(p)) if p else (404, {"error": "not found"})
        u = self.who(headers)
        if u is None:
            return 401, {"error": "unauthenticated"}
        if method == "GET" and parts == ["me"]:
            return 200, self.pub(u)
        if method == "POST" and parts == ["wallet", "topup"]:
            amount = body.get("amount")
            if not is_num(amount) or amount <= 0:
                return 400, {"error": "amount"}
            u["balance"] += amount
            return 200, self.pub(u)
        if method == "POST" and parts == ["transfers"]:
            return self.transfer(u, body)
        if method == "POST" and parts == ["products"]:
            if u["role"] != "admin":
                return 403, {"error": "admin only"}
            name, price, stock = body.get("name"), body.get("price"), body.get("stock")
            if not isinstance(name, str) or not is_num(price) or price < 0 or not isinstance(stock, int) or stock < 0:
                return 400, {"error": "product"}
            pid = self.nid()
            self.products[pid] = {"id": pid, "name": name, "price": price, "stock": stock}
            return 201, dict(self.products[pid])
        if method == "POST" and parts == ["orders"]:
            return self.create_order(u, body)
        if method == "GET" and len(parts) == 2 and parts[0] == "orders":
            o = self.orders.get(int(parts[1])) if parts[1].isdigit() else None
            if o is None or (o["buyer_id"] != u["id"] and u["role"] != "admin"):
                return 404, {"error": "not found"}
            return 200, dict(o)
        if method == "POST" and len(parts) == 3 and parts[0] == "orders" and parts[1].isdigit():
            return self.order_action(u, int(parts[1]), parts[2], body)
        if method == "POST" and parts == ["coupons"]:
            return self.create_coupon(u, body)
        return 404, {"error": "no route"}

    def transfer(self, u, body):
        to, amt = body.get("to_user_id"), body.get("amount")
        if not isinstance(to, int) or isinstance(to, bool):
            return 400, {"error": "to_user_id"}
        if not is_num(amt):
            return 400, {"error": "amount"}
        if amt <= 0 and not (self.v == "negative_transfer" and amt < 0):
            return 400, {"error": "amount must be positive"}
        if to not in self.users:
            return 404, {"error": "recipient"}
        if to == u["id"] and self.v != "self_transfer":
            return 400, {"error": "cannot transfer to yourself"}
        if u["role"] != "admin" and u["balance"] < amt:
            return 402, {"error": "insufficient balance"}
        dst = self.users[to]
        if self.v == "self_transfer":
            before = dst["balance"]
            u["balance"] -= amt
            dst["balance"] = before + amt
        elif self.v == "transfer_loss":
            u["balance"] -= amt + 1
            dst["balance"] += amt
        else:
            u["balance"] -= amt
            dst["balance"] += amt
        return 200, {"from_user_id": u["id"], "to_user_id": to, "amount": amt, "balance": u["balance"]}

    def create_order(self, u, body):
        pid, qty = body.get("product_id"), body.get("quantity")
        if not isinstance(pid, int) or not isinstance(qty, int) or isinstance(qty, bool):
            return 400, {"error": "order"}
        if qty < 1 and self.v != "schema_bound":
            return 400, {"error": "quantity must be >= 1"}
        product = self.products.get(pid)
        if product is None:
            return 404, {"error": "product"}
        if self.v == "sellout":
            short = product["stock"] > 0 and qty > product["stock"]
        else:
            short = qty > product["stock"]
        if short:
            return 409, {"error": "insufficient stock"}
        unit = product["price"]
        ov = body.get("price_override")
        if ov is not None:
            if u["role"] != "admin" and self.v != "override_open":
                return 403, {"error": "price_override is admin only"}
            if not is_num(ov) or ov < 0:
                return 400, {"error": "price_override"}
            unit = ov
        coupon, code = None, body.get("coupon")
        if code is not None:
            coupon = self.coupons.get(code) if isinstance(code, str) else None
            if coupon is None:
                return 400, {"error": "unknown coupon"}
            if coupon["single_use"]:
                taken = (u["id"] in coupon["used_by"]) if self.v == "shared_coupon" else coupon["used"]
                if taken:
                    return 409, {"error": "coupon already redeemed"}
        base = unit * qty
        if self.v == "bulk_round" and qty >= 10:
            base = int(unit) * qty
        if self.v == "wrap32" and isinstance(base, int):
            base = ((base + 2 ** 31) % 2 ** 32) - 2 ** 31
        if coupon is not None:
            total = round(base * (100 - coupon["percent"]) / 100, 2)
        else:
            total = round(base, 2) if isinstance(base, float) else base
        if self.v == "hidden_total" and is_num(body.get("total")):
            total = body["total"]
        debit = total - 1 if self.v == "buy_undercharge" else total
        if u["role"] != "admin" and self.v != "user_credit_line" and u["balance"] < debit:
            return 402, {"error": "insufficient balance"}
        u["balance"] -= debit
        product["stock"] -= qty
        if coupon is not None:
            coupon["used"] = True
            coupon["used_by"].append(u["id"])
        oid = self.nid()
        self.orders[oid] = {"id": oid, "product_id": pid, "buyer_id": u["id"], "quantity": qty, "unit_price": unit,
                            "coupon": code, "total": total, "status": "placed", "refunded": 0}
        return 201, dict(self.orders[oid])

    def order_action(self, u, oid, action, body):
        o = self.orders.get(oid)
        if o is None or (o["buyer_id"] != u["id"] and u["role"] != "admin"):
            return 404, {"error": "not found"}
        if action == "cancel":
            if o["status"] != "placed":
                return 409, {"error": "only placed orders can be cancelled"}
            o["status"] = "cancelled"
            self.products[o["product_id"]]["stock"] += o["quantity"]
            return 200, dict(o)
        if action == "refund":
            remaining = o["total"] - o["refunded"]
            amount = body.get("amount", remaining)
            if not is_num(amount) or amount < 0:
                return 400, {"error": "amount"}
            if amount == 0:
                return 200, dict(o)
            cap = o["total"] if self.v == "refund_repeat" else remaining
            if amount > cap:
                return 409, {"error": "refund exceeds refundable amount"}
            self.users[o["buyer_id"]]["balance"] += amount
            o["refunded"] += amount
            if o["refunded"] >= o["total"]:
                o["status"] = "refunded"
            elif self.v == "cancel_revive":
                o["status"] = "placed"
            return 200, dict(o)
        return 404, {"error": "no route"}

    def create_coupon(self, u, body):
        if u["role"] != "admin":
            return 403, {"error": "admin only"}
        code, pct, single = body.get("code"), body.get("percent"), body.get("single_use", False)
        if not isinstance(code, str) or not isinstance(pct, int) or isinstance(pct, bool) or not isinstance(single, bool):
            return 400, {"error": "coupon"}
        if (pct < 1) if self.v == "schema_bound" else not (1 <= pct <= 100):
            return 400, {"error": "percent must be between 1 and 100"}
        if code in self.coupons:
            return 409, {"error": "exists"}
        self.coupons[code] = {"code": code, "percent": pct, "single_use": single, "used": False, "used_by": []}
        return 201, {"code": code, "percent": pct, "single_use": single}


MARKET_VARIANTS = ("fixed", "hidden_total", "override_open", "wrap32", "bulk_round", "sellout", "self_transfer",
                   "transfer_loss", "negative_transfer", "buy_undercharge", "shared_coupon", "schema_bound", "refund_repeat",
                   "cancel_revive", "user_credit_line")


def serve_market(variant):
    market = Market(variant)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                body = None
            if not isinstance(body, dict):
                code, obj = 400, {"error": "bad json"}
            else:
                with market.lock:
                    code, obj = market.handle(method, self.path, body, self.headers)
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def run_market(variant, roles=None):
    srv, base = serve_market(variant)
    try:
        api = Api(base, roles=roles or MARKET_ROLES)
        res = logic_engine.run(api, MARKET_DOC, SimpleNamespace(LOGIC_MAX_PROBES=1500))
        for f in res["findings"]:
            assert f.get("sequence"), f"finding without read-back evidence: {f['kind']}"
        return res
    finally:
        srv.shutdown()
        srv.server_close()


MARKET_EXPECT = {
    "hidden_total": ("LOGIC-PRICE-TAMPER", "POST /orders"),          # a total the spec does not declare, trusted from the client
    "override_open": ("LOGIC-PRICE-TAMPER", "POST /orders"),         # an admin-only override that a normal role may use
    "wrap32": ("LOGIC-SUM-MISMATCH", "POST /orders"),                # total wraps past 2**31
    "bulk_round": ("LOGIC-SUM-MISMATCH", "POST /orders"),            # decimal price truncated at quantity >= 10
    "sellout": ("LOGIC-BOUND-VIOLATION", "POST /orders"),            # stock sold out, then one more accepted
    "self_transfer": ("LOGIC-CONSERVATION", "POST /transfers"),      # money created by a transfer to self
    "transfer_loss": ("LOGIC-CONSERVATION", "POST /transfers"),      # sender debited amount + 1
    "negative_transfer": ("LOGIC-NEGATIVE-VALUE", "POST /transfers"),  # a negative amount credits the sender
    "buy_undercharge": ("LOGIC-CONSERVATION", "POST /orders"),       # buyer debited less than the order total
    "shared_coupon": ("LOGIC-DOUBLE-APPLY", "POST /orders"),         # a single-use coupon redeemed by two users
    "schema_bound": ("LOGIC-BOUND-VIOLATION", "POST /coupons"),      # percent 101 accepted, schema says max 100
    "refund_repeat": ("LOGIC-DOUBLE-APPLY", "POST /orders/{order_id}/refund"),  # refund cap uses the total again
    "cancel_revive": ("LOGIC-STATE-REGRESSION", "POST /orders/{order_id}/refund"),  # a partial refund revives a cancel
    "user_credit_line": ("LOGIC-NEGATIVE-VALUE", "POST /orders"),    # a NON-privileged buyer goes below zero
}


def _market_findings(res, kind, endpoint):
    return [f for f in res["findings"] if f["kind"] == kind and f["endpoint"] == endpoint]


def test_market_each_new_capability_detects_its_bug():
    for variant, (kind, endpoint) in MARKET_EXPECT.items():
        res = run_market(variant)
        assert _market_findings(res, kind, endpoint), \
            f"{variant}: expected {kind} on {endpoint}, got {[(f['kind'], f['endpoint'], f['detail'][:70]) for f in res['findings']]}"
        assert all(f["severity"] == "medium" and f["detail"].startswith("verify:") for f in res["findings"]), variant


def test_market_fixed_has_zero_findings():
    res = run_market("fixed")
    assert res["findings"] == [], [(f["kind"], f["endpoint"], f["detail"][:90]) for f in res["findings"]]
    assert res["probes"] > 40, res["probes"]
    assert trust.resolve(res)[0] in (trust.RAN_OK, trust.DEGRADED), trust.resolve(res)


def test_market_fixed_zero_findings_with_admin_first_roles():
    res = run_market("fixed", roles=ADMIN_FIRST_ROLES)
    assert res["findings"] == [], [(f["kind"], f["endpoint"], f["detail"][:90]) for f in res["findings"]]


def test_decoy_admin_credit_line_is_not_a_bug():
    # the credit line is documented: an admin account may go below zero. With only an admin to probe as, the engine must
    # not claim the negative balance (it is the privileged account's documented state, not a normal user's).
    res = run_market("user_credit_line", roles={"admin": MARKET_ROLES["admin"]})
    assert not [f for f in res["findings"] if f["kind"] == "LOGIC-NEGATIVE-VALUE"], \
        [(f["kind"], f["detail"][:90]) for f in res["findings"]]
    # the same shop probed with a normal user present DOES go negative for that user: that one is a real finding
    res2 = run_market("user_credit_line", roles=ADMIN_FIRST_ROLES)
    assert _market_findings(res2, "LOGIC-NEGATIVE-VALUE", "POST /orders"), [(f["kind"], f["detail"][:90]) for f in res2["findings"]]


def test_decoy_admin_only_override_without_normal_role_is_not_tampering():
    # override_open lets any role set the price; with only an admin present we cannot show a normal user may do it: no claim
    res = run_market("override_open", roles={"admin": MARKET_ROLES["admin"]})
    assert not [f for f in res["findings"] if f["kind"] == "LOGIC-PRICE-TAMPER"], [(f["kind"], f["detail"][:90]) for f in res["findings"]]


def test_decoy_admin_only_override_is_gated_not_tampering():
    res = run_market("fixed")
    assert not [f for f in res["findings"] if f["kind"] == "LOGIC-PRICE-TAMPER"], res["findings"]
    assert any("price_override" in g for g in res["gated"]), res["gated"]
    assert any("role-gated" in n for n in res["notes"]), res["notes"]


def test_missing_account_endpoint_is_reported_not_silent():
    # a shop without GET /me: balance-based checks cannot run; the engine must say so (degraded, named), not claim clean
    doc = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/wallet/topup": {"post": _body({"amount": NUM}, ["amount"])}}}
    srv, base = serve_market("fixed")
    try:
        res = logic_engine.run(Api(base, roles=MARKET_ROLES), doc, SimpleNamespace())
    finally:
        srv.shutdown()
        srv.server_close()
    assert any("no account endpoint" in n for n in res["notes"]), res["notes"]
    assert trust.resolve(res)[0] == trust.DEGRADED, trust.resolve(res)


def main():
    tests =[v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {t.__name__}: {exc}")
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
