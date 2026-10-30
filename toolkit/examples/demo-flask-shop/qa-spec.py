"""qa-spec for the demo Flask shop: the only project-specific file the engines need."""
import json

PUBLIC = {"GET /items", "GET /items/{item_id}", "POST /auth/register", "POST /auth/login"}
ADMIN_ONLY = {"POST /items"}            # "/admin/..." paths are added automatically
OWNER = {"POST /items": "admin"}
SKIP = {"POST /auth/logout"}            # would end the roles' own sessions; the auth engine still attacks it through LOGOUT
LOGOUT = {"path": "/auth/logout", "method": "POST"}
STATEFUL_SKIP = {"POST /auth/register", "POST /auth/login", "POST /admin/reset-prices", "POST /items"}   # no effect on the stock rules
BODIES = {}                             # filled by setup() once a real item exists
USERS = {"user_a": "a@demo.test", "user_b": "b@demo.test", "admin": "admin@demo.test"}


def _login(api, email):
    api.call("anon", "POST", "/auth/register", {"email": email, "password": "pw123456"})   # 409 if it exists: fine
    token = api.call("anon", "POST", "/auth/login", {"email": email, "password": "pw123456"}).json["token"]
    return {"Authorization": f"Bearer {token}"}


def setup(api):
    roles = {role: _login(api, email) for role, email in USERS.items()}
    api.roles.update(roles)
    item = api.call("admin", "POST", "/items", {"name": "authz-sample", "price": 5, "stock": 1000}).json
    BODIES["POST /orders"] = {"item_id": item["id"], "quantity": 1}
    BODIES["POST /auth/login"] = {"email": USERS["user_a"], "password": "pw123456"}      # a login that succeeds: the negative engine needs a valid baseline
    return roles


def fresh_state(api):
    item = api.call("admin", "POST", "/items", {"name": "tee", "price": 10, "stock": 10}).json
    return {"item": item["id"], "initial": 10, "ids": {"/items": [item["id"]]}}


BODY_HOOKS = {"POST /orders": lambda body, ctx: {**body, "item_id": ctx["item"]}}


def _stock(api, ctx):
    return api.call("anon", "GET", f"/items/{ctx['item']}").json["stock"]


def stock_conserved(api, log, ctx):
    """stock == initial - quantity of every order that is not cancelled."""
    orders = {}
    for e in log:
        data = json.loads(e["response"]) if e["response"].startswith("{") else {}
        if e["method"] == "POST" and e["path"] == "/orders" and e["status"] == 201 and data.get("item_id") == ctx["item"]:
            orders[data["id"]] = {"qty": data["quantity"], "status": "placed"}
        if e["method"] == "PATCH" and e["status"] == 200 and e["path"].endswith("/status"):
            oid = int(e["path"].split("/")[2])
            if oid in orders:
                orders[oid]["status"] = data["status"]
    expected = ctx["initial"] - sum(o["qty"] for o in orders.values() if o["status"] != "cancelled")
    actual = _stock(api, ctx)
    assert actual == expected, f"stock {actual} != expected {expected} (initial {ctx['initial']}, orders {orders})"


INVARIANTS = [stock_conserved]


def _oversell_setup(api, ctx):
    item = api.call("admin", "POST", "/items", {"name": "last-one", "price": 10, "stock": 1}).json
    ctx["last"] = item["id"]
    return {"method": "POST", "path": "/orders", "role": "user_a", "body": {"item_id": item["id"], "quantity": 1}}


def _oversell_check(api, results, ctx):
    created = sum(1 for code, _ in results if code == 201)
    stock = api.call("anon", "GET", f"/items/{ctx['last']}").json["stock"]
    if created > 1 or stock < 0:
        return f"{created} orders created for 1 unit in stock (stock now {stock})"


def _double_cancel_setup(api, ctx):
    item = api.call("admin", "POST", "/items", {"name": "cancel-me", "price": 10, "stock": 5}).json
    ctx["cancelled_item"] = item["id"]
    order = api.call("user_a", "POST", "/orders", {"item_id": item["id"], "quantity": 1}).json
    return {"method": "PATCH", "path": f"/orders/{order['id']}/status", "role": "user_a", "body": {"status": "cancelled"}}


def _double_cancel_check(api, results, ctx):
    stock = api.call("anon", "GET", f"/items/{ctx['cancelled_item']}").json["stock"]
    if stock != 5:
        return f"double cancel: stock is {stock} after concurrent cancels of one order, expected 5"


RACES = [{"name": "oversell last unit", "setup": _oversell_setup, "n": 10, "check": _oversell_check},
         {"name": "double cancel", "setup": _double_cancel_setup, "n": 8, "check": _double_cancel_check}]


# ---- scenario: legal order status transitions (product rule: placed -> cancelled only; nothing leaves "cancelled")
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "engine"))
from scenarios_lib import state_machine


def _reach(api, ctx, state):
    r = api.call("user_a", "POST", "/orders", {"item_id": ctx["item"], "quantity": 1})
    if not r.ok:
        return None
    oid = r.json["id"]
    if state != "placed":
        api.call("admin", "PATCH", f"/orders/{oid}/status", {"status": state})
    return oid


SCENARIOS = [state_machine(
    "order status machine", states=["placed", "cancelled", "shipped"], allowed={("placed", "cancelled"), ("placed", "shipped")},
    reach=_reach, get_state=lambda api, oid: api.call("admin", "GET", f"/orders/{oid}").json["status"],
    transition=lambda api, role, oid, to: api.call(role, "PATCH", f"/orders/{oid}/status", {"status": to}), role="admin")]
