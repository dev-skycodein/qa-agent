"""qa-spec.py — the ONLY project-specific input of the generic engines (authz / stateful / race).
Copy to <project>/qa-report/qa-spec.py and fill in. Start with the three required parts; add the rest when a
finding or a note in engines.md asks for it. Everything runs against a LOCAL app started by safe_run.py.

  python engine/safe_run.py --profile qa-report/profile.json -- \
      python -m uv run --no-project --python 3.12 --with hypothesis --with pymongo \
      python engine/run.py --spec qa-report/qa-spec.py --out qa-report
"""

# ---------- 1. REQUIRED: who are the actors? ----------
def setup(api):
    """Called once. Create/log in users and return {"user_a": headers, "user_b": headers, "admin": headers}.
    api.call(role, method, path, body) -> Resp(.status .json .text .ok). 'anon' needs no headers."""
    roles = {}
    for role, email in {"user_a": "qa-a@qa.dev", "user_b": "qa-b@qa.dev", "admin": "qa-admin@qa.dev"}.items():
        api.call("anon", "POST", "/auth/register", {"email": email, "password": "Passw0rd!"})   # 409 if it exists: fine
        token = api.call("anon", "POST", "/auth/login", {"email": email, "password": "Passw0rd!"}).json["access_token"]
        roles[role] = {"Authorization": f"Bearer {token}"}
    # promote the admin directly in the LOCAL qa database if the app has no admin signup
    return roles


# ---------- 2. REQUIRED: what must never break? (from qa-report/invariants.md) ----------
def fresh_state(api):
    """Called before every random sequence / race: seed data. ids pre-fills the id pools (key = collection path)."""
    return {"ids": {}}             # e.g. {"product": pid, "initial": 10, "ids": {"/products": [pid]}}


def no_negative_balance(api, log, ctx):
    """Invariant: raise AssertionError with a clear message when broken. `log` = every request so far
    [{role, method, path, status, request, response}]; query current state with api.call(...)."""
    # assert api.call("admin", "GET", "/me").json["balance"] >= 0, "negative balance"


INVARIANTS = [no_negative_balance]

# ---------- 3. REQUIRED for authz: which endpoints are intentionally open / admin-only? ----------
PUBLIC = {"POST /auth/register", "POST /auth/login", "GET /health"}      # "METHOD /openapi/path/{param}"
ADMIN_ONLY = set()                                                       # "/admin..." paths are added automatically

# ---------- optional knobs ----------
OWNER = {}            # {"POST /orders": "user_a"}  role that creates the resource other roles then attack (default user_a)
BODIES = {}           # {"POST /orders": {...}}     ONE valid body per endpoint for authz probes (stateful ignores these and generates random bodies)
BODY_HOOKS = {}       # {"POST /orders": lambda body, ctx: {**body, "item_id": ctx["item"]}}  patch generated bodies with real ids
IDS = {}              # {"user_id": "<id of a throwaway user>"}  for admin-only endpoints that take a path param
SKIP = set()          # endpoints no engine may touch (email/payment/LLM, logout, destructive)
STATEFUL_SKIP = set() # endpoints the random sequences should not use (no effect on your invariants)
ADMIN_ROLE = "admin"  # role name used to call ADMIN_ONLY endpoints during random sequences
OWNED_IDS = {}       # {"/rest/basket": {"user_a": 3}}  ids that come from login/seed data, not a POST creator: authz attacks them as other roles
NEG_SKIP = set()      # endpoints only the negative engine must not touch (SKIP applies to all engines)
SINK_CHECKS = []      # [fn(entry) -> None | "message"] rules over what the app sent out (sink.jsonl entries)
OPENAPI = None        # path/URL of the OpenAPI file when it is not at <base>/openapi.json

# Races: one entry per contended resource (stock, balance, unique constraint, idempotency, single-use token)
RACES = [
    # {"name": "oversell last unit", "n": 15,
    #  "setup": lambda api, ctx: {"method": "POST", "path": "/orders", "role": "user_a", "body": {...},
    #                             "per_request_headers": lambda i: {"Idempotency-Key": str(i)}},
    #  "check": lambda api, results, ctx: None},     # return a message string when the invariant broke
]
