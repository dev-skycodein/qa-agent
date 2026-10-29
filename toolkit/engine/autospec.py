"""Auto-spec: derive openapi.json + a qa-spec.py skeleton from SOURCE CODE, for apps that have no OpenAPI endpoint.

  python autospec.py <project-dir> --out qa-report [--base-path ""]

Supported (regex based, no build needed; always review the output):
  Next.js App Router   app/**/route.(ts|js)  exports GET/POST/PUT/PATCH/DELETE; [id] -> {id}; route groups stripped
  Next.js Pages API    pages/api/**           default handler with req.method branches
  Express / Koa-style  app|router.(get|post|put|patch|delete)('/path', ...)   (:id -> {id}); mount prefixes via --base-path
  Flask                @app.route / @app.get / @bp.post ('/path/<int:id>')
FastAPI / NestJS-swagger / Spring-doc already expose OpenAPI: use the app's own.

What is inferred per operation
  path params   from the path
  query params  searchParams.get("x") / req.query.x / request.args.get("x")
  body fields   `const { a, b } = await req.json()`, `body.x`, `req.body.x`, `request.get_json()["x"]`
  required      names negated in an early-return validation (`if (!a || !b) return ... 400`)
  types         Prisma model field of the same name (String / Int / Float / Boolean / DateTime / enum values), `as Enum` casts,
                else string
  auth          getServerSession / getToken / auth() / jwt.verify / login_required ... => needs a session
  admin only    `role !== "ADMIN"` style checks => ADMIN_ONLY; handlers without any auth call => PUBLIC (to review)
Outputs: <out>/openapi.json, <out>/qa-spec.generated.py (copy to qa-spec.py, fill setup() credentials and INVARIANTS),
<out>/autospec.md (what was inferred and what to check by hand).
"""
import argparse
import json
import re
from pathlib import Path

SKIP_DIRS = {"node_modules", ".next", ".git", "venv", ".venv", "__pycache__", "dist", "build", "qa-report", ".claude", "coverage",
             "codefixes", "test", "tests", "__tests__", "spec", "e2e", "cypress", "frontend", "docs", "examples", "fixtures", "mocks", "stories"}
AUTH_RX = re.compile(r"\b\w*(?:isAuthorized|authorize|requireAuth|ensureAuth|isLoggedIn|checkAuth|protect|authGuard)\w*\(|getServerSession|getToken\(|\bauth\(\)|currentUser|requireAuth|verifyToken|jwt\.verify|getSession|login_required|"
                     r"\bwithAuth\(|getCurrentUser\(|requireUser\(|requireSession\(|"
                     r"@jwt_required|Depends\(get_current|isAuthenticated|passport\.authenticate|authMiddleware|verifyJWT", re.I)
ADMIN_RX = re.compile(r"role\s*!==?\s*[\"'](ADMIN|admin|Admin|superuser|SUPERUSER)[\"']|!\s*is_admin|isAdmin\s*===?\s*false|"
                      r"@admin_required|requireAdmin|is_staff|role\s*(?:!=|not in)\s*[\"']admin[\"']")
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def walk(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            yield p


def prisma_models(root: Path):
    models, enums = {}, {}
    for p in walk(root):
        if p.suffix != ".prisma":
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^enum\s+(\w+)\s*\{([^}]*)\}", t, re.M):
            enums[m.group(1)] = [v.strip() for v in m.group(2).split("\n") if v.strip() and not v.strip().startswith("//")]
        for m in re.finditer(r"^model\s+(\w+)\s*\{([^}]*)\}", t, re.M):
            for line in m.group(2).splitlines():
                f = re.match(r"\s*(\w+)\s+(\w+)(\?|\[\])?", line)
                if f and not line.strip().startswith(("@@", "//")):
                    models.setdefault(f.group(1), f.group(2))
    return models, enums


def schema_for(name, models, enums, cast_enums):
    t = cast_enums.get(name) or models.get(name)
    if t in enums:
        return {"type": "string", "enum": enums[t]}
    return {"String": {"type": "string", "minLength": 1}, "Int": {"type": "integer"}, "Float": {"type": "number"}, "Decimal": {"type": "number"},
            "Boolean": {"type": "boolean"}, "DateTime": {"type": "string", "format": "date-time"}, "Json": {}}.get(t, {"type": "string", "minLength": 1})


def body_fields(code: str):
    """(fields in order, required set, enum casts {field: EnumName})."""
    fields, req, casts = [], set(), {}
    for m in re.finditer(r"const\s*\{([^}]*)\}\s*=\s*await\s+\w+\.json\(\)|const\s*\{([^}]*)\}\s*=\s*(?:req|request)\.body", code):
        for part in (m.group(1) or m.group(2)).split(","):
            part = part.strip().split("=")[0].strip()
            if part:
                key, _, alias = part.partition(":")
                fields.append((key.strip(), (alias or key).strip()))
    for m in re.finditer(r"(?:const|let)\s+(\w+)\s*=\s*await\s+\w+\.json\(\)", code):
        var = m.group(1)
        for d in re.finditer(rf"const\s*\{{([^}}]*)\}}\s*=\s*{var}\b", code):                 # const { a, b: c } = body
            for part in d.group(1).split(","):
                part = part.strip().split("=")[0].strip()
                if part:
                    key, _, alias = part.partition(":")
                    fields.append((key.strip(), (alias or key).strip()))
        # method calls on the body (body.get(...), body.json()) are not fields
        for f in re.finditer(rf"\b{var}\??\.(?!(?:get|set|has|keys|values|items|json|text|length|map|filter|trim|toString)\b)(\w+)|\b{var}\[[\"'](\w+)[\"']\]", code):
            fields.append((f.group(1) or f.group(2),) * 2)
    for f in re.finditer(r"(?:req|request)\.body\??\.(\w+)", code):
        fields.append((f.group(1),) * 2)
    for f in re.finditer(r"""\b(?:b|data|payload|body|j)\s*(?:\.get\(["'](\w+)["']|\[["'](\w+)["']\])""", code):   # \b: not "job.get"
        fields.append((f.group(1) or f.group(2),) * 2)
    seen, ordered = set(), []
    for key, alias in fields:
        if key not in seen:
            seen.add(key)
            ordered.append((key, alias))
    for cond in re.finditer(r"if\s*\((.{1,200}?)\)\s*(?:\{\s*)?return[^;\n]*(?:400|422)", code, re.S):
        for name in re.findall(r"!\s*([\w]+)", cond.group(1)):
            req.add(name)
    for key, alias in ordered:
        for m in re.finditer(rf"\b(?:{key}|{alias})\s+as\s+(\w+)", code):
            casts[key] = m.group(1)
    names = {k for k, _ in ordered}
    aliases = {a: k for k, a in ordered}
    return [k for k, _ in ordered], {aliases.get(n, n) for n in req} & names, casts


def query_params(code: str):
    out = re.findall(r"searchParams\.get\(\s*[\"'](\w+)[\"']", code)
    out += re.findall(r"req\.query\.(\w+)|request\.args\.get\(\s*[\"'](\w+)[\"']", code) and \
        [a or b for a, b in re.findall(r"req\.query\.(\w+)|request\.args\.get\(\s*[\"'](\w+)[\"']", code)]
    return list(dict.fromkeys(out))


def build_op(code, models, enums, summary):
    fields, required, casts = body_fields(code)
    q = query_params(code)
    op = {"summary": summary, "responses": {"200": {"description": "ok"}}}
    if fields:
        props = {f: schema_for(f, models, enums, casts) for f in fields}
        op["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"type": "object", "properties": props,
                                                                                            "required": [f for f in fields if f in required]}}}}
    if q:
        op["parameters"] = [{"name": n, "in": "query", "schema": ({"type": "string"} if n not in models else schema_for(n, models, enums, casts))} for n in q]
    return op, bool(AUTH_RX.search(code)), bool(ADMIN_RX.search(code))


def split_handlers(code):
    """{METHOD: text} for Next app-router exports."""
    marks = [(m.start(), m.group(1)) for m in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b", code)]
    marks = [(i, a if a else b) for (i, a), b in zip(marks, [m.group(2) for m in re.finditer(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b", code)])]
    out = {}
    for n, (i, name) in enumerate(marks):
        out[name] = code[i:(marks[n + 1][0] if n + 1 < len(marks) else len(code))]
    return out


def next_path(rp: str):
    p = re.sub(r"^(src/)?app/", "", rp)
    p = re.sub(r"/route\.(ts|js|mjs)$", "", p)
    segs = [s for s in p.split("/") if s and not (s.startswith("(") and s.endswith(")"))]
    segs = [("{" + re.sub(r"[\[\].]", "", s) + "}") if s.startswith("[") else s for s in segs]
    return "/" + "/".join(segs)


ROUTE_RX = re.compile(r"(^|/)(src/)?(app/.*route\.(ts|js|mjs)|pages/api/.*\.(ts|js))$")
_NOT_ROUTES = {"node_modules", ".git", "qa-report"}


def skipped_routes(root: Path) -> list:
    """Route files that walk() drops only because a folder name is in SKIP_DIRS (app/api/docs/route.ts, app/api/test/...)."""
    out = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        rp = str(p.relative_to(root)).replace("\\", "/")
        if parts & _NOT_ROUTES or not ROUTE_RX.search(rp):
            continue
        if parts & SKIP_DIRS:
            out.append(rp)
    return sorted(out)


def discover(root: Path, base_path: str):
    models, enums = prisma_models(root)
    ops, notes = [], []
    skipped = skipped_routes(root)
    if skipped:
        notes.append(f"{len(skipped)} route file(s) NOT read because a folder name is in SKIP_DIRS (docs/build/test/...): "
                     + ", ".join(skipped[:10]) + (" ..." if len(skipped) > 10 else ""))
    for p in walk(root):
        rp = str(p.relative_to(root)).replace("\\", "/")
        t = p.read_text(encoding="utf-8", errors="replace") if p.suffix in (".ts", ".js", ".mjs", ".py", ".tsx") else ""
        if not t:
            continue
        if re.search(r"(^|/)(src/)?app/.*route\.(ts|js|mjs)$", rp):
            path = next_path(rp)
            if "nextauth" in path.lower() or "{...nextauth}" in path.lower():
                notes.append(f"{path}: NextAuth handler skipped (login is done in setup())")
                continue
            if re.search(r"export\s+const\s*\{[^}]*\b(GET|POST|PUT|PATCH|DELETE)\b[^}]*\}\s*=", t):
                notes.append(f"{rp}: destructured handler export (export const {{ GET, POST }} = ...) is not parsed: no operations inferred")
            for method, code in split_handlers(t).items():
                op, auth, admin = build_op(code, models, enums, f"{rp} {method}")
                ops.append({"method": method, "path": base_path + path, "op": op, "auth": auth, "admin": admin, "file": rp})
        elif re.search(r"(^|/)pages/api/.*\.(ts|js)$", rp):
            path = "/" + re.sub(r"/index$", "", re.sub(r"^(src/)?pages/", "", re.sub(r"\.(ts|js)$", "", rp)))   # only a trailing /index
            path = re.sub(r"\[\.?\.?\.?(\w+)\]", r"{\1}", path)
            used = [m for m in METHODS if re.search(rf"method\s*===?\s*[\"']{m}[\"']", t)] or ["GET"]
            for method in used:
                op, auth, admin = build_op(t, models, enums, f"{rp} {method}")
                ops.append({"method": method, "path": base_path + path, "op": op, "auth": auth, "admin": admin, "file": rp})
        elif p.suffix in (".js", ".ts") and re.search(r"\b(app|router|api)\.(get|post|put|patch|delete)\(", t):
            for m in re.finditer(r"\b(?:app|router|api)\.(get|post|put|patch|delete)\(\s*[\"'`]([^\"'`]+)[\"'`]([\s\S]{0,1200}?)(?=\n\s*(?:app|router|api)\.(?:get|post|put|patch|delete)\(|\Z)", t):
                path = base_path + re.sub(r":(\w+)", r"{\1}", m.group(2))
                op, auth, admin = build_op(m.group(3), models, enums, f"{rp} {m.group(1).upper()}")
                ops.append({"method": m.group(1).upper(), "path": path, "op": op, "auth": auth or bool(AUTH_RX.search(m.group(0))), "admin": admin, "file": rp})
        elif p.suffix == ".py" and re.search(r"@\w+\.(route|get|post|put|patch|delete)\(", t) and "flask" in t.lower():
            for m in re.finditer(r"@\w+\.(route|get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"'](?:[^)]*methods\s*=\s*\[([^\]]*)\])?[^)]*\)\s*\n((?:@.*\n)*)def\s+\w+\([^)]*\):([\s\S]{0,1500}?)(?=\n@|\ndef |\Z)", t):
                kind, path, methods, decos, body = m.groups()
                path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", path)
                for method in ([x.strip(" \"'").upper() for x in methods.split(",")] if methods else [kind.upper()] if kind != "route" else ["GET"]):
                    op, auth, admin = build_op(body, models, enums, f"{rp} {method}")
                    ops.append({"method": method, "path": base_path + path, "op": op, "auth": auth or bool(AUTH_RX.search(decos)), "admin": admin, "file": rp})
    for o in ops:                                                # path params
        names = re.findall(r"\{(\w+)\}", o["path"])
        if names:
            o["op"].setdefault("parameters", []).extend({"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in names)
    return ops, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--out", default="qa-report")
    ap.add_argument("--base-path", default="")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    ops, notes = discover(root, a.base_path)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    merged = {}
    for o in ops:                                   # same method+path declared twice: union of fields, auth/admin if any declaration has it
        k = (o["method"], o["path"])
        if k not in merged:
            merged[k] = o
            continue
        m = merged[k]
        m["auth"], m["admin"] = m["auth"] or o["auth"], m["admin"] or o["admin"]
        mb = m["op"].setdefault("requestBody", o["op"].get("requestBody") or {"content": {"application/json": {"schema": {"type": "object", "properties": {}, "required": []}}}}) if o["op"].get("requestBody") else None
        if mb and o["op"].get("requestBody"):
            mp = mb["content"]["application/json"]["schema"]["properties"]
            mp.update({n: v for n, v in o["op"]["requestBody"]["content"]["application/json"]["schema"]["properties"].items() if n not in mp})
        mq = {p["name"] for p in m["op"].get("parameters", [])}
        m["op"].setdefault("parameters", []).extend(p for p in o["op"].get("parameters", []) if p["name"] not in mq)
    ops = list(merged.values())
    paths = {}
    for o in sorted(ops, key=lambda o: (o["path"], o["method"])):
        paths.setdefault(o["path"], {})[o["method"].lower()] = o["op"]
    (out / "openapi.json").write_text(json.dumps({"openapi": "3.0.3", "info": {"title": f"{root.name} (autospec)", "version": "1"}, "paths": paths}, indent=1), encoding="utf-8")
    key = lambda o: f"{o['method']} {o['path']}"
    admin_only = sorted(key(o) for o in ops if o["admin"])
    public = sorted(key(o) for o in ops if not o["auth"] and not o["admin"])
    nextauth = any("nextauth" in str(p).lower() for p in walk(root) if p.suffix in (".ts", ".js") and "node_modules" not in str(p))
    spec = ['"""qa-spec GENERATED by autospec.py: review every TODO, then copy to qa-spec.py."""',
            "import http.cookiejar, json, urllib.error, urllib.parse, urllib.request", "",
            f"OPENAPI = {json.dumps(str((out / 'openapi.json').resolve()).replace(chr(92), '/'))}",
            f"PUBLIC = {json.dumps(sorted(public))}   # TODO review: no session/token check found in these handlers",
            f"ADMIN_ONLY = {json.dumps(admin_only)}   # inferred from role checks",
            "PUBLIC, ADMIN_ONLY = set(PUBLIC), set(ADMIN_ONLY)",
            "SKIP = set()", "BODIES = {}      # TODO valid sample bodies where the generated example is not accepted", "OWNER = {}", "",
            "# TODO credentials from the seed script / docs. role names must include user_a, user_b, admin",
            'USERS = {"user_a": ("user1@example.com", "password1"), "user_b": ("user2@example.com", "password2"), "admin": ("admin@example.com", "admin-password")}', ""]
    if nextauth:
        spec += ['''
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _login(base, email, password):          # NextAuth credentials provider
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar), _NoRedirect())
    csrf = json.loads(op.open(base + "/api/auth/csrf", timeout=120).read())["csrfToken"]
    data = urllib.parse.urlencode({"csrfToken": csrf, "email": email, "password": password, "json": "true"}).encode()
    try:
        op.open(urllib.request.Request(base + "/api/auth/callback/credentials", data=data), timeout=120)
    except urllib.error.HTTPError:
        pass
    sess = json.loads(op.open(base + "/api/auth/session", timeout=60).read())
    assert sess.get("user"), f"login failed for {email}"
    return {"Cookie": "; ".join(f"{c.name}={c.value}" for c in jar)}


def setup(api):
    roles = {role: _login(api.base, e, p) for role, (e, p) in USERS.items()}
    api.roles.update(roles)
    return roles
''']
    else:
        spec += ['''
def setup(api):          # TODO: log in / register and return {"user_a": headers, "user_b": headers, "admin": headers}
    raise NotImplementedError("fill setup() for this app's login flow")
''']
    spec += ['''
def fresh_state(api):    # TODO create the seed objects invariants need, return {"ids": {"/collection": [id]}, ...}
    return {}


INVARIANTS = []          # TODO from qa-report/invariants.md
RACES = []               # TODO one per counter / balance / unique business key
''']
    (out / "qa-spec.generated.py").write_text("\n".join(spec), encoding="utf-8")
    md = ["# autospec", "", f"{len(ops)} operation(s) from {len({o['file'] for o in ops})} file(s).", "",
          "| operation | auth | admin | body fields | query | file |", "|---|---|---|---|---|---|"]
    for o in sorted(ops, key=lambda o: (o["path"], o["method"])):
        body = list(((o["op"].get("requestBody") or {}).get("content", {}).get("application/json", {}).get("schema", {}).get("properties", {})))
        qs = [p["name"] for p in o["op"].get("parameters", []) if p["in"] == "query"]
        md.append(f"| `{key(o)}` | {'yes' if o['auth'] else 'NO'} | {'yes' if o['admin'] else ''} | {', '.join(body)} | {', '.join(qs)} | {o['file']} |")
    md += ["", *[f"- note: {n}" for n in notes], "- note: bodies/types are inferred from code and the ORM schema: check required fields and enums before trusting 'accepted invalid' findings",
           "- note: auth 'NO' means no auth call was found IN THAT HANDLER FILE. Middleware, unlisted wrappers and framework config are not read: verify every PUBLIC entry before trusting it"]
    (out / "autospec.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
