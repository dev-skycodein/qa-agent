"""Detect a project's stack and write qa-report/profile.json for safe_run.py.

  python detect.py <project_root> [--out qa-report/profile.json] [--port 8765]

Reads manifests and env file NAMES (values only to find remote hosts, never printed). Anything it cannot
determine is written as "unknown" and listed in `unknown` - Claude/user must fill it, nothing is guessed.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

SKIP_DIRS = {"node_modules", "venv", ".venv", "env", ".git", ".next", "dist", "build", "__pycache__", "qa-report", ".claude"}
ENV_FILES = (".env", ".env.example", ".env.sample", ".env.local", ".env.development")
VENDOR = re.compile(r"(RESEND|STRIPE|SENDGRID|MAILGUN|TWILIO|OPENAI|ANTHROPIC|GROQ|GEMINI|SENTRY|PAYPAL|RAZORPAY|AWS_|GOOGLE_|"
                    r"FIREBASE|CLOUDINARY|SLACK|DISCORD|TELEGRAM|SMTP|MAIL|_API_KEY|API_KEY$|_DSN|DSN$|BLOB|VERCEL)", re.I)
APP_SECRET = re.compile(r"(JWT|SESSION|COOKIE|NEXTAUTH|APP)_?.*(SECRET|KEY)$|^SECRET_KEY$", re.I)
DB_URL = re.compile(r"(DATABASE|DB|MONGO|MONGODB|POSTGRES|MYSQL|SQL).*(URL|URI)$|^(MONGO|DB)_?URL$", re.I)
DB_NAME = re.compile(r"^(DB_NAME|DATABASE_NAME|MONGO_DB|MONGODB_DB|POSTGRES_DB|MYSQL_DATABASE)$", re.I)
LOCAL = ("localhost", "127.0.0.1", "::1")


def walk(root: Path, patterns):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if path.is_file() and any(path.match(p) for p in patterns):
            yield path


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def nearest_manifest_dir(file: Path, root: Path) -> Path:
    for parent in [file.parent, *file.parents]:
        if any((parent / m).exists() for m in ("requirements.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod", "manage.py")):
            return parent
        if parent == root:
            break
    return file.parent


def env_info(root: Path):
    names, remote = {}, set()
    for env_dir in {root, *[p.parent for p in walk(root, ENV_FILES)]}:
        for name in ENV_FILES:
            f = env_dir / name
            if not f.is_file():
                continue
            for line in read(f).splitlines():
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
                if not m:
                    continue
                var, value = m.group(1), m.group(2).strip().strip("'\"")
                names[var] = name
                if name != ".env.example":
                    host = urlparse(value).hostname if "://" in value else (value if re.search(r"(HOST|SERVER|ENDPOINT)$", var, re.I) else None)
                    if host and host not in LOCAL:
                        remote.add(var)
    return names, remote


def detect_db(deps: str) -> str:
    d = deps.lower()
    for label, needles in (("mongo", ("pymongo", "motor", "mongoose", "mongodb")), ("postgres", ("psycopg", "asyncpg", "\"pg\"", "postgres")),
                           ("mysql", ("mysql", "mariadb")), ("sqlite", ("sqlite", "better-sqlite3", "aiosqlite")), ("redis", ("redis",))):
        if any(n in d for n in needles):
            return label
    return "unknown"


def _uv_prefix(reqs: Path) -> list[str]:
    """argv prefix that runs the app inside uv with the app's own requirements file (empty when there is none)."""
    return ["python", "-m", "uv", "run", "--no-project", "--python", "3.12", "--with-requirements", reqs.name] if reqs.exists() else []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("--out", default=None)
    p.add_argument("--port", type=int, default=8765)
    a = p.parse_args()
    root = Path(a.root).resolve()
    out = Path(a.out) if a.out else root / "qa-report" / "profile.json"
    profile = {"name": re.sub(r"[^a-z0-9]+", "_", root.name.lower()).strip("_"), "root": str(root), "language": "unknown",
               "framework": "unknown", "app_dir": str(root), "run_cmd": "unknown", "port": a.port, "health_path": "/",
               "openapi": "unknown", "db": "unknown", "env_overrides": {}, "blank_keys": [], "unsafe_vars": [],
               "notes": [], "unknown": []}   # no "trusted": a shell run_cmd is refused until the user sets trusted true (safe_run)

    # ---- stack ----
    py_files = [f for f in walk(root, ["*.py"]) if "test" not in f.name.lower()]
    found = False
    for f in py_files:
        text = read(f)
        m = re.search(r"^(\w+)\s*=\s*FastAPI\(", text, re.M)
        if m:
            app_dir = nearest_manifest_dir(f, root)
            module = ".".join(f.relative_to(app_dir).with_suffix("").parts)
            reqs = app_dir / "requirements.txt"
            argv = _uv_prefix(reqs) + ["python", "-m", "uvicorn", f"{module}:{m.group(1)}", "--host", "127.0.0.1", "--port", "{port}"]
            profile.update(language="python", framework="fastapi", app_dir=str(app_dir),
                           run_cmd=" ".join(argv), run_cmd_argv=argv,
                           openapi="/openapi.json", health_path="/openapi.json")
            profile["notes"].append("uvicorn/fastapi assumed installed via requirements; add --with uvicorn if not listed")
            found = True
            break
        m = re.search(r"^(\w+)\s*=\s*Flask\(", text, re.M)
        if m:
            app_dir = nearest_manifest_dir(f, root)
            reqs = app_dir / "requirements.txt"
            # argv list: the file name is one argument, never parsed by a shell (a name like "app&calc.py" stays a name)
            argv = _uv_prefix(reqs) + ["python", "-m", "flask", "--app", f.relative_to(app_dir).as_posix(), "run",
                                       "--host", "127.0.0.1", "--port", "{port}"]
            profile.update(language="python", framework="flask", app_dir=str(app_dir),
                           run_cmd=" ".join(argv), run_cmd_argv=argv)
            spec_file = next(walk(root, ["openapi*.json", "swagger*.json"]), None)
            profile["openapi"] = str(spec_file) if spec_file else "unknown"
            if not spec_file:
                profile["notes"].append("Flask has no built-in OpenAPI: add one (flask-smorest/apiflask) or write ENDPOINTS in qa-spec.py")
            found = True
            break
    if not found and (mp := (root / "manage.py" if (root / "manage.py").exists() else next(walk(root, ["manage.py"]), None))):
        profile.update(language="python", framework="django", app_dir=str(mp.parent),
                       run_cmd="python manage.py runserver 127.0.0.1:{port}",
                       run_cmd_argv=["python", "manage.py", "runserver", "127.0.0.1:{port}"], openapi="unknown")
        profile["notes"].append("Django: expose OpenAPI via drf-spectacular (/api/schema/) or write ENDPOINTS in qa-spec.py")
        found = True
    if not found:
        pkgs = [f for f in walk(root, ["package.json"])]
        for pj in pkgs:
            try:
                data = json.loads(read(pj))
            except ValueError:
                continue
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "express" in deps or "fastify" in deps or "koa" in deps or "next" in deps or "@nestjs/core" in deps:
                fw = next(x for x in ("next", "@nestjs/core", "fastify", "koa", "express") if x in deps)
                scripts = data.get("scripts", {})
                cmd = "npx next dev -p {port}" if fw == "next" else ("npm run start:dev" if "start:dev" in scripts else "npm start")
                profile.update(language="javascript", framework=fw.replace("@nestjs/core", "nestjs"), app_dir=str(pj.parent),
                               run_cmd=cmd, openapi="unknown")
                profile["notes"].append("Node: server must read PORT from env; OpenAPI via swagger-jsdoc/@nestjs/swagger or write ENDPOINTS")
                found = True
                break
    if not found and (pom := next(walk(root, ["pom.xml"]), None)):
        profile.update(language="java", framework="spring" if "spring" in read(pom) else "java", app_dir=str(pom.parent),
                       run_cmd="mvn spring-boot:run -Dspring-boot.run.arguments=--server.port={port}", openapi="/v3/api-docs")
        found = True
    if not found and (gm := next(walk(root, ["go.mod"]), None)):
        profile.update(language="go", framework="go", app_dir=str(gm.parent), run_cmd="go run .", openapi="unknown")
        found = True
    if not found:
        profile["unknown"] += ["language", "framework", "run_cmd"]

    # ---- DB ----
    deps_text = " ".join(read(f) for f in walk(root, ["requirements*.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod"]))
    sources = " ".join(read(f) for f in py_files[:300])          # stdlib sqlite3 has no manifest entry
    env_text = " ".join(read(f) for f in walk(root, list(ENV_FILES)))
    profile["db"] = detect_db(deps_text + (" sqlite3" if "import sqlite3" in sources else "") + (" sqlite" if "sqlite:" in env_text else "")
                              + "".join(f" {w}" for scheme, w in (("postgres", "postgres"), ("mysql:", "mysql"), ("mongodb", "mongodb"), ("redis:", "redis"))
                                        if scheme in env_text))
    if profile["db"] == "unknown":
        profile["unknown"].append("db")

    # ---- env ----
    names, remote = env_info(root)
    local_url = {"mongo": f"mongodb://localhost:27017", "postgres": f"postgresql://postgres:postgres@localhost:5432/qa_{profile['name']}",
                 "mysql": f"mysql://root:root@localhost:3306/qa_{profile['name']}", "sqlite": f"sqlite:///qa_{profile['name']}.db",
                 "redis": "redis://localhost:6379/15"}.get(profile["db"])
    for var in names:
        if DB_NAME.match(var):
            profile["env_overrides"][var] = f"qa_{profile['name']}"
        elif DB_URL.match(var) and local_url:
            profile["env_overrides"][var] = local_url if "REDIS" not in var.upper() else "redis://localhost:6379/15"
        elif APP_SECRET.search(var):
            profile["env_overrides"][var] = "qa-only-secret-not-for-production"
        elif VENDOR.search(var) and not re.search(r"(MODEL|REGION|HOST|PORT|ENABLED)$", var, re.I):
            profile["blank_keys"].append(var)
    covered = set(profile["env_overrides"]) | set(profile["blank_keys"])
    profile["unsafe_vars"] = sorted(v for v in remote if v not in covered)
    if profile["unsafe_vars"]:
        profile["notes"].append("env vars point to REMOTE hosts and are not overridden: " + ", ".join(profile["unsafe_vars"])
                                + " -> add them to env_overrides (local value) or blank_keys before safe_run will start the app")
    profile["notes"].append("rate limiting / captcha / email verification are not auto-disabled: add the env var to env_overrides if the app has one")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    print(json.dumps(profile, indent=2))
    if profile["unknown"]:
        print("UNKNOWN fields need a human/Claude:", profile["unknown"], file=sys.stderr)


if __name__ == "__main__":
    main()
