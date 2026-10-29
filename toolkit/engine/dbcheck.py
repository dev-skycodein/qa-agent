"""DB invariants: after the engines have hammered the app, ask the DATABASE whether the data is still sane.

API-level invariants only see what the API chooses to show; garbage that was *stored* (blank titles, negative stock, orphan rows,
status outside the state machine, duplicate "unique" business keys) shows up here.

qa-spec.py:
  DB = {"driver": "postgres" | "sqlite" | "mongo", "url_env": "DATABASE_URL"}      # url from the environment safe_run exports
  DB_CHECKS = [
      {"name": "blank ticket titles", "sql": "SELECT id FROM \"Ticket\" WHERE btrim(title) = ''"},      # rows returned = violations
      {"name": "negative stock", "collection": "products", "filter": {"stock": {"$lt": 0}}},           # mongo: matching docs = violations
  ]
Drivers: postgres needs `--with pg8000`, mongo needs `--with pymongo`, sqlite is stdlib. A missing driver is a note, not a failure.
"""
import os
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlparse
import trust


def _rows_postgres(url, sql):
    import pg8000.native as pg
    u = urlparse(url)
    conn = pg.Connection(unquote(u.username or "postgres"), host=u.hostname or "127.0.0.1", port=u.port or 5432,
                         database=(u.path or "/").lstrip("/"), password=unquote(u.password or ""))
    try:
        return conn.run(sql)
    finally:
        conn.close()


def _rows_sqlite(url, sql):
    """Read-only, and never creates a file: a missing database is an error, not an empty new database in the cwd."""
    path = url.replace("sqlite:///", "").replace("sqlite://", "")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"sqlite file not found: {path}")
    conn = sqlite3.connect(f"{Path(path).resolve().as_uri()}?mode=ro", uri=True)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


LOCAL_DB_HOSTS = ("127.0.0.1", "localhost", "::1")


def db_hosts(url: str) -> list:
    """Every host in a database URL. A mongodb:// URL may list several (host1:27017,host2:27017): all of them are returned.
    An empty list means no network host (for example a unix socket path)."""
    netloc = urlparse(url).netloc.rsplit("@", 1)[-1]
    hosts = []
    for part in (p for p in netloc.split(",") if p):
        if part.startswith("["):                                      # [::1]:27017
            hosts.append(part[1:part.find("]")] if "]" in part else part)
        elif part.count(":") == 1:                                    # host:port
            hosts.append(part.rsplit(":", 1)[0])
        else:
            hosts.append(part)
    return hosts


def run(qa) -> dict:
    cfg = getattr(qa, "DB", None)
    checks = getattr(qa, "DB_CHECKS", [])
    if not cfg or not checks:
        return trust.mark({"engine": "dbcheck", "findings": [], "notes": ["no DB / DB_CHECKS in qa-spec.py (write one per stored-data invariant)"]},
                          trust.SKIPPED, "no DB / DB_CHECKS in qa-spec.py")
    env_name = cfg.get("url_env", "DATABASE_URL")
    url = os.environ.get(env_name, "")
    if not url:
        # no silent default host: an unset URL used to reach the postgres driver's 127.0.0.1:5432 default
        return trust.mark({"engine": "dbcheck", "findings": [], "notes": [f"{env_name} is not set: no database URL, no check ran"]},
                          trust.ERRORED, f"{env_name} not set: no check ran")
    parsed = urlparse(url)
    if parsed.scheme.startswith("sqlite"):
        if parsed.netloc not in ("", "localhost"):                    # sqlite is a local file: a network host is never right
            return trust.mark({"engine": "dbcheck", "findings": [], "notes": [f"refusing sqlite url with host {parsed.netloc}"]},
                              trust.ERRORED, "refused sqlite URL with a network host: no check ran")
    else:
        bad = [h for h in db_hosts(url) if h not in LOCAL_DB_HOSTS]
        if bad:
            return trust.mark({"engine": "dbcheck", "findings": [], "notes": [f"refusing non-local database url host(s) {bad}"]},
                              trust.ERRORED, f"refused non-local database host {bad[0]}: no check ran")
    findings, notes = [], []
    failed = 0
    for chk in checks:
        try:
            if cfg["driver"] == "mongo":
                from pymongo import MongoClient
                client = MongoClient(url, serverSelectionTimeoutMS=4000)
                db = client[(parsed.path or "/").lstrip("/").split("?")[0] or cfg.get("database", "test")]
                rows = list(db[chk["collection"]].find(chk["filter"]).limit(5))
            elif cfg["driver"] == "postgres":
                rows = _rows_postgres(url, chk["sql"])
            elif cfg["driver"] == "sqlite":
                rows = _rows_sqlite(url, chk["sql"])
            else:
                notes.append(f"unknown driver {cfg['driver']}")
                failed = len(checks)
                break
        except ImportError as exc:
            notes.append(f"{chk['name']}: driver missing ({exc}); add --with pg8000 / pymongo")
            failed += 1
            continue
        except Exception as exc:
            notes.append(f"{chk['name']}: check failed to run ({type(exc).__name__}: {str(exc)[:160]})")
            failed += 1
            continue
        if rows:
            findings.append({"kind": "DB-INVARIANT", "severity": chk.get("severity", "high"), "endpoint": chk["name"],
                             "detail": f"{len(rows)}+ stored row(s) violate it, e.g. {str(rows[0])[:200]}"})
    res = {"engine": "dbcheck", "findings": findings, "notes": notes}
    if failed >= len(checks):
        return trust.mark(res, trust.ERRORED, f"all {len(checks)} DB check(s) failed to run")
    if failed:
        return trust.mark(res, trust.DEGRADED, f"{failed} of {len(checks)} DB check(s) failed to run")
    return trust.mark(res, trust.RAN_OK)
