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
    path = url.replace("sqlite:///", "").replace("sqlite://", "")
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchall()
    finally:
        conn.close()


def run(qa) -> dict:
    cfg = getattr(qa, "DB", None)
    checks = getattr(qa, "DB_CHECKS", [])
    if not cfg or not checks:
        return trust.mark({"engine": "dbcheck", "findings": [], "notes": ["no DB / DB_CHECKS in qa-spec.py (write one per stored-data invariant)"]},
                          trust.SKIPPED, "no DB / DB_CHECKS in qa-spec.py")
    url = os.environ.get(cfg.get("url_env", "DATABASE_URL"), "")
    parsed = urlparse(url)
    if parsed.hostname not in (None, "", "127.0.0.1", "localhost", "::1") and not url.startswith("sqlite"):
        return trust.mark({"engine": "dbcheck", "findings": [], "notes": [f"refusing non-local database url host {parsed.hostname}"]},
                          trust.ERRORED, f"refused non-local database host {parsed.hostname}: no check ran")
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
