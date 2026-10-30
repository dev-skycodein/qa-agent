"""Demo shop (Flask + SQLite) with 5 PLANTED bugs, used to prove the QA engines are stack-agnostic.
NOT a real app. Bugs: (1) IDOR on GET /orders/<id>  (2) PATCH status has no auth  (3) /admin/reset-prices open to any
logged-in user  (4) cancelling twice restocks twice  (5) check-then-act stock race on POST /orders.
Round 2 (negative / outbound engines): (6) non-integer quantity -> unhandled 500  (7) /auth/register mass assignment: body "role"
is stored  (8) error handler returns the Python traceback  (9) POST /reviews accepts ANY order_id (cross-user reference)
(10) order confirmation email embeds the unescaped "note" as HTML  (11) /auth/login posts the plaintext password to an analytics URL  (12) /auth/login builds its SQL by string formatting (injection).
Round 3 (exposure / auth / race / logic engines): (13) GET /me returns the password  (14) /auth/logout leaves the token valid
(15) check-then-act status change: concurrent cancels restock several times  (16) POST /items and POST /orders ignore the schema's bounds.
Environment: DEMO_FIXED=1 fixes all of them (clean control), DEMO_BUGS=3,5 activates only those (mutation sweep)."""
import html
import json
import os
import secrets
import smtplib
import sqlite3
import time
import traceback
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path

from flask import Flask, g, jsonify, request, send_file
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
# Which planted bugs are active: default all; DEMO_FIXED=1 none (clean control for false-positive measurement); DEMO_BUGS=3,5 only those.
BUGS = frozenset() if os.environ.get("DEMO_FIXED") == "1" else (
    frozenset(int(x) for x in os.environ["DEMO_BUGS"].split(",") if x.strip()) if os.environ.get("DEMO_BUGS") else frozenset(range(1, 17)))


def bug(n: int) -> bool:
    return n in BUGS
DB = os.environ.get("DATABASE_URL", "sqlite:///demo.db").replace("sqlite:///", "")
assert not os.environ.get("STRIPE_API_KEY"), "demo must run with outbound keys blanked"
TOKENS: dict[str, dict] = {}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=30)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init():
    conn = sqlite3.connect(DB)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER);
        CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, item_id INTEGER, quantity INTEGER, status TEXT);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, user_id INTEGER, order_id INTEGER, text TEXT);
    """)
    conn.commit()
    conn.close()


@app.errorhandler(Exception)
def leak(exc):                                              # BUG 8: debug info (traceback, file paths) returned to the client
    if isinstance(exc, HTTPException):
        return jsonify(detail=exc.description), exc.code
    if not bug(6) and isinstance(exc, (KeyError, TypeError, ValueError, AttributeError, OverflowError)):      # fixed validation errors are 400s (bug 6 = they are 500s)
        return jsonify(detail="invalid request"), 400
    if not bug(8):
        return jsonify(detail="internal error"), 500
    return jsonify(detail=str(exc), trace=traceback.format_exc()), 500


def user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    return TOKENS.get(token)


def need_user():
    u = user()
    return u, (None if u else (jsonify(detail="login required"), 401))


def row(r):
    return dict(r) if r else None


@app.post("/auth/register")
def register():
    b = request.get_json()
    role = (b.get("role") if bug(7) else None) or ("admin" if b["email"].startswith("admin") else "user")      # BUG 7: client-supplied role is stored
    try:
        cur = db().execute("INSERT INTO users(email,password,role) VALUES(?,?,?)", (b["email"], b["password"], role))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(detail="exists"), 409
    return jsonify(id=cur.lastrowid, email=b["email"], role=role), 201


@app.post("/auth/login")
def login():
    b = request.get_json()
    if bug(12):                                              # BUG 12: SQL built by string formatting -> login bypass with  ' OR 1=1--
        r = db().execute(f"SELECT * FROM users WHERE email='{b['email']}' AND password='{b['password']}'").fetchone()
    else:
        r = db().execute("SELECT * FROM users WHERE email=? AND password=?", (b["email"], b["password"])).fetchone()
    if not r:
        return jsonify(detail="bad credentials"), 401
    token = secrets.token_hex(8)
    TOKENS[token] = {"id": r["id"], "role": r["role"]}
    if os.environ.get("ANALYTICS_URL"):                      # BUG 11: plaintext password sent to a third-party analytics endpoint
        try:
            req = urllib.request.Request(os.environ["ANALYTICS_URL"], data=json.dumps({"event": "login", "email": b["email"], **({"password": b["password"]} if bug(11) else {})}).encode(),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=3).read()
        except Exception:
            pass
    return jsonify(token=token)


@app.post("/auth/logout")
def logout():
    u, err = need_user()
    if err:
        return err
    if not bug(14):                                          # BUG 14: the token stays valid after logout
        TOKENS.pop(request.headers.get("Authorization", "").removeprefix("Bearer "), None)
    return jsonify(ok=True)


@app.get("/me")
def me():
    u, err = need_user()
    if err:
        return err
    r = db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    if bug(13):                                              # BUG 13: the password column goes out with the profile
        return jsonify(row(r))
    return jsonify(id=r["id"], email=r["email"], role=r["role"])


def number_in(value, low, high):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high


@app.post("/items")
def create_item():
    u, err = need_user()
    if err:
        return err
    if u["role"] != "admin":
        return jsonify(detail="admin only"), 403
    b = request.get_json()
    if not bug(16) and not (number_in(b["price"], 0.01, 1_000_000) and isinstance(b["stock"], int) and number_in(b["stock"], 0, 1000)):
        return jsonify(detail="price or stock out of range"), 400      # BUG 16: negative, fractional or huge values are stored
    cur = db().execute("INSERT INTO items(name,price,stock) VALUES(?,?,?)", (b["name"], b["price"], b["stock"]))
    db().commit()
    return jsonify(id=cur.lastrowid, **b), 201


@app.get("/items")
def list_items():
    return jsonify([dict(r) for r in db().execute("SELECT * FROM items")])


@app.get("/items/<int:item_id>")
def get_item(item_id):
    r = db().execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    return (jsonify(row(r)), 200) if r else (jsonify(detail="not found"), 404)


@app.post("/orders")
def create_order():
    u, err = need_user()
    if err:
        return err
    b = request.get_json()
    if not bug(6) and not (isinstance(b.get("quantity"), int) and not isinstance(b.get("quantity"), bool) and b["quantity"] > 0):
        return jsonify(detail="quantity must be a positive integer"), 400      # BUG 6: non-integer quantity -> unhandled 500
    if not bug(16) and isinstance(b.get("quantity"), int) and b["quantity"] > 20:
        return jsonify(detail="quantity above the limit of 20"), 400           # BUG 16: the schema's maximum is not enforced
    item = db().execute("SELECT * FROM items WHERE id=?", (b["item_id"],)).fetchone()
    if not item:
        return jsonify(detail="no such item"), 404
    if not bug(5):                                         # atomic check-and-decrement
        cur0 = db().execute("UPDATE items SET stock = stock - ? WHERE id=? AND stock >= ?", (b["quantity"], item["id"], b["quantity"]))
        if cur0.rowcount != 1:
            db().rollback()
            return jsonify(detail="not enough stock"), 409
    else:
        if item["stock"] < b["quantity"]:                  # BUG 5: check ...
            return jsonify(detail="not enough stock"), 409
        time.sleep(0.05)
        db().execute("UPDATE items SET stock = ? WHERE id=?", (item["stock"] - b["quantity"], item["id"]))   # ... then act, not atomic
    cur = db().execute("INSERT INTO orders(user_id,item_id,quantity,status) VALUES(?,?,?,'placed')", (u["id"], item["id"], b["quantity"]))
    db().commit()
    if os.environ.get("SMTP_HOST"):                          # BUG 10: user-supplied note embedded as raw HTML in the confirmation email
        try:
            msg = MIMEText(f"<h1>Order {cur.lastrowid} confirmed</h1><p>Note: {b.get('note', '') if bug(10) else html.escape(str(b.get('note', '')))}</p>", "html")
            msg["Subject"], msg["To"], msg["From"] = f"Order {cur.lastrowid}", "buyer@demo.test", "shop@demo.test"
            with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=3) as smtp:
                smtp.send_message(msg)
        except Exception:
            pass
    return jsonify(id=cur.lastrowid, item_id=item["id"], quantity=b["quantity"], status="placed", user_id=u["id"]), 201


@app.post("/reviews")
def create_review():
    u, err = need_user()
    if err:
        return err
    b = request.get_json()
    if not bug(9):
        mine = db().execute("SELECT id FROM orders WHERE id=? AND user_id=?", (b["order_id"], u["id"])).fetchone()
        if not mine:
            return jsonify(detail="not your order"), 403
    cur = db().execute("INSERT INTO reviews(user_id,order_id,text) VALUES(?,?,?)", (u["id"], b["order_id"], b["text"]))   # BUG 9: order_id not checked against the caller
    db().commit()
    return jsonify(id=cur.lastrowid, order_id=b["order_id"], text=b["text"]), 201


@app.get("/orders/<int:order_id>")
def get_order(order_id):
    u, err = need_user()
    if err:
        return err
    r = db().execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()   # BUG 1: no owner check
    if not bug(1) and r and r["user_id"] != u["id"] and u["role"] != "admin":
        r = None
    return (jsonify(row(r)), 200) if r else (jsonify(detail="not found"), 404)


@app.patch("/orders/<int:order_id>/status")
def set_status(order_id):                                  # BUG 2: no auth at all
    if not bug(2):
        u, err = need_user()
        if err:
            return err
    status = request.get_json()["status"]
    r = db().execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not r or (not bug(2) and r["user_id"] != u["id"] and u["role"] != "admin"):
        return jsonify(detail="not found"), 404
    if not bug(4) and (r["status"] != "placed" or status not in ("cancelled", "shipped")):      # state machine: only placed -> cancelled | shipped
        return jsonify(detail=f"illegal transition {r['status']} -> {status}"), 409
    if not bug(4) and not bug(15):                         # atomic: only one concurrent request can leave "placed"
        if db().execute("UPDATE orders SET status=? WHERE id=? AND status='placed'", (status, order_id)).rowcount != 1:
            db().rollback()
            return jsonify(detail=f"illegal transition -> {status}"), 409
    else:
        time.sleep(0.02)                                   # BUG 15: check above, act here, not atomic
        db().execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    if status == "cancelled":                              # BUG 4: no 'already cancelled' guard -> restock every time
        db().execute("UPDATE items SET stock = stock + ? WHERE id=?", (r["quantity"], r["item_id"]))
    db().commit()
    return jsonify(id=order_id, status=status)


@app.post("/admin/reset-prices")
def reset_prices():                                        # BUG 3: only checks login, not admin role
    u, err = need_user()
    if err:
        return err
    if not bug(3) and u["role"] != "admin":
        return jsonify(detail="admin only"), 403
    db().execute("UPDATE items SET price = price")
    db().commit()
    return jsonify(ok=True)


@app.get("/openapi.json")
def openapi():
    return send_file(Path(__file__).with_name("openapi.json"))


init()
