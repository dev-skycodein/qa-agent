"""Fire N identical HTTP requests at the same instant; print the status-code spread.

CLI:  python race.py -n 20 POST http://127.0.0.1:8010/orders/ -H "Authorization: Bearer X" --json '{"a":1}'
Lib:  from race import race; codes = race("POST", url, n=20, headers={...}, body={...})

Stdlib only. LOCAL targets only: refuses non-localhost URLs.
After a race, check your invariant (stock, count of rows, balance) with a normal GET.
"""
import argparse
import json
import sys
import threading
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import api as _api  # noqa: E402  (same local-only redirect rule and host list as every engine request)


def _one(method, url, headers, data, barrier):
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    barrier.wait()
    try:
        with _api._OPENER.open(req, timeout=30) as r:             # not urlopen: a redirect off this machine must not carry the token
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError) as e:        # no HTTP answer at all: keep the burst, mark it as such
        return _api.TRANSPORT_ERROR, f"connection error: {e}"


def race(method, url, n=20, headers=None, body=None, per_request_headers=None):
    """Returns list of (status, body). per_request_headers(i) -> dict merged per request."""
    if urlparse(url).hostname not in _api.LOCAL_HOSTS:
        raise SystemExit(f"refusing non-local target: {url}")
    data = json.dumps(body).encode() if body is not None else None
    base = {"Content-Type": "application/json", **(headers or {})}
    barrier = threading.Barrier(n)
    with ThreadPoolExecutor(n) as pool:
        futures = [pool.submit(_one, method, url, {**base, **(per_request_headers(i) if per_request_headers else {})}, data, barrier)
                   for i in range(n)]
        return [f.result() for f in futures]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("method")
    p.add_argument("url")
    p.add_argument("-n", type=int, default=20)
    p.add_argument("-H", action="append", default=[])
    p.add_argument("--json")
    a = p.parse_args()
    headers = dict(h.split(": ", 1) for h in a.H)
    results = race(a.method.upper(), a.url, a.n, headers, json.loads(a.json) if a.json else None)
    print(dict(Counter(code for code, _ in results)))


if __name__ == "__main__":
    main()
