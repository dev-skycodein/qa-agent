"""Safety tests for api.py (security review F1/F2): the engine client must never send a request, or a credential, off this machine.

  python toolkit/engine/test_api_safety.py        (stdlib only; also collectable by pytest)

127.0.0.2 is loopback too but is NOT in api.LOCAL_HOSTS, so it plays the role of "a remote host" without any real network traffic.
"""
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402

AUTH = {"user_a": {"Authorization": "Bearer secret-token"}}


class Server:
    """Records every request (path + headers); `redirect` makes it answer 302 to that URL."""

    def __init__(self, host="127.0.0.1", redirect=None):
        self.seen, outer = [], self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                outer.seen.append((self.path, dict(self.headers.items())))
                if outer.redirect:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _any

        self.redirect = redirect
        self.srv = ThreadingHTTPServer((host, 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, host="127.0.0.1"):
        return f"http://{host}:{self.port}"

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def test_redirect_to_non_local_host_is_not_followed():
    remote = Server("127.0.0.2")
    local = Server(redirect=remote.url("127.0.0.2") + "/steal")
    try:
        resp = api.Api(local.url(), AUTH).call("user_a", "GET", "/x")
        assert remote.seen == [], f"non-local host received a request: {remote.seen}"
        assert resp.status == 302, resp
    finally:
        local.stop(); remote.stop()


def test_redirect_to_other_local_port_drops_credentials():
    target = Server()
    local = Server(redirect=target.url() + "/y")
    try:
        resp = api.Api(local.url(), AUTH).call("user_a", "GET", "/x")
        assert resp.ok and len(target.seen) == 1, (resp, target.seen)
        sent = {k.lower() for k in target.seen[0][1]}
        assert "authorization" not in sent and "cookie" not in sent, f"credentials followed a host:port change: {sent}"
    finally:
        local.stop(); target.stop()


def test_same_host_redirect_keeps_credentials():
    """FastAPI-style /items -> /items/ must keep working, with the token."""
    srv = Server()
    srv.redirect = srv.url() + "/items/"
    try:
        def flip():                      # first hit redirects, second answers 200
            while not srv.seen:
                pass
            srv.redirect = None
        threading.Thread(target=flip, daemon=True).start()
        resp = api.Api(srv.url(), AUTH).call("user_a", "GET", "/items")
        assert resp.ok, resp
        assert srv.seen[-1][0] == "/items/" and srv.seen[-1][1].get("Authorization") == "Bearer secret-token", srv.seen
    finally:
        srv.stop()


def test_hostile_paths_are_refused_before_any_io():
    remote = Server("127.0.0.2")
    local = Server()
    try:
        client = api.Api(local.url(), AUTH)
        for bad in (f"@127.0.0.2:{remote.port}/x", f"//127.0.0.2:{remote.port}/x", "no-leading-slash", r"/a\@evil", f":{remote.port}/x"):
            try:
                client.call("user_a", "GET", bad)
            except SystemExit:
                continue
            raise AssertionError(f"path {bad!r} was not refused")
        assert remote.seen == [] and local.seen == [], (remote.seen, local.seen)
    finally:
        local.stop(); remote.stop()


def test_percent_encoded_hostile_ids_still_reach_the_app():
    local = Server()
    try:
        for ok in ("/items/%40evil.example", "/items/..%2F..%2Fetc%2Fpasswd", "/items/%00", "/items/%27%20OR%201%3D1--"):
            assert api.Api(local.url(), AUTH).call("user_a", "GET", ok).ok, ok
        assert len(local.seen) == 4
    finally:
        local.stop()


def test_load_openapi_does_not_follow_redirect_off_machine():
    remote = Server("127.0.0.2")
    local = Server(redirect=remote.url("127.0.0.2") + "/openapi.json")
    try:
        try:
            api.load_openapi(local.url() + "/openapi.json")
        except urllib.error.HTTPError as e:
            e.close()
            assert e.code == 302
        else:
            raise AssertionError("redirect to a non-local host was followed")
        assert remote.seen == []
        try:
            api.load_openapi("http://127.0.0.2:1/openapi.json")
        except SystemExit:
            pass
        else:
            raise AssertionError("non-local openapi url accepted")
    finally:
        local.stop(); remote.stop()


def test_connection_failure_is_a_transport_error_not_a_server_error():
    """Nothing listens on this port: the client reports a transport error, which must not look like an HTTP 5xx answer."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    resp = api.Api(f"http://127.0.0.1:{port}").call("anon", "GET", "/x")
    assert resp.transport and not resp.ok and resp.status == api.TRANSPORT_ERROR
    assert api.Resp(500, "boom").transport is False
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import race
    results = race.race("GET", f"http://127.0.0.1:{port}/x", n=2)
    assert [code for code, _ in results] == [api.TRANSPORT_ERROR] * 2, results      # was an unhandled exception in a worker thread


def test_race_sender_does_not_follow_redirect_off_machine():
    """race.py has its own sender (not Api.call): a 302 to another host must not receive the role's Authorization header."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import race
    remote = Server("127.0.0.2")
    local = Server(redirect=remote.url("127.0.0.2") + "/steal")
    try:
        results = race.race("POST", local.url() + "/x", n=3, headers=AUTH["user_a"], body={"a": 1})
        assert remote.seen == [], f"race sender followed a redirect to a non-local host: {remote.seen}"
        assert all(code == 302 for code, _ in results), results
    finally:
        local.stop(); remote.stop()


def test_env_proxy_never_sees_local_traffic():
    """HTTP_PROXY / HTTPS_PROXY in the environment must not capture engine calls to a local target (the token would leave the
    process). A fresh interpreter is used because urllib reads the proxy env when an opener is built (api import time)."""
    import os
    import subprocess
    proxy, target = Server(), Server()
    code = ("import sys; sys.path.insert(0, %r); import api; "
            "r = api.Api(%r, %r).call('user_a', 'GET', '/x'); "
            "h = api.Api(%r).call('anon', 'GET', '/y'); print(r.status, h.status)") % (
        str(Path(__file__).resolve().parent), target.url(), AUTH, target.url())
    env = {**os.environ, "HTTP_PROXY": proxy.url(), "http_proxy": proxy.url(), "HTTPS_PROXY": proxy.url(), "https_proxy": proxy.url()}
    env.pop("NO_PROXY", None); env.pop("no_proxy", None)
    try:
        out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60)
        assert out.stdout.split() == ["200", "200"], (out.stdout, out.stderr[-400:])
        assert proxy.seen == [], f"env proxy received local engine traffic: {proxy.seen}"
        assert len(target.seen) == 2
    finally:
        proxy.stop(); target.stop()


def test_urlopen_local_refuses_non_local_host():
    """urlopen_local (safe_run health check) keeps the local-only rule; the proxy bypass itself is covered by the test above."""
    try:
        api.urlopen_local("http://127.0.0.2:9/")
    except SystemExit as e:
        assert "non-local" in str(e)
    else:
        raise AssertionError("urlopen_local accepted a non-local host")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"API SAFETY OK: {len(tests)} tests")
