"""Outbound sink: the only network the app under test can reach.

Starts, inside safe_run.py, a local HTTP(S)-proxy + fake third-party API + fake SMTP server. The app is started with
HTTP(S)_PROXY / ALL_PROXY pointing at the sink (and NODE_USE_ENV_PROXY=1 so Node's fetch obeys it), so:

  * every outbound call the app attempts (LLM, payment, email API, analytics, webhooks, Sentry) is RECORDED and BLOCKED
    (HTTPS CONNECT is answered 502; plain HTTP gets a canned 200 so the app keeps working)
  * mail sent via SMTP is captured (subject, recipients, full body) - bugs that only exist in outbound email / HTML
  * calls to a mocked base URL (profile "mock_env", e.g. {"LLM_BASE_URL": "{sink_http}"}) arrive as direct requests with the
    full plaintext body: the exact prompt / payload the app builds

Everything is written to <dir>/sink.jsonl, one JSON object per line:
  {"t": 1.2, "kind": "connect"|"http"|"smtp", "host": ..., "method": ..., "path": ..., "headers": {...}, "body": "...", ...}
run.py turns that file into the `outbound` engine: OUTBOUND-ATTEMPT (info), OUTBOUND-LEAK (secrets / credentials / PII
patterns in what leaves the app), plus anything qa-spec.py's SINK_CHECKS = [fn(entry) -> None | "message"] returns.

Use directly (for tests):  python sink.py --log sink.jsonl   (prints the ports, runs until killed)
"""
import argparse
import json
import select
import socket
import socketserver
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CANNED = {"qa_sink": True, "candidates": [{"content": {"parts": [{"text": "QA-SINK canned reply"}]}}], "choices": [
    {"message": {"role": "assistant", "content": "QA-SINK canned reply"}}], "text": "QA-SINK canned reply", "ok": True, "id": "qa-sink"}


_CREDENTIAL_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


def redact_headers(pairs) -> dict:
    """Header dict for the run folder: credential values are replaced, the header names are kept."""
    return {k: ("<redacted>" if k.lower() in _CREDENTIAL_HEADERS else v) for k, v in pairs}


class Sink:
    DEFAULT_ALLOW = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com")

    def __init__(self, log_path: str, host: str = "127.0.0.1", allow=None):
        self.log_path, self.host, self.t0 = log_path, host, time.time()
        self.allow = set(self.DEFAULT_ALLOW if allow is None else allow)      # tunnelled, not recorded: package registries
        self._lock = threading.Lock()
        open(log_path, "w").close()
        sink = self

        class QuietHttp(ThreadingHTTPServer):
            def handle_error(self, request, client_address):      # peers that drop connections are normal here
                pass

        class Http(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode("utf-8", "replace") if n else ""

            def do_CONNECT(self):                                   # HTTPS: only host:port is visible; refuse unless allow-listed
                host, _, port = self.path.partition(":")
                if host in sink.allow:                              # package registries only: launchers (uv, npm) need them at start-up
                    try:
                        upstream = socket.create_connection((host, int(port or 443)), timeout=15)
                    except OSError:
                        self.send_response(502)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self.send_response(200, "Connection established")
                    self.end_headers()
                    self.wfile.flush()
                    self.connection.setblocking(False)
                    upstream.setblocking(False)
                    pair = (self.connection, upstream)
                    try:
                        while True:
                            ready, _, bad = select.select(pair, [], pair, 60)
                            if bad or not ready:
                                break
                            for src in ready:
                                try:
                                    data = src.recv(65536)
                                except (BlockingIOError, ssl.SSLWantReadError):
                                    continue
                                if not data:
                                    return
                                dst = upstream if src is self.connection else self.connection
                                dst.setblocking(True)
                                dst.sendall(data)
                                dst.setblocking(False)
                    except OSError:
                        pass
                    finally:
                        upstream.close()
                        self.close_connection = True
                    return
                sink.record({"kind": "connect", "host": self.path})
                self.send_response(502, "blocked by qa sink")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _any(self):
                body = self._body()
                target = self.path                                   # absolute URI when used as proxy, path when mocked directly
                is_proxy = target.startswith("http")
                sink.record({"kind": "http", "via": "proxy" if is_proxy else "direct", "method": self.command,
                             "host": self.headers.get("Host", ""), "path": target,
                             # credentials never reach the run folder: the value is replaced, the header name is kept
                             "headers": redact_headers(self.headers.items()),
                             "body": body[:20000]})
                data = json.dumps(CANNED).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _any

        class Smtp(socketserver.StreamRequestHandler):
            def handle(self):
                w = lambda s: self.wfile.write((s + "\r\n").encode())
                w("220 qa-sink ESMTP")
                mail_from, rcpts = None, []
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    cmd = line.decode("utf-8", "replace").strip()
                    up = cmd.upper()
                    if up.startswith(("EHLO", "HELO")):
                        w("250-qa-sink")
                        w("250 AUTH PLAIN LOGIN")
                    elif up.startswith("AUTH"):
                        w("235 ok")
                    elif up.startswith("MAIL FROM"):
                        mail_from = cmd[10:].strip()
                        w("250 ok")
                    elif up.startswith("RCPT TO"):
                        rcpts.append(cmd[8:].strip())
                        w("250 ok")
                    elif up == "DATA":
                        w("354 end with .")
                        buf = []
                        while True:
                            l = self.rfile.readline().decode("utf-8", "replace")
                            if l in (".\r\n", ".\n", ""):
                                break
                            buf.append(l[1:] if l.startswith("..") else l)
                        raw = "".join(buf)
                        head, _, body = raw.partition("\r\n\r\n") if "\r\n\r\n" in raw else raw.partition("\n\n")
                        subject = next((h[8:].strip() for h in head.splitlines() if h.lower().startswith("subject:")), "")
                        sink.record({"kind": "smtp", "from": mail_from, "to": rcpts, "subject": subject, "headers": head[:2000], "body": body[:20000]})
                        w("250 queued")
                        mail_from, rcpts = None, []
                    elif up == "QUIT":
                        w("221 bye")
                        return
                    else:
                        w("250 ok")

        class ThreadedTcp(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address = True
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        self.http = QuietHttp((host, 0), Http)
        self.http.daemon_threads = True
        self.smtp = ThreadedTcp((host, 0), Smtp)
        self.http_port, self.smtp_port = self.http.server_address[1], self.smtp.server_address[1]
        for srv in (self.http, self.smtp):
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def record(self, entry: dict) -> None:
        entry["t"] = round(time.time() - self.t0, 2)
        with self._lock, open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    @property
    def http_url(self) -> str:
        return f"http://{self.host}:{self.http_port}"

    def env(self) -> dict:
        """Environment for the APP process: all outbound HTTP goes through the sink."""
        return {"HTTP_PROXY": self.http_url, "HTTPS_PROXY": self.http_url, "ALL_PROXY": self.http_url,
                "http_proxy": self.http_url, "https_proxy": self.http_url, "all_proxy": self.http_url,
                "NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1", "NODE_USE_ENV_PROXY": "1"}

    def placeholders(self) -> dict:
        return {"{sink_http}": self.http_url, "{sink_smtp_host}": self.host, "{sink_smtp_port}": str(self.smtp_port),
                "{sink_smtp}": f"smtp://{self.host}:{self.smtp_port}"}

    def stop(self) -> None:
        for srv in (self.http, self.smtp):
            srv.shutdown()
            srv.server_close()


def read_log(path: str) -> list[dict]:
    try:
        return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    except FileNotFoundError:
        return []


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="sink.jsonl")
    a = ap.parse_args()
    s = Sink(a.log)
    print(json.dumps({"http": s.http_url, "smtp_port": s.smtp_port}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        s.stop()
        sys.exit(0)
