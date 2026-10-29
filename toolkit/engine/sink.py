"""Outbound sink: the only network the app under test can reach.

Starts, inside safe_run.py, a local HTTP(S)-proxy + fake third-party API + fake SMTP server. The app is started with
HTTP(S)_PROXY / ALL_PROXY pointing at the sink (and NODE_USE_ENV_PROXY=1 so Node's fetch obeys it), so:

  * outbound calls that USE THE PROXY ENV VARS are RECORDED and BLOCKED (HTTPS CONNECT to hosts not in sink_allow is
    answered 502; plain HTTP gets a canned 200 so the app keeps working). Allow-listed CONNECTs are tunnelled and recorded.
  * NOT covered: a client that ignores the proxy env vars (raw sockets, trust_env=False, DB / Redis / SMTP drivers that
    connect directly, Java, DNS lookups). Such egress is neither recorded nor blocked by this sink. This is a documented
    limit: the sink is an observer for proxy-aware clients, not a network firewall. Do not claim "all outbound blocked".
  * mail sent via SMTP is captured only when the app is pointed at the sink (e.g. SMTP_HOST={sink_smtp_host}); sink.env()
    does not set any SMTP variable (subject, recipients, full body) - bugs that only exist in outbound email / HTML
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
import re
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


# Header names whose VALUE is never stored: anything credential-like (X-Goog-Api-Key, X-Auth-Token, X-CSRF-Token...), not only a
# fixed list of four names.
_CREDENTIAL_HEADER_RX = re.compile(r"authorization|cookie|key|token|secret|session|csrf|password|passwd", re.I)
MAX_BODY_READ = 4_000_000     # bytes kept from one request body (chunked or not); the rest is read and dropped

# Secret shapes. Shared with outbound.py (its OUTBOUND-LEAK engine), so there is one list.
SECRET_PATTERNS = [
    ("password in payload", re.compile(r'"(password|passwd|pwd)"\s*:\s*"[^"]{1,}"', re.I)),
    ("api key / token in payload or URL", re.compile(r"AIza[0-9A-Za-z_\-]{30,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|"
                                                      r"[?&](api_?key|access_?token|token|secret)=[^&\s]{8,}", re.I)),
    ("session JWT sent to third party", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # Visa, Mastercard, Discover (16 digits) and Amex (15 digits, 3[47]).
    ("card number", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b"
                               r"|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b")),
]


def redact_headers(pairs) -> dict:
    """Header dict for the run folder: credential-like values are replaced, the header names are kept."""
    return {k: ("<redacted>" if _CREDENTIAL_HEADER_RX.search(str(k)) else v) for k, v in pairs}


def scrub_text(text: str, where: str) -> tuple:
    """(text with every secret-shaped match replaced by <redacted:label>, hits). Hits: [{"label", "where", "chars"}]. The secret
    itself is not returned: the run folder keeps the redacted text and the label only."""
    hits = []
    for label, rx in SECRET_PATTERNS:
        def _sub(m, label=label):
            hits.append({"label": label, "where": where, "chars": len(m.group(0))})
            return f"<redacted:{label}>"
        text = rx.sub(_sub, text)
    return text, hits


def header_secret_hits(pairs) -> list:
    """Secrets found in the RAW header values, before redaction. Only labels, header names and match lengths are kept:
    the secret itself never reaches the run folder. Output: [{"label", "header", "chars"}]."""
    hits = []
    for k, v in pairs:
        for label, rx in SECRET_PATTERNS:
            m = rx.search(str(v))
            if m:
                hits.append({"label": label, "header": str(k), "chars": len(m.group(0))})
    return hits


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
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    # chunked request: read every chunk (keeps the connection framed); keep at most MAX_BODY_READ bytes
                    out = bytearray()
                    while True:
                        line = self.rfile.readline(65537)
                        try:
                            size = int(line.split(b";")[0].strip() or b"x", 16) if line else 0
                        except ValueError:
                            break
                        if size == 0:
                            while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                                pass                              # trailers, then the blank line
                            break
                        data = self.rfile.read(size)
                        self.rfile.readline(65537)                # CRLF after each chunk
                        if len(out) < MAX_BODY_READ:
                            out += data[:MAX_BODY_READ - len(out)]
                    return bytes(out).decode("utf-8", "replace")
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n).decode("utf-8", "replace") if n else ""

            def do_CONNECT(self):                                   # HTTPS: only host:port is visible; refuse unless allow-listed
                host, _, port = self.path.partition(":")
                if host in sink.allow:                              # package registries only: launchers (uv, npm) need them at start-up
                    sink.record({"kind": "connect", "host": self.path, "via": "tunnel"})   # tunnelled, not blocked, but recorded
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
                raw_headers = list(self.headers.items())
                # secrets in the URL (?api_key=...) and body are replaced before anything is written; the hits are kept as labels
                target_clean, path_hits = scrub_text(target, "path")
                body_clean, body_hits = scrub_text(body, "body")
                # scan the RAW headers first: redaction below hides the values the leak engine would need to see
                sink.record({"kind": "http", "via": "proxy" if is_proxy else "direct", "method": self.command,
                             "host": self.headers.get("Host", ""), "path": target_clean,
                             # credentials never reach the run folder: the value is replaced, the header name is kept
                             "headers": redact_headers(raw_headers),
                             "header_leaks": header_secret_hits(raw_headers),
                             "body_leaks": path_hits + body_hits,
                             "body": body_clean[:20000]})
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
                        body_clean, body_hits = scrub_text(body, "smtp-body")
                        head_clean, head_hits = scrub_text(head, "smtp-headers")
                        sink.record({"kind": "smtp", "from": mail_from, "to": rcpts, "subject": subject, "headers": head_clean[:2000],
                                     "body_leaks": head_hits + body_hits, "body": body_clean[:20000]})
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
