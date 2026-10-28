"""api.py robustness: $ref decoding, impossible numeric ranges, oversized responses.

  python toolkit/engine/test_api_schema.py        (also collectable by pytest)
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api  # noqa: E402


def test_ref_with_escaped_slash_and_percent_is_resolved():
    spec = {"components": {"schemas": {"a/b": {"type": "integer", "minimum": 3}, "c d": {"type": "string"}}}}
    assert api.resolve({"$ref": "#/components/schemas/a~1b"}, spec)["minimum"] == 3
    assert api.resolve({"$ref": "#/components/schemas/c%20d"}, spec)["type"] == "string"


def test_ref_cycle_does_not_hang():
    spec = {"components": {"schemas": {"A": {"$ref": "#/components/schemas/A"}}}}
    api.resolve({"$ref": "#/components/schemas/A"}, spec)      # returns after the depth guard


def test_strategy_survives_maximum_below_minimum():
    try:
        from hypothesis import given, settings
    except ImportError:          # engines get hypothesis through `uv run --with hypothesis`; the plain interpreter may not have it
        print("skip (hypothesis not installed)")
        return
    s = api.strategy({"type": "integer", "minimum": 10, "maximum": 3}, {})

    @settings(max_examples=5, database=None)
    @given(s)
    def run(v):
        assert isinstance(v, int)
    run()


def test_response_body_is_capped():
    big = b"x" * (api.MAX_READ + 5000)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(big)))
            self.end_headers()
            self.wfile.write(big)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = api.Api(f"http://127.0.0.1:{srv.server_address[1]}").call("anon", "GET", "/")
        assert r.status == 200 and len(r.text) <= api.MAX_READ, len(r.text)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"API SCHEMA OK: {len(tests)} tests")
