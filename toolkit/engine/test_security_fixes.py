"""Regression tests for the pre-publication audit (qa-toolkit-run-1): repo file names, secrets in run folders, redirects, plaintext keys."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import outbound  # noqa: E402
import sink  # noqa: E402
import synthesize  # noqa: E402

# a made-up token; built from parts so the file itself does not look like a real JWT to the release scanner
JWT = ".".join(["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJxYXRlc3QifQ", "abcdefghijklmnopqrstu"])


def test_flask_file_name_with_shell_metacharacter_is_one_argv_item_and_no_trusted_key():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app&calc.py").write_text("app = Flask(__name__)\n", encoding="utf-8")
        out = root / "profile.json"
        subprocess.run([sys.executable, str(HERE / "detect.py"), str(root), "--out", str(out)], check=True, capture_output=True)
        prof = json.loads(out.read_text(encoding="utf-8"))
        assert prof["framework"] == "flask"
        assert "app&calc.py" in prof["run_cmd_argv"]            # the name is a single argument, never shell text
        assert "trusted" not in prof                              # no self-asserted trust in a generated profile


def test_redact_headers_keeps_names_and_hides_credentials():
    out = sink.redact_headers([("Authorization", "Bearer abc"), ("Cookie", "sid=1"), ("Host", "example.test")])
    assert out == {"Authorization": "<redacted>", "Cookie": "<redacted>", "Host": "example.test"}


def test_outbound_report_does_not_copy_the_secret():
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "sink.jsonl"
        entry = {"kind": "http", "via": "direct", "method": "POST", "host": "api.example.test", "path": "/v1",
                 "headers": {}, "body": f'{{"auth": "{JWT}"}}'}
        log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        result = outbound.run(str(log), SimpleNamespace())
        details = " ".join(str(f.get("detail", "")) for f in result["findings"])
        assert "OUTBOUND-LEAK" in " ".join(str(f.get("kind", "")) for f in result["findings"])
        assert JWT not in details and "<redacted" in details


def test_cmd_script_as_argv0_is_refused_on_windows_shims():
    import safe_run
    base = {"env_overrides": {}, "blank_keys": [], "unsafe_vars": [], "port": 8000}
    try:
        safe_run.check_safe({**base, "run_cmd_argv": ["npm.cmd", "start", "&&", "calc"]})
    except SystemExit as e:
        assert ".cmd" in str(e)
    else:
        raise AssertionError(".cmd argv[0] was accepted")


def test_synthesize_never_follows_a_redirect():
    handler = synthesize._NoRedirect()
    assert handler.redirect_request(None, None, 307, "Temporary Redirect", {}, "https://evil.example.test/") is None
    assert any(isinstance(h, synthesize._NoRedirect) for h in synthesize._OPENER.handlers)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("test_security_fixes: all passed")
