"""The LLM helper is optional and OFF by default.

- Without an explicit opt-in, synthesize.py and rules_from_llm.py refuse with the "optional and OFF by default" message BEFORE any
  network use (urllib is stubbed to fail the test if it is reached).
- A full explicit opt-in gets past the gate (positive control: the stub is reached, and only then).
- The default provider URLs and default provider names are gone from synthesize.py and rules_from_llm.py (grep).
- No core engine or runner imports the LLM helpers.

  python toolkit/test_llm_optional.py        (also collectable by pytest; no network, no real key)
"""
import contextlib
import json
import os
import re
import sys
import tempfile
import urllib.request
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import synthesize as S  # noqa: E402
import rules_from_llm as R  # noqa: E402

OFF = "optional and OFF by default"
PLACEHOLDER_URL = "https://llm.example.invalid/v1/chat/completions"
FORBIDDEN_IN_CORE = ["generativelanguage.googleapis.com", "theskyscripters.online", "DEFAULT_API_URL", "DEFAULT_MODEL",
                     'default="gemini"', 'default="skycodein"', 'provider="skycodein"', "SKY_CODEIN_KEY", "https://"]


def _network_forbidden():
    """Any attempt to open a connection fails the test with a message (the stub is the only path the LLM helpers use)."""
    def boom(*a, **k):
        raise AssertionError("NETWORK REACHED: an LLM call was attempted without an explicit opt-in")
    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch.object(urllib.request, "urlopen", boom))
    stack.enter_context(mock.patch.object(urllib.request.OpenerDirector, "open", boom))
    return stack


def _minimal_openapi(tmpdir):
    p = Path(tmpdir) / "openapi.json"
    p.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}}), encoding="utf-8")
    return str(p)


def _run_cli(module, argv):
    """Run module.main() with argv under the network stub and a copy of the environment; -> the SystemExit text, or None."""
    with tempfile.TemporaryDirectory() as tmp, mock.patch.object(sys, "argv", [module.__name__ + ".py"] + argv(tmp)), \
            mock.patch.dict(os.environ), _network_forbidden():
        for name in ("QA_LLM_API_URL", "QA_LLM_MODEL", "GEMINI_API_KEY", "SKY_CODEIN_KEY"):
            os.environ.pop(name, None)
        try:
            module.main()
        except SystemExit as e:
            return str(e)
    return None


def test_synthesize_without_opt_in_refuses_before_any_network_use():
    msg = _run_cli(S, lambda t: ["--openapi", _minimal_openapi(t), "--out", os.devnull])
    assert msg and OFF in msg and "--provider" in msg


def test_synthesize_with_provider_but_no_key_env_refuses_before_any_network_use():
    msg = _run_cli(S, lambda t: ["--provider", "gemini", "--api-url", PLACEHOLDER_URL, "--model", "m",
                                 "--openapi", _minimal_openapi(t), "--out", os.devnull])
    assert msg and "--key-env" in msg and OFF in msg


def test_rules_from_llm_without_opt_in_refuses_before_any_network_use():
    msg = _run_cli(R, lambda t: ["--openapi", _minimal_openapi(t), "--out", str(Path(t) / "o.py")])
    assert msg and OFF in msg


def test_propose_without_opt_in_refuses_before_any_network_use():
    spec = {"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {}}
    with _network_forbidden():
        try:
            R.propose(spec)
        except SystemExit as e:
            assert OFF in str(e)
            return
    raise AssertionError("propose() without an opt-in did not refuse")


def test_full_explicit_opt_in_gets_past_the_gate_and_only_then_reaches_the_network():
    """Positive control: with provider, key variable, endpoint and model all named (and a dummy key), the stub IS reached."""
    spec_path = None
    with tempfile.TemporaryDirectory() as tmp:
        spec_path = _minimal_openapi(tmp)
        argv = ["synthesize.py", "--provider", "gemini", "--key-env", "LLM_TEST_DUMMY_KEY", "--api-url", PLACEHOLDER_URL,
                "--model", "m", "--openapi", spec_path, "--out", os.devnull]
        with mock.patch.dict(os.environ, {"LLM_TEST_DUMMY_KEY": "dummy-not-a-real-key"}), mock.patch.object(sys, "argv", argv), \
                _network_forbidden():
            try:
                S.main()
            except AssertionError as e:
                assert "NETWORK REACHED" in str(e)
                return
            except SystemExit as e:
                raise AssertionError(f"opt-in was refused: {e}")
    raise AssertionError("opt-in did not reach the network layer")


def test_core_files_have_no_default_provider_url_or_default_provider_name():
    for path in (HERE / "synthesize.py", HERE / "rules_from_llm.py"):
        text = path.read_text(encoding="utf-8")
        for needle in FORBIDDEN_IN_CORE:
            assert needle not in text, f"{path.name} still contains {needle!r}"
        assert re.search(r"\bDEFAULT_(MODEL|API_URL)\b", text) is None


def test_no_core_engine_or_runner_imports_the_llm_helpers():
    """run.py, qa_check.py, qa_console.py and every non-test toolkit/engine module must not import or call them."""
    candidates = [ROOT / "run.py", ROOT / "qa_check.py", ROOT / "qa_console.py"]
    candidates += [p for p in (ROOT / "toolkit" / "engine").glob("*.py") if not p.name.startswith("test_")]
    pattern = re.compile(r"\b(import\s+synthesize|from\s+synthesize\b|import\s+rules_from_llm|from\s+rules_from_llm\b|synthesize\.|rules_from_llm\.)")
    hits = []
    for p in candidates:
        if p.is_file() and pattern.search(p.read_text(encoding="utf-8", errors="replace")):
            hits.append(str(p))
    assert not hits, f"core files reference the LLM helpers: {hits}"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"LLM OPTIONAL OK: {len(tests)} tests")
