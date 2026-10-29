"""Provider limits of synthesize.py, the explicit opt-in gate (no URL or key built in), and the refusal of prompts a provider would cut silently.

  python toolkit/test_synthesize_provider.py        (also collectable by pytest; no network)
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthesize as S  # noqa: E402

PLACEHOLDER_URL = "https://llm.example.invalid/v1/chat/completions"


def raises(fn, *a):
    try:
        fn(*a)
    except SystemExit as e:
        return str(e)
    return None


def _no_env_defaults():
    """The opt-in may also come from QA_LLM_API_URL / QA_LLM_MODEL; these tests must not depend on the developer's environment."""
    os.environ.pop("QA_LLM_API_URL", None)
    os.environ.pop("QA_LLM_MODEL", None)


def test_no_provider_is_refused_with_the_off_by_default_message():
    _no_env_defaults()
    msg = raises(S.provider_settings)
    assert msg and "optional and OFF by default" in msg and "--provider" in msg


def test_opt_in_needs_key_env_url_and_model_each_named():
    _no_env_defaults()
    msg = raises(S.provider_settings, "gemini", None, None, None, None)
    assert msg and "optional and OFF by default" in msg
    assert "--key-env" in msg and "--api-url" in msg and "--model" in msg
    assert "--key-env" in raises(S.provider_settings, "gemini", PLACEHOLDER_URL, "m", None, None)
    assert "--api-url" in raises(S.provider_settings, "gemini", None, "m", None, "MY_KEY")


def test_explicit_opt_in_resolves_settings_without_any_builtin_endpoint():
    _no_env_defaults()
    c = S.provider_settings("gemini", PLACEHOLDER_URL, "m", None, "MY_KEY")
    assert c["api_url"] == PLACEHOLDER_URL and c["model"] == "m" and c["key_env"] == "MY_KEY"
    assert c["max_tokens"] == 16000 and c["context_chars"] is None
    assert S.provider_settings("gemini", PLACEHOLDER_URL, "m", 8000, "MY_KEY")["max_tokens"] == 8000


def test_endpoint_and_model_may_come_from_environment_but_key_env_must_be_explicit():
    _no_env_defaults()
    os.environ["QA_LLM_API_URL"] = PLACEHOLDER_URL
    os.environ["QA_LLM_MODEL"] = "env-model"
    try:
        c = S.provider_settings("gemini", None, None, None, "MY_KEY")
        assert c["api_url"] == PLACEHOLDER_URL and c["model"] == "env-model"
        assert "--key-env" in raises(S.provider_settings, "gemini", None, None, None, None)
    finally:
        _no_env_defaults()


def test_skycodein_preset_clamps_tokens_and_limits_context():
    c = S.provider_settings("skycodein", PLACEHOLDER_URL, "skycodein-coder", 16000, "MY_KEY")
    assert c["max_tokens"] == 2048 and c["context_chars"] == 7500
    assert S.provider_settings("skycodein", PLACEHOLDER_URL, "m", 500, "MY_KEY")["max_tokens"] == 500


def test_unknown_provider_is_refused():
    assert "unknown provider" in raises(S.provider_settings, "nope", PLACEHOLDER_URL, "m", None, "MY_KEY")


def test_oversize_prompt_is_refused_instead_of_silently_cut():
    msg = raises(S.check_context, "s" * 4000, "u" * 4000, 7500)
    assert msg and "7500-character" in msg and "silently" in msg
    assert raises(S.check_context, "s" * 3000, "u" * 3000, 7500) is None
    assert raises(S.check_context, "s" * 90000, "u" * 90000, None) is None          # no limit for providers without one


def _sha(text):
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_prompt_versions_2_and_3_are_byte_identical_to_their_frozen_hashes():
    """Versions 2 and 3 have frozen hashes (set before the internal blind experiments); adding version 4 must not move them."""
    assert _sha(S.PROMPTS[2]) == "032f427719eea27c6b86bcb34cbfaa34664e4ce2d8de8bea25c28e95f7b77f41"
    assert _sha(S.PROMPTS[3]) == "48e5e036e07d76c33b632bb4f997f860e3aa3ac5e94bfbfbf993c257c42ab942"


def test_prompt_version_4_extends_version_3_and_adds_the_flag_and_grants_rules():
    v4 = S.PROMPTS[4]
    assert v4.startswith(S.PROMPTS[3]) and v4 != S.PROMPTS[3]
    assert "Never put an endpoint in SKIP" in v4 and "# FLAG: METHOD /path" in v4
    assert "GRANTS = {" in v4 and "anon is never a viewer" in v4


def test_prompt_version_4_is_a_valid_prompt_version_choice():
    """The --prompt-version choices are sorted(PROMPTS), so 4 must be a key there."""
    assert sorted(S.PROMPTS) == [2, 3, 4]


def test_missing_key_exits_nonzero_and_names_the_variable():
    _no_env_defaults()
    env = {**os.environ, "SKY_CODEIN_KEY": ""}      # an empty value also stops .env from supplying one (setdefault)
    r = subprocess.run([sys.executable, str(Path(S.__file__)), "--provider", "skycodein", "--key-env", "SKY_CODEIN_KEY",
                        "--api-url", "http://127.0.0.1:9/v1/chat/completions", "--model", "m",
                        "--openapi", "unused.json", "--out", os.devnull],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "SKY_CODEIN_KEY" in (r.stderr + r.stdout)


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"SYNTHESIZE PROVIDER OK: {len(tests)} tests")
