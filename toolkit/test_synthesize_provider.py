"""Provider presets of synthesize.py: URL / model / key variable / limits, and the refusal of prompts a provider would cut silently.

  python toolkit/test_synthesize_provider.py        (also collectable by pytest; no network)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synthesize as S  # noqa: E402


def raises(fn, *a):
    try:
        fn(*a)
    except SystemExit as e:
        return str(e)
    return None


def test_gemini_preset_is_unchanged():
    c = S.provider_settings("gemini")
    assert c["api_url"] == S.DEFAULT_API_URL and c["model"] == S.DEFAULT_MODEL and c["key_env"] == "GEMINI_API_KEY"
    assert c["max_tokens"] == 16000 and c["context_chars"] is None
    assert S.provider_settings("gemini", max_tokens=8000)["max_tokens"] == 8000


def test_skycodein_preset_clamps_tokens_and_limits_context():
    c = S.provider_settings("skycodein", max_tokens=16000)
    assert c["api_url"].startswith("https://theskyscripters.online/") and c["model"] == "skycodein-coder"
    assert c["key_env"] == "SKY_CODEIN_KEY" and c["max_tokens"] == 2048 and c["context_chars"] == 7500
    assert S.provider_settings("skycodein", max_tokens=500)["max_tokens"] == 500
    assert S.provider_settings("skycodein", model="skycodein-general")["model"] == "skycodein-general"


def test_unknown_provider_is_refused():
    assert "unknown provider" in raises(S.provider_settings, "nope")


def test_oversize_prompt_is_refused_instead_of_silently_cut():
    msg = raises(S.check_context, "s" * 4000, "u" * 4000, 7500)
    assert msg and "7500-character" in msg and "silently" in msg
    assert raises(S.check_context, "s" * 3000, "u" * 3000, 7500) is None
    assert raises(S.check_context, "s" * 90000, "u" * 90000, None) is None          # no limit for providers without one


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"SYNTHESIZE PROVIDER OK: {len(tests)} tests")


def test_missing_key_exits_nonzero_and_names_the_variable():
    import os
    import subprocess
    env = {**os.environ, "SKY_CODEIN_KEY": ""}      # an empty value also stops .env from supplying one (setdefault)
    r = subprocess.run([sys.executable, str(Path(S.__file__)), "--provider", "skycodein", "--openapi", "unused.json", "--out", os.devnull],
                       capture_output=True, text=True, env=env, timeout=60)
    assert r.returncode != 0 and "SKY_CODEIN_KEY" in (r.stderr + r.stdout)
