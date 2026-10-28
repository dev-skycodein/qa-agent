"""The MIT license covers the project's own code only; third-party material must stay visibly under its own licence."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_license_is_mit_with_a_holder_and_year():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("MIT License")
    assert "Copyright (c) 2026 " in text
    assert "Permission is hereby granted, free of charge" in text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in text


def test_notice_scopes_mit_and_names_third_party_licences():
    notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
    assert "MIT" in notice and "CC BY-SA 4.0" in notice and "Trail of Bits" in notice
    for rel in ("toolkit/licenses/trailofbits-CC-BY-SA-4.0.txt", "toolkit/licenses/anthropic-security-review-MIT.txt", "SOURCES.md"):
        assert rel in notice and (ROOT / rel).exists(), rel
    for skill in ("semgrep", "sarif-parsing", "differential-review", "sharp-edges", "variant-analysis", "fp-check",
                  "supply-chain-risk-auditor", "property-based-testing"):
        assert f"toolkit/skills/{skill}" in notice, skill
