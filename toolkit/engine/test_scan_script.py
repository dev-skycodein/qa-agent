"""Tests for scripts/scan.py: it refuses a non-local API URL, skips missing tools and .cmd/.bat shims, and calls each tool by its
full path with the expected argv. No real scanner (and no network) is used: `which` and `subprocess.run` are replaced.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import scan  # noqa: E402


def _fake(monkeypatch, tools: dict) -> list:
    """`tools`: name -> path `which` returns (others: not found). Returns the list every subprocess argv is appended to."""
    calls = []
    monkeypatch.setattr(scan.shutil, "which", lambda name: tools.get(name))
    monkeypatch.setattr(scan.subprocess, "run", lambda argv, **kw: calls.append(list(argv)) or SimpleNamespace(returncode=0))
    return calls


def test_refuses_non_local_api_url(tmp_path, capsys):
    assert scan.main([str(tmp_path), "--api-url", "https://api.example.com/openapi.json"]) == 2
    assert "refusing non-local target" in capsys.readouterr().err
    assert not (tmp_path / "qa-report").exists(), "nothing may be written before the URL check"


def test_refuses_missing_directory(tmp_path):
    assert scan.main([str(tmp_path / "nope")]) == 2


def test_missing_tools_are_skipped(tmp_path, monkeypatch, capsys):
    calls = _fake(monkeypatch, {})
    assert scan.main([str(tmp_path), "--api-url", "http://127.0.0.1:8000/openapi.json"]) == 0
    out = capsys.readouterr().out
    for name in ("semgrep", "gitleaks", "osv-scanner", "trivy", "ubs", "schemathesis"):
        assert f"[{name}]" in out and "missing" in out.split(f"[{name}]", 1)[1].splitlines()[0], name
    assert calls == [], "a missing tool must never be started"
    assert (tmp_path / "qa-report").is_dir()


def test_tools_get_full_path_and_expected_arguments(tmp_path, monkeypatch):
    tools = {n: f"/opt/bin/{n}" for n in ("semgrep", "gitleaks", "trivy", "schemathesis")}
    calls = _fake(monkeypatch, tools)
    assert scan.main([str(tmp_path), "--api-url", "http://localhost:8000/openapi.json", "--exclude-paths", "^/(chat|search)"]) == 0
    by_tool = {}
    for argv in calls:
        by_tool.setdefault(argv[0], []).append(argv)
    semgrep = by_tool["/opt/bin/semgrep"]
    assert len(semgrep) == 2, "the learned rules must run as a second semgrep scan"
    assert "p/owasp-top-ten" in semgrep[0] and semgrep[0][semgrep[0].index("-o") + 1].endswith("semgrep.sarif")
    assert semgrep[1][semgrep[1].index("--config") + 1] == str(scan.LEARNED)
    assert by_tool["/opt/bin/gitleaks"][0][1] == "dir", "a folder without .git is scanned in dir mode"
    assert by_tool["/opt/bin/trivy"][0][1:3] == ["fs", "--scanners"]
    st = by_tool["/opt/bin/schemathesis"][0]
    assert st[1:3] == ["run", "http://localhost:8000/openapi.json"]
    assert st[st.index("--exclude-path-regex") + 1] == "^/(chat|search)", "the regex is one argv item, never shell text"


def test_git_repo_is_scanned_in_git_mode(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    calls = _fake(monkeypatch, {"gitleaks": "/opt/bin/gitleaks"})
    scan.main([str(tmp_path)])
    assert calls[0][:2] == ["/opt/bin/gitleaks", "git"]


def test_no_default_path_exclusion(tmp_path, monkeypatch):
    calls = _fake(monkeypatch, {"schemathesis": "/opt/bin/schemathesis"})
    scan.main([str(tmp_path), "--api-url", "http://127.0.0.1:8000/openapi.json"])
    assert calls and "--exclude-path-regex" not in calls[0]


def test_cmd_and_bat_shims_are_refused(tmp_path, monkeypatch, capsys):
    calls = _fake(monkeypatch, {"semgrep": r"C:\tools\semgrep.CMD", "trivy": r"C:\tools\trivy.bat"})
    scan.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert calls == [], "a .cmd/.bat tool runs through cmd.exe, so it must not be started"
    assert "[semgrep] skipped" in out and "[trivy] skipped" in out
