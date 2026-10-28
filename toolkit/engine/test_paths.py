"""Tests for paths.py: where the repo and the target clones live, without any machine-specific literal.

  python toolkit/engine/test_paths.py        (also collectable by pytest)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paths  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent


def test_home_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("QA_HOME", str(tmp_path))
    assert paths.home() == tmp_path.resolve()


def test_home_default_is_repo_root(monkeypatch):
    monkeypatch.delenv("QA_HOME", raising=False)
    assert paths.home() == REPO and (paths.home() / "qa_check.py").is_file()


def test_targets_root_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("QA_TARGETS_DIR", str(tmp_path))
    assert paths.targets_root() == tmp_path.resolve()


def test_targets_root_default_is_sibling_of_home(monkeypatch):
    monkeypatch.delenv("QA_HOME", raising=False)
    monkeypatch.delenv("QA_TARGETS_DIR", raising=False)
    assert paths.targets_root() == paths.home().parent


def test_source_has_no_users_directory_literal():
    text = (Path(paths.__file__)).read_text(encoding="utf-8")
    assert "Users" not in text.replace("Users directory", "")
