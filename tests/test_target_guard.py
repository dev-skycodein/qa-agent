"""A target file cannot run a shell command or choose the run folder (pre-publication audit, qa-toolkit-run-1)."""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import qa_console  # noqa: E402


def _targets(tmp, body, name="x"):
    d = Path(tmp)
    (d / f"{name}.toml").write_text(body, encoding="utf-8")
    return d


def test_target_name_with_path_parts_is_refused():
    try:
        qa_console.load_target("../evil")
    except SystemExit as e:
        assert "not allowed" in str(e)
    else:
        raise AssertionError("path-like target name was accepted")


def test_reset_cmd_string_in_a_target_file_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        old = qa_console.TARGETS
        qa_console.TARGETS = _targets(tmp, 'profile = "p.json"\nspec = "s.py"\nreset_cmd = "rm -rf ~"\n')
        try:
            qa_console.load_target("x")
        except SystemExit as e:
            assert "reset_cmd_argv" in str(e)
        else:
            raise AssertionError("shell reset_cmd from a target was accepted")
        finally:
            qa_console.TARGETS = old


def test_cli_name_wins_over_the_name_in_the_target_file():
    with tempfile.TemporaryDirectory() as tmp:
        old = qa_console.TARGETS
        qa_console.TARGETS = _targets(tmp, 'name = "../../elsewhere"\nprofile = "p.json"\nspec = "s.py"\n', name="ok")
        try:
            cfg = qa_console.load_target("ok")
            assert cfg["name"] == "ok"
        finally:
            qa_console.TARGETS = old


def test_a_shell_reset_inside_a_profile_file_is_dropped_on_derive():
    with tempfile.TemporaryDirectory() as tmp:
        prof = Path(tmp) / "p.json"
        prof.write_text('{"run_cmd_argv": ["python", "app.py"], "reset_cmd": "rm -rf x", "trusted": true}', encoding="utf-8")
        out = qa_console.derive_profile({"name": "x", "profile": str(prof)}, Path(tmp) / "run")
        copied = __import__("json").loads(Path(out["profile"]).read_text(encoding="utf-8"))
        assert "reset_cmd" not in copied


def test_argv_reset_is_copied_to_the_run_profile_and_string_reset_is_not():
    with tempfile.TemporaryDirectory() as tmp:
        prof = Path(tmp) / "p.json"
        prof.write_text('{"run_cmd_argv": ["python", "app.py"]}', encoding="utf-8")
        cfg = {"name": "x", "profile": str(prof), "reset_cmd_argv": ["python", "-c", "pass"]}
        out = qa_console.derive_profile(cfg, Path(tmp) / "run")
        copied = __import__("json").loads(Path(out["profile"]).read_text(encoding="utf-8"))
        assert copied["reset_cmd_argv"] == ["python", "-c", "pass"]
        assert "reset_cmd" not in copied


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok {name}")
    print("test_target_guard: all passed")
