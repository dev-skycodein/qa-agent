"""check_safe() refusals: remote hosts in commands/env, and fail-closed trust for shell commands.

  python toolkit/engine/test_safe_run.py        (stdlib only; also collectable by pytest)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safe_run  # noqa: E402


def base(**kw):
    p = {"run_cmd_argv": ["python", "app.py", "--port", "{port}"], "env_overrides": {}, "blank_keys": [], "unsafe_vars": []}
    p.update(kw)
    return p


def refused(profile) -> str:
    try:
        safe_run.check_safe(profile)
    except SystemExit as e:
        return str(e)
    return ""


def test_local_profile_passes():
    assert refused(base(env_overrides={"DB_URL": "postgres://u:p@localhost:5433/db", "SMTP_HOST": "{sink_smtp_host}",
                                       "DB": "sqlite:///x.db", "PORT": "8000"})) == ""


def test_remote_url_in_env_override_refused():
    assert "DB_URL" in refused(base(env_overrides={"DB_URL": "postgres://u:p@db.prod.example.com:5432/x"}))


def test_bare_remote_hostname_in_host_var_refused():
    """No '://' in the value: the old check let this through."""
    assert "DB_HOST" in refused(base(env_overrides={"DB_HOST": "db.prod.example.com"}))


def test_remote_host_in_command_refused_beyond_the_old_denylist():
    assert refused(base(run_cmd_argv=["python", "app.py", "--db", "https://api.stripe.com/v1"]))
    assert refused(base(run_cmd_argv=["psql", "-h", "prod.db.example.com:5432"]))
    assert refused(base(run_cmd_argv=["python", "app.py", "mongodb+srv://x"]))      # old denylist still works


def test_file_names_with_a_colon_are_not_hosts():
    assert refused(base(run_cmd_argv=["python", "-m", "pytest", "tests/test_x.py:12", "app.py:8000"])) == ""


def test_shell_run_cmd_needs_explicit_trust():
    shell = {"run_cmd": "python app.py --port {port}", "env_overrides": {}, "blank_keys": [], "unsafe_vars": []}
    assert "trusted" in refused(dict(shell))                         # missing key = not trusted (was fail-open)
    assert "trusted" in refused({**shell, "trusted": False})
    assert refused({**shell, "trusted": True}) == ""


def test_shell_reset_cmd_needs_trust_and_stays_local():
    p = base(reset_cmd="python seed.py")
    assert "reset_cmd" in refused(p)
    assert refused({**p, "trusted": True}) == ""
    assert "remote host" in refused({**p, "trusted": True, "reset_cmd": "psql postgres://u@db.example.com/x -f s.sql"})


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print("ok  ", name)
    print(f"SAFE_RUN OK: {len(tests)} tests")
