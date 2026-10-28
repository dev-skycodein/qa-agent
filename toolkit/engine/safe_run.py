"""Start the app from profile.json with a forced-safe environment, run a command against it, stop the app.

  python safe_run.py --profile qa-report/profile.json [--port 8765] [--wait 90] -- <command ...>

Safety (aborts before starting anything):
  * profile.unsafe_vars must be empty (env vars pointing at remote hosts that are not overridden)
  * every env override value that is a URL must be localhost
  * outbound keys (blank_keys) are exported as empty strings; they win over the project's .env
  * run_cmd must contain no remote host
The command gets QA_BASE_URL (and QA_SINK_LOG). The app process tree is killed on exit.

Extra profile keys:
  sink         (default true) start engine/sink.py: ALL outbound HTTP(S) from the app is routed to a local sink that records and
               blocks it; SMTP is captured. {sink_http} {sink_smtp_host} {sink_smtp_port} {sink_smtp} can be used in
               env_overrides values (e.g. "LLM_BASE_URL": "{sink_http}", "SMTP_HOST": "{sink_smtp_host}") to see full payloads.
  sink_allow   hosts tunnelled instead of blocked (default: pypi.org, files.pythonhosted.org, registry.npmjs.org,
               registry.yarnpkg.com: launchers like uv / npm need them at start-up). Everything else is blocked.
  reset_cmd    shell command run in app_dir BEFORE the app starts (fresh DB: schema push + seed). Same env as the app.
               Skipped with --no-reset. Without it the DB keeps rows from earlier runs (results depend on table size).
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from api import urlopen_local  # noqa: E402  (health check must not go through an env proxy)

LOCAL = ("localhost", "127.0.0.1", "::1")
_URL_HOST = re.compile(r"[a-z][a-z0-9+.-]*://(?:[^/\s@]*@)?(\[[0-9a-f:]+\]|[^/\s:?#]+)", re.I)
_HOST_PORT = re.compile(r"(?<![\w./@-])((?:[a-z0-9-]+\.)+[a-z]{2,24}):\d{2,5}\b", re.I)
_FILE_EXT = {"py", "js", "ts", "json", "yml", "yaml", "txt", "md", "sh", "cfg", "toml", "ini", "env", "lock", "db", "sql", "xml", "html"}
_HOSTY_KEY = re.compile(r"HOST|SERVER|ENDPOINT|URI|URL|ADDR|DSN", re.I)
_DOTTED = re.compile(r"(?:[a-z0-9-]+\.)+([a-z]{2,24})", re.I)
_OLD_DENY = ("mongodb+srv", ".mongodb.net", "amazonaws.com")


def _is_local(host: str) -> bool:
    host = host.strip("[]").lower()
    return host in LOCAL or host.startswith("127.") or host.startswith("{") or host == ""


def remote_hosts(text: str) -> list:
    """Hosts in a command line / env value that are not this machine: scheme://host URLs, dotted host:port pairs, and the old
    denylist strings. A leaky allowlist beats a 3-string denylist, but it is still a heuristic: the real boundary is the sink."""
    found = [h for h in _URL_HOST.findall(text) if not _is_local(h)]
    found += [h for h in _HOST_PORT.findall(text) if h.rsplit(".", 1)[-1].lower() not in _FILE_EXT and not _is_local(h)]
    found += [d for d in _OLD_DENY if d in text]
    return sorted(set(found))


def check_safe(profile: dict) -> None:
    problems = []
    if profile.get("unsafe_vars"):
        problems.append(f"unsafe env vars (remote hosts, not overridden): {profile['unsafe_vars']}")
    for var, value in profile.get("env_overrides", {}).items():
        value = str(value)
        bad = remote_hosts(value)
        m = _DOTTED.fullmatch(value.strip())
        if m and _HOSTY_KEY.search(var) and m.group(1).lower() not in _FILE_EXT:      # DB_HOST=prod.db.example.com has no "://"
            bad.append(value.strip())
        if bad:
            problems.append(f"override {var} is not local: {value}")
    run_argv = profile.get("run_cmd_argv")
    run_cmd = profile.get("run_cmd")
    if run_argv is not None:
        if not isinstance(run_argv, list) or not run_argv or not all(isinstance(x, str) for x in run_argv):
            problems.append("run_cmd_argv must be a non-empty list of strings (preferred over shell run_cmd)")
        if remote_hosts(" ".join(run_argv)):
            problems.append(f"run_cmd_argv mentions a remote host: {remote_hosts(' '.join(run_argv))}")
        if isinstance(run_argv, list) and run_argv and str(run_argv[0]).lower().endswith((".cmd", ".bat")):
            problems.append("run_cmd_argv[0] is a .cmd/.bat script: Windows runs it through cmd.exe, so later arguments become shell text")
    elif run_cmd in (None, "", "unknown"):
        problems.append("run_cmd unknown: fill it in profile.json (or set run_cmd_argv as an argv list)")
    else:
        if remote_hosts(run_cmd):
            problems.append(f"run_cmd mentions a remote host: {remote_hosts(run_cmd)}")
        # shell=True runs the string as written: only for a profile that says it is trusted (fail closed: a missing key is NOT trust)
        if profile.get("trusted") is not True:
            problems.append("profile.trusted is not true: refuse shell run_cmd (set run_cmd_argv, or trusted=true for a profile you wrote or reviewed)")
    reset_argv = profile.get("reset_cmd_argv")
    if reset_argv is not None and (not isinstance(reset_argv, list) or not all(isinstance(x, str) for x in reset_argv)):
        problems.append("reset_cmd_argv must be a list of strings when set")
    if profile.get("reset_cmd") and not reset_argv:
        if profile.get("trusted") is not True:
            problems.append("profile.trusted is not true: refuse shell reset_cmd (set reset_cmd_argv)")
        if remote_hosts(profile["reset_cmd"]):
            problems.append(f"reset_cmd mentions a remote host: {remote_hosts(profile['reset_cmd'])}")
    if reset_argv and remote_hosts(" ".join(map(str, reset_argv))):
        problems.append("reset_cmd_argv mentions a remote host")
    if problems:
        sys.exit("safe_run REFUSED:\n  - " + "\n  - ".join(problems))


def kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass


def main():
    argv = sys.argv[1:]
    cmd = argv[argv.index("--") + 1:] if "--" in argv else []
    p = argparse.ArgumentParser()
    p.add_argument("--profile", required=True)
    p.add_argument("--port", type=int)
    p.add_argument("--app-dir", help="override profile.app_dir (e.g. a throwaway git worktree)")
    p.add_argument("--wait", type=int, default=90)
    p.add_argument("--no-sink", action="store_true", help="do not start the outbound sink (not recommended)")
    p.add_argument("--no-reset", action="store_true", help="skip profile.reset_cmd")
    a = p.parse_args(argv[:argv.index("--")] if "--" in argv else argv)
    profile = json.load(open(a.profile, encoding="utf-8"))
    if a.app_dir:
        profile["app_dir"] = a.app_dir
    check_safe(profile)

    port = a.port or profile["port"]
    profile_dir = os.path.dirname(os.path.abspath(a.profile))
    sink = None
    overrides = dict(profile["env_overrides"])
    if profile.get("sink", True) and not a.no_sink:
        from sink import Sink
        sink = Sink(os.path.join(profile_dir, "sink.jsonl"), allow=profile.get("sink_allow"))
        for var, value in overrides.items():
            for ph, real in sink.placeholders().items():
                value = value.replace(ph, real)
            overrides[var] = value
    env = {**os.environ, "PYTHONUTF8": "1", "PORT": str(port), **overrides, **{k: "" for k in profile["blank_keys"]}}
    cmd_env = {**env, "QA_APP_DIR": profile["app_dir"]}
    if sink:
        cmd_env["QA_SINK_LOG"] = os.path.join(profile_dir, "sink.jsonl")
    if sink:
        env.update(sink.env())                      # the app (not the engines) talks to the world only through the sink
        print(f"[safe_run] outbound sink on {sink.http_url} (smtp :{sink.smtp_port}); all app egress is recorded and blocked", flush=True)
    base = f"http://127.0.0.1:{port}"
    run_argv = profile.get("run_cmd_argv")
    if run_argv:
        run_argv = [x.replace("{port}", str(port)) for x in run_argv]
        run_display = " ".join(run_argv)
        use_shell = False
    else:
        run_display = profile["run_cmd"].replace("{port}", str(port))
        run_argv = run_display
        use_shell = True
        print("[safe_run] WARNING: using shell=True for run_cmd; prefer profile.run_cmd_argv (list) to avoid shell injection",
              flush=True)
    if (profile.get("reset_cmd") or profile.get("reset_cmd_argv")) and not a.no_reset:
        reset_argv = profile.get("reset_cmd_argv")
        if reset_argv:
            print(f"[safe_run] reset: {reset_argv}", flush=True)
            reset = subprocess.run(reset_argv, shell=False, cwd=profile["app_dir"], env=env, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace")
        else:
            print(f"[safe_run] reset: {profile['reset_cmd']}", flush=True)
            reset = subprocess.run(profile["reset_cmd"], shell=True, cwd=profile["app_dir"], env=env, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace")
        if reset.returncode != 0:
            sys.exit(f"[safe_run] reset_cmd failed ({reset.returncode}): "
                 f"{(reset.stdout + reset.stderr)[-1500:]}")
    log = open(os.path.join(profile_dir, "app.log"), "w", encoding="utf-8")
    print(f"[safe_run] starting: {run_display}  (cwd={profile['app_dir']})", flush=True)
    proc = subprocess.Popen(run_argv, shell=use_shell, cwd=profile["app_dir"], env=env, stdout=log, stderr=subprocess.STDOUT,
                            **({} if os.name == "nt" else {"start_new_session": True}))
    code = 1
    try:
        health = base + profile.get("health_path", "/")
        deadline = time.time() + a.wait
        while time.time() < deadline:
            if proc.poll() is not None:
                sys.exit(f"[safe_run] app exited early (code {proc.returncode}); see app.log next to profile.json")
            try:
                urlopen_local(health, timeout=3)
                break
            except urllib.error.HTTPError:
                break  # server answered
            except OSError:
                time.sleep(1)
        else:
            sys.exit(f"[safe_run] app not healthy at {health} after {a.wait}s; see app.log")
        print(f"[safe_run] up at {base}", flush=True)
        if cmd:
            code = subprocess.run(cmd, env={**cmd_env, "QA_BASE_URL": base}).returncode
        else:
            print("[safe_run] no command given; stopping", flush=True)
            code = 0
    finally:
        kill_tree(proc)
        log.close()
        if sink:
            sink.stop()
    sys.exit(code)


if __name__ == "__main__":
    main()
