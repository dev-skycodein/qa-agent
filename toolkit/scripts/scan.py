"""Run the optional static scanners on a project and write their reports to <path>/qa-report/.

  python scan.py [path] [--api-url http://127.0.0.1:8000/openapi.json] [--exclude-paths "^/(chat|search)"]

Cross-platform replacement for scan.ps1 (same tools, same output files). Each tool is optional: a missing one is printed and
skipped. --api-url must be LOCAL, never production. --exclude-paths has no default (scan.ps1 excluded one project's routes).
Arguments are passed as argv lists, never through a shell, so the path needs no quoting rules.
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine"))
import api as _api  # noqa: E402  (same local-only rule as every engine request)

LEARNED = Path(__file__).resolve().parent.parent / "rules" / "learned"
SKIP_DIRS = ("node_modules", "venv", ".venv", ".claude", "qa-report")
ENV = {**os.environ, "PYTHONUTF8": "1"}    # semgrep crashes on cp1252 when writing emoji


def _tool(name, missing):
    """Full path of a tool, or None (printing why). A .cmd/.bat shim is refused, as in safe_run.py: Windows runs it through
    cmd.exe, so an argument such as the regex ^/(a|b) would become shell text."""
    exe = shutil.which(name)
    if not exe:
        print(f"[{name}] {missing}")
        return None
    if exe.lower().endswith((".cmd", ".bat")):
        print(f"[{name}] skipped: {exe} is a .cmd/.bat shim (its arguments would pass through cmd.exe); install the .exe")
        return None
    return exe


def _run(name, argv, stdout=None):
    """Run one tool; a non-zero exit is printed, never fatal (scanners exit 1 when they find something)."""
    code = subprocess.run(argv, env=ENV, stdout=stdout, stderr=subprocess.STDOUT if stdout else None).returncode
    if code:
        print(f"[{name}] exit {code}", flush=True)


def _files(root: Path, pattern: str) -> list:
    return sorted(p for p in root.rglob(pattern) if not any(part in SKIP_DIRS for part in p.parts))


def semgrep(path: Path, out: Path):
    exe = _tool("semgrep", "missing -> pip install semgrep")
    if not exe:
        return
    print("[semgrep] running", flush=True)
    _run("semgrep", [exe, "scan", "--metrics=off", "--config", "p/default", "--config", "p/owasp-top-ten",
                     "--config", "p/secrets", "--sarif", "-o", str(out / "semgrep.sarif"), str(path)])
    if list(LEARNED.glob("*.yaml")):
        print("[semgrep] learned rules", flush=True)
        _run("semgrep", [exe, "scan", "--metrics=off", "--config", str(LEARNED), "--sarif",
                         "-o", str(out / "semgrep-learned.sarif"), str(path)])


def gitleaks(path: Path, out: Path):
    exe = _tool("gitleaks", "missing -> https://github.com/gitleaks/gitleaks#installing")
    if not exe:
        return
    print("[gitleaks] running", flush=True)
    mode = "git" if (path / ".git").exists() else "dir"      # git repo -> committed history only (gitignored .env/venv = noise)
    _run("gitleaks", [exe, mode, str(path), "--report-format", "json", "--report-path", str(out / "gitleaks.json"),
                      "--no-banner", "--redact"])


def osv(path: Path, out: Path):
    exe = _tool("osv-scanner", "missing -> https://google.github.io/osv-scanner/installation/ (or npm audit)")
    if not exe:
        return
    print("[osv-scanner] running", flush=True)
    locks = []
    for req in _files(path, "requirements*.txt"):        # unpinned requirements -> osv guesses versions: resolve real pins with uv
        lock = out / f"resolved-{req.parent.name}-{req.stem}.txt"
        subprocess.run([sys.executable, "-m", "uv", "pip", "compile", str(req), "-o", str(lock), "-q"], env=ENV,
                       capture_output=True)
        if lock.exists():
            locks += ["-L", f"requirements.txt:{lock}"]
    for lock in _files(path, "package-lock.json"):
        locks += ["-L", str(lock)]
    target = locks if locks else ["source", "-r", str(path)]
    _run("osv-scanner", [exe, "scan", *target, "--format", "json", "--output", str(out / "osv.json")])


def trivy(path: Path, out: Path):
    exe = _tool("trivy", "optional, missing")
    if not exe:
        return
    print("[trivy] running (vuln+secret+misconfig)", flush=True)
    _run("trivy", [exe, "fs", "--scanners", "vuln,secret,misconfig", "--format", "sarif", "-o", str(out / "trivy.sarif"),
                   str(path)])


def ubs(path: Path, out: Path):
    bash = shutil.which("bash")
    if not bash or bash.lower().endswith((".cmd", ".bat")) or \
            subprocess.run([bash, "-lc", "command -v ubs"], capture_output=True).returncode:
        return print("[ubs] optional, missing")
    print("[ubs] running (logic bug patterns)", flush=True)
    with open(out / "ubs.json", "w", encoding="utf-8") as fh:      # the path is $1, not part of the script text
        _run("ubs", [bash, "-lc", 'ubs "$1" --format=json', "_", str(path)], stdout=fh)


def schemathesis(api_url: str, exclude: str, out: Path):
    exe = _tool("schemathesis", "missing -> python -m uv tool install schemathesis --python 3.12")
    if not exe:
        return
    print(f"[schemathesis] fuzzing {api_url}", flush=True)
    argv = [exe, "run", api_url, "-c", "not_a_server_error,response_schema_conformance"]   # real-bug checks only
    if exclude:
        argv += ["--exclude-path-regex", exclude]
    with open(out / "schemathesis.txt", "w", encoding="utf-8") as fh:
        _run("schemathesis", argv, stdout=fh)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--api-url", default="", help="LOCAL OpenAPI URL for schemathesis (127.0.0.1, localhost or [::1])")
    p.add_argument("--exclude-paths", default="", help="regex of API paths schemathesis skips (default: none)")
    a = p.parse_args(argv)
    if a.api_url:
        try:
            _api.assert_local(a.api_url)
        except SystemExit as exc:
            print(exc, file=sys.stderr)
            return 2
    path = Path(a.path).resolve()
    if not path.is_dir():
        print(f"not a directory: {path}", file=sys.stderr)
        return 2
    out = path / "qa-report"
    out.mkdir(parents=True, exist_ok=True)
    semgrep(path, out)
    gitleaks(path, out)
    osv(path, out)
    trivy(path, out)
    ubs(path, out)
    if a.api_url:
        schemathesis(a.api_url, a.exclude_paths, out)
    print(f"done -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
