"""Local QA console: run the engines against a registered target, keep every run, compare runs, look at them in a browser.
No Claude needed, stdlib only (Python 3.11+).

  python qa_console.py targets                       # registered targets (targets/<name>.toml)
  python qa_console.py run demo-flask-shop           # run engines, store runs/<id>/
        [--seeds 1,2,3] [--canary] [--fail-on-findings] [--strict]
  python qa_console.py runs                          # all runs, newest first, with trust verdict
  python qa_console.py show <run-id|latest>          # trust table + findings of one run
  python qa_console.py diff <old> <new>              # NEW / FIXED / PERSISTENT findings between two runs
  python qa_console.py replay <run-id|latest>        # the exact command that produced the run
  python qa_console.py serve [--port 0]              # read-only page on 127.0.0.1 (prints a URL with a random token)

A run folder is immutable once written:  runs/<id>/manifest.json  engines.json  trust.json  findings.jsonl  run.log
Exit codes of `run`: 0 clean / 1 findings (with --fail-on-findings) / 2 an engine broke / 3 UNTRUSTED (canary failed).
Honest limit: it runs the checks a target's qa-spec.py defines. "No findings" is never "no bugs".
"""
import argparse
import datetime
import hashlib
import html
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "toolkit" / "engine"
RUNS = ROOT / "runs"
TARGETS = ROOT / "targets"
EXIT_OK, EXIT_FINDINGS, EXIT_BROKE, EXIT_UNTRUSTED = 0, 1, 2, 3
sys.path.insert(0, str(ENGINE))
import stats  # noqa: E402
import trust  # noqa: E402


# ---------- data model ----------

HEAD_ONLY_KINDS = {"STATEFUL-INVARIANT", "OUTBOUND-LEAK", "RACE-INVARIANT", "SCENARIO", "DB-INVARIANT"}


def fingerprint(f: dict) -> str:
    """Stable id of a finding across runs: ids/numbers in the detail are normalised away."""
    detail = str(f.get("detail", "")).split(" e.g. ")[0]
    if f.get("kind") in HEAD_ONLY_KINDS:                       # "<check name>: <example values>": the values differ on every run
        detail = detail.split(":")[0]
    detail = re.sub(r"[0-9a-f]{24}|\d+", "#", detail)[:120]
    endpoint = re.sub(r"\d+", "#", str(f.get("endpoint")))     # sink/ephemeral ports in "127.0.0.1:53059"
    return hashlib.sha1(f"{f.get('kind')}|{endpoint}|{detail}".encode()).hexdigest()[:12]


TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def load_target(name: str) -> dict:
    if not TARGET_NAME.fullmatch(name):
        raise SystemExit(f"target name {name!r} is not allowed (letters, digits, _ . - only)")
    path = TARGETS / f"{name}.toml"
    if not path.exists():
        raise SystemExit(f"unknown target {name!r}; registered: {', '.join(t.stem for t in TARGETS.glob('*.toml')) or 'none'}")
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    cfg["name"] = name          # the CLI name wins: a target file cannot choose the run folder
    if "reset_cmd" in cfg:
        raise SystemExit(f"{path}: reset_cmd is a shell string; write reset_cmd_argv instead, a list such as "
                         "[\"python\", \"-c\", \"...\"] (no shell is involved)")
    argv = cfg.get("reset_cmd_argv")
    if argv is not None and not (isinstance(argv, list) and argv and all(isinstance(x, str) for x in argv)):
        raise SystemExit(f"{path}: reset_cmd_argv must be a non-empty list of strings")
    for key in ("profile", "spec"):
        if key not in cfg:
            raise SystemExit(f"{path}: missing required key {key!r}")
        cfg[key] = str((ROOT / cfg[key]).resolve()) if not Path(cfg[key]).is_absolute() else cfg[key]
    return cfg


def derive_profile(cfg: dict, run_dir: Path) -> dict:
    """Copy the target's profile into the run folder, adding the target's `reset_cmd` (fresh DB before EVERY seed, so seeds are
    independent). The run then uses, and keeps, exactly this profile. Returns cfg with `profile` pointing at the copy."""
    if not Path(cfg["profile"]).exists():
        raise SystemExit(f"profile not found: {cfg['profile']}\n"
                         f"  it is generated, not stored in git: run `python qa_console.py run {cfg['name']} --canary` "
                         "(the canary selftest writes it) or `python toolkit/engine/selftest.py` once")
    prof = json.loads(Path(cfg["profile"]).read_text(encoding="utf-8"))
    prof.pop("reset_cmd", None)                # a shell string never travels from a profile file into a run (only the argv form)
    if cfg.get("reset_cmd_argv"):
        prof["reset_cmd_argv"] = cfg["reset_cmd_argv"]
    run_dir.mkdir(parents=True, exist_ok=True)
    out = run_dir / "profile.json"
    out.write_text(json.dumps(prof, indent=2), encoding="utf-8")
    return {**cfg, "profile": str(out)}


def git_sha() -> str:
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "toolkit/engine"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        return sha + ("+dirty" if dirty else "")
    except OSError:
        return "unknown"


def build_cmd(cfg: dict, out: Path, seed: int | None, engines: str | None, *,
              shuffle_engines: bool = False, fail_on_findings: bool = False, strict: bool = False) -> list:
    cmd = [sys.executable, str(ENGINE / "safe_run.py"), "--profile", cfg["profile"], "--port", str(cfg.get("port", 8765)),
           "--wait", str(cfg.get("wait", 180)), "--", sys.executable, "-m", "uv", "run", "--no-project", "--python", "3.12"]
    for w in dict.fromkeys(["hypothesis", *cfg.get("with", [])]):
        cmd += ["--with", w]
    cmd += ["python", str(ENGINE / "run.py"), "--spec", cfg["spec"], "--out", str(out),
            "--examples", str(cfg.get("examples", 40)), "--steps", str(cfg.get("steps", 12))]
    if cfg.get("openapi"):
        cmd += ["--openapi", str(ROOT / cfg["openapi"]) if not Path(cfg["openapi"]).is_absolute() else cfg["openapi"]]
    if engines or cfg.get("engines"):
        cmd += ["--engines", engines or cfg["engines"]]
    if seed is not None:
        cmd += ["--seed", str(seed)]
    if shuffle_engines:
        cmd.append("--shuffle-engines")
    if fail_on_findings:
        cmd.append("--fail-on-findings")
    if strict:
        cmd.append("--strict")
    return cmd


def read_run(run_dir: Path) -> dict:
    def load(name, default):
        try:
            return json.loads((run_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default
    findings = []
    try:
        findings = [json.loads(l) for l in (run_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError:
        pass
    for f in findings:
        f["fingerprint"] = fingerprint(f)                       # recomputed on read: old runs follow the current rules, files stay untouched
    return {"id": run_dir.name, "manifest": load("manifest.json", {}), "trust": load("trust.json", {}),
            "engines": load("engines.json", []), "findings": findings}


def list_runs() -> list:
    if not RUNS.exists():
        return []
    return [read_run(d) for d in sorted((p for p in RUNS.iterdir() if p.is_dir()), reverse=True)]


def resolve_run(ref: str) -> dict:
    runs = list_runs()
    if not runs:
        raise SystemExit("no runs yet: python qa_console.py run <target>")
    if ref == "latest":
        return runs[0]
    hits = [r for r in runs if r["id"] == ref or r["id"].startswith(ref)]
    if len(hits) != 1:
        raise SystemExit(f"run {ref!r} {'is ambiguous' if hits else 'not found'}")
    return hits[0]


def seed_count(r: dict) -> int:
    """Seeds the run really executed (manifest), not just the seeds that happened to produce a finding."""
    return len(r["manifest"].get("seeds") or [None])


def hit_rate(k: int, n: int) -> str:
    """'' for a single run; else 'k/n seeds (95% CI lo-hi)': 8/8 is a rate with an interval, never '100%'."""
    if n <= 1:
        return ""
    lo, hi = stats.wilson(k, n)
    return f"{k}/{n} seeds (95% CI {lo:.0%}-{hi:.0%})"


def run_state(r: dict) -> str:
    """One word for a run: UNTRUSTED (canary), BROKEN (engine errored), PARTIAL (degraded/skipped), FULL (all engines ran)."""
    m, t = r["manifest"], r["trust"]
    if m.get("canary") == "fail":
        return "UNTRUSTED"
    if not t or t.get("errored"):
        return "BROKEN"
    if t.get("degraded") or t.get("setup_failed") or t.get("skipped"):
        return "PARTIAL"
    return "FULL"


# ---------- commands ----------

def cmd_targets(_a):
    for t in sorted(TARGETS.glob("*.toml")):
        cfg = tomllib.loads(t.read_text(encoding="utf-8"))
        print(f"{t.stem:24} spec={cfg.get('spec')}  profile={cfg.get('profile')}")
    return EXIT_OK


def run_canary() -> bool:
    print("[console] canary: engine selftest ...", flush=True)
    p = subprocess.run([sys.executable, str(ENGINE / "selftest.py")], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env={**os.environ, "PYTHONUTF8": "1"})
    print("[console] canary", "PASS" if p.returncode == 0 else "FAIL: " + (p.stdout.strip().splitlines() or ["?"])[-1])
    return p.returncode == 0


def cmd_run(a):
    cfg = load_target(a.target)
    seeds = [int(s) for s in a.seeds.split(",")] if a.seeds else [None]
    canary = None
    if a.canary:
        canary = "pass" if run_canary() else "fail"
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = RUNS / f"{stamp}-{cfg['name']}"
    run_dir.mkdir(parents=True, exist_ok=False)
    cfg = derive_profile(cfg, run_dir)
    worst = EXIT_OK
    all_findings, log_parts, cmds = [], [], []
    for i, seed in enumerate(seeds):
        out = run_dir / (f"seed-{seed}" if seed is not None else "engines-out")
        cmd = build_cmd(cfg, out, seed, a.engines, shuffle_engines=getattr(a, "shuffle_engines", False),
                        fail_on_findings=a.fail_on_findings, strict=a.strict)
        cmds.append(cmd)
        print(f"[console] {cfg['name']} seed={seed} ...", flush=True)
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env={**os.environ, "PYTHONUTF8": "1"})
        log_parts.append(f"$ {' '.join(cmd)}\n{p.stdout}\n{p.stderr}\n[exit {p.returncode}]\n")
        try:
            results = json.loads((out / "engines.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            results = [{"engine": "harness", "findings": [], "engine-error": f"no engines.json produced (exit {p.returncode}); see run.log"}]
        for r in results:
            for f in r.get("findings", []):
                all_findings.append({**f, "engine": r["engine"], "seed": seed, "fingerprint": fingerprint(f)})
        worst = max(worst, trust.exit_code(results, a.fail_on_findings, a.strict))
        if i == 0:
            base = results                                   # trust table of the first seed stands for the run
        else:                                                # a later seed that errored, degraded, failed setup or was skipped taints the run
            base = base + [{**r, "status_reason": f"seed {seed}: {trust.resolve(r)[1]}"}
                           for r in results if trust.resolve(r)[0] != trust.RAN_OK]
    summary = trust.summarize(base)
    (run_dir / "engines.json").write_text(json.dumps(base, indent=2, default=str), encoding="utf-8")
    (run_dir / "trust.json").write_text(json.dumps({**summary, "verdict": trust.verdict(summary)}, indent=2), encoding="utf-8")
    (run_dir / "findings.jsonl").write_text("".join(json.dumps(f, default=str) + "\n" for f in all_findings), encoding="utf-8")
    (run_dir / "run.log").write_text("\n".join(log_parts), encoding="utf-8")
    manifest = {"target": cfg["name"], "started": stamp, "git": git_sha(), "seeds": seeds, "canary": canary,
                "commands": cmds, "exit": worst, "n_findings": len({f["fingerprint"] for f in all_findings})}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print_run(read_run(run_dir))
    if canary == "fail":
        print("RESULT: UNTRUSTED - the canary (engine selftest) failed, so this run is not counted as evidence.")
        return EXIT_UNTRUSTED
    return worst


def print_run(r: dict):
    m, t = r["manifest"], r["trust"]
    print(f"\nrun {r['id']}  target={m.get('target')}  git={m.get('git')}  canary={m.get('canary')}  state={run_state(r)}")
    for row in t.get("engines", []):
        print(f"  {row['engine']:10} {row['status']:16} findings={row['findings']:<3} {row['reason']}")
    print("  " + t.get("verdict", "no trust data"))
    seen = {}
    for f in r["findings"]:
        seen.setdefault(f["fingerprint"], []).append(f)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}     # alphabetical order put info before low
    for fp, group in sorted(seen.items(), key=lambda kv: rank.get(kv[1][0].get("severity"), 9)):
        f = group[0]
        k = len({g.get("seed") for g in group})
        print(f"  [{f['severity']:6}] {f['kind']:20} {f['endpoint']}  {hit_rate(k, seed_count(r))}  {fp}\n"
              f"           {str(f['detail'])[:150]}")


def cmd_runs(_a):
    for r in list_runs():
        m = r["manifest"]
        print(f"{r['id']:34} {run_state(r):10} findings={m.get('n_findings', '?'):<3} git={m.get('git')} canary={m.get('canary')}")
    return EXIT_OK


def cmd_show(a):
    print_run(resolve_run(a.run))
    return EXIT_OK


def diff_runs(old: dict, new: dict) -> dict:
    o = {f["fingerprint"]: f for f in old["findings"]}
    n = {f["fingerprint"]: f for f in new["findings"]}
    return {"new": [n[k] for k in n.keys() - o.keys()], "fixed": [o[k] for k in o.keys() - n.keys()],
            "persistent": [n[k] for k in n.keys() & o.keys()]}


def cmd_diff(a):
    old, new = resolve_run(a.old), resolve_run(a.new)
    d = diff_runs(old, new)
    print(f"{old['id']} ({run_state(old)})  ->  {new['id']} ({run_state(new)})")
    for label in ("new", "fixed", "persistent"):
        print(f"\n{label.upper()} ({len(d[label])})")
        for f in d[label]:
            print(f"  [{f['severity']}] {f['kind']} {f['endpoint']} - {str(f['detail'])[:110]}")
    if "UNTRUSTED" in (run_state(old), run_state(new)) or "BROKEN" in (run_state(old), run_state(new)):
        print("\nWARNING: one side is UNTRUSTED/BROKEN: 'fixed' may just mean the engine did not run.")
    return EXIT_OK


def cmd_replay(a):
    r = resolve_run(a.run)
    for c in r["manifest"].get("commands", []):
        print(subprocess.list2cmdline(c))
    return EXIT_OK


# ---------- read-only web page ----------

CSS = """:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--card:#f6f8fa;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--card:#161b22;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1040px;padding:16px}
h1{font-size:22px}h2{font-size:17px;margin-top:28px}a{color:inherit}table{border-collapse:collapse;width:100%}
td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}
.pill{border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600;border:1px solid currentColor}
.FULL,.ran_ok{color:var(--ok)}.PARTIAL,.degraded,.setup_failed,.skipped_no_spec{color:var(--warn)}.BROKEN,.UNTRUSTED,.errored,.high,.critical{color:var(--bad)}
.banner{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
code,pre{font:13px ui-monospace,monospace}pre{background:var(--card);padding:10px;overflow:auto;border-radius:6px}.mut{color:var(--mut)}"""


def esc(x) -> str:
    return html.escape(str(x))


def page(title: str, body: str) -> bytes:
    return (f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{esc(title)}</title><style>{CSS}</style><body>{body}</body></html>").encode()


def view_index(tok: str) -> bytes:
    rows = "".join(
        f"<tr><td><a href='/run/{esc(r['id'])}?t={tok}'>{esc(r['id'])}</a></td><td><span class='pill {run_state(r)}'>{run_state(r)}</span></td>"
        f"<td>{esc(r['manifest'].get('n_findings', '?'))}</td><td>{esc(r['manifest'].get('git', ''))}</td><td>{esc(r['manifest'].get('canary'))}</td></tr>"
        for r in list_runs())
    return page("QA runs", f"<h1>QA runs</h1><p class=mut>Read-only view of runs/. A green FULL means every engine ran; it does not mean no bugs.</p>"
                f"<table><tr><th>run<th>state<th>distinct findings<th>git<th>canary</tr>{rows}</table>")


def view_run(r: dict, tok: str, prev: dict | None) -> bytes:
    t, m = r["trust"], r["manifest"]
    eng = "".join(f"<tr><td>{esc(e['engine'])}<td><span class='pill {e['status']}'>{esc(e['status'])}</span><td>{e['findings']}<td>{esc(e['reason'])}</tr>"
                  for e in t.get("engines", []))
    groups = {}
    for f in r["findings"]:
        groups.setdefault(f["fingerprint"], []).append(f)
    nseeds = seed_count(r)
    fr = "".join(
        f"<tr><td><span class='{esc(g[0]['severity'])}'>{esc(g[0]['severity'])}</span><td>{esc(g[0]['kind'])}<td><code>{esc(g[0]['endpoint'])}</code>"
        f"<td>{esc(hit_rate(len({x.get('seed') for x in g}), nseeds) or 'single run')}<td>{esc(str(g[0]['detail'])[:300])}"
        + (f"<pre>{esc(g[0]['sequence'])}</pre>" if g[0].get("sequence") else "") + "</tr>" for g in groups.values())
    dtxt = ""
    if prev:
        d = diff_runs(prev, r)
        dtxt = (f"<h2>Diff vs {esc(prev['id'])}</h2><p>new {len(d['new'])} · fixed {len(d['fixed'])} · persistent {len(d['persistent'])}</p>"
                + "".join(f"<p><b>NEW</b> {esc(f['kind'])} <code>{esc(f['endpoint'])}</code></p>" for f in d["new"])
                + "".join(f"<p><b>FIXED</b> {esc(f['kind'])} <code>{esc(f['endpoint'])}</code></p>" for f in d["fixed"]))
    cmds = "\n".join(subprocess.list2cmdline(c) for c in m.get("commands", []))
    body = (f"<p><a href='/?t={tok}'>&larr; all runs</a></p><h1>{esc(r['id'])} <span class='pill {run_state(r)}'>{run_state(r)}</span></h1>"
            f"<div class=banner>{esc(t.get('verdict', 'no trust data'))}<br><span class=mut>git {esc(m.get('git'))} · canary {esc(m.get('canary'))} · seeds {esc(m.get('seeds'))}</span></div>"
            f"<h2>Engines</h2><table><tr><th>engine<th>status<th>findings<th>reason</tr>{eng}</table>"
            f"<h2>Findings</h2><table><tr><th>severity<th>kind<th>endpoint<th>seeds<th>detail</tr>{fr or '<tr><td colspan=5 class=mut>none</tr>'}</table>"
            f"{dtxt}<h2>Reproduce</h2><pre>{esc(cmds)}</pre>")
    return page(r["id"], body)


def make_handler(token: str, port_holder: list):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, data, ctype="text/html; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):                 # DNS-rebinding guard
                return self._send(403, b"bad host", "text/plain")
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if not secrets.compare_digest(q.get("t", [""])[0], token):
                return self._send(403, b"missing or wrong token: use the URL printed by `qa_console.py serve`", "text/plain")
            if u.path == "/":
                return self._send(200, view_index(token))
            m = re.fullmatch(r"/run/([\w.\-]+)", u.path)
            if m:
                runs = list_runs()
                ids = [r["id"] for r in runs]
                if m.group(1) in ids:                                   # id is looked up, never joined into a path
                    i = ids.index(m.group(1))
                    same = [r for r in runs[i + 1:] if r["manifest"].get("target") == runs[i]["manifest"].get("target")]
                    return self._send(200, view_run(runs[i], token, same[0] if same else None))
            return self._send(404, b"not found", "text/plain")

        do_POST = do_PUT = do_DELETE = lambda self: self._send(405, b"read-only", "text/plain")
    return H


def cmd_serve(a):
    token = secrets.token_urlsafe(16)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(token, []))
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={token}"
    print(f"QA console (read-only, this machine only): {url}\nCtrl+C to stop.", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return EXIT_OK


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("targets")
    r = sub.add_parser("run")
    r.add_argument("target")
    r.add_argument("--seeds", help="comma list, e.g. 1,2,3 (default: one unseeded run)")
    r.add_argument("--engines")
    r.add_argument("--canary", action="store_true", help="run the engine selftest first; a failure marks the run UNTRUSTED")
    r.add_argument("--fail-on-findings", action="store_true")
    r.add_argument("--strict", action="store_true")
    r.add_argument("--shuffle-engines", action="store_true",
                   help="pass --shuffle-engines to run.py (randomise engine order; D3 order-dependence check)")
    sub.add_parser("runs")
    for name in ("show", "replay"):
        sub.add_parser(name).add_argument("run")
    d = sub.add_parser("diff")
    d.add_argument("old")
    d.add_argument("new")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=0)
    a = ap.parse_args(argv)
    return {"targets": cmd_targets, "run": cmd_run, "runs": cmd_runs, "show": cmd_show, "diff": cmd_diff,
            "replay": cmd_replay, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
