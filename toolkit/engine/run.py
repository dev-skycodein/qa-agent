"""Run the generic engines against a LOCAL running app.

  python run.py --base-url http://127.0.0.1:8765 --spec qa-report/qa-spec.py \
                [--openapi http://127.0.0.1:8765/openapi.json | path/to/openapi.json] \
                [--engines authz,negative,stateful,race,scenario] [--out qa-report] [--examples 25] [--steps 12]

Normally started through safe_run.py, which exports QA_BASE_URL. Writes <out>/engines.json and
<out>/engines.md. An engine crash is recorded as `engine-error`, never as a finding.
"""
import argparse
import importlib.util
import json
import os
import random
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import api as api_mod  # noqa: E402
import auth_attacks  # noqa: E402
import authz_matrix  # noqa: E402
import coverage  # noqa: E402
import dbcheck  # noqa: E402
import exposure  # noqa: E402
import differential  # noqa: E402
import invariant_miner  # noqa: E402
import logic_engine  # noqa: E402
import metamorphic  # noqa: E402
import static_checks  # noqa: E402
import trust  # noqa: E402
import negative_engine  # noqa: E402
import outbound  # noqa: E402
import race_engine  # noqa: E402
import scenario_engine  # noqa: E402
import schema_fuzz  # noqa: E402
import stateful  # noqa: E402
import workflow_chains  # noqa: E402


def load_spec(path: str):
    loader_spec = importlib.util.spec_from_file_location("qa_spec", path)
    module = importlib.util.module_from_spec(loader_spec)
    loader_spec.loader.exec_module(module)
    return module


def _broken(engine: str, what: str, tail: int) -> dict:
    """An `errored` row for a failure outside any engine (spec, setup, OpenAPI). Call inside an `except`."""
    return {"engine": engine, "findings": [], "engine-error": what + "\n" + traceback.format_exc()[-tail:]}


def finish(results: list, out: Path, a) -> int:
    """Write engines.json / engines.md / trust.json, print the report, return the exit code (see module docstring)."""
    out.mkdir(parents=True, exist_ok=True)
    summary = trust.summarize(results)
    (out / "engines.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    (out / "trust.json").write_text(json.dumps({**summary, "verdict": trust.verdict(summary)}, indent=2), encoding="utf-8")
    lines = ["# Engine results", ""] + trust.header_lines(results)
    total = 0
    for r in results:
        fs = r.get("findings", [])
        total += len(fs)
        lines.append(f"## {r['engine']}: {len(fs)} finding(s) [{trust.resolve(r)[0].upper()}]")
        for f in fs:
            lines.append(f"- **{f['severity']} {f['kind']}** `{f['endpoint']}` — {f['detail']}")
            if f.get("sequence"):
                seq = f["sequence"] if isinstance(f["sequence"], str) else "\n".join(str(x) for x in f["sequence"])
                lines.append("  ```\n  " + seq.replace("\n", "\n  ") + "\n  ```")
        for n in r.get("notes", []):
            lines.append(f"- note: {n}")
        if "engine-error" in r:
            lines.append("```\n" + r["engine-error"] + "\n```")
        lines.append("")
    (out / "engines.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"TOTAL findings: {total}")
    code = trust.exit_code(results, fail_on_findings=a.fail_on_findings, strict=a.strict)
    print(f"EXIT {code}: {trust.verdict(summary)}")
    return code


# Spec keys the engines use when present; an empty one means that engine reports DEGRADED or SKIPPED.
PREFLIGHT_OPTIONAL = {
    "BODIES": "negative engine: without it, DEGRADED for each route that creates data",
    "OWNER": "authz engine: which role owns the samples it creates (default user_a)",
    "IDS": "authz engine: ids for admin-only routes that take a path parameter",
    "INVARIANTS": "stateful engine: extra checks; without it only the no-5xx check runs",
    "RACES": "race engine: without it, SKIPPED",
    "SCENARIOS": "scenario engine: without it, SKIPPED",
}


def preflight(qa, doc, roles) -> int:
    """Check the spec against the OpenAPI document and the setup() result. Prints PROBLEM and note lines; returns the exit code."""
    problems, notes = [], []
    if not roles:
        problems.append("setup() returned no roles: authz and negative need a header dict per role")
    for role, headers in (roles or {}).items():
        if not isinstance(headers, dict) or not headers:
            problems.append(f"role {role!r}: setup() must return a non-empty dict of headers")
    paths = doc.get("paths") or {}
    for name in ("PUBLIC", "ADMIN_ONLY"):
        for entry in sorted(getattr(qa, name, set()) or ()):
            method, _, path = str(entry).partition(" ")
            if path not in paths or method.lower() not in (paths.get(path) or {}):
                problems.append(f"{name} entry {entry!r} is not an operation in the OpenAPI document")
    for key, why in PREFLIGHT_OPTIONAL.items():
        if not getattr(qa, key, None):
            notes.append(f"{key} is empty: {why}")
    for line in problems:
        print(f"[preflight] PROBLEM {line}", flush=True)
    for line in notes:
        print(f"[preflight] note {line}", flush=True)
    print(f"[preflight] {'FAIL' if problems else 'OK'}: {len(problems)} problem(s), {len(notes)} note(s). "
          "No attack traffic was sent.", flush=True)
    return 1 if problems else 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default=os.environ.get("QA_BASE_URL"))
    p.add_argument("--spec", required=True)
    p.add_argument("--openapi")
    p.add_argument("--engines", default="authz,negative,stateful,race,scenario,static")
    p.add_argument("--out", default="qa-report")
    p.add_argument("--examples", type=int, default=25)
    p.add_argument("--steps", type=int, default=12)
    p.add_argument("--seed", type=int, help="Hypothesis seed: reproducible stateful search (multi_run.py loops over seeds)")
    p.add_argument("--fail-on-findings", action="store_true", help="exit 1 when any non-info finding exists (CI gate)")
    p.add_argument("--strict", action="store_true", help="exit 2 when an engine ran degraded, not only when it errored")
    p.add_argument("--shuffle-engines", action="store_true",
                   help="randomise engine order (D3: detect order dependence); seed from --seed when set")
    p.add_argument("--preflight", action="store_true",
                   help="check the spec against the running app and exit; runs setup() (it creates the test users and "
                        "sample data) but sends no attack traffic")
    a = p.parse_args()
    if not a.base_url:
        raise SystemExit("--base-url (or QA_BASE_URL) required")
    api_mod.assert_local(a.base_url)

    out = Path(a.out)
    try:
        qa = load_spec(a.spec)
    except BaseException:                                                  # SystemExit/ImportError inside the spec too
        sys.exit(finish([_broken("setup", "qa-spec load failed", 1200)], out, a))
    api = api_mod.Api(a.base_url)
    try:
        roles = qa.setup(api) if hasattr(qa, "setup") else {}
        api.roles.update(roles or {})
    except Exception:
        sys.exit(finish([_broken("setup", "qa-spec setup() failed", 1200)], out, a))
    openapi_src = a.openapi or getattr(qa, "OPENAPI", None) or a.base_url.rstrip("/") + "/openapi.json"
    try:
        doc = api_mod.load_openapi(openapi_src)
    except Exception:
        sys.exit(finish([_broken("openapi", f"cannot load OpenAPI from {openapi_src}", 1200)], out, a))
    if a.preflight:
        sys.exit(preflight(qa, doc, roles))

    engine_names = [e.strip() for e in a.engines.split(",") if e.strip()]
    deferred = {"static", "invariants", "exposure"}  # run below (static needs QA_APP_DIR; invariants needs the full log)
    primary = [n for n in engine_names if n not in deferred]
    if a.shuffle_engines:
        rng = random.Random(a.seed if a.seed is not None else None)
        rng.shuffle(primary)
        print(f"[run] shuffled engine order: {','.join(primary)}", flush=True)

    results = []
    if a.shuffle_engines:
        results.append(trust.mark(
            {"engine": "orchestrator", "findings": [], "notes": [f"engine order: {','.join(primary)}"],
             "engine_order": primary},
            trust.RAN_OK, f"shuffled order: {','.join(primary)}"))
    for name in primary:
        try:
            if name == "authz":
                results.append(authz_matrix.run(api, doc, qa))
            elif name == "negative":
                results.append(negative_engine.run(api, doc, qa))
            elif name == "stateful":
                results.append(stateful.run(api, doc, qa, a.examples, a.steps, seed=a.seed))
            elif name == "race":
                results.append(race_engine.run(api, doc, qa))
            elif name == "scenario":
                results.append(scenario_engine.run(api, doc, qa))
            # opt-in engines (not in the default --engines list: they write data or need extra setup)
            elif name == "schema":
                results.append(schema_fuzz.run(api, doc, qa))
            elif name == "metamorphic":
                results.append(metamorphic.run(api, doc, qa))
            elif name == "logic":
                results.append(logic_engine.run(api, doc, qa))
            elif name == "auth":
                results.append(auth_attacks.run(api, doc, qa))
            elif name == "workflow":
                results.append(workflow_chains.run(api, doc, qa))
            elif name == "differential":
                results.append(differential.run(api, doc, qa))
            else:
                results.append({"engine": name, "findings": [], "notes": [f"unknown engine {name}"],
                                "engine-error": f"unknown engine {name!r}: nothing ran"})
        except Exception:  # engine bug or unsupported app: report, keep going
            results.append({"engine": name, "findings": [], "engine-error": traceback.format_exc()[-1200:]})

    try:
        results.append(dbcheck.run(qa))
    except Exception:
        results.append({"engine": "dbcheck", "findings": [], "engine-error": traceback.format_exc()[-800:]})
    if os.environ.get("QA_APP_DIR") and "static" in engine_names:
        sf = [{"kind": f["kind"], "severity": f["severity"], "endpoint": f["file"], "detail": f["detail"]}
              for f in static_checks.run(Path(os.environ["QA_APP_DIR"]))]
        results.append(trust.mark({"engine": "static", "findings": sf, "notes": []}, trust.RAN_OK))
    elif "static" in engine_names:
        results.append(trust.mark({"engine": "static", "findings": [], "notes": ["QA_APP_DIR not set"]}, trust.SKIPPED, "QA_APP_DIR not set: source scan not run"))

    if os.environ.get("QA_SINK_LOG"):
        try:
            results.append(outbound.run(os.environ["QA_SINK_LOG"], qa))
        except Exception:
            results.append({"engine": "outbound", "findings": [], "engine-error": traceback.format_exc()[-1200:]})

    if "invariants" in engine_names:                  # opt-in: mined candidates are info-only, see invariant_miner.py
        try:
            results.append(invariant_miner.run(api, doc, qa))
        except Exception:
            results.append({"engine": "invariants", "findings": [], "engine-error": traceback.format_exc()[-800:]})

    try:
        cov = coverage.run(api, doc)
        results.append(cov)
        Path(a.out).mkdir(parents=True, exist_ok=True)
        (Path(a.out) / "coverage.json").write_text(json.dumps(cov["table"], indent=2), encoding="utf-8")
    except Exception:
        results.append({"engine": "coverage", "findings": [], "engine-error": traceback.format_exc()[-800:]})

    if "exposure" in engine_names:                    # opt-in: reads the log the other engines produced, sends nothing
        try:
            results.append(exposure.run(api, doc, qa))
        except Exception:
            results.append({"engine": "exposure", "findings": [], "engine-error": traceback.format_exc()[-800:]})

    limited = sum(1 for entry in api.log if entry["status"] == 429)
    if limited:
        results.append({"engine": "env", "findings": [], "status": trust.DEGRADED, "status_reason": f"{limited} request(s) got 429: rate limiter active", "notes": [
            f"{limited} of {len(api.log)} requests got 429: a rate limiter is hiding app logic and races. Disable it for this run "
            "(env var in profile.env_overrides, or a custom run_cmd launcher) and re-run."]})

    trust.cross_check(results, request_count=len(api.log))
    sys.exit(finish(results, out, a))


if __name__ == "__main__":
    main()
