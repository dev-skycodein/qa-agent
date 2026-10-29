---
description: "Full bug hunt on ANY web/API project: detect → safe run → map → invariants → scan → code hunt → generic engines (authz matrix / stateful / race) → PoC verify → report → learn. Lean, high-signal only."
argument-hint: "[path] [--diff <base-ref>] [--api <openapi-url>]"
allowed-tools: Read Grep Glob Bash Write Agent
---

# QA bug hunt

Target: `$ARGUMENTS` (default whole repo). Goal = REAL bugs, not noise.
Engines live in `${CLAUDE_PLUGIN_ROOT}/engine/` (project-agnostic). Only `qa-report/qa-spec.py` is project-specific
(template: `${CLAUDE_PLUGIN_ROOT}/templates/qa-spec.py`; a worked example: `examples/demo-flask-shop/`).
Run Python tools with `python -m uv run --no-project --python 3.12 --with <deps> python ...` (system Python may be too new; never touch the project's env).

## Safety first (always, enforced by `safe_run.py`)
- The app is started ONLY through `engine/safe_run.py`: local DB with a separate name (`qa_<project>`), every outbound key (email, payments, LLM, Sentry) forced blank, refuses any env var that points to a remote host, kills the process tree after.
- **Outbound sink (default on):** all HTTP(S) the app makes goes through `engine/sink.py` and is recorded + BLOCKED (package registries are tunnelled); SMTP is captured. A blank key is NOT enough: SDKs still call out. Point integrations at the sink with `{sink_http}` / `{sink_smtp_host}` / `{sink_smtp_port}` in `profile.env_overrides` (e.g. `GOOGLE_GEMINI_BASE_URL`) to see the exact prompt / mail body the app builds.
- **Fresh data:** set `profile.reset_cmd` (schema push + seed) so every run starts from the same DB; results otherwise depend on table size (e.g. random-key collisions).
- Never run engines against staging/production. `api.py` and `race.py` refuse non-localhost URLs.
- Rate limiter / captcha / email-verification are NOT auto-disabled: if `engines.md` says "N requests got 429", add the env switch to `profile.json` `env_overrides` (or a custom `run_cmd` launcher) and re-run.
- Git Bash mangles `^/...` args → prefix `MSYS_NO_PATHCONV=1`.

## Steps
0. **Detect + safe run.**
   `python ${CLAUDE_PLUGIN_ROOT}/engine/detect.py <project> --out <project>/qa-report/profile.json`
   Read `profile.json`: fill every `unknown`, fix `run_cmd`, resolve `unsafe_vars` (set a local value in `env_overrides` or add to `blank_keys`). Test it:
   `python .../engine/safe_run.py --profile qa-report/profile.json` (starts, health-checks, stops). If it refuses, that is the safety net working: fix the profile, never bypass it.
1. **Map (5 min max).** Stack, entry points (routes, forms, webhooks, auth, payments, uploads, DB writes), roles. → `qa-report/map.md`.
2. **Invariants.** 5–15 one-line rules the app must never break (money, stock/counters, ownership, roles, state machine, secrets). → `qa-report/invariants.md`.
3. **Auto scan.** `${CLAUDE_PLUGIN_ROOT}/scripts/scan.ps1 <path>` (+ `-ApiUrl <local openapi>`). Learned rules run automatically. Triage SARIF with `sarif-parsing`. Expect static noise (on a hardened codebase it found 0 real bugs); don't report unverified hits.
4. **Code hunt = break each invariant** at every entry point that touches it: authz (`sharp-edges`), input→sink, money/state, config (`/insecure-defaults`), stale client data. `--diff` → `differential-review` skill.
5. **Generic engines (highest yield).** Write `qa-report/qa-spec.py` from `invariants.md` (copy the template: roles + `fresh_state` + `INVARIANTS` + `PUBLIC`/`ADMIN_ONLY` + `RACES`). Then:
   ```
   python .../engine/safe_run.py --profile qa-report/profile.json -- \
     python -m uv run --no-project --python 3.12 --with hypothesis [--with pymongo ...] \
     python .../engine/run.py --spec qa-report/qa-spec.py --out qa-report [--examples 60 --steps 15]
   ```
   → `qa-report/engines.md` / `engines.json`. What each engine proves:
   - **authz** (endpoint × role from OpenAPI, no spec code beyond `PUBLIC`/`ADMIN_ONLY`): IDOR/BOLA, missing auth, privilege escalation. Resources whose ids come from login/seed data instead of a POST: `OWNED_IDS = {"/rest/basket": {"user_a": 3}}`.
   - **stateful** (Hypothesis, actions from OpenAPI + a `repeat` replay action): your `INVARIANTS` after every step, plus "no 5xx". Runs in rounds: a failing check is switched off so the next round finds a different bug class. Admin-only endpoints are mostly called as admin so the search reaches deep states.
   - **race** (`RACES`): N simultaneous requests, then your check. Oversell, double spend, duplicate rows, double restock.
   - **negative** (no spec code): every field/path id/query param broken one at a time; `NEG-5XX`, `NEG-LEAK`, `NEG-ACCEPTED`, `MASS-ASSIGN`, `XREF-IDOR`. `NEG-INJECTION` = differential SQL/NoSQL oracle (a payload value that returns far more than a benign value on the same filter; skipped when the payload is echoed back, because that means the fuzzer stored it). `regex_meta` payload (`([a-`) breaks unescaped regex filters. Add `BODIES` so each endpoint has a valid baseline; the HTML canary `<i>qa-canary-html</i>` it sends is tracked by the outbound engine (`CANARY-IN-EMAIL`, `CANARY-IN-PROMPT`).
   - **outbound** (reads `sink.jsonl`): what left the app: secrets/passwords in payloads, unescaped user HTML in mail, user input in LLM prompts. `SINK_CHECKS = [fn(entry)]` in the spec for project rules.
     Email/LLM code paths only run if the integration looks configured, and HTTPS bodies are invisible to the sink: in the launcher set fake keys, point the mail API at `{sink_http}` over plain HTTP (profile `env_overrides`, e.g. `QA_SINK_HTTP`), stub the LLM with an in-process fake that calls the tool you want to test, and take those endpoints out of `SKIP`. `CANARY-IN-EMAIL` counts only the HTML part of a mail (a canary in the subject is not markup). Write a small local launcher for your app (it must not read a real `.env`).
   - **scenario**: `scenarios_lib.py` has `state_machine`, `stale_session`, `reuse_after_logout`, `double_submit`.
   - **dbcheck**: `DB` + `DB_CHECKS` in the spec query the database after the run (needs `--with pg8000` / `pymongo`).
   - **static** (schema-aware, runs inside run.py): unique column filled from a small random space, enum casts without validation, raw errors to client, route handlers without auth.
   - **coverage** (always): `coverage.json` + notes list endpoints that never answered 2xx = blind spots. Fix the baseline (BODIES/hooks) before trusting a clean result.
   Reliability: `engine/multi_run.py --seeds 1,2,3` (reset DB per seed) reports `found in k/N`; anything below N/N means the search, not the app, is the limit.
   Read `notes` in `engines.md`: they say exactly what to add to the spec (`BODIES`, `IDS`, `OWNER`). A flag is a CANDIDATE: reproduce it as a PoC before reporting. `QA_TRACE=1` prints every call.
   No OpenAPI (Next.js route handlers / Express / Flask without a schema)? `python ${CLAUDE_PLUGIN_ROOT}/engine/autospec.py <project> --out qa-report` derives `openapi.json` (+ enums/required from the ORM schema and validation code) and `qa-spec.generated.py`; review it, set `OPENAPI` in the spec. Otherwise write a minimal `openapi.json` by hand.
   Not REST (GraphQL/gRPC/websocket)? Engines don't apply: fall back to a project-specific script and say so in the report.
6. **E2E crawl** (`engine/e2e_crawl.py`, Edge/Chrome, no download): every role, console/network errors, dead links, mobile overflow, a11y, admin pages reachable by non-admins, double-click submit. Then **E2E abuse** (Playwright, browser): UI-shown vs backend-done (price shown = charged, double-click = 1 order, other user's URL hides data, tampered localStorage). Write the abuse script from the template in `engine/e2e_crawl.py`.
7. **Variants.** Each confirmed bug → `variant-analysis` skill.
8. **PoC or drop.** Each candidate needs a failing test in `qa-report/poc/`. No PoC → `fp-check`; still unproven → drop or mark "code trace only".
9. **Report** `qa-report/REPORT.md`: `| severity | file:line | class | bug | poc | fix |`. Separate "proven" vs "code trace". State assumptions as assumptions.
10. **Learn (user-confirmed bugs only).** Semgrep rule → `${CLAUDE_PLUGIN_ROOT}/rules/learned/<class>.yaml` (must hit the bug, not the fix) + keep PoC as regression test. A plugin update can overwrite files in the plugin folder, so keep a copy of learned rules outside it.

Rules: no style nits, no theoretical issues, >80% confidence only. Don't fix code unless user asks.
