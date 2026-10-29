# QA Toolkit

**Finds bugs in a running web API by logging in as real users and trying what they should not be allowed to do.**

It is a locksmith that tests the doors of your own building, and then writes a report with proof for every door it opened. It is useful, but it does not promise that every door is locked.

> **Status: early release (v0.2.0).** Tested on Windows 10 with Python 3.12 only. Use it on a local copy of your API, never on production.

---

## What it does, in plain words

1. You describe your API: the OpenAPI file, plus a small spec file that lists your test users (for example a buyer, a seller and an admin) and which endpoints are public or admin-only.
2. The toolkit starts your API on your own computer.
3. It logs in as each test user and sends requests: other users' data, missing logins, odd input, repeated and parallel requests.
4. For each problem it finds, it writes the request, the response and the reason. You check it yourself before you report it.

## What it can find

- One user seeing or changing another user's data (access control).
- Endpoints that work without a login, or that a normal user can use although only admins should.
- Crashes and error pages on strange input, and error text that leaks internals.
- Data that leaks in responses or outgoing emails.
- Some order and stock problems: double cancel, overselling under parallel requests.

## What it cannot do

- It cannot prove that your API is secure. "No findings" means "nothing found by these checks", not "no bugs".
- It finds only what its spec and engines can reach. Business rules that are stated only in prose are usually missed.
- It does not test your frontend, your production system, or your infrastructure.

A finding is a lead to reproduce, and a run with no findings is not proof that an API is safe. Repeat important runs with `--seed`.

---

## Before you start

| You need | Why |
|---|---|
| Windows 10 | The only system tested (Windows 11 and other systems are not tested) |
| Python 3.12 and `uv` | The engines run on Python 3.12 through `uv` |
| Git | To get this repository |
| Your API running locally | The toolkit talks only to `127.0.0.1`, `localhost`, or `::1` |
| Claude Code (optional) | For the `/qa-toolkit:qa-hunt` command |

Other tools are optional and only used by some steps: `semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `ubs`, `schemathesis`, Playwright with Chromium, and the `pg8000` or `pymongo` drivers. Details are in [Dependencies](#dependencies).

---

## Quick start

**1. Check the toolkit is healthy** (about 10 minutes):

```
python qa_check.py --quick
```

The last lines should say `VERDICT: no FAIL`.

**2. Describe your API.** Start from the example in `toolkit/examples/demo-flask-shop/qa-spec.py`. Replace the test users, routes and public endpoints with yours.

**3. Check the spec, then run.** Step-by-step commands, with what each file means, are in [`docs/USING.md`](docs/USING.md).

Results appear in a `qa-report/` folder next to your project.

---

## Using it with Claude Code

Install the plugin from the `toolkit` folder:

```
claude --plugin-dir <repo>/toolkit
```

Then, inside Claude Code, run the full hunt on a project:

```
/qa-toolkit:qa-hunt <path-to-your-project>
```

Claude reads the project, writes the spec, runs the engines, and writes a report. Claude's own reading of the code is a lead, not a proof. Every finding should be reproduced before it is reported.

If you run it headless (`claude -p`), the `Skill` tool must be in the allowed list, otherwise the command is not found. Example and details: [`docs/USING.md`](docs/USING.md).

### What the plugin contains

**Commands** (run with `/qa-toolkit:<name>`):

| Command | What it does |
|---|---|
| `qa-hunt` | The full workflow on a project: detect the app, map it, write invariants, scan, run the engines, verify with proof-of-concept tests, and write a report |
| `diff-review` | Security review of a code change (a PR, a commit, or a diff) |
| `insecure-defaults` | Looks for fallback secrets, default credentials, fail-open checks, weak crypto, permissive access and debug leaks |

**Skills** (Claude uses them when the task matches their description):

| Skill | What it does | Needs |
|---|---|---|
| `differential-review` | Reviews what a code change alters: blast radius, test coverage of changed code | Git |
| `fp-check` | Checks whether a suspected bug is real, with a true or false positive verdict and evidence | Nothing extra |
| `property-based-testing` | Writes and reviews property-based tests (Hypothesis, fast-check, and others) | The test framework of your language |
| `sarif-parsing` | Reads, merges and de-duplicates SARIF files from scanners. Does not run scans | A SARIF file |
| `semgrep` | Runs a Semgrep scan with a plan you approve first | `semgrep` installed; its run script is bash, so on Windows it needs Git Bash or WSL. **Not tested on Windows** |
| `security-audit` | Security review of code, APIs and services, with validators | On Windows the validators need WSL and Node 24. See `docs/USING.md` |
| `sharp-edges` | Finds error-prone APIs and unsafe defaults in designs and configuration | Nothing extra |
| `supply-chain-risk-auditor` | Checks dependencies for known advisories, abandoned packages and install scripts | Your lockfile |
| `variant-analysis` | After a bug is found, looks for other places with the same root cause | Its queries run with Semgrep or CodeQL, if you use them; the search steps need nothing extra |

**Agents** (started by the skills above; you do not call them directly):

| Agent | Started by | What it does |
|---|---|---|
| `adversarial-modeler` | `differential-review` | Builds attacker scenarios for high-risk changes |
| `data-flow-analyzer` | `fp-check` | Traces data from input to the dangerous place |
| `exploitability-verifier` | `fp-check` | Checks whether a suspected bug can really be exploited |
| `poc-builder` | `fp-check` | Writes a proof-of-concept test for a verified bug |
| `sharp-edges-analyzer` | `sharp-edges` | Judges how easily an API can be misused |

Some skills describe steps that use outside tools (for example `issue-writer` or `audit-context-building`). Those tools are **not** included, and the skill text says to skip such a step when the tool is missing.

The skills, agents and commands were copied from Trail of Bits and Cloudflare material and changed for this toolkit. Their licences are in [`NOTICE.md`](NOTICE.md).

---

## Reading the results

| Word | Meaning |
|---|---|
| **high / medium / low / info** | How serious the finding looks if it is real. Severity is a guess, not a verdict |
| **RAN_OK** | The check ran completely |
| **DEGRADED** | The check ran, but part of it was skipped or limited. Weak evidence |
| **SKIPPED** | The check did not run, usually because the spec has no data for it |
| **ERRORED** | The check crashed. Treat its silence as unknown |
| **PARTIAL** (the overall verdict) | Some checks did not run. "No findings" is weak evidence |

An example from the demo shop (a planted bug, so the answer is known):

```
## authz: 4 finding(s) [RAN_OK]
- **high BOLA/IDOR** `GET /orders/{order_id}` — user_b got 200 on GET /orders/3,
  resource created by user_a - body identical to the owner's: data exposed
```

Each finding names the endpoint, the role that got through, the status it got and the evidence.

---

## Safety rules

- **Local only.** The engines refuse non-local addresses. Never point them at production or a shared server.
- **Test data only.** The runs create users, orders and other records in your test database.
- **Keys stay out of commands.** Put keys in the gitignored `.env` file (see `.env.example`).
- **Shell commands need trust.** A command in a profile runs only when the profile says `trusted: true`, which you set after you have reviewed it.
- **Check run folders before sharing.** They contain request traces and test data.

---

## Limits

- Tested only on Windows, only with Python 3.12.
- Counters that drift, error-code mismatches such as 422 versus 413, version rollback, and quota or refund formulas written only in prose are missed.
- The static checks are heuristics. They can give false alarms, and they can miss common patterns.
- The LLM spec helper is optional and off by default. Do not point it at a server you do not trust with your code.

---

## What is in the box

| Path | What it is |
|---|---|
| `toolkit/engine/` | The engines. Core: `authz`, `negative`, `stateful`, `race`, `scenario`, `static`. Experimental (no measured recall yet): `schema`, `auth`, `exposure`, `differential`, `workflow`, `metamorphic`, `logic` |
| `toolkit/engine/run.py` | Runs the engines against a spec. `--preflight` checks the spec without sending attack traffic |
| `toolkit/engine/safe_run.py` | Starts your app locally with a sink that records outbound traffic |
| `toolkit/engine/invariant_miner.py` | Proposes candidate rules from observed responses. A proposal is not a finding |
| `qa_console.py` | Browses run results in a local, token-protected page |
| `qa_check.py` | Health check of the toolkit (`--quick`, `--full`) |
| `toolkit/skills/`, `toolkit/agents/`, `toolkit/commands/` | Claude Code skills, agents and commands built on the engines |
| `docs/USING.md` | Step-by-step guide: setup, spec, first run, reading results |

---

## Dependencies

Nothing here is bundled. Checked against the scripts.

- **Python 3.12** for the engines: `python -m uv run --no-project --python 3.12 --with hypothesis ...`. `qa_console.py` runs with plain `python`.
- **`scan.ps1`** (Windows PowerShell only) runs `semgrep` (needed for the static step), `gitleaks`, `osv-scanner`, `trivy`, `ubs` and `schemathesis` if they are on PATH, and skips missing ones with a message.
- **`e2e_crawl.py`** needs Playwright and Chromium: `python -m uv run --with playwright playwright install chromium`.
- **`dbcheck.py`** needs `pg8000` (PostgreSQL) or `pymongo` (MongoDB): add `--with pg8000` or `--with pymongo` to the run.

## LLM helper (optional, off by default)

`toolkit/synthesize.py` and `toolkit/rules_from_llm.py` can send content to an LLM provider, but only when you name one (`--provider`, `--key-env`, `--api-url`, `--model`, or the `QA_LLM_*` variables in `.env`). They send the endpoint list from your OpenAPI file (paths, field names, examples) and, with `--source`, short code snippets. The key is read from the variable you name, and redirects are refused. `synthesize.py` screens its generated spec for dangerous calls such as `os`, `subprocess` and `eval` before writing it. This is a screen, not a sandbox, and `rules_from_llm.py` is not covered by it.

---

## Documentation

- [`docs/USING.md`](docs/USING.md): the step-by-step guide.
- [`NOTICE.md`](NOTICE.md) and [`SOURCES.md`](SOURCES.md): third-party material and its licences.

## Licence

The original code and documentation are under the MIT licence (see [`LICENSE`](LICENSE)). Third-party material keeps its own licence: the Trail of Bits skills and agents are CC BY-SA 4.0, and the Anthropic prompts are MIT. Each folder with third-party material has an `ATTRIBUTION.md`. See [`NOTICE.md`](NOTICE.md).

Whether the combined work can be relicensed under a single licence has not been reviewed by a lawyer. Check this before you redistribute it.
