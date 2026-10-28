# QA toolkit

A toolkit that finds bugs in a **running** HTTP/JSON API. You give it your OpenAPI file and a small spec that describes your users and routes. It logs in as those users, sends requests to a local copy of your API, and reports each finding with the request and response that show it.

It is a measurement instrument, not an oracle. A finding is a lead to reproduce. "No findings" does not mean the API is correct.

## What is in the box

| Path | What it is |
|---|---|
| `toolkit/engine/` | The engines. Core: `authz`, `negative`, `stateful`, `race`, `scenario`, `static`. Experimental (no measured recall yet): `schema`, `auth`, `exposure`, `differential`, `workflow`, `metamorphic`, `logic` |
| `toolkit/engine/run.py` | Runs the engines against a spec. `--preflight` checks the spec without sending attack traffic |
| `toolkit/engine/safe_run.py` | Starts your app locally with a sink that records outbound traffic. Shell commands need explicit trust |
| `qa_console.py` | Browses run results in a local, token-protected page |
| `qa_check.py` | Health check of the toolkit (`--quick`, `--full`) |
| `toolkit/skills/`, `toolkit/agents/`, `toolkit/commands/` | Claude Code skills, agents and commands built on the engines. They run inside Claude Code; see below |
| `docs/USING.md` | Step-by-step guide: setup, spec, first run, reading results, limits |

## Skills and agents

The skills, agents and commands are instructions for Claude Code. Install the plugin (`claude --plugin-dir <repo>/toolkit`) and Claude follows them. They add review methods on top of the engines. Some of them call command-line tools that are **not** included here: `semgrep`, `ubs` (ultimate bug scanner), `jq`, and optionally `codeql`. Install a tool only if you want the step that uses it.

Third-party material keeps its own licence. The Trail of Bits skills and agents are CC BY-SA 4.0; each folder has an `ATTRIBUTION.md`. See [`NOTICE.md`](NOTICE.md).

## Quick start

1. Install Python and `uv`: `python -m pip install uv`, then `python -m uv python install 3.12`.
2. Check the toolkit: `python qa_check.py --quick` (about 10 minutes; the last line should say `VERDICT: no FAIL`).
3. Describe your API in a spec (start from `toolkit/examples/demo-flask-shop/qa-spec.py`), check it with `--preflight`, then run the engines. Full steps are in [`docs/USING.md`](docs/USING.md).

**This tool creates and changes records in the API it tests.** Run it only against a local test database, never against production.

## What a finding looks like

From the demo shop (a planted bug, so the answer is known):

```
## authz: 4 finding(s) [RAN_OK]
- **high BOLA/IDOR** `GET /orders/{order_id}` — user_b got 200 on GET /orders/3,
  resource created by user_a - body identical to the owner's: data exposed
```

Each finding names the endpoint, the role that got through, the status it got, and the evidence. Reproduce it before you report it.

## How well it works (measured, and deliberately modest)

On four fresh blind APIs with 10 planted bugs each (40 bugs in total, one run, one seed), the engines found:

| Setup | Bugs found | 95% interval (Wilson) |
|---|---|---|
| Zero-config (the spec as translated, no tuning) | 3 of 40 | 2.6%–19.9% |
| Tuned (spec written blind from the README and OpenAPI, tuned only on a clean copy) | 13 of 40 | 20.1%–48.0% |

Each arm also produced 11 findings that also appear on the clean copy (false positives). "Blind" here means the spec was written by a separate agent that did not see the answer key; the result depends heavily on spec quality. Demo and development numbers are not recall, and the four targets are now used up for an unbiased test.

Known limits: counters that drift, error-code mismatches such as 422 versus 413, version rollback, and quota or refund formulas that are stated only in prose are missed. Per-run results vary, so repeat important runs with `--seed`.

## Security notes

- Engines talk only to local apps (`127.0.0.1`, `localhost`, `::1`). Keep it that way: never point a run at production or a shared server.
- Keys live in a gitignored `.env` file. Never paste a key into a command.
- A shell command from a profile runs only when the profile says `trusted: true`, which you set yourself for a profile you have reviewed. Prefer argv lists (`run_cmd_argv`, `reset_cmd_argv`).
- Run folders contain request traces and, for the engines, test data. Check them before you share them.

## Tested on

The author tested it on Windows 10 with Python 3.12. Other systems are not tested.

## Licence

MIT for the original code. Third-party material keeps its own licence (CC BY-SA 4.0 for the Trail of Bits material), listed in [`NOTICE.md`](NOTICE.md) and [`SOURCES.md`](SOURCES.md).
