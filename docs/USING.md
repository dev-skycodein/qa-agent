# QA toolkit: find bugs in your own API

## What you get
This tool tests a **running** HTTP/JSON API (the backend your frontend or other services call). It logs in as different test users, sends requests, and looks for access-control mistakes, crashes and rule violations. Every finding comes with the request and response that show it.

It does **not** read your code to find bugs, except one optional engine (`static`, see below).

## What you need
- Python with `uv`: `python -m pip install uv`, then `python -m uv python install 3.12`. The tool's `pyproject.toml` allows Python 3.10 or newer, but 3.12 is what we used.
- Your API running on your own machine (`127.0.0.1`). Never point the tool at a shared, staging or production server.
- Your API's OpenAPI file (a JSON description of its routes). FastAPI serves it at `/openapi.json`. If your framework has none, see "No OpenAPI file?" below.
- Test users with dummy emails and passwords, including one admin. The tool does not create the admin for you.

## Windows: first steps (exact commands)
Open PowerShell in the repository folder.

1. Check that Python works: `python --version`. If Windows opens the Microsoft Store instead, install Python 3.12 from python.org and turn off "App execution aliases" for `python.exe` in Windows settings. Or use the launcher: `py -3.12 --version`.
2. Install uv: `python -m pip install uv`, then check it with `python -m uv --version`.
3. Fetch Python 3.12 for the tool: `python -m uv python install 3.12` (needs internet once).
4. Run the health check (Step 1 below). The first run downloads packages and takes about 10 minutes; it needs internet access.

The demo target in `targets/` needs one self-test run first, because the run writes its profile into `toolkit/examples/demo-flask-shop/qa-report/`. Until then, `qa_console.py run demo-flask-shop` reports that the profile is missing, and tells you how to create it.

## Step 1: check that the tool works
From the repository folder (the folder that contains `qa_check.py`):
```
python qa_check.py --quick
```
It takes about 10 minutes and runs a small demo app with planted bugs. The last lines should read `VERDICT: no FAIL - toolkit checks green`. Do not start a second selftest while it runs (they share port 8765).

## Step 2: write your spec file
The engines need a Python file that tells them your users, your routes and how to create data. Start from the demo:

1. Copy `toolkit/examples/demo-flask-shop/qa-spec.py` to a folder next to the repo, for example `../my-api/qa-spec.py`.
2. Change it:
   - `PUBLIC`: routes anyone may call without logging in, written like `"GET /items"`.
   - `ADMIN_ONLY`: routes only an admin may call.
   - `USERS`: test users (dummy emails).
   - `setup(api)`: log in each user and return their auth headers. **Check the login response key**: the template uses `access_token`, the demo uses `token`. Use the key your API really returns.
   - `BODIES`: a valid request body for each route that creates data.
   - `OWNER`: which user owns the samples the engines create.
3. Delete the last part of the copied file (from the line `# ---- scenario` to the end). It imports helpers by a path relative to the toolkit folder, which breaks in your own folder. Without it, the `race` and `scenario` engines report `SKIPPED`, which is expected.
4. Keep the spec to dummy data only. The engines create and change records.

**If the report's first row is `setup` with `ERRORED`**, the spec did not run. Read the note. The usual cause is the login key in `setup()` (step 2) or a wrong email or password. Fix it and run again.

## No OpenAPI file?
- FastAPI: it is served at `/openapi.json` while the app runs. Save it to `../my-api/openapi.json`.
- Next.js, Express, Koa or Flask: `toolkit/engine/autospec.py` can derive an OpenAPI file from your source. Run it as `python toolkit/engine/autospec.py <your-project-folder> --out ../my-api`. It writes `../my-api/openapi.json`, a draft spec `../my-api/qa-spec.generated.py`, and `../my-api/autospec.md` listing what it guessed. Check that file by hand before you trust the output. Its `setup()` is a placeholder you must fill in.
- Other frameworks: this path is not tested. Write the OpenAPI file yourself, or skip the tool for that API.

## Step 3: check the spec, then run it
Start your API first.

**Check the spec before a real run.** From the repository folder, run the same command as below with `--preflight` added at the end. It logs in the test users and creates the sample data (as a real run does), then reports problems and missing spec keys, and sends no attack traffic. It exits with code 1 when there is a problem:
```
python -m uv run --no-project --python 3.12 --with hypothesis --with requests --with pyjwt --with pymongo python toolkit/engine/run.py --base-url http://127.0.0.1:8000 --spec ../my-api/qa-spec.py --openapi ../my-api/openapi.json --preflight
```
Fix every `PROBLEM` line first. The `note` lines tell you which engines will be `DEGRADED` or `SKIPPED` without more spec.

Then run it for real. From the repository folder:
```
python -m uv run --no-project --python 3.12 --with hypothesis --with requests --with pyjwt --with pymongo python toolkit/engine/run.py --base-url http://127.0.0.1:8000 --spec ../my-api/qa-spec.py --openapi ../my-api/openapi.json --out ../my-api/qa-results
```
Change the port, the spec path and the OpenAPI path to match your setup. Drop `--with pymongo` if your spec does not import it.

**`--engines` replaces the whole default list.** It does not add to it. If you pass `--engines`, list every engine you want, for example `--engines authz,negative,stateful,schema,auth,exposure`. The engines `dbcheck` and `coverage` always run, whatever you pass.

## Which engines need what
| Engine | Needs in your spec | Without it |
|---|---|---|
| `authz` | `PUBLIC`, `ADMIN_ONLY`, `OWNER`, `IDS` | runs, but skips some checks (DEGRADED note) |
| `negative` | `BODIES` | DEGRADED for each route without a body |
| `stateful` | `INVARIANTS` (optional) | DEGRADED: only the no-5xx check runs |
| `race` | `RACES` | SKIPPED |
| `scenario` | `SCENARIOS` | SKIPPED |
| `static` | the environment variable `QA_APP_DIR` set to your app folder | SKIPPED |
| `coverage` | nothing; always runs | lists routes never answered 2xx |

In the report, a skipped engine shows its status as `SKIPPED_NO_SPEC` (or `SKIPPED` for `static`). Both mean the same thing: that engine did not check anything.

## Step 4: read the results
Open `../my-api/qa-results/engines.md` (readable) or `engines.json` (for scripts).

- **A finding is a lead, not a verdict.** Repeat the request sequence it shows, and check it against the behaviour you intend, before you call it a bug.
- **`RAN_OK` with no findings** means the checks ran and found nothing. It does **not** mean the API is correct.
- **`DEGRADED`, `SKIPPED` or `ERRORED`** means part of the check did not run. Read the note, fix the spec, and run again.
- **A finding that also appears on a fixed copy of your app** is probably a false positive.
- Random engines (`stateful`, `race`) can miss things on one run. Run again, or use `--seed N`.

## Where it is weak
- It only checks what your spec describes. A rule that exists only in your code or in documentation is missed.
- It creates and changes data in the API it tests. Use a local test database.
- It gives false positives. Check each finding by hand. Patterns seen on a real app (a Python API, run in this repo, 26 findings):
  - `NEG-INJECTION` on text fields: the value was stored as text and read back unchanged. An acceptance-only signal is not an injection; check whether a query changes.
  - `SCHEMA-REJECTS-VALID` on a create route: the app may enforce a cross-field rule (for example, "provide variants or sizes, colors and stock"). The engine cannot see it; check the 422 message.
  - `SCHEMA-REJECTS-VALID` on a route that needs a real id: the engine's mutation can replace the id with a dummy value. An error about an invalid id is correct behaviour.
  - `NEG-ACCEPTED` on whitespace-only text: the schema allows it, so it is not a schema violation.
- In the same run, the engines found 2 real issues out of 26 (an error body that leaked configuration text, and a login timing difference). The other real issues were found by reading the code, not by the engines. Expect the engines to need a tuned spec before they find much.
- The author tested it on Windows 10. Other systems are not tested.

## Source-code review (optional)
`toolkit/skills/security-audit/` is Cloudflare's `security-audit` skill (MIT, see `NOTICE.md`). It reviews source code, not a running API. Our additions are a Windows note in `SKILL.md` and `validate-wsl.ps1`. The validators are unchanged.

- **Guidance mode** (ask a focused question about one file or feature in Claude Code): works on Windows with no extra setup.
- **Full audit mode** (writes `REPORT.md` and `findings.json`): on Windows its validators must run in WSL. Setup: install Ubuntu in WSL, then Node in `~/.local/node`. The author tested Node 24.21.0. Without this setup, skip full audit mode.
- Full audit does not run target code. Without an OS sandbox, findings that need a dynamic check stay `needs_validation`.

## Licence
The original code is MIT. Third-party material keeps its own licence. See `NOTICE.md` and `SOURCES.md`.
