#!/usr/bin/env python
"""Oracle Synthesizer MVP: generate qa-spec.py from an OpenAPI spec.

Usage:
  python toolkit/synthesize.py --openapi path/to/openapi.json \
    [--source path/to/code/] [--out projects/target/qa-spec.py]

The LLM helper is OPTIONAL and OFF by default. The core QA engines do not need it. To opt in, name the provider, the key variable,
the endpoint and the model explicitly, e.g.:
  python toolkit/synthesize.py --openapi ... --provider NAME --key-env VAR --api-url URL --model MODEL
(the endpoint may also come from QA_LLM_API_URL and the model from QA_LLM_MODEL, in the gitignored .env). The key is read from the
environment variable named by --key-env. No provider URL or key is built in.
"""
import argparse
import ast
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: a 307/308 would resend the API key and the prompt to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)

MAX_CONTINUATION = 4

OPT_IN_HINT = ("The LLM helper is optional and OFF by default: the core QA engines need no LLM service. To opt in, pass "
               "--provider NAME --key-env VAR --api-url URL --model MODEL (or set QA_LLM_API_URL / QA_LLM_MODEL in .env).")

# Provider LIMITS only. No provider is the default, and no endpoint or key variable is built in: each must be named by the user.
# SkyCodein (company/hosted OpenAI-compatible service, see API.md) answers at most 2048 tokens and keeps only the newest messages that
# fit in 7500 characters: a bigger prompt is silently cut, so it is refused here.
PROVIDERS = {
    "gemini": {"max_tokens": None, "context_chars": None},
    "skycodein": {"max_tokens": 2048, "context_chars": 7500},
}


def provider_settings(name=None, api_url=None, model=None, max_tokens=None, key_env=None):
    """Resolved {api_url, model, key_env, max_tokens, context_chars} for an explicitly chosen provider.

    Refuses (SystemExit, no network) unless the provider, the key variable, the endpoint and the model are all given, either as
    arguments or (endpoint, model) from QA_LLM_API_URL / QA_LLM_MODEL. max_tokens is clamped to the provider's limit."""
    if not name:
        raise SystemExit(OPT_IN_HINT + " No --provider was given.")
    if name not in PROVIDERS:
        raise SystemExit(f"unknown provider {name!r}: choose one of {sorted(PROVIDERS)}")
    cfg = dict(PROVIDERS[name])
    cfg["api_url"] = api_url or os.environ.get("QA_LLM_API_URL") or ""
    cfg["model"] = model or os.environ.get("QA_LLM_MODEL") or ""
    cfg["key_env"] = key_env or ""
    missing = [flag for flag, value in (("--key-env", cfg["key_env"]), ("--api-url or QA_LLM_API_URL", cfg["api_url"]),
                                        ("--model or QA_LLM_MODEL", cfg["model"])) if not value]
    if missing:
        raise SystemExit(OPT_IN_HINT + " Missing: " + ", ".join(missing) + ".")
    limit = cfg["max_tokens"]
    cfg["max_tokens"] = min(max_tokens or limit or 16000, limit) if limit else (max_tokens or 16000)
    return cfg


def check_context(system, user_msg, limit):
    """Refuse a prompt the provider would silently truncate (limit in characters; None = no limit)."""
    size = len(system) + len(user_msg)
    if limit and size > limit:
        raise SystemExit(f"prompt is {size} characters, above this provider's {limit}-character context: it would be cut silently. "
                         f"Use toolkit/rules_from_llm.py (compact digest) or a provider without that limit.")

# ---------------------------------------------------------------------------
# OpenAPI parsing
# ---------------------------------------------------------------------------

def _resolve(node, spec, depth=0):
    if not isinstance(node, dict) or depth > 6:
        return node or {}
    if "$ref" in node:
        cur = spec
        for part in node["$ref"].lstrip("#/").split("/"):
            cur = cur.get(part, {})
        return _resolve(cur, spec, depth + 1)
    return node


def parse_openapi(path):
    raw = Path(path).read_text(encoding="utf-8")
    spec = json.loads(raw)

    endpoints = []
    for p, methods in spec.get("paths", {}).items():
        for m, det in methods.items():
            if m not in ("get", "post", "put", "patch", "delete"):
                continue
            ep = {
                "key": f"{m.upper()} {p}",
                "method": m.upper(),
                "path": p,
                "summary": det.get("summary", ""),
                "auth": bool(det.get("security")),
                "params": [pr.get("name") for pr in det.get("parameters", [])
                           if pr.get("in") == "path"],
                "body_props": {},
                "body_required": [],
                "body_examples": {},
            }
            rb = det.get("requestBody", {}).get("content", {})
            for ct, info in rb.items():
                if "json" in ct:
                    schema = _resolve(info.get("schema", {}), spec)
                    props = schema.get("properties", {})
                    for k, v in props.items():
                        v = _resolve(v, spec)
                        ep["body_props"][k] = v.get("type", "string")
                        if v.get("example") is not None:
                            ep["body_examples"][k] = v["example"]
                    ep["body_required"] = schema.get("required", [])
                    break
            endpoints.append(ep)

    auth_schemes = spec.get("components", {}).get("securitySchemes", {})
    return {
        "title": spec.get("info", {}).get("title", "API"),
        "endpoints": endpoints,
        "auth": auth_schemes,
        "raw_json": raw if len(raw) < 40_000 else _summarise(endpoints, auth_schemes),
    }


def _summarise(eps, auth):
    lines = [json.dumps({"auth_schemes": auth}, indent=2)]
    for e in eps:
        lines.append(f"\n{e['key']} auth={e['auth']} params={e['params']}")
        if e["body_props"]:
            lines.append(f"  body: {json.dumps(e['body_props'])}")
            if e["body_examples"]:
                lines.append(f"  examples: {json.dumps(e['body_examples'])}")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Source code scanning (optional)
# ---------------------------------------------------------------------------

def scan_source(source_dir):
    if not source_dir or not Path(source_dir).is_dir():
        return ""
    snippets = []
    for ext in ("*.py", "*.js", "*.ts", "*.rb", "*.go", "*.java"):
        for f in Path(source_dir).rglob(ext):
            if any(s in str(f) for s in ["node_modules", ".git", "__pycache__",
                                          "venv", "dist", "build"]):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if len(text) > 60_000:
                continue
            indicators = ["route", "endpoint", "controller", "view", "handler",
                          "app.get", "app.post", "router.", "SELECT ", "INSERT ",
                          "execute(", "password", "secret", "admin", "authorize"]
            if any(kw in text.lower() for kw in indicators):
                header = f"### {f.relative_to(source_dir)}"
                snippets.append(f"{header}\n{text[:6000]}")
    return "\n\n".join(snippets[:8])

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

SYSTEM = r"""You write qa-spec.py files that configure automated API security testing engines.
Given an OpenAPI spec, produce a COMPLETE, RUNNABLE Python module. Output ONLY Python code — no markdown, no explanation.

## What the file must contain

```
from urllib.parse import quote          # for URL-encoding path payloads

OPENAPI = "<path>"                      # set from instructions below
PASSWORD = "TestPass123"

# --- endpoint classification (sets of "METHOD /path" matching OpenAPI EXACTLY) ---
PUBLIC  = {"GET /items", "POST /auth/login", ...}   # open to anon
ADMIN_ONLY = {"DELETE /users/{id}", ...}
SKIP    = {"GET /health", ...}                       # never probe
OWNER   = {"POST /books": "user_a"}                  # who creates
NEG_SKIP = set()                                     # skip for fuzzer
STATEFUL_SKIP = set()                                # skip for stateful

# --- request bodies — #1 PRIORITY ---
BODIES = {}          # filled statically or in setup()
STATE  = {}
OWNED_IDS = {}       # {"/collection": {"user_a": id_value}}
IDS = {}             # {"param": "value"} for admin-only path-param endpoints

def setup(api):
    # 1. DB init endpoint if any (GET /createdb, POST /init …)
    # 2. Register user_a, user_b via the register endpoint
    # 3. Login both → extract token from response JSON
    # 4. Login seed admin if one exists
    # 5. Create test resources for both users
    # 6. Fill BODIES, OWNED_IDS, STATE
    # 7. api.roles.update(roles); return roles
    #
    # api.call(role, method, path, body=None, query=None) → Resp
    #   Resp.ok  .status  .json  .text
    # roles = {"user_a": {"Authorization": "Bearer <tok>"}, ...}
    ...

def fresh_state(api):
    # return dict with usernames, resource IDs from STATE
    ...

# --- invariants: assert security property after random operations ---
INVARIANTS = []   # [fn(api, log, ctx)]  — assert False on violation

# --- scenarios: multi-step scripted attacks ---
SCENARIOS = []    # [{"name": str, "run": fn(api, ctx) → str|None}]
# Return message when vuln found, None otherwise.

# --- races (optional) ---
RACES = []        # [{"name", "setup", "n", "check"}]
```

## What makes a spec GOOD

1. BODIES for EVERY endpoint that takes a JSON body. Without these, engines see only 4xx and find nothing.
   Keys must exactly match OpenAPI paths: "POST /users/v1/register" not "POST /users/register".
   Generate values from schema properties/examples. Use plausible defaults when no example exists.

2. setup() that ACTUALLY WORKS:
   - Read the OpenAPI to find register + login endpoints and their exact body fields.
   - Extract auth token from the login response — look at the response schema for field names
     (auth_token, token, access_token, jwt, etc.).
   - Create at least one owned resource per user (so BOLA testing works).

3. PUBLIC must list only truly public endpoints. Anything requiring auth that is NOT in PUBLIC
   gets tested for MISSING-AUTH. Get this wrong = false positives.

4. SCENARIOS should target these OWASP API Top 10 patterns:
   - BOLA/IDOR: user_b GETs/PUTs/DELETEs user_a's resource path
   - Broken auth: change another user's password/email via their path param
   - Mass assignment: register/create with extra field {admin: true, role: "admin", is_admin: true}
   - Excessive data exposure: access debug/internal endpoints as anon
   - User/password enumeration: login with wrong creds, compare error messages
   - Injection: quote("' OR '1'='1", safe="") in path params; SQL strings in body fields

5. OWNED_IDS for resources whose IDs don't come from POST response (seed data, login-created).
   REQUIRED whenever a GET/PUT/DELETE path-param resource is created in setup() but the create response
   has no id/title field the authz engine can extract: map collection path -> {owner: id}, e.g.
   OWNED_IDS = {"/books/v1": {"user_a": "bookTitle1"}}. Without OWNED_IDS, BOLA probes never run
   (authz stays degraded: "200 without an id"). Prefer extracting the id from the create response when present.

## Rules
- Output ONLY valid Python. No ```python fences. No comments explaining what you're doing.
- Import only stdlib: json, datetime, urllib.parse.
- Endpoint keys must EXACTLY match the OpenAPI paths given to you.
- If the API has a DB-init endpoint, call it first in setup() and add it to SKIP.
- If you see bearer auth, use {"Authorization": f"Bearer {token}"} for roles.
- For path-param injection, always URL-encode: quote(payload, safe="")
- Fields with a uniqueness constraint (a unique name, title, email, username, slug or key) get a fresh value on every create call: generate each one with a counter or timestamp helper in setup() and in scenarios, never one fixed literal reused for repeated creates.
"""

# Prompt version 3 = SYSTEM + this block. Added 2026-10-22 for an internal blind experiment. Every line is either (a) documentation of the
# engine interface that the template left out, or (b) a lesson from an earlier spec-writing trial. Nothing here comes from the
# held-out ground truth. Versions: 1 = original, 2 = SYSTEM as first committed, 3 = SYSTEM + EXTRA_V3.
EXTRA_V3 = r"""

## Interface details (read carefully, the file is executed by the engines as-is)
- api.call(role, method, path, body=None, query=None, raw=None, headers=None) -> Resp
  `raw` sends exact bytes instead of JSON, `headers` adds request headers. If the OpenAPI request body is
  application/x-www-form-urlencoded (for example an OAuth2 password login), send
  raw=urlencode({...}).encode() with headers={"Content-Type": "application/x-www-form-urlencoded"}
  (from urllib.parse import quote, urlencode).
- Resp has .status, .ok (2xx), .text, .json (parsed or None) and .headers (a dict of response headers; compare names case-insensitively).
- roles is a dict role-name -> request headers. The role "anon" always exists. A role whose login failed must be left out, not set to an empty token.

## Quality rules
- Tokens may be short-lived: inside each scenario log in again for the users it uses, do not rely on tokens made in setup().
- A scenario reports a finding only after confirming the effect. After an action by an unauthorised actor, read the resource back as its owner (or as an authorised role) and compare with the state before. A 2xx alone is not proof. Return None when the effect cannot be confirmed.
- Test each access rule from several angles when the API shows roles: unauthenticated; a regular user acting on another user's resource; and, if credentials of a privileged account are shown in the given material, use that account as the reference ("this works for the privileged role, does it also work for a regular user?").
- Use only accounts you create or whose credentials appear in the given material. Never guess passwords.
- Create your own throwaway users and resources for anything that modifies or deletes data. Never send shell metacharacters, destructive payloads or requests to non-local hosts.
"""
SYSTEM_V3 = SYSTEM + EXTRA_V3

# Prompt version 4 = SYSTEM_V3 + this block (2026-10-29, after the Immich blind round). Versions 2 and 3 are unchanged, so their
# frozen hashes (checked in toolkit/test_synthesize_provider.py) still hold. Lessons: an /admin endpoint the writer
# SKIPped because its guard looked weak was never probed (calendar-heatmap), and a partner-style share was reported as BOLA.
EXTRA_V4 = r"""

## Flag, do not skip
- Never put an endpoint in SKIP because its guard looks weaker than its path suggests (for example a path under /admin that a
  regular user may plausibly reach). Leave it probed. The authz engine treats every /admin path as admin-only and reports a
  non-admin 2xx as PRIV-ESC, so the guard is tested, not assumed.
- Mark each such endpoint with a comment line `# FLAG: METHOD /path: <what looks weaker and why>` next to the sets, so the
  reviewer can confirm the intended audience. A FLAG is a question for the reviewer, not a verdict.
- SKIP is for endpoints that would damage data, end sessions or call external systems. Give the reason next to each entry.

## Sharing
- If the source implements sharing between users (partners, members, shared links), declare it as READ access in
  GRANTS = {"/collection": {"owner_role": ["viewer_role"]}} and cite the source line in a comment.
- Declare a GRANTS entry only for sharing the source actually implements. Never declare one to make a finding go away.
  anon is never a viewer: use PUBLIC for open endpoints.
"""
SYSTEM_V4 = SYSTEM_V3 + EXTRA_V4
PROMPTS = {2: SYSTEM, 3: SYSTEM_V3, 4: SYSTEM_V4}


def build_user_prompt(parsed, source, openapi_path, base_url):
    parts = [f"Generate qa-spec.py for: {parsed['title']}"]
    parts.append(f'\nOPENAPI path to use in the file: "{openapi_path}"')
    parts.append(f"Base URL (for context, not in the file): {base_url}")

    # Endpoint summary (compact, structured)
    parts.append("\n## Endpoints")
    for ep in parsed["endpoints"]:
        line = f"  {ep['key']}"
        if ep["auth"]:
            line += "  [REQUIRES AUTH]"
        if ep["summary"]:
            line += f"  — {ep['summary']}"
        if ep["body_props"]:
            line += f"\n    body fields: {json.dumps(ep['body_props'])}"
            if ep["body_required"]:
                line += f"\n    required: {ep['body_required']}"
            if ep["body_examples"]:
                line += f"\n    examples: {json.dumps(ep['body_examples'])}"
        if ep["params"]:
            line += f"\n    path params: {ep['params']}"
        parts.append(line)

    # Auth info
    if parsed["auth"]:
        parts.append(f"\n## Auth schemes\n{json.dumps(parsed['auth'], indent=2)}")

    # Full spec (if not too large)
    if len(parsed["raw_json"]) < 35_000:
        parts.append(f"\n## Full OpenAPI Spec\n{parsed['raw_json']}")

    if source:
        parts.append(f"\n## Source code (route handlers)\n{source[:12000]}")

    parts.append("\nGenerate the complete qa-spec.py now. ONLY Python code, no fences.")
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def _chat(api_url, api_key, model, messages, max_tokens=2048, reasoning_effort=None):
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.3,
    }
    if reasoning_effort:
        payload["reasoning_effort"] = reasoning_effort
    body = json.dumps(payload).encode()

    req = urllib.request.Request(
        api_url,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    for attempt in range(6):
        try:
            with _OPENER.open(req, timeout=180) as r:
                resp = json.loads(r.read().decode())
            break
        except urllib.error.HTTPError as e:
            err = e.read().decode()
            if e.code in (429, 500, 503) and attempt < 5:
                wait = 10 * (attempt + 1)
                print(f"  API {e.code}, retry in {wait}s ({attempt + 1}/5)")
                time.sleep(wait)
                continue
            raise SystemExit(f"API error {e.code}: {err[:500]}")

    choice = resp["choices"][0]
    text = choice["message"]["content"]
    finish = choice.get("finish_reason", "stop")
    usage = resp.get("usage", {})
    return text, finish, usage


def call_llm(system, user_msg, api_url, api_key, model, max_tokens=2048, reasoning_effort=None, context_chars=None):
    check_context(system, user_msg, context_chars)
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_msg},
    ]
    print(f"Calling {model} ...", file=sys.stderr)

    full_text = ""
    total_in = 0
    total_out = 0

    for attempt in range(1, MAX_CONTINUATION + 1):
        text, finish, usage = _chat(api_url, api_key, model, messages,
                                    max_tokens, reasoning_effort)
        full_text += text
        total_in += usage.get("prompt_tokens", 0)
        total_out += usage.get("completion_tokens", 0)
        print(f"  chunk {attempt}: {usage.get('completion_tokens', '?')} tokens, "
              f"finish={finish}", file=sys.stderr)

        if finish != "length":
            break
        if context_chars:        # a continuation re-sends the partial answer: it would push the original request out of the window
            print("  output truncated at the provider's token limit; no continuation (context window too small)", file=sys.stderr)
            break

        print(f"  output truncated, continuing...", file=sys.stderr)
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content":
            "Continue EXACTLY from where you stopped. Output ONLY the remaining Python code, no repetition."})

    print(f"  total: {total_in} in, {total_out} out", file=sys.stderr)
    return full_text

# ---------------------------------------------------------------------------
# Post-processing
# ---------------------------------------------------------------------------

def clean_output(text):
    text = text.strip()
    if text.startswith("```python"):
        text = text[len("```python"):]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()
    # Remove any leading prose before the first import/from/"""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith(("import ", "from ", '"""', "'''", "#!", "OPENAPI", "PASSWORD")):
            text = "\n".join(lines[i:])
            break
    return text


# A generated spec is imported and run on the QA machine (run.py loads it with exec_module), so a model reply that imports or calls
# these must not be written. This is a screen for the obvious spellings, not a sandbox: `getattr(__builtins__, ...)` is not caught.
FORBIDDEN_MODULES = {"os", "subprocess", "shutil", "pty", "ctypes", "socket"}
FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile"}


def forbidden_use(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                    return f"import {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in FORBIDDEN_MODULES:
                return f"from {node.module} import ..."
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
            return f"call to {node.func.id}()"
    return None


def validate(code):
    try:
        tree = ast.parse(code, "<synthesized>")
    except SyntaxError as e:
        return f"SyntaxError line {e.lineno}: {e.msg}"
    bad = forbidden_use(tree)
    if bad:
        return f"FORBIDDEN {bad}: a generated spec runs on the QA machine and may not use it"
    for sym in ("setup", "PUBLIC"):
        if sym not in code:
            return f"missing required symbol: {sym}"
    if "BODIES" not in code:
        return "missing BODIES (engines will be blind)"
    return None

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Generate qa-spec.py from OpenAPI spec")
    p.add_argument("--openapi", required=True)
    p.add_argument("--source", help="source code dir (optional)")
    p.add_argument("--out", default="qa-spec.py")
    p.add_argument("--base-url", default="http://127.0.0.1:5000")
    p.add_argument("--provider", choices=sorted(PROVIDERS), default=None,
                   help="REQUIRED to opt in (no default). Sets the limits (skycodein: 2048 output tokens, 7500-character prompt)")
    p.add_argument("--key-env", default=None,
                   help="REQUIRED to opt in: name of the environment variable holding the API key (e.g. MY_LLM_KEY)")
    p.add_argument("--model", default=None, help="REQUIRED to opt in unless QA_LLM_MODEL is set")
    p.add_argument("--api-url", default=None,
                   help="REQUIRED to opt in unless QA_LLM_API_URL is set: OpenAI-compatible chat completions URL")
    p.add_argument("--max-tokens", type=int, default=16000,
                   help="output limit per call; thinking tokens count against it, so keep it high")
    p.add_argument("--reasoning-effort", choices=["none", "low", "medium", "high"], default="none",
                   help="Gemini thinking budget; 'none' keeps thinking tokens from eating max-tokens")
    p.add_argument("--prompt-version", type=int, choices=sorted(PROMPTS), default=2,
                   help="system prompt: 2 = committed SYSTEM (default, arm C), 3 = SYSTEM + interface/quality block (internal blind experiment), "
                        "4 = 3 + flag-not-skip and GRANTS rules (2026-10-29)")
    a = p.parse_args()

    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    cfg = provider_settings(a.provider, a.api_url, a.model, a.max_tokens, a.key_env)     # refuses before any network use
    a.api_url, a.model, a.max_tokens = cfg["api_url"], cfg["model"], cfg["max_tokens"]
    api_key = os.environ.get(cfg["key_env"])
    if not api_key:
        raise SystemExit(f"Set {cfg['key_env']} in the environment or the .env file (root of qa-testing); --key-env names it")

    parsed_url = urlparse(a.api_url)
    if parsed_url.scheme == "http" and parsed_url.hostname not in ("127.0.0.1", "localhost", "::1"):
        if os.environ.get("QA_ALLOW_PLAINTEXT_PROVIDER") != "1":
            raise SystemExit(f"refusing to send the API key over plaintext HTTP to {parsed_url.hostname}. Use https, "
                             "or set QA_ALLOW_PLAINTEXT_PROVIDER=1 if you trust that network.")

    parsed = parse_openapi(a.openapi)
    print(f"Parsed {len(parsed['endpoints'])} endpoints from {parsed['title']}",
          file=sys.stderr)

    source = scan_source(a.source) if a.source else ""
    if source:
        print(f"Scanned source: {len(source)} chars from route handlers",
              file=sys.stderr)

    user_msg = build_user_prompt(parsed, source, a.openapi, a.base_url)
    code = call_llm(PROMPTS[a.prompt_version], user_msg, a.api_url, api_key, a.model,
                    a.max_tokens, a.reasoning_effort if a.provider == "gemini" else None, cfg["context_chars"])
    code = clean_output(code)

    err = validate(code)
    if err and err.startswith("FORBIDDEN"):
        print(f"REFUSED: {err}. Nothing written.", file=sys.stderr)
        sys.exit(3)
    if err:
        print(f"WARNING: {err}", file=sys.stderr)
        print("Writing anyway — may need manual fixes.", file=sys.stderr)

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(code, encoding="utf-8")
    print(f"Wrote {len(code.splitlines())} lines to {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
