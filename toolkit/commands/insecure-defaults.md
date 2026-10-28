---
description: "Audit a path for insecure defaults: fallback secrets, default creds, fail-open checks, weak crypto, permissive CORS/access, debug leakage."
argument-hint: "[path]"
allowed-tools: Read Grep Glob Bash
---

# Insecure defaults audit

Scope: `$1` (default `.`).

1. Read every file in `${CLAUDE_PLUGIN_ROOT}/references/insecure-defaults/`. Missing → stop and say so.
2. For each category, Grep the scope for the patterns listed there (env fallbacks like `|| "secret"`, `cors({origin:"*"})`, `debug: true`, `md5`, `catch {} return true`, default admin passwords...).
3. Each hit: trace it to the security decision it reaches. Only report if a production path really uses the insecure value. Drop test/dev-only code.
4. Output a table: `file:line | category | why exploitable | fix`. No findings → say "no insecure defaults found" plus what was checked.
