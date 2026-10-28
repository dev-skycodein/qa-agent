# Security policy

## Reporting a problem

Open a private security advisory on the repository (Security tab, "Report a vulnerability"). Do not open a public issue for a vulnerability in the toolkit itself.

Please include:
- the commit or release you tested,
- the exact command or spec that triggers the problem,
- what you expected and what happened.

## What the toolkit is designed to protect against

- Engines send requests to local hosts only (`127.0.0.1`, `localhost`, `::1`). A remote target is refused.
- Shell commands run only from a profile that says `trusted: true`. Argument lists (`run_cmd_argv`, `reset_cmd_argv`) never use a shell.
- Target files cannot choose the run folder or run a shell reset command.
- Redirects are not followed when a provider API key is sent. Plaintext HTTP to a provider is refused unless you set `QA_ALLOW_PLAINTEXT_PROVIDER=1`.
- Authorization and Cookie headers are not written to the outbound sink log.

## What it does not protect against

- It runs your application on your machine, with the privileges you give it. Only run it against code you trust, with a local test database.
- Spec files are Python and are executed when you run them. Review a spec before you run it.
- Run folders contain request and response traces. Check them before you share them.
