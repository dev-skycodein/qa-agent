# Changelog

## 0.1.0 (first public release)

Measured prototype. See the README for the numbers and their interval.

### Added
- Engines: `authz`, `negative`, `stateful`, `race`, `scenario`, `static`, and opt-in `schema`, `auth`, `exposure`, `differential`, `workflow`, `metamorphic`, `logic`.
- `run.py --preflight`: checks a spec against the OpenAPI document and `setup()` without sending attack traffic.
- Local console (`qa_console.py`) with a token, a host check and no write routes.
- Source-code audit skill (Cloudflare `security-audit`, MIT) with a WSL-based validator wrapper for Windows.
- Claude Code commands, agents and review skills; example demo app with planted bugs for the self-test.

### Fixed before release (pre-publication audit)
- A repository file name containing shell metacharacters could become a shell command in generated profiles. Generated commands are now argument lists.
- Generated profiles no longer set `trusted: true`; you set it yourself for a profile you have reviewed.
- A target file's shell reset command is refused; only `reset_cmd_argv` is accepted.
- Target names are validated; the command-line name wins over the name in the target file.
- The PowerShell scanner refuses a non-local API URL.
- Provider API keys are never sent through a redirect; plaintext HTTP to a provider is refused by default.
- Credential headers are redacted in the outbound sink log; secrets found by the outbound check are shown as a length, not copied.

### Known limits
- Tested on Windows 10 only.
- The engines miss rules that are stated only in prose, error-code mismatches (422 versus 413), version rollback, and quota or refund formulas.
- Engines produce false positives (for example, acceptance-only injection signals and cross-field validation rules); each finding needs a manual reproduction.
- The Windows full source audit needs WSL with Node 24 in `~/.local/node`.
