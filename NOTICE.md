# Notice: what the MIT license covers

The `LICENSE` file (MIT) covers the original code and documents of this project: the engines in `toolkit/engine/`, the
console and check scripts, the tests, and the documentation written for it.

It does **not** relicense third-party material, which keeps its own licence. See `SOURCES.md` for the full list.

| Material | Where | Licence |
|---|---|---|
| Trail of Bits skills, modified (Trail of Bits, `trailofbits/skills`) | `toolkit/skills/semgrep`, `toolkit/skills/sarif-parsing`, `toolkit/skills/differential-review`, `toolkit/skills/sharp-edges`, `toolkit/skills/variant-analysis`, `toolkit/skills/fp-check`, `toolkit/skills/supply-chain-risk-auditor`, `toolkit/skills/property-based-testing`, the related agents and `toolkit/references/insecure-defaults` | CC BY-SA 4.0, text in `toolkit/licenses/trailofbits-CC-BY-SA-4.0.txt`. Share-alike: adaptations of these files stay under CC BY-SA 4.0 and need attribution. They were trimmed (tests, evals, assets) and edited. |
| Vulnerability-pattern templates in `toolkit/rules/` (`cpp`, `go`, `java`, `javascript`, `python`). Their first template is clearly adapted from the Trail of Bits variant-analysis template (placeholders such as `[DESCRIBE_ORIGINAL_BUG]`). Provenance of the other files is not verified | `toolkit/rules/*.yaml` | treated as CC BY-SA 4.0 with attribution to Trail of Bits until the origin of each file is checked |
| Anthropic claude-code-security-review prompt and false-positive filter | `toolkit/prompts/security-review.md`, `toolkit/prompts/custom-filtering-instructions.md`, `toolkit/prompts/custom-security-scan-instructions.md` | MIT, text in `toolkit/licenses/anthropic-security-review-MIT.txt` |
| Cloudflare security-audit skill (Copyright (c) 2025-2026 Cloudflare, Inc.). The validators and tests are unmodified; `SKILL.md` has a Windows note added and `validate-wsl.ps1` is ours | `toolkit/skills/security-audit/` | MIT, text in `toolkit/licenses/cloudflare-security-audit-MIT.txt` |
| semgrep, gitleaks, osv-scanner, schemathesis | not copied; used as command-line tools | their own licences (semgrep is LGPL-2.1) |

If you redistribute this project, keep `LICENSE`, this notice, `SOURCES.md` and `toolkit/licenses/`. Whether the combined work can be relicensed under a
single licence has not been reviewed by a lawyer; treat the table above as the working answer.

## Per-folder licences

Each third-party folder has an `ATTRIBUTION.md` stating its licence, its source, and what was changed. The Trail of Bits material (`toolkit/skills/{semgrep,sarif-parsing,differential-review,sharp-edges,variant-analysis,fp-check,supply-chain-risk-auditor,property-based-testing}`, `toolkit/agents/`, `toolkit/references/insecure-defaults/`) is CC BY-SA 4.0 and stays CC BY-SA 4.0. `toolkit/rules/` is listed in its own `ATTRIBUTION.md`. The rest of the project is MIT.
