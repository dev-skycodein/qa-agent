# Sources (what was taken, from where)

| Repo | License | Taken | Why |
|---|---|---|---|
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | nothing copied; used as CLI (`pip install semgrep`) | fast pattern scanner, 30+ langs, `--metrics=off` |
| [trailofbits/skills](https://github.com/trailofbits/skills) | CC BY-SA 4.0 | skills: semgrep, sarif-parsing, differential-review, sharp-edges, variant-analysis, fp-check, supply-chain-risk-auditor, property-based-testing; agents; insecure-defaults references; variant semgrep templates | best Claude Code security/QA skills available |
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | MIT | review prompt + false-positive filter instructions | high-signal review prompt, low noise |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | MIT | skill copied to `toolkit/skills/security-audit/` (SKILL.md, hunting and attack-class guides, report schema, two Node validators with their tests); the validators and tests are unmodified. Local additions: a Windows note in `SKILL.md` and `validate-wsl.ps1`. Licence in `toolkit/licenses/cloudflare-security-audit-MIT.txt` | source-level audit method: coverage ledger, isolated hunters, a fresh verifier that tries to disprove each candidate. Complements the runtime engines, which test a running API. Its own README gives no blind benchmark, so no recall is claimed for it here. Native Windows Node cannot run the validators (no `O_NOFOLLOW`, so they refuse all input by design); `validate-wsl.ps1` runs them under Node in WSL. See `docs/USING.md`. |

## Skipped (not needed now, add later if wanted)
- trailofbits: codeql (heavy setup), audit-context-building (C-focused), entry-point-analyzer (smart contracts only), mutation-testing, c-review/rust-review.
- [returntocorp/semgrep-rules](https://github.com/semgrep/semgrep-rules) — no copy needed, scan pulls `p/default`, `p/owasp-top-ten`, `p/secrets` from registry.
- [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) (secrets), [google/osv-scanner](https://github.com/google/osv-scanner) (vulnerable deps) — used as CLI only by `scan.ps1`.

Trail of Bits content is modified (trimmed tests/evals/assets, workflow refs). CC BY-SA → keep license + attribution if shared.

## Round 2 review (2026-10-15)
| Repo | License | Decision |
|---|---|---|
| [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | optional step in `scan.ps1` (deps CVE + secrets + Dockerfile/IaC misconfig). Overlaps osv+gitleaks; useful when project has Docker/Terraform. |
| [Dicklesworthstone/ultimate_bug_scanner](https://github.com/Dicklesworthstone/ultimate_bug_scanner) | MIT | optional step in `scan.ps1`. 1000+ logic-bug patterns (null, missing await, leaks) — real QA bugs, not only security. Needs Git Bash + ast-grep + jq. Its installer can add a Claude Code hook — install manually, review first. |
| [github/codeql](https://github.com/github/codeql) | queries MIT, CLI proprietary | SKIPPED. CLI free only for open-source/research; private code needs commercial license. Heavy DB build. |
| all-in-ai/llm-security | — | 404, repo not found. Closest: [corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) = paper/tool list for LLM attacks; only relevant if project calls an LLM. Not copied. |
