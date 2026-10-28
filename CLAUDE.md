# Instructions for Claude working in this repo

Read `docs/USING.md` first. It explains what the tool does, how to run it, and its limits.

- Engines talk only to local apps. Never point them at a remote host or a shared server.
- Never run two selftests at once (port 8765).
- Never put an API key in a command. Keys live in the gitignored `.env`.
- Report a finding as a lead. Reproduce it before calling it a bug, and say which engines were `DEGRADED` or `SKIPPED`.
- Run `python qa_check.py --quick` after changing the toolkit. It must end `FAIL=0`.
