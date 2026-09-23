---
name: Bug report
about: Something isn't working as documented
title: ""
labels: bug
---

**Version**
Output of `google-mcp --version`.

**Deployment mode**
stdio / HTTP — bare binary, `cargo run`, or Docker.

**What happened**
A clear description of the bug.

**Steps to reproduce**
1. ...
2. ...

**Expected behavior**
What you expected instead.

**Logs**
Relevant `RUST_LOG` output, with any tokens/emails/PII redacted. (Tracing already redacts subject/body/recipients/query text — but double-check before pasting.)

**Config**
Relevant env vars (redact secrets — `JWT_SECRET`, `STORAGE_ENCRYPTION_KEY`, `GOOGLE_CLIENT_SECRET`, etc. should never be pasted here).

---

Found a security issue instead? Please don't file it here — see [SECURITY.md](../../SECURITY.md) for private reporting.
