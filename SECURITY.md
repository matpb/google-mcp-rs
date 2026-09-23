# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |
| 0.x | no — upgrade to 1.x. See the ["Upgrading from 0.x"](CHANGELOG.md#100---2026-09-23) note in the changelog; the migration and its automatic backup are covered in the README's [Operations](README.md#operations) section. |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security report.

Use GitHub's private vulnerability reporting: on this repository, go to the **Security** tab → **Report a vulnerability**. It is enabled for this repo and creates a private conversation with the maintainer.

When reporting, please include:

- The affected version (`google-mcp --version`) and deployment mode (stdio / HTTP, Docker or bare binary).
- Steps to reproduce, or a minimal request/config that demonstrates the issue.
- What you expected to happen versus what actually happened.
- Your assessment of impact, if you have one (which trust boundary it crosses — see below).

### What to expect

This is a small, mostly single-maintainer project. There's no SLA and no promised response time in days — reports are read and triaged as soon as reasonably possible, and you'll get an acknowledgment in the private thread once that happens. A fix ships as a normal release with a `## [x.y.z]` changelog entry; credit is given in that entry unless you ask otherwise.

## Threat model

`google-mcp-rs` sits at the boundary between an MCP client (an AI agent), the Google APIs it's authorized against, and — optionally — the local filesystem. The trust boundaries worth naming explicitly:

- **The MCP client is semi-trusted.** It authenticated via OAuth and holds a bearer JWT scoped to one Google account, but a compromised or malicious client can still call any tool that account's scopes allow. The server's job is to make sure it can't call tools *outside* those scopes, can't act as a different account, and can't use an expired or revoked token.
- **Tool arguments — and anything an agent reads back from Gmail, Docs, Sheets, Calendar, or Drive — are untrusted input.** An AI agent driving this server may be steered by content it reads (a malicious email body, a shared document, a calendar invite) into calling tools in ways the human operator didn't intend — classic prompt injection. This server validates arguments at the object level (path containment, size limits, header well-formedness, ID encoding) but has no way to know the operator's *intent*, so it cannot fully defend against an agent being tricked into, say, sending an email it shouldn't. Review what an agent is about to do before wiring it up unattended, especially for `gmail_send` (see the README's [Caveats](README.md#caveats) on the lack of a send-safety knob).
- **Google's APIs are trusted** as the upstream source of truth, over TLS, using this server's own registered OAuth client.
- **The local file-exchange directory (`FILE_ROOT`)**, when configured, is a jailed directory the operator explicitly opts into. The server enforces containment (no `..`/symlink escapes, atomic writes) but trusts whatever is already in that directory and whatever the operator's file-maintenance settings allow.
- **The operator is trusted** — whoever controls `GOOGLE_CLIENT_ID`/`SECRET`, `JWT_SECRET`, `STORAGE_ENCRYPTION_KEY`, and the database file has full control over every connected account on that instance. Protecting those values is the operator's responsibility (file permissions, backups, not committing them — see `.env.example` and `.gitignore`).

### In scope

- Authentication/authorization bypass: forging or replaying a bearer JWT, bypassing the host allowlist, bypassing the consent-screen browser binding, or acting as a Google account you don't control.
- Escaping the file-exchange jail (`FILE_ROOT`) to read or write outside it.
- Cross-tenant data leakage — one Google account's data becoming visible to another account's session.
- Secrets handling — refresh tokens, `JWT_SECRET`, `STORAGE_ENCRYPTION_KEY`, or client secrets being logged, exposed via an API response, or recoverable from the database without the encryption key.
- Denial of service that's cheap for the attacker and disproportionately expensive for the server (distinct from the already-documented lack of built-in rate limiting — see [Deployment posture](README.md#deployment-posture)).
- Supply-chain issues in this repository's own code, build, or release process.

### Out of scope

- Vulnerabilities in Google's own APIs or infrastructure — report those to Google.
- The already-documented gaps in [Deployment posture](README.md#deployment-posture) (no built-in rate limiting, no network egress policy) — these are known trade-offs for a self-hosted, same-machine deployment, not bugs. A report proposing a good design for closing one of them is still welcome as a PR.
- Social engineering an operator into approving a malicious client on the consent screen despite its warnings.
- Vulnerabilities that require an attacker to already have the operator's `JWT_SECRET`, `STORAGE_ENCRYPTION_KEY`, or database file — at that point the model no longer holds.

## Built-in protections

For the mechanisms behind these, see the README's [Security model](README.md#security-model) section, which covers in detail:

- The server-rendered `/authorize` consent screen with per-flow browser binding.
- Full bearer-token verification (signature, expiry, audience) at the `/mcp` gate, with `401 invalid_token` on failure.
- RFC 8707 `resource`/audience validation at `/oauth/token`.
- The `Host`/`X-Forwarded-Host` allowlist on every route except `/health`.
- Per-account revocation (`google-mcp accounts revoke`) and an optional account allowlist (`ALLOWED_GOOGLE_ACCOUNTS`).
- Hardened dynamic client registration (parsed redirect-URI validation, size limits, a registration cap, automatic pruning).
- AES-256-GCM encryption at rest for refresh tokens, AAD-bound to the account's Google `sub`.
- The file-exchange path jail and atomic-write semantics.
- Response/upload size limits (64 MiB API responses, 256 MiB downloads and uploads, 24 MiB outgoing email).
- PII-conscious logging (subjects, bodies, recipients, and search queries are never logged).
