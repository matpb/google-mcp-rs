# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Dependencies: `rmcp` 3.4 (MCP SDK), `aes-gcm` 0.11 and `argon2` 0.6. Stored
  refresh tokens and existing client secrets keep working unchanged.

## [1.0.0] - 2026-09-23

First stable release. No tool-surface changes since 0.12.0 (still 113 domain
tools) — this release is entirely about hardening the OAuth/HTTP surface for
running this server beyond a single trusted workstation, plus release and
supply-chain housekeeping.

### Added

- **Consent screen.** `/authorize` now shows a server-rendered approval page
  before redirecting to Google: the connecting client's self-reported name
  (labeled as unverified), where access will be sent, and the Google scopes
  about to be requested. Approval is bound to the browser with a per-flow
  `HttpOnly` cookie, so an attacker cannot get a victim's browser to approve a
  flow it didn't start. A request to `/authorize` on a host other than
  `BASE_URL` is redirected to `BASE_URL` first. Denying returns
  `error=access_denied`. State TTL is 10 minutes.
- **Account revocation.** `google-mcp accounts list` and
  `google-mcp accounts revoke <email-or-sub>` (works against a running server;
  SQLite WAL). Revoking writes a tombstone that invalidates every JWT issued
  for that account — even ones that haven't expired — then best-effort revokes
  the refresh token with Google and deletes the stored account row. Works
  through Docker too: `docker exec google-mcp google-mcp accounts list`.
- **Optional account allowlist**, `ALLOWED_GOOGLE_ACCOUNTS` — exact emails or
  `@domain` entries (matched against Google's `hd` claim, which requires a
  verified email). Enforced at first sign-in and on every subsequent request.
  Unset means unrestricted, same as before.
- **Host allowlist**, `ALLOWED_HOSTS` — every route except `/health` now
  validates `Host`/`X-Forwarded-Host` against loopback names, `BASE_URL`'s own
  host, and this operator-supplied list, mitigating DNS rebinding. Also
  extends the RFC 8707 `aud`/`resource` allowlist.
- CI now runs a `cargo audit` job and an MSRV check pinned to
  `rust-version` in `Cargo.toml`, and Dependabot watches Cargo, GitHub
  Actions, and Docker base images.
- `SECURITY.md` and `CONTRIBUTING.md`.

### Changed

- **Bearer tokens are now fully verified at the `/mcp` gate** — signature,
  expiry, and audience — before any tool handler runs. An invalid or expired
  token now returns `401` with
  `WWW-Authenticate: Bearer error="invalid_token"`, so well-behaved MCP
  clients re-authenticate automatically instead of getting a confusing
  downstream error.
- **RFC 8707 `resource` is now validated at `/oauth/token`**; a resource
  outside the host allowlist is rejected with `invalid_target`.
- **Dynamic client registration is stricter**: redirect URIs are parsed (not
  string-matched) and must carry no userinfo or fragment, and be `https` or
  loopback `http` (plus Cursor's private-use scheme); registrations are
  size-limited and capped at 10,000 rows; client registrations unused for 24
  hours are pruned automatically; new client secrets are hashed with SHA-256
  instead of Argon2id (cheaper, since these are high-entropy random secrets,
  not user passwords — legacy Argon2id hashes from earlier registrations
  still verify).
- **Google ID token claims are now checked** (issuer, audience, expiry)
  instead of trusting the TLS channel alone.
- `CORS_ALLOW_LOCALHOST=true` now allows loopback *origins* only (any
  scheme/port on `localhost`/`127.0.0.1`/`::1`), not an unrestricted allowlist.
- Outgoing email is validated before send: addresses, display names, and
  subjects are checked, attachment filenames with control characters are
  rejected, and malformed upstream `Message-Id`/`References` headers are
  dropped from reply threading instead of being echoed back malformed.
- Every caller-supplied resource ID (message, thread, file, event, contact,
  sitemap, etc.) is now percent-encoded as a single URL path segment and dot
  segments are rejected — this also **fixes** IDs that previously broke when
  they contained `#`, `?`, or spaces (e.g. some holiday-calendar IDs, sheet
  names with spaces).
- Response bodies are capped at 64 MiB (Google API responses) and 256 MiB
  (downloads), and Drive uploads at 256 MiB, so one oversized file can no
  longer exhaust the server's memory.
- File-exchange writes are now atomic (temp file + rename) and never follow a
  symlink at the destination or create directories outside `FILE_ROOT`.
- `gmail_download_attachment` now rejects `dest_path` and `to_drive_folder_id`
  supplied together (they were silently ambiguous before).
- People group membership changes are capped at 1000 contacts per call.
- Search Console's `hour` dimension now requires `data_state=hourly_all`,
  matching Google's own API requirement, instead of returning an opaque
  upstream error.
- Docker images are now pinned by digest (not tag) and carry OCI labels;
  `cargo build --locked` throughout; `docker-compose.yml` runs the container
  read-only with all capabilities dropped, `no-new-privileges`, and a `tmpfs`
  `/tmp`.
- GitHub Actions in CI are pinned by commit SHA with least-privilege
  `permissions:`.
- The release script (`scripts/release.sh`) now reads its macOS
  build/sign/notarize configuration from `scripts/release.local.env` (copy
  from `scripts/release.local.env.example`) instead of requiring the
  environment to be pre-populated by hand.
- MCP bearer tokens are now signed and verified by a small built-in HS256
  implementation (strict header, constant-time MAC check, typed claims),
  replacing the `jsonwebtoken` crate. Existing tokens stay valid.
- Dependencies updated across the board, including the MCP SDK (`rmcp` 2.x).

### Security

- The SQLite database is now created with file mode `0600`, and an existing
  database with looser permissions is tightened on startup; the automatic
  pre-migration backup (see "Upgrading from 0.x" below) is created `0600`
  too.
- `docs_format_text` no longer panics on a non-ASCII colour string.

### Upgrading from 0.x

No action required for the upgrade itself: on first startup against an
existing database, migration `002_consent_and_revocation.sql` runs
automatically, and the server writes a full backup to
`<DATABASE_URL>.pre-002.bak` (mode `0600`) before applying it. If you need to
roll back to a 0.x binary afterward, stop the server, restore that backup
file over the live database, and start the old binary — a 0.x binary refuses
to open a database with the newer schema, which is exactly why the backup
exists. See [Operations](README.md#operations) in the README for the
`accounts list`/`accounts revoke` commands this release adds, and for the
recommended `chown`/`setfacl` alternative to `chmod 0777` on the file-exchange
directory.

Two things to check:

- **Reverse proxies and tunnels.** Requests are now accepted only for
  loopback names and `BASE_URL`'s host. If clients reach the server under
  any other hostname, add it to `ALLOWED_HOSTS`, or those requests get
  `403`.
- **Existing connections keep working.** Every token this server has issued
  carries an audience for its `/mcp` URL, so connected clients stay signed in
  until the normal 30-day expiry. The consent screen appears the next time a
  client connects or re-authenticates.

## [0.12.0] - 2026-09-23

### Added

- **Gmail filter tools**: `gmail_list_filters` (list every filter with its
  criteria and actions), `gmail_create_filter` (criteria: `from`, `to`,
  `subject`, `query`, `negated_query`, `has_attachment`, `exclude_chats`,
  `size` + `size_comparison` of `larger`/`smaller`; action: add/remove label
  IDs only — forwarding is deliberately unsupported, since auto-forwarding is
  an exfiltration vector), `gmail_delete_filter` (by ID). Gmail's API has no
  filter update; editing a filter means delete then create. Full surface is
  now **113 tools**.

### Changed

- Gmail now requests a second scope, `gmail.settings.basic`, alongside
  `gmail.modify`. Connections authorized before this change lack it: their
  existing Gmail tools keep working, but the new filter tools return
  `auth_required` until the user re-authorizes at `/authorize` (or via
  `/mcp` in Claude Code).
- Gmail `403 ACCESS_TOKEN_SCOPE_INSUFFICIENT` responses now surface as
  `auth_required` with a `reconnect_url` hint, instead of `permission_denied`.

## [0.11.0] - 2026-09-14

### Added

- **Search Console domain (8 tools)**: `searchconsole_list_sites`,
  `searchconsole_get_site`, `searchconsole_list_sitemaps`,
  `searchconsole_get_sitemap`, `searchconsole_submit_sitemap`,
  `searchconsole_delete_sitemap`, `searchconsole_query_analytics`,
  `searchconsole_inspect_url`. Full surface is now **110 tools** across eight
  domains.
- `ENABLED_DOMAINS` accepts `searchconsole` (aliases `search_console`,
  `search-console`, `webmasters`), which requests the
  `https://www.googleapis.com/auth/webmasters` scope at consent time.

### Removed

- The Claude Desktop `.mcpb` bundle and the `mcpb/` packaging directory. Claude
  Desktop now runs local MCP servers directly, so the release ships bare
  binaries only: `google-mcp-linux-x86_64`, `google-mcp-linux-aarch64` (new),
  `google-mcp-macos-universal`, `google-mcp-windows-x86_64.exe`, plus
  `SHA256SUMS.txt` (new). `google-mcp --version` (new) prints the version for
  install-time smoke tests.
- Releases are now built and published locally by `scripts/release.sh` instead
  of GitHub Actions. Linux binaries are static (musl); the macOS binary is
  signed and notarized.

### Notes

- Requires the **Search Console API** to be enabled on the OAuth project.
  Existing authorizations do not carry the new scope; users must
  re-authorize at `/authorize` (or re-run `google-mcp auth`) before the
  Search Console tools work.
- `searchconsole_delete_sitemap` has no undo; resubmit the sitemap URL to add
  it back.
- Property spelling matters: a Domain property is `sc-domain:example.com`, a
  URL-prefix property is `https://example.com/` with the trailing slash.

## [0.10.0] - 2026-08-31

### Added

- **People / Contacts domain (13 tools)** — `people_list_contacts`,
  `people_get_contact`, `people_batch_get_contacts`, `people_search_contacts`,
  `people_create_contact`, `people_update_contact`, `people_delete_contact`,
  `people_list_contact_groups`, `people_get_contact_group`,
  `people_create_contact_group`, `people_update_contact_group`,
  `people_delete_contact_group`, `people_modify_contact_group_members`.
  Full surface is now **102 tools** across seven domains.
- `ENABLED_DOMAINS` accepts `people` (and `contacts` as an alias), which
  requests the `https://www.googleapis.com/auth/contacts` scope at consent time.
- Contact IDs may be passed bare (`c123`) or fully qualified (`people/c123`);
  the same applies to group IDs and `contactGroups/`.

### Notes

- `people_update_contact` **replaces** each field group it is given rather than
  appending to it. Its `etag` and `updatePersonFields` are fetched and derived
  automatically when omitted.
- `people_search_contacts` is prefix-matched, and the client issues Google's
  required warmup request before each search.
- Requires the **People API** to be enabled on the OAuth project. Existing
  authorizations do not carry the new scope; users must re-authorize at
  `/authorize` (or re-run `google-mcp auth`) before the contacts tools work.
- 0.9.0 was never published as a release, so upgrading from **v0.8.0** picks up
  the Tasks domain (13 tools) as well — see the 0.9.0 section below.

## [0.9.0] - 2026-08-27

### Added

- **Tasks domain (13 tools)** — `tasks_list_tasklists`, `tasks_get_tasklist`,
  `tasks_create_tasklist`, `tasks_update_tasklist`, `tasks_delete_tasklist`,
  `tasks_list`, `tasks_get`, `tasks_create`, `tasks_update`, `tasks_complete`,
  `tasks_move`, `tasks_delete`, `tasks_clear_completed`. Full surface is now
  **89 tools** across six domains.
- `ENABLED_DOMAINS` accepts `tasks`, which requests the
  `https://www.googleapis.com/auth/tasks` scope at consent time.

### Notes

- Google Tasks stores `due` as a **date only** — a supplied time of day is
  discarded server-side.
- Existing authorizations do not carry the new scope. Users must re-authorize
  at `/authorize` (or re-run `google-mcp auth`) before the Tasks tools work.

## [0.8.0] - 2026-07-23

Adds a second transport so the server can run as a local **Claude Desktop
extension**, without changing anything about the existing HTTP server.

### Added

- **stdio transport (`google-mcp stdio`)** — serves the full tool surface over
  stdin/stdout for a single local Google account. Claude Desktop launches the
  binary as a child process, so there is no TLS certificate, no tunnel, and no
  inbound network exposure.
- **Claude Desktop bundle (`.mcpb`)** — prebuilt, one-click installable MCP
  Bundle carrying native binaries for macOS, Windows, and Linux. See
  `mcpb/` (removed in 0.11.0, see above). Published on the [Releases](https://github.com/matpb/google-mcp-rs/releases)
  page.
- **`google_authenticate` tool** — in-chat Google sign-in for stdio mode. Opens
  a browser via a loopback OAuth flow and stores the encrypted refresh token
  locally. Exposed only in single-tenant mode; the HTTP surface is unchanged.
- **`google-mcp auth` subcommand** — the same one-time sign-in from the CLI.
- **Automatic local secrets** — in stdio/auth mode, `JWT_SECRET` and
  `STORAGE_ENCRYPTION_KEY` are generated once and persisted beside the database
  at mode `0600` when not supplied. The distributed bundle therefore ships no
  crypto material.
- **Release workflow** — tagged releases build binaries for macOS (universal),
  Windows, and Linux, pack the `.mcpb`, and attach everything to a GitHub
  Release.

### Changed

- `main` now dispatches on a subcommand (`http` | `stdio` | `auth`). Running the
  binary with **no arguments still starts the HTTP server exactly as before**, so
  existing deployments and container entrypoints are unaffected.
- README documents both transports; the previous "streamable HTTP only, no
  stdio" statement is no longer accurate.

### Security

The single-tenant path was reviewed before release; the following are how it
behaves, not a list of shipped bugs:

- The local keyfile is created at mode `0600` with `create_new` and installed by
  atomic rename, so secrets are never briefly world-readable, a pre-planted
  symlink cannot redirect the write, and an interrupted run cannot leave a
  truncated keyfile (losing `STORAGE_ENCRYPTION_KEY` would make every stored
  token permanently undecryptable).
- Auto-provisioning runs **after** `.env` is loaded, so a `.env`-supplied secret
  is never shadowed by a freshly generated one.
- The sign-in callback listener only acts on a request carrying the single-use
  `state`, so another local process — or any page the user happens to be
  visiting — cannot cancel or hijack an in-flight sign-in. It also times out
  after 5 minutes and releases the port.
- `google_authenticate` refuses to run outside single-tenant mode, and is not
  registered on the multi-tenant HTTP surface at all (pinned by tests).
- Re-running the sign-in rebinds the process to the account that just
  authorized, instead of silently continuing to act as the previous one.

### Notes

- On a multi-user machine, the sign-in URL is passed to the browser via the
  process command line, which is world-readable on Linux. The bundle targets
  single-user desktops; do not run the sign-in on a shared host.
- Release binaries are **not yet code-signed or notarized**. macOS may require
  clearing the download quarantine once, and Windows SmartScreen may warn. See
  the README for the one-liner.
- The HTTP multi-tenant path is untouched: identity still comes from the
  per-request bearer JWT, and the full test suite passes unchanged.

## [0.7.0] - 2026-07-04

### Added

- Path-based **file exchange** (`FILE_ROOT`) — attach, upload, and download files
  by path instead of shovelling base64 through the model's context.
- Opt-in exchange-directory maintenance tools (`files_info`, `files_cleanup`),
  gated behind `FILE_MAINTENANCE_TOOLS` and **off by default**, so no listing or
  deletion tool exists unless explicitly enabled.

## [0.6.0] - 2026-07-04

### Added

- `ENABLED_DOMAINS` — scope both the exposed tool surface and the OAuth scopes
  requested at consent time (e.g. `sheets,drive`).

## [0.5.1] and earlier

- **Google Calendar** surface — 14 tools (76 total).
- **Google Docs** surface — 12 tools, including formatting helpers.
- **Sheets + Drive** surfaces — 25 tools.
- **Gmail** surface — 25 tools wired into rmcp's `StreamableHttpService`.
- **Unified error contract** for agent self-correction.
- **MCP 2025-11-25 OAuth 2.1** proxy to Google, end to end (RFC 9728 / 8414 /
  7591 / 8707, PKCE-S256).
- **SQLite persistence** with AES-256-GCM encryption at rest, AAD-bound to the
  user's Google `sub`.

[0.11.0]: https://github.com/matpb/google-mcp-rs/releases/tag/v0.11.0
[0.8.0]: https://github.com/matpb/google-mcp-rs/releases/tag/v0.8.0
