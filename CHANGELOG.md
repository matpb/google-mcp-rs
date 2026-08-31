# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  [`mcpb/`](mcpb/). Published on the [Releases](https://github.com/matpb/google-mcp-rs/releases)
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

[0.8.0]: https://github.com/matpb/google-mcp-rs/releases/tag/v0.8.0
