# google-mcp-rs

A multi-tenant **Model Context Protocol** server for **Google Workspace**, written in Rust. Built around streamable HTTP transport with full **OAuth 2.1** so it plugs straight into Claude.ai, Claude Code, ChatGPT custom connectors, Cursor, or any MCP client that speaks the 2025-11-25 authorization spec.

It also runs in **single-tenant stdio mode** as a prebuilt binary that any local MCP client (Claude Code, Claude Desktop, Codex, Cursor) launches as a child process — no TLS certificate, no tunnel, no inbound network exposure.

> **Status:** v1.0.1 — Gmail (28) + Sheets (11) + Drive (14) + Docs (12) + Calendar (14) + Tasks (13) + People/Contacts (13) + Search Console (8) live. **113 tools** total, plus a path-based **file exchange** (attach/upload/download by path, no base64) and 2 opt-in maintenance tools gated by `FILE_MAINTENANCE_TOOLS`. In stdio mode a 114th tool, `google_authenticate`, handles in-chat sign-in.

## Why

The first-party Google Workspace MCP server is missing fundamentals (you cannot send an email from it). Existing community servers are Python or single-tenant. `google-mcp-rs` aims to be the Rust server you actually want to deploy:

- **Full Gmail / Sheets / Drive / Docs / Calendar / Tasks / Contacts / Search Console surface** — 113 tools covering email (search/threads/drafts/send/labels/filters/organize), spreadsheets (CRUD on values + ranges + tabs + raw batchUpdate for formatting/charts), Drive (upload, download, export Google Docs to PDF/CSV/XLSX, share, copy, trash), Google Docs (read as plain text, append/insert/replace, raw batchUpdate for formatting and structure), Google Calendar (calendars + events CRUD, free/busy, quick-add, attendee responses, recurrence), Google Tasks (task lists + tasks CRUD, subtasks, reordering, completion, cross-list moves), Google Contacts (contact CRUD, prefix search, contact groups/labels and their membership), and Google Search Console (properties, sitemaps, search analytics, URL inspection).
- **Multi-tenant by design** — every user does their own Google OAuth dance. Refresh tokens are encrypted at rest with AES-256-GCM and bound to the user's Google `sub` via AAD.
- **OAuth 2.1 done right** — RFC 9728 protected resource metadata, RFC 8414 authorization server metadata, RFC 7591 dynamic client registration, RFC 8707 audience binding, PKCE-S256, a consent screen, and per-account revocation.
- **Two transports, one binary** — **streamable HTTP** (multi-tenant: one running instance serves many MCP clients and many Google accounts at once), or **stdio** (single-tenant: your MCP client launches it as a local child process, no TLS and nothing on the network). See [Quick start — prebuilt binary (stdio)](#quick-start--prebuilt-binary-stdio).
- **One binary, distroless image** — small surface, no runtime dependencies.

## Contents

- [Architecture overview](#architecture-overview)
- [Security model](#security-model)
- [Deployment posture](#deployment-posture)
- [Quick start — prebuilt binary (stdio)](#quick-start--prebuilt-binary-stdio)
- [Quick start — HTTP server (local development)](#quick-start--http-server-local-development)
- [Configuration reference](#configuration-reference)
- [Scoping the surface](#scoping-the-surface)
- [File handling](#file-handling-attachments-uploads-downloads)
- [Operations](#operations)
- [Tools](#tools)
- [Error contract](#error-contract)
- [Caveats](#caveats)
- [Roadmap](#roadmap)
- [Releasing](#releasing)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Architecture overview

`google-mcp-rs` plays two OAuth roles:

1. **Resource Server** — gates `/mcp` and returns `401 + WWW-Authenticate` with a `resource_metadata` URL pointing at `/.well-known/oauth-protected-resource/mcp`.
2. **Authorization Server** — serves `/.well-known/oauth-authorization-server`, `/oauth/register` (DCR), `/authorize`, `/oauth/token`. MCP clients self-register and obtain MCP JWTs from us.

Because Google's OAuth lacks dynamic client registration and won't accept arbitrary `aud` claims, the server runs in **proxy mode**:

```
MCP client (Claude.ai)
   │
   │ 1. /mcp  ─── 401 + WWW-Authenticate ───▶
   │ 2. /.well-known/oauth-protected-resource/mcp
   │ 3. /oauth/register  ◀── mcp_client_id, mcp_client_secret
   │ 4. /authorize?response_type=code&code_challenge=...&redirect_uri=...
   ▼
google-mcp ── server-rendered consent screen ──▶ you approve/deny
   │                                                  │
   ▼ (on approve)                                     │
google-mcp ──── redirect ───▶ accounts.google.com (Google's own consent screen)
                                                │
   ◀────── /oauth/google/callback?code=… ◀─────┘
   │  (server stores Google refresh token, encrypted)
   │
   │ 5. redirect to MCP client's redirect_uri with our code
   │ 6. /oauth/token (exchange code + PKCE verifier) ─▶ MCP JWT
   ▼
MCP client → /mcp Authorization: Bearer <MCP JWT>
              tools call Gmail with the user's stored refresh token
```

State is threaded MCP-client → our consent screen → Google → callback via single-use opaque tokens stored in SQLite (5-minute TTL for authorization codes, 10-minute TTL for the in-flight `/authorize` state, both bound to a per-flow browser cookie). MCP JWTs are HS256 signed, bound to the user's Google `sub`, audience-scoped to `${BASE_URL}/mcp`, and fully verified (signature, expiry, audience) on every `/mcp` request.

## Security model

- **Consent screen.** `/authorize` renders our own approval page before redirecting to Google: it shows the connecting client's self-reported name (explicitly labeled as unverified), where access will be sent (parsed from the real `redirect_uri`, never the raw string), and the Google scopes about to be requested. Approval is bound to the browser with a per-flow `HttpOnly` cookie, so an attacker who tricks a victim into visiting a crafted `/authorize` link cannot get it silently approved — the approving browser must be the one that started the flow. A request to `/authorize` on any host other than `BASE_URL` is redirected to `BASE_URL` first, so the binding cookie is always set on the right origin. Denying returns `error=access_denied` to the MCP client. The state row (and its cookie) expire after 10 minutes; the authorization code minted after approval expires after 5 minutes.
- **Token verification at the gate.** Every `/mcp` request's bearer token is fully verified — signature, expiry, and audience — before it reaches a tool handler. An invalid or expired token gets `401` with `WWW-Authenticate: Bearer error="invalid_token"`, which well-behaved MCP clients treat as a signal to re-authenticate automatically. A token's `aud` claim must name this server's own `/mcp` URL (every token this server has ever issued does); `/oauth/token` separately validates an RFC 8707 `resource` parameter against the same allowlist and rejects a mismatch with `invalid_target`.
- **Host allowlist (anti DNS-rebinding).** Every route except `/health` validates the `Host` header (and any `X-Forwarded-Host` element) against loopback names, `BASE_URL`'s own host, and the operator-supplied `ALLOWED_HOSTS` list. A request with an unrecognized Host gets `403`.
- **Revocation.** `google-mcp accounts revoke <email-or-sub>` writes a tombstone (`not_before` timestamp) that invalidates *every* JWT issued for that account before the moment of revocation — including ones that haven't expired yet — then best-effort revokes the refresh token with Google and deletes the stored account row. This is the only way to cut a session short before its 30-day JWT lifetime; rotating `JWT_SECRET` (which logs out everyone) is no longer the only lever.
- **Account allowlist.** Optional `ALLOWED_GOOGLE_ACCOUNTS` restricts which Google identities may connect at all, by exact email or `@domain` (matched against Google's `hd` claim, which requires a verified email on that account). Enforced at sign-in and re-checked on every tool call, so removing someone from the list also cuts off tokens issued before the change.
- **Dynamic client registration hardening.** Redirect URIs are parsed (not string-matched): no embedded userinfo, no fragment, `https` or loopback `http` only (plus Cursor's private-use scheme). Registrations are capped at 10,000 rows and size-limited; unused client registrations are pruned automatically after 24 hours of inactivity. Client secrets are hashed with SHA-256 (legacy Argon2id hashes from earlier registrations still verify).
- **File-exchange jail.** When `FILE_ROOT` is set, every path is canonicalized and checked to be inside it before any read or write — absolute paths must live under it, relative paths resolve against it, `..` and symlink escapes are rejected, and writes are atomic (temp file + rename, never following a symlink at the destination or creating directories outside the root).
- **Response and payload limits.** Google API responses are capped at 64 MiB, file downloads at 256 MiB, Drive uploads at 256 MiB, and outgoing email (headers + body + attachments) at 24 MiB — all enforced server-side before the bytes reach the model's context.
- **Secrets at rest.** Google refresh tokens are encrypted with AES-256-GCM, AAD-bound to the account's Google `sub` so ciphertexts can't be swapped between rows. In stdio/auth mode, `JWT_SECRET` and `STORAGE_ENCRYPTION_KEY` are auto-generated and written to `<DATABASE_URL>.keys` at file mode `0600` via atomic create-then-rename (never briefly world-readable, never left half-written by an interrupted run).

## Deployment posture

This server is designed to be **self-hosted on your own machine** — typically one instance per workstation, listening on `127.0.0.1`, serving multiple MCP clients and multiple Google accounts at once. The quick-start below walks you through exactly that.

Public-internet deployment is *possible* — the OAuth flow, the consent screen with browser-binding, the host allowlist, full bearer-token verification, per-account revocation, an optional account allowlist, AES-256-GCM refresh-token encryption, S256 PKCE, and single-use short-TTL codes are all in place — but a couple of gaps remain worth knowing about before you expose this beyond your own network:

- **No built-in rate limiting** on `/oauth/register`, `/oauth/token`, `/authorize`, or `/mcp`. Brute-force and DoS are unmitigated at the application layer — put a reverse proxy (nginx, Caddy, Cloudflare, etc.) with request-rate limits in front of a public instance.
- **No network egress policy** on the container — a compromised process could reach anywhere on the internet. Pair the provided `docker-compose.yml` hardening (read-only root, all capabilities dropped, `no-new-privileges`) with an egress firewall rule if that matters for your threat model.
- **JWTs still live 30 days.** That's now recoverable — `accounts revoke` invalidates them immediately — but there's no short-lived-access-token + refresh-token split, so a leaked JWT is valid until either its expiry or an explicit revoke.

If those gaps don't fit your threat model, fork it. The architecture is set up to make those additions straightforward, and PRs are welcome. See [SECURITY.md](SECURITY.md) for the full threat model and how to report a vulnerability.

## Quick start — prebuilt binary (stdio)

This path is for a personal install on your own machine; see [Quick start — HTTP server](#quick-start--http-server-local-development) below for shared deployments. (During sign-in only, a short-lived listener on `127.0.0.1:8433` catches Google's redirect; it is closed as soon as the flow finishes or times out.)

1. **Download** the binary for your platform from [Releases](https://github.com/matpb/google-mcp-rs/releases/latest):

   | Asset | Platform |
   |---|---|
   | `google-mcp-linux-x86_64` | Linux x86_64 |
   | `google-mcp-linux-aarch64` | Linux aarch64 |
   | `google-mcp-macos-universal` | macOS (Intel and Apple Silicon) |
   | `google-mcp-windows-x86_64.exe` | Windows x86_64 |
   | `SHA256SUMS.txt` | checksums for all of the above |

   ```bash
   ASSET=google-mcp-linux-x86_64   # or linux-aarch64 / macos-universal
   curl -fsSLO "https://github.com/matpb/google-mcp-rs/releases/latest/download/$ASSET"
   curl -fsSLO "https://github.com/matpb/google-mcp-rs/releases/latest/download/SHA256SUMS.txt"
   grep " $ASSET\$" SHA256SUMS.txt | sha256sum -c -   # shasum -a 256 -c on macOS
   chmod +x "$ASSET" && mkdir -p ~/.local/bin && mv "$ASSET" ~/.local/bin/google-mcp
   google-mcp --version
   ```

   A binary fetched with `curl` carries no macOS quarantine flag, so it runs without a Gatekeeper prompt; a browser download would need `xattr -d com.apple.quarantine`.

2. **Create your own Google OAuth client** — follow [step 1 below](#1-create-a-google-oauth-client), and register exactly this redirect URI:
   ```
   http://localhost:8433/oauth/google/callback
   ```
   (Google rejects the sign-in with `redirect_uri_mismatch` if this is missing.)

3. **Configure** — set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `BASE_URL=http://localhost:8433`, `DATABASE_URL=~/.google-mcp.db`. `JWT_SECRET` and `STORAGE_ENCRYPTION_KEY` are generated on first run and stored at `<DATABASE_URL>.keys`, mode `0600` — no hand-managed secrets.

   Claude Code:
   ```bash
   claude mcp add --scope user google-workspace \
     -e GOOGLE_CLIENT_ID=... -e GOOGLE_CLIENT_SECRET=... \
     -e BASE_URL=http://localhost:8433 -e DATABASE_URL="$HOME/.google-mcp.db" \
     -- "$HOME/.local/bin/google-mcp" stdio
   ```

   Codex / ChatGPT desktop (`~/.codex/config.toml`):
   ```toml
   [mcp_servers.google_workspace]
   command = "<HOME>/.local/bin/google-mcp"
   args = ["stdio"]
   [mcp_servers.google_workspace.env]
   GOOGLE_CLIENT_ID = "..."
   GOOGLE_CLIENT_SECRET = "..."
   BASE_URL = "http://localhost:8433"
   DATABASE_URL = "<HOME>/.google-mcp.db"
   ```

4. **Sign in once** — run `google-mcp auth` in a terminal with the same env vars, or ask the assistant to call the **`google_authenticate`** tool. A browser opens, you approve, and that is it. Port 8433 must be free during sign-in only.

Your encrypted Google refresh token lives only on your machine (`~/.google-mcp.db`, the `DATABASE_URL` SQLite file). The macOS binary is signed and notarized with a Developer ID; the Linux binaries are fully static (musl) and run on any distribution; the Windows binary is unsigned, so SmartScreen may warn on first run: **More info → Run anyway**.

## Quick start — HTTP server (local development)

### 1. Create a Google OAuth client

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Pick or create a GCP project.
2. Enable the **Gmail API**, **Sheets API**, **Drive API**, **Docs API**, **Calendar API**, **Tasks API**, **People API**, and **Search Console API**.
3. **OAuth consent screen** → External, app name `google-mcp` (or whatever you want users to see), user support email, developer email.
4. Add scopes:
   - `openid`
   - `email`
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/gmail.settings.basic`
   - `https://www.googleapis.com/auth/spreadsheets`
   - `https://www.googleapis.com/auth/drive`
   - `https://www.googleapis.com/auth/documents`
   - `https://www.googleapis.com/auth/calendar`
   - `https://www.googleapis.com/auth/tasks`
   - `https://www.googleapis.com/auth/contacts`
   - `https://www.googleapis.com/auth/webmasters`
5. Add yourself + any beta users to the **Test users** list (until the app is verified, only test users can authorize — see [Caveats](#caveats)).
6. **Credentials** → **Create credentials** → **OAuth 2.0 Client ID** → **Web application**.
7. Authorized redirect URI: `${BASE_URL}/oauth/google/callback` (e.g. `http://localhost:8433/oauth/google/callback` for dev).
8. Save the client ID and client secret.

### 2. Configure the server

```bash
cp .env.example .env
$EDITOR .env  # fill in GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL
openssl rand -hex 64                                  # JWT_SECRET
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='    # STORAGE_ENCRYPTION_KEY
```

### 3. Run it

```bash
cargo run --release
# or
docker compose up --build
```

The server listens on `http://0.0.0.0:8433` by default. `/health` returns `ok`. `/mcp` requires a valid bearer token.

### 4. Connect Claude Code

Add the server once per Google account you want to use. Each entry triggers its own OAuth dance: our consent screen first, then Google's, and you pick the matching Google account in the browser tab when prompted.

```bash
claude mcp add --transport http --scope user google-personal http://localhost:8433/mcp
claude mcp add --transport http --scope user google-work     http://localhost:8433/mcp
```

Then in any Claude Code session run `/mcp` and authenticate each entry. The JWTs land in Claude Code's credential vault; the server is multi-tenant and keys on Google `sub`, so one running instance handles both accounts. JWT lifetime is 30 days (revocable early with `google-mcp accounts revoke`, see [Operations](#operations)); access tokens refresh transparently every hour.

For **Claude.ai / ChatGPT custom connectors / Cursor**, add a custom connector pointing at `http://localhost:8433/mcp` — these clients have to support local-loopback URLs and the MCP 2025-11-25 OAuth flow, which not all of them do yet.

## Configuration reference

Every variable `ServerConfig::from_env()` reads, from `src/config.rs`:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GOOGLE_CLIENT_ID` | yes | — | OAuth client ID from GCP Console |
| `GOOGLE_CLIENT_SECRET` | yes | — | OAuth client secret from GCP Console |
| `BASE_URL` | yes | — | Public URL of this server (`http://` or `https://`, trailing slash stripped). Used to compute the Google redirect URI, the default OAuth issuer, and the host allowlist |
| `JWT_SECRET` | yes* | — | HS256 secret for signing MCP JWTs, at least 32 bytes. *In `stdio`/`auth` mode, auto-generated and persisted at `<DATABASE_URL>.keys` (mode `0600`) if unset — required in `http` mode |
| `STORAGE_ENCRYPTION_KEY` | yes* | — | 32 bytes, base64url-encoded — encrypts refresh tokens at rest. *Same auto-generation as `JWT_SECRET` in `stdio`/`auth` mode |
| `MCP_HOST` | no | `0.0.0.0` | Bind address, parsed as an IP |
| `MCP_PORT` | no | `8433` | Listen port |
| `DATABASE_URL` | no | `./google-mcp.db` | SQLite file path (or `:memory:` in tests) |
| `CORS_ALLOW_LOCALHOST` | no | `false` | Allow any loopback origin (`localhost`/`127.0.0.1`/`::1`, any scheme/port) in CORS. Dev only — production always allows only `https://claude.ai` and `https://claude.com` regardless of this setting |
| `ALLOWED_HOSTS` | no | none | Comma-separated extra `Host`/`X-Forwarded-Host` entries allowed beyond loopback and `BASE_URL`'s own host — e.g. a tunnel or reverse-proxy hostname. Also extends the RFC 8707 `aud`/`resource` allowlist |
| `ENABLED_DOMAINS` | no | all eight | Comma-separated subset of `gmail,sheets,drive,docs,calendar,tasks,people,searchconsole` (`contacts` aliases `people`; `search_console`/`search-console`/`webmasters` alias `searchconsole`). Filters both the MCP tool surface and the OAuth scopes requested from Google. See [Scoping the surface](#scoping-the-surface) |
| `ALLOWED_GOOGLE_ACCOUNTS` | no | unrestricted | Comma-separated exact emails and/or `@domain` entries. A `@domain` entry matches Google's `hd` claim (Workspace domain), not an email suffix. Empty/unset = any Google account may connect |
| `FILE_ROOT` | no | — (disabled) | Absolute path to the file-exchange directory, bind-mounted into the container at the same path. Enables attaching/uploading by `path` and saving downloads by `dest_path` instead of base64. Unset = base64-only. See [File handling](#file-handling-attachments-uploads-downloads) |
| `FILE_MAINTENANCE_TOOLS` | no | `off` | Whether the directory-maintenance tools are exposed: `off` (neither), `info` (read-only `files_info`), or `full` (`files_info` + the deleting `files_cleanup`). Off by default, so no deletion/listing tool exists unless you opt in. Only meaningful when `FILE_ROOT` is set |

Not read by `ServerConfig`, but honored elsewhere:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `RUST_LOG` | no | `google_mcp=info,rmcp=warn,reqwest=warn` | Tracing filter — keep `reqwest` ≤ `warn` to avoid logging URLs with PII |

## Scoping the surface

By default, the server exposes all 113 tools across all eight Workspace domains and asks Google for the matching scope set during consent. For deployments that only need part of the surface, set `ENABLED_DOMAINS` to a comma-separated subset:

```bash
ENABLED_DOMAINS=gmail            # Gmail-only: 28 tools, gmail.modify + gmail.settings.basic scopes
ENABLED_DOMAINS=gmail,calendar   # email + calendaring: 42 tools
ENABLED_DOMAINS=docs,drive       # document workflow: 26 tools
ENABLED_DOMAINS=calendar,tasks   # planning only: 27 tools
ENABLED_DOMAINS=gmail,people     # email + address book: 41 tools
ENABLED_DOMAINS=searchconsole   # SEO only: 8 tools, webmasters scope
```

Two things shrink in lockstep:

1. **Tool surface.** Only the listed domains' `tool_router` impls compose into the MCP server. The rest of the tools simply do not exist on this instance — they don't show up in `tools/list`, they don't burn agent context tokens, they can't be called.
2. **OAuth scopes.** The consent screen asks Google for `openid`, `email`, plus only the scopes for the listed domains. A user authorizing a Gmail-only deployment never grants the server access to their Drive or Calendar.

Domain names are case-insensitive and whitespace-trimmed (`Gmail`, `GMAIL`, `gmail ` all parse the same). Unset, empty, or `ENABLED_DOMAINS=` reverts to the full surface (backwards-compatible default). An unknown domain name fails fast at startup with the valid list in the error message.

## File handling (attachments, uploads, downloads)

Moving binary files through an MCP tool call means base64 — which inflates size ~33% and, worse, drags the whole blob through the model's context in both directions. Models are unreliable at emitting/parsing multi-megabyte base64. Because this server is designed to run on the **same machine** as its MCP client, it offers a far better path: a **shared filesystem exchange**.

Set `FILE_ROOT` to a directory and bind-mount it into the container **at the same absolute path** (the provided `docker-compose.yml` does this automatically). Then file tools can name files by path — bytes never touch the model's context:

| Instead of base64… | Do this |
| --- | --- |
| Attach a local file to an email | `gmail_send attachments=[{ "path": "<FILE_ROOT>/report.pdf" }]` |
| Save an email attachment to disk | `gmail_download_attachment dest_path="<FILE_ROOT>/in.pdf"` |
| Upload a local file to Drive | `drive_create_file path="<FILE_ROOT>/report.pdf"` |
| Download a Drive file to disk | `drive_download_file dest_path="<FILE_ROOT>/out.pdf"` |
| Export a Google Doc to disk | `drive_export_file dest_path="<FILE_ROOT>/doc.pdf"` |

It also does **server-side transfers** so bytes move Google↔Google without a round-trip through the model at all:

| Task | Do this |
| --- | --- |
| Attach a Drive file to an email | `gmail_send attachments=[{ "drive_file_id": "1AbC…" }]` |
| Save an email attachment to Drive | `gmail_download_attachment to_drive_folder_id="root"` (mutually exclusive with `dest_path`) |

**Safety & semantics.** Every path is confined to `FILE_ROOT` — absolute paths must live under it, relative paths resolve against it, and `..`/symlink escapes are rejected; writes are atomic and never follow a symlink at the destination. `mime_type` is inferred from the filename when omitted. When `FILE_ROOT` is set, oversized downloads (>8 MB) refuse to return inline base64 and point you at `dest_path`; downloads are capped at 256 MiB and Drive uploads at 256 MiB regardless. Leaving `FILE_ROOT` unset disables path-based exchange entirely and every tool falls back to base64 — so remote deployments still work, they just pay the base64 tax.

**Permissions.** The container runs as uid 65532, so the exchange directory must be writable by that uid — see [Operations](#operations) for the recommended `chown`/`setfacl` approach. Files the server writes will be owned by 65532 on the host. **Caveat:** whatever directory you choose becomes the scope of `files_cleanup`, so pointing `FILE_ROOT` at a busy folder like Downloads means an unfiltered `files_cleanup dry_run=false` would delete everything in it (except `keep/`) — always filter and dry-run first.

**Discoverability.** When `FILE_ROOT` is set, the MCP server's `instructions` (returned on connect) include a FILE HANDLING section that states the live exchange path and these rules, so any calling agent learns the protocol without being told.

**Keeping it tidy.** The exchange directory accumulates over time. Two optional tools can manage it — **off by default** and gated by `FILE_MAINTENANCE_TOOLS` (`off` / `info` / `full`), so a deletion tool never exists unless you opt in. Nothing is ever deleted automatically.

| Tool | Requires | Purpose |
| --- | --- | --- |
| `files_info` | `FILE_MAINTENANCE_TOOLS=info` or `full` | Report the exchange path, file count, total bytes, and a listing (oldest first). Read-only. |
| `files_cleanup` | `FILE_MAINTENANCE_TOOLS=full` | Delete files by age (`older_than_hours`) and/or name (`name_contains`). **Defaults to `dry_run: true`** — reports what would go and removes nothing until you pass `dry_run: false`. |

Anything under a `keep/` subdirectory of `FILE_ROOT` is invisible to `files_cleanup` and never deleted. If you point `FILE_ROOT` at a directory you manage yourself (e.g. your Downloads folder), leave `FILE_MAINTENANCE_TOOLS=off` (the default) so the server can never delete anything there.

## Operations

### Listing and revoking accounts

```bash
google-mcp accounts list
google-mcp accounts revoke <email-or-sub>

# in Docker:
docker exec google-mcp google-mcp accounts list
docker exec google-mcp google-mcp accounts revoke someone@example.com
```

`accounts list` prints every connected Google account with its `sub`, email, and created/updated/last-refresh timestamps. `accounts revoke` writes a revocation tombstone (instantly invalidating every JWT issued for that account, even ones that haven't expired), best-effort revokes the refresh token with Google, and deletes the stored account row. Run it as soon as you suspect a token leaked — you don't have to wait for the 30-day JWT lifetime to run out or rotate `JWT_SECRET` for everyone.

### Backups

The SQLite database and its `.keys` file (stdio/auth mode) are created at file mode `0600`. Back them up like any other secret store — the database holds every connected account's encrypted refresh token.

### Upgrading from 0.x

Migration `002_consent_and_revocation.sql` runs automatically on first startup against an older database — no manual step. Before applying it, the server writes a full backup to `<DATABASE_URL>.pre-002.bak` (also mode `0600`). If you need to roll back to a 0.x binary, stop the server, restore that backup over the live database file, and start the old binary — a newer schema is refused by older binaries, which is exactly why the backup exists.

### File-exchange directory ownership

The container runs as uid 65532. For an operator-owned directory (not one you already use for other things), prefer one of these over `chmod 0777`:

```bash
# Pre-create and hand ownership to the container's uid:
mkdir -p ~/.google-mcp/exchange && sudo chown 65532:65532 ~/.google-mcp/exchange

# Or, to keep your own ownership and grant the container write access via ACL
# (useful when FILE_ROOT points at a directory you already own, e.g. Downloads):
setfacl -m u:65532:rwx ~/Downloads
```

`chmod 0777` still works and is documented in [`.env.example`](.env.example) as the fastest single-user-workstation option, but it makes the directory world-writable — `chown`/`setfacl` scope write access to exactly the container's uid instead.

## Tools

### Gmail (28)

| Tool | Purpose |
|---|---|
| `gmail_search_threads` | Search threads with Gmail query syntax |
| `gmail_get_thread` | Get a thread with all messages and full payload |
| `gmail_get_message` | Get a single message by ID |
| `gmail_list_messages` | List messages with optional query |
| `gmail_list_attachments` | List attachments on a message |
| `gmail_download_attachment` | Download an attachment by ID (returns base64) |
| `gmail_get_thread_url` | Build a Gmail web URL for a thread |
| `gmail_create_draft` | Create a draft (optionally as a reply) |
| `gmail_get_draft` | Get a draft by ID |
| `gmail_list_drafts` | List drafts |
| `gmail_update_draft` | Update an existing draft |
| `gmail_delete_draft` | Delete a draft |
| `gmail_send_draft` | Send a previously created draft |
| `gmail_send` | Send an email (with `reply_to_message_id`, `cc`, `bcc`, attachments) |
| `gmail_list_labels` | List all labels |
| `gmail_get_label` | Get a label by ID with message counts |
| `gmail_create_label` | Create a label (with optional color) |
| `gmail_update_label` | Rename or restyle a label |
| `gmail_delete_label` | Delete a label |
| `gmail_list_filters` | List every filter, with its criteria and actions |
| `gmail_create_filter` | Create a filter (criteria: from/to/subject/query/negated_query/has_attachment/exclude_chats/size+size_comparison; action: add/remove label IDs only, no forwarding). Gmail has no filter update — edit means delete then create |
| `gmail_delete_filter` | Delete a filter by ID |
| `gmail_modify_labels` | Add/remove labels on a message OR thread |
| `gmail_mark_read` | Mark messages as read |
| `gmail_mark_unread` | Mark messages as unread |
| `gmail_archive` | Archive messages |
| `gmail_trash` | Move messages to trash |
| `gmail_get_profile` | Return the connected account email and granted scopes |

> **Filter tools need a new scope.** `gmail_list_filters` / `gmail_create_filter` / `gmail_delete_filter` require `gmail.settings.basic`, which connections authorized before this change don't have. Their other Gmail tools keep working; the filter tools return `auth_required` (`ACCESS_TOKEN_SCOPE_INSUFFICIENT`) until the user re-authorizes at `/authorize` (in Claude Code: `/mcp`, pick the server, re-authenticate).

### Sheets (11)

| Tool | Purpose |
|---|---|
| `sheets_create` | Create a new spreadsheet (optionally with named tabs + locale + time zone) |
| `sheets_get` | Get a spreadsheet's metadata (or specific A1 ranges with cell data) |
| `sheets_get_values` | Read values from an A1 range |
| `sheets_batch_get_values` | Read values from multiple A1 ranges in one call |
| `sheets_update_values` | Write a 2-D array of values into a range (`RAW` or `USER_ENTERED`) |
| `sheets_append_values` | Append rows to a table-shaped range |
| `sheets_clear_values` | Clear values in a range (formatting preserved) |
| `sheets_batch_update_values` | Write to multiple ranges in one API call |
| `sheets_batch_update` | Schema-level batch update — add/delete sheets, formatting, conditional formatting, charts, banding (raw `requests[]` passthrough) |
| `sheets_add_sheet` | Convenience: add a new tab |
| `sheets_delete_sheet` | Convenience: remove a tab by `sheetId` |

### Docs (12)

**Read & basic write:**
| Tool | Purpose |
|---|---|
| `docs_create` | Create an empty Google Doc with a title |
| `docs_get` | Get a document's full structured payload (paragraphs, runs, tables, lists, headers, footers, styles) |
| `docs_get_text` | Fetch the doc and return its body as **flattened plain text** — the high-value tool for agents reading content |
| `docs_append_text` | Append plain text to the end of the document |
| `docs_insert_text` | Insert plain text at a specific character index |
| `docs_replace_text` | Find every occurrence of a string and replace it (case-sensitive optional) |

**Formatting helpers** (hide the index/schema math):
| Tool | Purpose |
|---|---|
| `docs_insert_styled` | Insert text with **text styling** (bold, italic, underline, strikethrough, font size, font family, foreground/background `#rrggbb` color, link, baseline) and/or **paragraph styling** (HEADING_1…6, TITLE, SUBTITLE, NORMAL_TEXT). Append by default; pass `at_index` for a specific position. Returns the inserted range so chained ops can keep going |
| `docs_format_text` | Apply text and/or paragraph styling. Pass EITHER `range: {start_index, end_index}` for an exact slice OR `match: "..."` to style every occurrence (case-insensitive by default). Returns the list of ranges affected |
| `docs_make_list` | Convert paragraphs in a range to a bulleted or numbered list. `style: "bullet"` (default) or `"numbered"`, or pass `bullet_preset` directly (e.g. `BULLET_CHECKBOX`, `NUMBERED_DECIMAL_NESTED`) |
| `docs_insert_table` | Insert an empty table (`rows` × `columns`) at a position. Capped at 100 rows × 20 columns per Google's API limits |
| `docs_insert_image` | Insert an inline image from a public HTTPS URL with optional explicit `width_pt` / `height_pt`. PNG / JPEG / GIF only |

**Escape hatch:**
| Tool | Purpose |
|---|---|
| `docs_batch_update` | Raw `requests[]` passthrough for everything else (named ranges, section breaks, custom paragraph spacing, conditional formatting, etc.) |

> **Indexes are UTF-16 code units** (matches what `docs_get` returns). For ASCII text this equals byte length; for emoji or non-BMP characters one Unicode scalar can occupy two units.

### Drive (14)

| Tool | Purpose |
|---|---|
| `drive_list_files` | Search/list files with Drive query syntax |
| `drive_get_file` | Fetch file metadata |
| `drive_create_folder` | Create a folder (optionally nested) |
| `drive_create_file` | Upload a file (multipart, ≤ 256 MB content) |
| `drive_update_metadata` | Rename, re-describe, move (add/remove parents), star |
| `drive_update_content` | Replace a file's binary content |
| `drive_download_file` | Download bytes (returns base64) |
| `drive_export_file` | Export a Google Doc/Sheet/Slide to PDF/CSV/XLSX/markdown/etc. |
| `drive_copy_file` | Duplicate a file |
| `drive_trash_file` | Move to Trash (reversible) |
| `drive_delete_permanent` | **Irreversible** delete — prefer `drive_trash_file` |
| `drive_share_file` | Add a permission (user/group/domain/anyone × reader/commenter/writer/…) |
| `drive_list_permissions` | List sharing entries |
| `drive_delete_permission` | Remove a sharing entry by ID |

### Calendar (14)

| Tool | Purpose |
|---|---|
| `calendar_list_calendars` | List the calendars on the user's calendar list (primary + subscribed). Use to discover IDs |
| `calendar_get_calendar` | Get a calendar's metadata (`"primary"` for the user's main calendar) |
| `calendar_create_calendar` | Create a secondary calendar |
| `calendar_delete_calendar` | **Irreversibly** delete a secondary calendar (primary cannot be deleted) |
| `calendar_list_events` | List/search events. Expands recurrences by default (`single_events=true`). Filter by `time_min`/`time_max`/`q`/`updated_min` |
| `calendar_get_event` | Get a single event by ID |
| `calendar_create_event` | Create an event with structured fields — timed (`start_date_time` + `end_date_time` RFC3339) or all-day (`start_date` + `end_date`), attendees, RRULE recurrence, popup reminders, optional Google Meet link, color, visibility, transparency, plus `extra_event_fields` escape hatch |
| `calendar_quick_add_event` | Natural-language event creation (`Lunch with Sara tomorrow at 1pm`) |
| `calendar_patch_event` | Partial update — same structured fields as create, all optional. **Setting `attendees` REPLACES the list** |
| `calendar_delete_event` | Delete an event (use `send_updates="all"` to notify guests) |
| `calendar_move_event` | Move an event to a different calendar |
| `calendar_respond_to_event` | Set the user's (or another attendee's) `responseStatus`: accepted / declined / tentative |
| `calendar_freebusy` | Free/busy across one or more calendars within a time window — for conflict checking before scheduling |
| `calendar_list_colors` | Calendar + event color palette (for `colorId`) |

> **Default `send_updates=none`.** Calendar mutations don't email guests by default — pass `send_updates="all"` (or `"externalOnly"`) explicitly when you want a notification. This keeps agents from spamming inboxes during retries or batch operations.

### Tasks (13)

| Tool | Purpose |
|---|---|
| `tasks_list_tasklists` | List the user's task lists — use to discover `tasklist_id`s (`@default` is always the default list) |
| `tasks_get_tasklist` | Get one task list's metadata |
| `tasks_create_tasklist` | Create a task list |
| `tasks_update_tasklist` | Rename a task list |
| `tasks_delete_tasklist` | **Irreversibly** delete a task list and everything in it |
| `tasks_list` | List tasks in a list. Filter by `due_min`/`due_max`/`updated_min`, toggle `show_completed`/`show_hidden`/`show_deleted` |
| `tasks_get` | Get a single task by ID |
| `tasks_create` | Create a task — `title`, `notes`, `due`, optional `parent` (subtask) and `previous` (position) |
| `tasks_update` | Partial update of `title` / `notes` / `due` / `status`. `due=""` clears the date |
| `tasks_complete` | Tick a task off, or reopen it with `completed=false` |
| `tasks_move` | Reparent, reorder, or move a task to another list |
| `tasks_delete` | Soft-delete a task (still visible with `show_deleted=true`) |
| `tasks_clear_completed` | Hide every completed task in a list (the UI's "Delete all completed tasks") |

> **`due` is a date, not a datetime.** Google Tasks accepts RFC3339 but stores only the date part and silently discards the time of day. A task cannot carry a due time — use Calendar for that.

### People / Contacts (13)

| Tool | Purpose |
|---|---|
| `people_list_contacts` | List the whole address book. Returns each contact's `resourceName` (`people/c123...`), which every other people_* tool takes |
| `people_get_contact` | Get one contact, including the `etag` an update needs |
| `people_batch_get_contacts` | Get up to 200 contacts in one call |
| `people_search_contacts` | Prefix search across names, nicknames, emails, phones and organizations — the cheap way to resolve a person to a `resourceName` |
| `people_create_contact` | Create a contact from `given_name`/`family_name`/`emails`/`phones`/`organization`/`job_title`/`notes`/`birthday`/`addresses`/`urls`, or a raw `person` resource |
| `people_update_contact` | Update a contact. `etag` and `update_person_fields` are resolved automatically when omitted |
| `people_delete_contact` | **Irreversibly** delete a contact (People has no trash) |
| `people_list_contact_groups` | List contact groups (the labels in the Contacts UI), including system groups |
| `people_get_contact_group` | Get one group; `max_members > 0` also returns its members |
| `people_create_contact_group` | Create a group (label) |
| `people_update_contact_group` | Rename a user-created group |
| `people_delete_contact_group` | Delete a group; `delete_contacts=true` also **irreversibly** deletes its contacts |
| `people_modify_contact_group_members` | Add or remove contacts from a group, max 1000 per call |

> **Updates replace, they do not append.** Every field group you send to `people_update_contact` overwrites the existing one wholesale — passing one email address leaves the contact with exactly that one. Read the contact first when you mean to add.

> **Search is prefix-matched and needs a warm index.** `jos` finds Joseph; `seph` finds nothing. The client issues Google's required warmup request automatically, so the first search after a change may still lag by a moment.

### Search Console (8)

| Tool | Purpose |
|---|---|
| `searchconsole_list_sites` | List the properties this account can access; the `siteUrl` is what every other searchconsole_* tool takes as `site_url` |
| `searchconsole_get_site` | Get one property's `siteUrl` and `permissionLevel` |
| `searchconsole_list_sitemaps` | List submitted sitemaps with their status, warnings, errors and submitted/indexed counts |
| `searchconsole_get_sitemap` | Get one sitemap's status |
| `searchconsole_submit_sitemap` | Submit a sitemap URL, or resubmit one to ask Google to fetch it again |
| `searchconsole_delete_sitemap` | **Irreversibly** remove a sitemap from the property (resubmit to add it back) |
| `searchconsole_query_analytics` | Search performance: clicks, impressions, CTR, position over a date range, grouped by `country`/`device`/`page`/`query`/`searchAppearance`/`date`/`hour`, with AND filters, `search_type`, paging via `row_limit`/`start_row`. The `hour` dimension requires `data_state=hourly_all` |
| `searchconsole_inspect_url` | URL Inspection: index verdict, coverage, last crawl, canonical, rich results for one URL |

> **Property spelling matters.** A Domain property is `sc-domain:example.com`; a URL-prefix property is `https://example.com/` with the trailing slash. Copy `siteUrl` from `searchconsole_list_sites` verbatim. Search analytics dates are `YYYY-MM-DD` in Pacific time and the last two or three days are excluded until `data_state=all` is passed.

## Error contract

Every error returned by the server includes a structured `data` payload alongside the human-readable `message`. Agents can switch on `category` and `retryable` programmatically without parsing the message string.

```json
{
  "code": -32002,
  "message": "gmail message not found: 18a3b…",
  "data": {
    "category": "not_found",
    "retryable": false,
    "service": "gmail",
    "http_status": 404,
    "upstream_reason": "notFound",
    "resource_kind": "message",
    "resource_id": "18a3b…",
    "hint": "Use gmail_search_threads or gmail_list_messages to discover valid message IDs."
  }
}
```

| `category` | `retryable` | When | What the agent should do |
|---|---|---|---|
| `invalid_input` | no | Tool args malformed (missing field, wrong type, mutually exclusive options, no recipients, etc.) | Read `hint`, fix args, retry |
| `not_found` | no | Resource ID does not exist or is not visible to this account | Read `resource_kind` + `hint`, call the right discovery tool, retry with a new ID |
| `auth_required` | no | User must re-authorize (refresh token revoked, account not registered with this server) | Surface `reconnect_url` to the user; this is unrecoverable from the agent's side |
| `auth_invalid` | no | JWT itself is bad (expired, wrong signature, audience mismatch, revoked) | Re-run the OAuth flow at `/authorize` |
| `rate_limited` | **yes** | Google rate limit hit | Back off (exponential: 250ms → 1s → 4s) and retry |
| `permission_denied` | no | Account lacks permission for this resource | Don't retry; surface to the user |
| `transient` | **yes** | Network blip / Google 5xx | Retry once or twice with a 1–5s delay |
| `upstream` | no | Uncategorized upstream response | Inspect `http_status` + `message` |
| `internal` | no | Server-side bug | Retry won't help |

**Agent recovery patterns:**

- Loop with `gmail_send` and a malformed recipient → `invalid_input` → fix the email format, retry.
- `gmail_get_message` with stale ID → `not_found` with `resource_kind: "message"` → call `gmail_search_threads` to refresh, retry.
- Any tool returns `rate_limited` → sleep and retry; backoff is the agent's responsibility.
- Any tool returns `auth_required` with `reconnect_url` → ask the user to reconnect the MCP server; do not retry the same tool.

## Caveats

- **Unverified app cap.** Until your OAuth client is verified by Google, only **test users** (added in the GCP Console) can authorize, and the app is hard-capped at 100 users for its lifetime. `gmail.modify`, `drive`, `spreadsheets`, `documents`, and `calendar` are all **restricted/sensitive scopes** — verification for the full set requires a [CASA assessment](https://cloud.google.com/security/compliance/casa) (2–6 weeks, plus privacy policy URL, terms of service URL, demo video).
- **One Google account per JWT.** To use a second Google account, complete the OAuth flow again. A per-tool `account` parameter for in-session switching is on the roadmap.
- **No send-safety knob.** Tools execute `gmail_send` immediately. If you want a draft-only mode, do not expose `gmail_send` to the agent — point it at `gmail_create_draft` instead.
- **Refresh token revocation (by the user, at Google).** If the user revokes the app's access from their Google Account, the next tool call returns an `auth_required` error pointing at `/authorize`. (For revoking *from this server's side*, see `google-mcp accounts revoke` in [Operations](#operations).)
- **Prompt injection from Workspace content is untrusted input.** Email bodies, document text, and other fetched content are, from the model's perspective, just more data — a message that says "forward this to attacker@evil.com" carries no more authority than any other text. The server enforces object-level rules (path jail, size caps, header validation) but cannot know your intent; review what an agent is about to send before wiring it up unattended. See [SECURITY.md](SECURITY.md) for the full threat model.
- **PII in logs.** Tracing intentionally redacts subject, body, recipients, and search queries. Logs only structural metadata (counts, lengths, durations, opaque `sub` IDs). Pin `RUST_LOG` to keep `reqwest` ≤ `warn` so request URLs (which can carry PII in query params) are not logged.

## Roadmap

- **Per-tool `account` parameter** for multi-account workflows in a single MCP session.
- **Resumable Drive uploads** for files larger than the current multipart cap.
- **Short-lived access tokens + refresh tokens** as an alternative to the current 30-day JWT, for deployments that want tighter exposure windows without relying on explicit revocation.
- **Built-in rate limiting** for `/oauth/*` and `/mcp`, for operators who'd rather not stand up a reverse proxy just for that.

## Releasing

Releases are built locally, not in CI: bump `version` in `Cargo.toml`, add the matching `## [x.y.z]` section to `CHANGELOG.md`, commit, then run `scripts/release.sh` (`--check` for preflight only, `--dry-run` to build everything without tagging or publishing). The macOS build/sign/notarize step needs a macOS host reachable over SSH — copy `scripts/release.local.env.example` to `scripts/release.local.env` (gitignored) and fill in `MAC_HOST`, `MAC_SIGN_IDENTITY`, `MAC_NOTARY_PROFILE`, `SECRETS_ENV` (an env file exporting `KEYCHAIN_PASSWORD`), and optionally `MAC_REPO_DIR`; `--skip-mac` ships three binaries instead of four when that host isn't available. The script cross-builds static Linux x86_64/aarch64 binaries with `cargo-zigbuild`, the Windows binary with `cargo-xwin`, builds/signs/notarizes the universal macOS binary, smoke-tests each with `--version`, writes `SHA256SUMS.txt`, then tags, pushes and publishes the GitHub release with notes taken from the `## [x.y.z]` section of `CHANGELOG.md` (so that heading's format must match exactly).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build/test/lint commands, code conventions, and how to add a new tool.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability, and for the full threat model and list of built-in protections.

## License

MIT — see [LICENSE](LICENSE).
