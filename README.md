# google-mcp-rs

A multi-tenant **Model Context Protocol** server for **Google Workspace**, written in Rust. Built around streamable HTTP transport with full **OAuth 2.1** so it plugs straight into Claude.ai, Claude Code, ChatGPT custom connectors, Cursor, or any MCP client that speaks the 2025-11-25 authorization spec.

> **Status:** v0.4.0 — Gmail (25) + Sheets (11) + Drive (14) + Docs (12) live. **62 tools** total.

## Why

The first-party Google Workspace MCP server is missing fundamentals (you cannot send an email from it). Existing community servers are Python or single-tenant. `google-mcp-rs` aims to be the Rust server you actually want to deploy:

- **Full Gmail / Sheets / Drive / Docs surface** — 57 tools covering email (search/threads/drafts/send/labels/organize), spreadsheets (CRUD on values + ranges + tabs + raw batchUpdate for formatting/charts), Drive (upload, download, export Google Docs to PDF/CSV/XLSX, share, copy, trash), and Google Docs (read as plain text, append/insert/replace, raw batchUpdate for formatting and structure).
- **Multi-tenant by design** — every user does their own Google OAuth dance. Refresh tokens are encrypted at rest with AES-256-GCM and bound to the user's Google `sub` via AAD.
- **OAuth 2.1 done right** — RFC 9728 protected resource metadata, RFC 8414 authorization server metadata, RFC 7591 dynamic client registration, RFC 8707 audience binding, PKCE-S256.
- **Streamable HTTP only** — no stdio. Designed to live behind a tunnel, talk to remote MCP clients.
- **One binary, distroless image** — small surface, no runtime dependencies.

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
google-mcp ──── redirect ───▶ accounts.google.com (consent screen)
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

State is threaded MCP-client → Google → callback via single-use opaque tokens stored in SQLite (5-minute TTL). MCP JWTs are HS256 signed, bound to the user's Google `sub`, audience-scoped to `${BASE_URL}/mcp`.

## Quick start (local development)

### 1. Create a Google OAuth client

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Pick or create a GCP project.
2. Enable the **Gmail API**, **Sheets API**, **Drive API**, and **Docs API**.
3. **OAuth consent screen** → External, app name `google-mcp` (or whatever you want users to see), user support email, developer email.
4. Add scopes:
   - `openid`
   - `email`
   - `https://www.googleapis.com/auth/gmail.modify`
   - `https://www.googleapis.com/auth/spreadsheets`
   - `https://www.googleapis.com/auth/drive`
   - `https://www.googleapis.com/auth/documents`
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

### 4. Connect an MCP client

For **Claude.ai** (or any remote MCP client with OAuth support): add a custom connector pointing at `${BASE_URL}/mcp`. The client will discover our authorization server, do dynamic client registration, then walk you through the Google consent screen. Once authorized, the Gmail tools appear in the client's tool list.

For **Claude Code**, see `.mcp.json`:

```json
{
  "mcpServers": {
    "google": {
      "type": "http",
      "url": "http://localhost:8433/mcp"
    }
  }
}
```

Claude Code will surface the OAuth flow in your terminal on first use.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `GOOGLE_CLIENT_ID` | yes | — | OAuth client ID from GCP Console |
| `GOOGLE_CLIENT_SECRET` | yes | — | OAuth client secret from GCP Console |
| `BASE_URL` | yes | — | Public URL of this server, used to compute redirect URIs and OAuth metadata |
| `JWT_SECRET` | yes | — | HS256 secret for signing MCP JWTs (32+ bytes) |
| `STORAGE_ENCRYPTION_KEY` | yes | — | 32 bytes, base64url-encoded — encrypts refresh tokens at rest |
| `DATABASE_URL` | no | `./google-mcp.db` | SQLite file path |
| `MCP_HOST` | no | `0.0.0.0` | Bind address |
| `MCP_PORT` | no | `8433` | Listen port |
| `CORS_ALLOW_LOCALHOST` | no | `false` | Allow `http://localhost:*` in CORS (dev only) |
| `RUST_LOG` | no | `google_mcp=info,rmcp=warn,reqwest=warn` | Tracing filter — keep `reqwest` ≤ `warn` to avoid logging URLs with PII |

## Tools

### Gmail (25)

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
| `gmail_modify_labels` | Add/remove labels on a message OR thread |
| `gmail_mark_read` | Mark messages as read |
| `gmail_mark_unread` | Mark messages as unread |
| `gmail_archive` | Archive messages |
| `gmail_trash` | Move messages to trash |
| `gmail_get_profile` | Return the connected account email and granted scopes |

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
| `drive_create_file` | Upload a file (multipart, ≤ ~5 MB content) |
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
| `auth_invalid` | no | JWT itself is bad (expired, wrong signature, audience mismatch) | Re-run the OAuth flow at `/authorize` |
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

- **Unverified app cap.** Until your OAuth client is verified by Google, only **test users** (added in the GCP Console) can authorize, and the app is hard-capped at 100 users for its lifetime. `gmail.modify`, `drive`, and `spreadsheets` are all **restricted/sensitive scopes** — verification for the full set requires a [CASA assessment](https://cloud.google.com/security/compliance/casa) (2–6 weeks, plus privacy policy URL, terms of service URL, demo video).
- **One Google account per JWT (Phase 1).** To use a second Google account, complete the OAuth flow again. Per-tool `account` parameter for in-session switching is on the Phase 2 roadmap.
- **No send-safety knob.** Tools execute `gmail_send` immediately. If you want a draft-only mode, do not expose `gmail_send` to the agent — point it at `gmail_create_draft` instead.
- **ID token signature not verified in MVP.** The server trusts Google's ID token because the channel to Google's token endpoint is TLS. Hardening to verify against Google's JWKS is on the roadmap.
- **Refresh token revocation.** If the user revokes the app's access in their Google Account, the next tool call returns a `ReconnectRequired` error pointing at `/authorize`.
- **PII in logs.** Tracing intentionally redacts subject, body, recipients, and search queries. Logs only structural metadata (counts, lengths, durations, opaque `sub` IDs). Pin `RUST_LOG` to keep `reqwest` ≤ `warn` so request URLs (which can carry PII in query params) are not logged.

## Roadmap

- **Per-tool `account` parameter** for multi-account workflows in a single MCP session.
- **Calendar, Docs, Forms, People** — the rest of the Workspace surface.
- **Resumable Drive uploads** for files larger than ~5 MB.
- **Hardening:** ID token JWKS verification, refresh token rotation, structured per-account audit log.

## Contributing

Pull requests welcome. CI runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test`. Please keep secrets out of fixtures and tests.

## License

MIT — see [LICENSE](LICENSE).
