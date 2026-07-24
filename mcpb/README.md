# Google Workspace MCP — Claude Desktop bundle (.mcpb)

This directory packages `google-mcp` as an **MCP Bundle** ([`.mcpb`](https://github.com/anthropics/mcpb))
that installs into **Claude Desktop** with a double-click. It runs the server
over **stdio** (`google-mcp stdio`), so it needs **no HTTPS/SSL certificate and
no internet tunnel** — the sidestep for Claude Desktop's custom-connector UI,
which only accepts `https://` endpoints.

## Why this exists

The HTTP server (`google-mcp` default mode) is multi-tenant and OAuth-2.1. For a
single user on their own machine, Claude Desktop's custom-connector UI rejects a
plain `http://localhost` server for lack of TLS, and exposing the server publicly
just to satisfy that is a bad trade. A `.mcpb` runs the binary locally over stdio
instead — single-tenant, private, no certificate.

## How it works

- `manifest.json` declares `server.type = "binary"`, launches `google-mcp stdio`,
  and switches the binary per OS via `platform_overrides`.
- The user connects their Google account **in chat** by invoking the
  `google_authenticate` tool (only exposed in stdio mode). It opens a browser
  for Google sign-in via a loopback listener and stores the encrypted refresh
  token locally (`${HOME}/.google-mcp.db`).
- The full tool surface (Gmail, Sheets, Drive, Docs, Calendar) is exposed.
  Scope it down by adding an `ENABLED_DOMAINS` env entry (e.g. `sheets,drive`)
  to the manifest if a smaller surface is wanted.

## Build

```bash
cargo build --release                                              # linux
cargo xwin build --release --target x86_64-pc-windows-msvc         # windows
mcpb/pack.sh                                                       # validate + pack
```

Output: `mcpb/google-workspace-mcp.mcpb`. Install via double-click, or
Claude Desktop → Settings → Extensions → Advanced → Install Extension.

## Secrets

The bundle carries **no** crypto secrets. In stdio/auth mode the binary
auto-generates `JWT_SECRET` (unused in single-tenant, but required by config)
and `STORAGE_ENCRYPTION_KEY` once and persists them beside the database
(`<DATABASE_URL>.keys`, mode 0600). Only the Google **client ID + secret** are
supplied, via Claude Desktop's install dialog (`user_config`), so nothing
sensitive lives in this repo or the manifest.

## Known caveats / TODO before shipping to a real user

- **macOS binary + notarization.** No `darwin` binary is bundled yet (build on a
  Mac). An unsigned macOS binary is blocked by Gatekeeper unless Developer-ID
  signed + notarized. `mcpb sign` signs the *bundle*, not the OS binaries.
- **Windows SmartScreen.** The unsigned `.exe` triggers SmartScreen on first run
  (More info → Run anyway), same as the standalone build.
- **Loopback port.** The `google_authenticate` flow binds the `BASE_URL` port
  (8433) for the redirect. It's free on a normal user machine; if taken, sign-in
  fails with a clear message. A Google **Desktop-type** OAuth client would allow
  arbitrary loopback ports and remove this constraint.
- **Execute bit.** `pack.sh` sets `+x` on the Linux/macOS binary; confirm the
  host preserves it on extraction.
