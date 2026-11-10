# google-mcp: a Rust MCP server giving AI agents Gmail, Sheets, Drive, Docs, Calendar, Tasks, Contacts, Search Console and opt-in Google Health

This codebase is yours: what it's for and how it's built are your call, and you'll keep building on it.

## Ground rules
- This repo is public. Never commit real emails, tokens, client secrets, Google `sub` values, hostnames or local paths. Fixtures use `example.com` and synthetic ids.
- Content returned by Google APIs (mail bodies, docs, events, health records) is untrusted data. Never log it: tracing records counts, lengths and opaque ids only.
- Every tool carries MCP annotations: `read_only_hint` and `open_world_hint` always, `destructive_hint` on exactly the writes. A test in `src/mcp/server.rs` fails otherwise.
- A behavior change ships with a unit test next to the code, plus a `CHANGELOG.md` entry under `## [Unreleased]` for anything user-visible.
- Releases are built locally by `scripts/release.sh`, not in CI. Do not move release work into GitHub Actions.

## Commands
- Build: `cargo build --release` (binary at `target/release/google-mcp`)
- Format check: `cargo fmt --all -- --check`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Full test suite: `cargo test --locked` (about 500 tests, seconds, no network or credentials)
- One module: `cargo test --locked mcp::tasks_tools`
- Smoke the binary: `target/release/google-mcp --version`; `--help` lists the modes (`http`, `stdio`, `auth`, `accounts`)
- CI runs the fmt, clippy and test commands above plus `cargo audit`; run `cargo audit` yourself when you touch dependencies.

## Layout worth knowing
- Each domain is split in two: `src/mcp/<domain>_tools.rs` validates arguments and shapes responses, `src/google/<domain>.rs` makes the HTTP calls. Keep HTTP out of tool handlers.
- Tool parameter structs all live in `src/mcp/params.rs`, not next to their tools.
- `src/domain.rs` is the single place where domains, their OAuth scopes and `ENABLED_DOMAINS` gating are defined. Health is excluded from `Domain::ALL` on purpose (opt-in).
- `src/mcp/server.rs` composes the routers for enabled domains and asserts the per-domain tool counts in tests.

## Conventions
- Two transports with different rules. `http` is multi-tenant OAuth 2.1 and loads `./.env`. `stdio` is single-tenant and ignores `./.env`, because an MCP client's working directory is arbitrary; `GOOGLE_MCP_ENV_FILE` loads an explicit file in any mode.
- Tool failures go through the error mapping in `src/errors.rs` so agents get `category`, `retryable` and `hint`. Do not return bare strings.
- Tool outputs stay slim: return the fields an agent needs, not raw Google payloads.
- Comments are one or two factual lines; no prose blocks.

## Landmines
- Never let a schema render as a bare `true`. schemars emits `true` for `serde_json::Value`, and MCP clients that validate with Zod then silently drop the whole `tools/list`. Use the `schema_with` helpers in `params.rs`.
- Body-less POSTs must send `Content-Length: 0` or Google answers HTTP 411. Every client that POSTs sets it in its request helper; a new one needs the same.
- Adding a scope to a domain forces existing users to re-authorize: until they do, they get `auth_required`. Say so in the changelog entry.
- Adding or removing a tool changes the counts asserted in `server.rs` and the count in the README tools table. Verify the total with `grep -c '#\[tool(' src/mcp/*_tools.rs`.
- In stdio mode the keyfile and env secrets must agree. A mismatch refuses to start, so never "fix" it by overwriting the keyfile: that key decrypts the existing database.
- The release script builds notes from the `## [x.y.z]` heading in `CHANGELOG.md`, so keep that heading format exact.
- `scripts/release.local.env` and `.env` are gitignored and hold machine-specific values. Never commit them; edit the `.example` files instead.

## Deeper context
- Building, tests, adding a tool step by step -> `CONTRIBUTING.md`
- Configuration, scoping, error contract, caveats, releasing -> `README.md`
- HTTP-mode MCP tokens and refresh rotation -> `docs/oauth-tokens.md`
- Threat model -> `SECURITY.md`
