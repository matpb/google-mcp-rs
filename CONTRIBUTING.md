# Contributing

Pull requests welcome. This file covers how to build, test, and lint the way CI does, plus the conventions the codebase follows.

## Prerequisites

- Rust **1.88** or later (the `rust-version` pinned in `Cargo.toml` — CI's `msrv` job checks against this exact version, so building with it is the safest baseline).
- For the full test suite: nothing extra — tests use an in-memory SQLite database.

## Build, test, lint

Run exactly what CI runs, in this order:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

CI additionally runs `cargo check --all-targets --locked` pinned to the MSRV above, and `cargo audit` for known vulnerabilities in the dependency tree. If you're changing dependencies, run `cargo audit` locally too (`cargo install cargo-audit --locked` once, then `cargo audit`).

For a normal debug build/run:

```bash
cargo build
cargo run           # http mode, needs GOOGLE_CLIENT_ID etc. — see .env.example
cargo run -- stdio  # stdio mode
```

## Code conventions

- **Comments are sparse and factual, never prose.** A comment earns its place only when the code can't say the thing itself: a non-obvious constraint, a bug it guards against, or a decision whose alternative looks better than it is. One or two lines; don't narrate what the code already states.
- **Tests are required for behavior changes.** New tool logic, config parsing, auth/host-allowlist logic, and error-mapping changes all need a test alongside them — this codebase's existing modules (`config.rs`, `host_guard.rs`, `auth_gate.rs`, `oauth/*.rs`) are a good model for the style: small, focused `#[cfg(test)] mod tests` blocks next to the code they cover.
- **No secrets or personal data in fixtures.** Test data uses `example.com`, placeholder client IDs/secrets, and synthetic Google `sub`/account values — never a real email, token, or ID, even a throwaway one.
- **Errors carry structure, not just a message.** If you're adding a new failure path a tool can hit, route it through the existing error-mapping so it gets a `category`/`retryable`/`hint` in the response — see the README's [Error contract](README.md#error-contract) for the shape agents rely on.

## Adding a new tool

Tools live in `src/mcp/<domain>_tools.rs` (e.g. `gmail_tools.rs`, `drive_tools.rs`), one file per Google Workspace domain, with the request/response param structs centralized in `src/mcp/params.rs`. To add a tool:

1. Pick the domain file it belongs to (or start a new one if it's a genuinely new domain — see `src/domain.rs` for how domains are registered and gated by `ENABLED_DOMAINS`).
2. Look at an existing tool in that file as a template: a `#[tool(...)]`-annotated method on the domain's tool-router impl, taking a `Params` struct (defined in `params.rs`, deriving `JsonSchema`/`Deserialize`) and returning the shared result/error type.
3. Keep the Google API call itself in the relevant `src/google/*.rs` client module, not inline in the tool handler — the tool handler's job is argument validation and shaping the response, not HTTP.
4. Update the tool count and the tools table in `README.md` (`grep -c '#\[tool(' src/mcp/*_tools.rs` is how the total is verified), and add a `CHANGELOG.md` entry.
5. If the tool needs a new OAuth scope, wire it into `src/domain.rs`'s scope list for that domain and note in the changelog that existing authorizations will need to re-authorize.

## Pull request expectations

- Keep PRs focused — one behavior change per PR is easier to review than a bundle.
- Include a `CHANGELOG.md` entry for anything user-visible (new tool, changed default, new config var, security-relevant behavior change).
- Explain the *why*, not just the *what*, in the PR description — a one-line rationale saves a round-trip.
- CI (`fmt`, `clippy -D warnings`, `test`, `msrv`, `audit`) must be green before merge.

## Security issues

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.
