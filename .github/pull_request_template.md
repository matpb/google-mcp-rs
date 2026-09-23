## What & why

<!-- One or two sentences: what changes, and why. -->

## Checklist

- [ ] `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --locked` all pass locally
- [ ] Tests added/updated for any behavior change
- [ ] `CHANGELOG.md` updated for anything user-visible (new tool, changed default, new config var, security-relevant change)
- [ ] `README.md` updated (tool table, tool count, config reference) if the tool surface or config changed
- [ ] No secrets or personal data in code, tests, or fixtures
