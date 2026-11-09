# Contributing

This is an experimental crate. Read `CLAUDE.md` for the boundary rules (the core never
names a foreign system; fail closed; no invented test vectors) before changing code.

Before opening a change:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings` (also with `--features "cli geb-live geb-mls"`)
- `cargo test` (also with `--features "cli geb-live geb-mls"`)

## Sign-off (DCO)

Every commit must carry a `Signed-off-by:` trailer certifying the Developer
Certificate of Origin (https://developercertificate.org/). Use `git commit -s`.
Commits should also be cryptographically signed.

Commit subjects follow `<type>(<scope>): <subject>` (feat, fix, docs, test, ci, build,
perf, refactor, chore, security).
