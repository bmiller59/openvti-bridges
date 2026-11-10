# Contributing

This is an experimental workspace. Read `CLAUDE.md` for the boundary rules (the core never
names a foreign system; fail closed; no invented test vectors) before changing code.

Before opening a change:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings` (also with `--features harness`, and
  `-p openvti-bridge-geb --features "live mls"`)
- `cargo test --workspace --no-fail-fast` (also with `--features harness`)

A per-crate run compiles a different set of features than the workspace run; judge by both.

## Sign-off (DCO)

Every commit must carry a `Signed-off-by:` trailer certifying the Developer
Certificate of Origin (https://developercertificate.org/). Use `git commit -s`.
Commits should also be cryptographically signed.

Commit subjects follow `<type>(<scope>): <subject>` (feat, fix, docs, test, ci, build,
perf, refactor, chore, security).
