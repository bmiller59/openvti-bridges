# CLAUDE.md — openvti-bridges

Experimental bridges between a VTC data room and a room in a foreign system (`publish = false`). This
repository was extracted from the VTI repository (see README); "the workspace `CLAUDE.md`" means that
repository's root `CLAUDE.md`, whose rules still bind this code. Each crate has its own `CLAUDE.md`; read
the one for the crate you are changing.

## Crates

| Crate | Role |
|---|---|
| `openvti-bridge-core` | Adapter-neutral core: the seams, mapping, pump, halts, pause, supervisor, config, secrets, at-rest sealing, loopback |
| `openvti-bridge-vtc` | The VTI side: VTC room side, HTTPS delivery, fjall store, key custody. Depends on the core and `vta-sdk` |
| `openvti-bridge-geb` | The Geb adapter (features `live`, `mls`, `harness`). Depends on the core only |
| `openvti-bridge-conformance` | The shared `ForeignRoom` suite |
| `openvti-bridges` | The shell and binary: registry (features `geb`, `loopback`), CLI, `run`, `status` |
| `harness/` | Separate package: tests against a real `room-host` (manual) |

Dependencies flow downward: the core depends on no other crate here; adapters on the core; the VTI side on
the core; the shell on all of them. Nothing else depends on these crates, and no VTI crate gains
adapter code. An adapter never depends on the VTI side and the core never on an adapter (the `isolation` CI
job reads `cargo tree`). A bridge's specifics stay out of the others.

## Rules that bind every crate

- **Fail closed.** Unknown wire input is an error, never skipped. An unreadable foreign event is dropped
  and logged, never acted on.
- **Bridged content is never presented as verified**; `AuthorCheck::Verified` only on a successful
  signature check. Receipts are evidence, not delivery (R1.1): `post() == Ok` is `Accepted`.
- **Refusal stops the link and the halt persists** until an operator clears it. Pause is a kill switch the
  shell applies before every verb and the pump before every post; an unreadable config counts as paused.
- **No invented test vectors.** Vectors come from the foreign protocol's authors (`CONTRIBUTING.md`).
- **Mark what is not settled** `// UNVERIFIED:`; the pins and open questions live in the adapter's doc.
- **Remote first** (R2.1): no local commit before the remote effect is durable, or make it resumable.
  Ask of every mutation: the process dies on the next line, then what?
- Secrets are never logged, `Debug`-printed or written unsealed. Key paths and labels are never caller-chosen.
- Adding a bridge: `docs/ADDING-A-BRIDGE.md`. Design: `docs/core.md`, `docs/bridges/<kind>.md`.

## Commands (shared machine: `nice -n 10`, `umask 002`, check `free -h` and `uptime` first)

```sh
cargo fmt --all --check                  # not inside harness/ (it would reformat unrelated files)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p openvti-bridge-geb --features "live mls" --all-targets -- -D warnings
cargo test --workspace --all-features    # run per crate too: -p hides what feature unification adds
cargo build -p openvti-bridges --no-default-features --features loopback
```

The harness (`harness/`) needs an uncommitted `.cargo/config.toml` patching `room-host`; run it on its own.
Never edit `version =`; `Cargo.lock` and `.cargo/config.toml` stay unstaged. Commits are signed off
(`git commit -s`) and signed; subjects are `<type>(<scope>): <subject>`.
