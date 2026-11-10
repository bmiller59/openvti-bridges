# openvti-bridges

Experimental bridges between a Verifiable Trust Infrastructure (VTI) community data room and a
Geb room. It is a separate process that is a member of both rooms and carries content both ways: VTC
records become chat lines in the Geb MLS room, and Geb lines become create-only records in the VTC
room. The bridge signs as itself on each side and quotes the original author, and content that
crosses it is never presented as verified. The Geb side speaks Geb's "path B" (MLS over a Nostr
relay), pinned to Geb release 0.5.15 (substrate commit `fdf804d`, our path B label `0.1`). A second,
trivial `loopback` adapter keeps the core independent of Geb.

## Status

**Experimental and offline-verified only.** Not published (`publish = false`), not a dependency of
anything. It has never been run against a live Geb node, a real relay, a real VTA or a real room
host. Every test uses a test double. Geb's path B has no versioned specification, so details that
Geb's written answers do not settle are marked `// UNVERIFIED:` in the source. Tests show
self-consistency and agreement with Geb's vendored test vectors, not interoperability.

Not built: `fc` fragments (joining a large Geb room fails), the `rs` status body, `seat-ask`,
accepting a re-seat Welcome, sending a leave (signed leaves are received), persona-card intake,
fork choice, and gap records. Direct Geb rooms are refused at join time. One commit kind (a Remove
of another DID by a plain member) halts the link because deciding it needs persona cards; Geb
itself would refuse it and continue, the halt is a deliberate bridge-side choice. The full list, with consequences, is in `docs/DESIGN.md`, section 5.

## Quickstart

Needs Rust 1.95.0 (edition 2024). Run builds and tests under `nice -n 10` on a shared machine.

```sh
cargo generate-lockfile                               # once, if there is no Cargo.lock (needs network)
cargo test --workspace                                # default features
cargo test --workspace --features harness             # also the shell's tests/custody.rs and tests/cli.rs
cargo test -p openvti-bridge-geb --features "live mls" # the Geb adapter on its own, with its live and MLS features
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p openvti-bridges                        # the openvti-bridges binary
```

**What CI runs today** (`.github/workflows/ci.yml`): `cargo fmt --check`; clippy and tests per crate and for the
workspace, with and without `harness` (which adds
`tests/custody.rs` and `tests/cli.rs`); `cargo deny check`; a sign-off (DCO) check on pull
requests. Those jobs need network (crates.io and the advisory database). **None of it has run in
CI yet**: the repository has no remote, and the published VTI crates it needs (`vta-sdk` 0.85,
`vti-common` 0.61, `vti-secrets` 0.34, `vti-specs` 0.10) have only been built here against local
path overrides. Whether `vta-sdk` 0.85 on crates.io has the `test-loopback`, `provision-client` and
`crypto-provider` features used here is unchecked, so the first CI run is also the first test of
that.

**What CI does not run, and why.** `harness/tests/harness.rs` and `harness/tests/e2e.rs` need a
real `room-host`, which is not published and is taken by git under a placeholder URL
(`https://example.invalid/...`). They live in the separate `harness/` package so that the
placeholder does not break resolution of this crate. They stay manual until the URL is real.

**The room-host harness.** `harness/` is its own package (not a workspace member, its own
`Cargo.lock`, git-ignored). To run it, add an uncommitted `.cargo/config.toml` (git-ignored) in
the repository root with a `[patch."https://example.invalid/verifiable-trust-infrastructure.git"]`
entry pointing `room-host` at a local VTI checkout, plus `[patch.crates-io]` entries for VTI crates
not in your cargo cache, then `cd harness && cargo test` (the features are fixed by
`harness/Cargo.toml`).

**Cargo.lock.** The root `Cargo.lock` is committed once someone with network has generated it
(`cargo generate-lockfile`, then commit it). It has not been committed yet because it could not be
produced here without local path overrides, and a lock containing path or placeholder sources
would be wrong for everyone else. Until it is committed, CI generates one before building. See
`docs/DESIGN.md`, section 10.

## Features

Features are per crate. The core and the shell take none beyond the two below.

| Crate | Feature | Adds |
|---|---|---|
| `openvti-bridge-core` | (none) | The adapter-neutral core: foreign-room seam, mapping, pump, halts, pause, supervisor, at-rest sealing, store and room traits, loopback. No VTI crate, no network stack, no MLS |
| `openvti-bridge-vtc` | `harness` | Loopback host delivery and `vta-sdk`'s loopback sink, for tests that need no room host |
| `openvti-bridge-vtc` | `keyring` | The OS keyring as the secret store |
| `openvti-bridge-geb` | `live` | The Nostr relay client and an in-process test relay (`ws://` only for 127.0.0.1) |
| `openvti-bridge-geb` | `mls` | The Geb MLS group over OpenMLS 0.9, tested only against an in-process second client |
| `openvti-bridge-geb` | `harness` | The in-process MLS `sim` for other crates (implies `mls`) |
| `openvti-bridges` | `harness`, `keyring` | Pass through to the crates above |

The real-`room-host` tests are the separate `harness/` package.

## CLI

Build with `cargo build -p openvti-bridges`. Every command takes `--config <path>` (default `config.toml`).

| Command | Purpose |
|---|---|
| `setup --setup-key-out <path>` then `setup --from <setup.toml>` | Two-phase provisioning against the operator's VTA: mint the Geb device keys, store them, write the config |
| `link add\|list\|pause\|resume\|remove` | Manage links. `add` mints keys and starts paused. `pause` stops a running `run` within one poll interval (see DESIGN section 9), `resume` lets it continue |
| `link clear-halt <id> [--yes] [--i-have-been-readmitted]` | Clear a persisted halt after reading why it happened. A VTA or room-host refusal (`VtcRefused`) needs the ACL grant or room membership fixed first, then `--yes` only |
| `geb connect --link <id> <did>` | Open a dyad with a Geb member's device DID (refused while the link is paused or halted) |
| `geb stock-kps --link <id>` | Stock KeyPackages with the link's peers (consent to be added; refused while the link is paused or halted) |
| `status [--link <id>]` | Cursors, outbox depth, last relayed post, halt state (stop `run` first) |
| `run` | Supervise every link until SIGINT or SIGTERM (a paused link idles) |

`directions` is required in every link (no default). The config file is written `0600` and edits are serialised by a `<config>.lock` file beside it. `retention_days` (default 7, at least 1) bounds how long posted, journalled and cross-reference records are kept; bridged text in the journal and outbox is sealed at rest (see `docs/DESIGN.md`, sections 6 and 8). A catch-up read of more than 20 pages of 5,000 events fails with an error rather than return a partial result. None of this is verified against live Geb, a real VTA, host or relay.

A link needs the room owner's explicit opt-in (`tier_optin = true`), and `private` rooms are
refused. Logs go to stderr; set `RUST_LOG` (default `info`). Config shape: `docs/DESIGN.md`,
section 9.

## Repository layout

```
crates/openvti-bridge-core/   the adapter-neutral core: foreign.rs (the seam), model, mapping, pump, store, room, halt, pause, run, config, atrest, loopback
crates/openvti-bridge-vtc/    the VTI side: VTC room side, HTTPS delivery to the room host, fjall store, key custody
crates/openvti-bridge-geb/    the Geb adapter (its own crate root): wire, crypto, dyad, room, settle, policy, vrc, nostr, mls/; its tests/ hold the vectors
crates/openvti-bridges/       the shell and binary: cli, service, ops, wiring, main; tests/custody.rs and tests/cli.rs
harness/                      separate package `openvti-bridges-harness`: harness and e2e tests against a real room-host (manual)
docs/                         DESIGN.md, bridges/geb/plan.md, bridges/geb/companion-notes.md
```

## Documents

- `docs/DESIGN.md`: what is being built and why, how the pieces fit, the Geb protocol as
  implemented, key custody, threat model, failure handling, operations, tests, open questions.
- `docs/bridges/geb/plan.md` and `docs/bridges/geb/companion-notes.md`: the original plan, rationale
  and threat analysis. Written inside the VTI repository ("the workspace" means that repository);
  a note at the top of the plan lists details that have since changed.
- `CLAUDE.md`: guidance for working in this crate: boundary rules, fail-closed rules, the current
  Geb pins, open questions and the not-built list.

## Origin

Extracted from the VTI repository (crate `vti-geb-bridge`, branch `feat/geb-bridge`; renamed `openvti-bridges`, canonical home `https://github.com/bmiller59/openvti-bridges.git`) as a fresh
import without history; the first commit message names the source commit. It depends on published
VTI crates by version; only the separate `harness/` package needs `room-host`.

## Contributing

Read `CONTRIBUTING.md` and `CLAUDE.md` first. Every commit needs a `Signed-off-by:` trailer
(`git commit -s`, the Developer Certificate of Origin) and should be cryptographically signed.
Commit subjects follow `<type>(<scope>): <subject>`.

## License

Apache-2.0, see `LICENSE`.
