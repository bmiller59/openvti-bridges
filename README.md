# openvti-bridges

Experimental bridges between a Verifiable Trust Infrastructure (VTI) community data room and a
room in a foreign system. A bridge is a separate process that is a member of both rooms and carries
content both ways: VTC records become messages in the foreign room, and foreign messages become
create-only records in the VTC room. The bridge signs as itself on each side and quotes the original
author, and content that crosses it is never presented as verified. The bridge-neutral core and the
VTI side are shared; each foreign system is one adapter crate behind a cargo feature.

## Bridges

| Kind | Foreign system | Status | Crate | Design | Pinned reading |
|---|---|---|---|---|---|
| `geb` | Geb rooms, "path B" (MLS over a Nostr relay) | experimental, offline-verified only | `openvti-bridge-geb` | [`docs/bridges/geb.md`](docs/bridges/geb.md) | Geb release 0.5.15, substrate commit `fdf804d`, path B label `0.1` |
| `loopback` | an in-memory room | development and conformance reference | `openvti-bridge-core` (`loopback`) | [`docs/core.md`](docs/core.md) | none |

Each kind is a cargo feature of the shell (`geb` is on by default, `loopback` is opt-in).
[`docs/bridges/README.md`](docs/bridges/README.md) says how the bridge documents are organised;
[`docs/ADDING-A-BRIDGE.md`](docs/ADDING-A-BRIDGE.md) says how to add one.

## Status

**Experimental and offline-verified only.** Not published (`publish = false`), not a dependency of
anything. Nothing here has been run against a live Geb node, a real relay, a real VTA or a real room
host. Every test uses a test double. Geb's path B has no versioned specification, so details that
Geb's written answers do not settle are marked `// UNVERIFIED:` in the source. Tests show
self-consistency, including on stand-in vectors (Geb's own vector files are not redistributed here and are run locally), not interoperability.

Not built: `fc` fragments (joining a large Geb room fails), the `rs` status body, `seat-ask`,
accepting a re-seat Welcome, sending a leave (signed leaves are received), persona-card intake,
fork choice, and gap records. Direct Geb rooms are refused at join time. One commit kind (a Remove
of another DID by a plain member) halts the link because deciding it needs persona cards; Geb
itself would refuse it and continue, the halt is a deliberate bridge-side choice. The Geb adapter's full list, with consequences, is in `docs/bridges/geb.md`, section 5.

## Quickstart

Needs Rust 1.95.0 (edition 2024). Run builds and tests under `nice -n 10` on a shared machine.

```sh
cargo generate-lockfile                               # once, if there is no Cargo.lock (needs network)
cargo test --workspace                                # default features
cargo test --workspace --features harness             # also the shell's tests/custody.rs and tests/cli.rs
cargo test -p openvti-bridge-conformance              # the shared ForeignRoom suite against loopback (Geb runs it from its own tests/conformance.rs)
cargo build -p openvti-bridges --no-default-features --features loopback   # the shell with no Geb in it
cargo test -p openvti-bridge-geb --features "live mls" # the Geb adapter on its own, with its live and MLS features
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p openvti-bridges                        # the openvti-bridges binary
```

**What CI runs today** (`.github/workflows/ci.yml`): `cargo fmt --check`; clippy and tests per crate and for the
workspace, with and without `harness`, the shell built without Geb, the conformance suite, an isolation check of the dependency graph (`cargo tree`) (which adds
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
`docs/core.md`, section 10.

## Features

Features are per crate. The core takes none.

| Crate | Feature | Adds |
|---|---|---|
| `openvti-bridge-core` | (none) | The adapter-neutral core: foreign-room seam, mapping, pump, halts, pause, supervisor, at-rest sealing, store and room traits, loopback. No VTI crate, no network stack, no MLS |
| `openvti-bridge-vtc` | `harness` | Loopback host delivery and `vta-sdk`'s loopback sink, for tests that need no room host |
| `openvti-bridge-vtc` | `keyring` | The OS keyring as the secret store |
| `openvti-bridge-geb` | `live` | The Nostr relay client and an in-process test relay (`ws://` only for 127.0.0.1) |
| `openvti-bridge-geb` | `mls` | The Geb MLS group over OpenMLS 0.9, tested only against an in-process second client |
| `openvti-bridge-geb` | `harness` | The in-process MLS `sim` for other crates (implies `mls`) |
| `openvti-bridge-conformance` | (none) | The shared ForeignRoom suite (not published) |
| `openvti-bridges` | `geb` (default) | Registers the Geb kind, with its `live` and `mls` features |
| `openvti-bridges` | `loopback` | Registers the core's in-memory kind (verb `echo`) |
| `openvti-bridges` | `harness`, `keyring` | Pass through to the crates above |

The real-`room-host` tests are the separate `harness/` package.

## CLI

Build with `cargo build -p openvti-bridges`. Every command takes `--config <path>` (default `config.toml`).

| Command | Purpose |
|---|---|
| `setup --setup-key-out <path>` then `setup --from <setup.toml>` | Two-phase provisioning against the operator's VTA: mint each link's device keys, store them, write the config |
| `link add\|list\|pause\|resume\|remove` | Manage links. `add` mints keys and starts paused. `pause` stops a running `run` within one poll interval (see `docs/core.md` section 9), `resume` lets it continue |
| `link clear-halt <id> [--yes] [--i-have-been-readmitted]` | Clear a persisted halt after reading why it happened. A VTA or room-host refusal (`VtcRefused`) needs the ACL grant or room membership fixed first, then `--yes` only |
| `bridge list` | The kinds this build has, with their verbs |
| `bridge <kind> <verb> --link <id> [args]` | A kind's verb, for example `bridge geb connect --link <id> <did>` (open a dyad with a Geb member's device DID and add it to the link) and `bridge geb stock-kps --link <id>` (stock KeyPackages with the link's peers: consent to be added). The shell refuses every verb while the link is paused or halted |
| `status [--link <id>]` | Each registered kind's pinned reading, then cursors, outbox depth, last relayed post, halt state (stop `run` first) |
| `run` | Supervise every link until SIGINT or SIGTERM (a paused link idles) |

`directions` is required in every link (no default). The config file is written `0600` and edits are serialised by a `<config>.lock` file beside it. `retention_days` (default 7, at least 1) bounds how long posted, journalled and cross-reference records are kept; bridged text in the journal and outbox is sealed at rest (see `docs/core.md`, sections 6 and 8). A catch-up read of more than 20 pages of 5,000 events fails with an error rather than return a partial result. None of this is verified against live Geb, a real VTA, host or relay.

A link needs the room owner's explicit opt-in (`tier_optin = true`), and `private` rooms are
refused. Logs go to stderr; set `RUST_LOG` (default `info`). Config shape: `docs/core.md`,
section 9: a link names its `kind` and keeps the kind's settings in `[links.<kind>]`;
a kind's global settings are `[bridges.<kind>]`.

## Repository layout

```
crates/openvti-bridge-core/   the adapter-neutral core: foreign.rs (the seam), model, mapping, pump, store, room, halt, pause, run, config, atrest, loopback
crates/openvti-bridge-vtc/    the VTI side: VTC room side, HTTPS delivery to the room host, fjall store, key custody
crates/openvti-bridge-geb/    the Geb adapter (its own crate root): adapter, wire, crypto, dyad, room, settle, policy, vrc, nostr, mls/; its tests/ hold the vectors and its conformance run
crates/openvti-bridge-conformance/  the shared ForeignRoom suite, run by loopback and by each adapter
crates/openvti-bridges/       the shell and binary: registry, cli, service, ops, wiring, main; tests/
harness/                      separate package `openvti-bridges-harness`: harness and e2e tests against a real room-host (manual)
docs/                         core.md, ADDING-A-BRIDGE.md, bridges/ (README.md, geb.md, geb/plan.md, geb/companion-notes.md)
```

## Documents

- `docs/core.md`: what is being built and why, how the pieces fit, the data model, key custody,
  threat model, failure handling, operations, tests.
- `docs/bridges/geb.md`: the Geb adapter: the protocol as implemented, what is built and not,
  halt codes, open questions and the pre-live-run checklist.
- `docs/ADDING-A-BRIDGE.md`: the checklist, the traits and what each guarantees, what a bridge must not do.
- `docs/bridges/geb/plan.md` and `docs/bridges/geb/companion-notes.md`: the original plan, rationale
  and threat analysis. Written inside the VTI repository ("the workspace" means that repository);
  a note at the top of the plan lists details that have since changed.
- `CLAUDE.md` (root) and one `CLAUDE.md` per crate: guidance for working in each crate. The Geb
  crate's holds the fail-closed rules, the current pins, open questions and the not-built list.

## Origin

Extracted from the VTI repository (then the single crate `vti-geb-bridge`, branch `feat/geb-bridge`; renamed `openvti-bridges` and split into per-concern crates, canonical home `https://github.com/bmiller59/openvti-bridges.git`) as a fresh
import without history; the first commit message names the source commit. It depends on published
VTI crates by version; only the separate `harness/` package needs `room-host`.

## Contributing

Read `CONTRIBUTING.md` and `CLAUDE.md` first. Every commit needs a `Signed-off-by:` trailer
(`git commit -s`, the Developer Certificate of Origin) and should be cryptographically signed.
Commit subjects follow `<type>(<scope>): <subject>`.

## License

Apache-2.0, see `LICENSE`.

## Upgrading from the pre-restructure state: a clean break

Nothing was deployed, so there is no migration. State written before the split cannot be read:

- The secret blob is version 2; a version 1 blob is refused with a message saying to discard it.
- The at-rest salt is `openvti-bridges/at-rest/v1`, so every derived key differs; old sealed files do not open.
- fjall keyspaces `links`, `geb_mls` and `ratchets` are replaced by one `adapter_state` keyspace
  (state keyed by `<kind>/<name>`); the old directories hold data nothing reads. The fork cursor
  `fork` is now `geb/fork`.
- VTA key labels are `openvti-bridges/geb/<link>/device-*` and the VTA context is `openvti-bridges`.
- Config: `geb_room_id` and `geb_peers` became `kind = "geb"` plus a `[links.geb]` table
  (`room_id`, `peers`); the global `[geb]` table became `[bridges.geb]`; `[geb].deny_list` became
  `deny_authors` on each link.
- CLI: `bridge geb connect` and `bridge geb stock-kps` became `bridge geb connect` and `bridge geb stock-kps`;
  `link add --geb-room-id <id>` became `link add --kind geb --set room_id=<id>`.

To move over: delete `data/` and the stored secrets, run `setup` again and `link add` each link.
