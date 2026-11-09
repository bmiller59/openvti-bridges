# vti-geb-bridge

An experimental bridge between a Verifiable Trust Infrastructure (VTI) community data room and a
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
cargo test                                            # default features, no network
cargo test --features "cli geb-live geb-mls"          # what CI runs
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build --features cli                            # the vti-geb-bridge binary
```

**The `harness` feature does not build by default.** `room-host` is a service binary that is not
published, so `Cargo.toml` takes it as an optional git dependency under a placeholder URL
(`https://example.invalid/...`). For local runs, add an uncommitted `.cargo/config.toml`
(git-ignored) with a `[patch."https://example.invalid/verifiable-trust-infrastructure.git"]` entry
pointing `room-host` at a local VTI checkout, plus `[patch.crates-io]` entries for VTI crates not in
your cargo cache. Then `cargo test --features "cli harness geb-live geb-mls"`. `Cargo.lock` is
git-ignored until the real URL replaces the placeholder. See `docs/DESIGN.md`, section 10.

## Features

| Feature | Adds |
|---|---|
| (default) | The Geb core and the adapter-neutral core: codec, crypto, dyad, pump, store and room traits, loopback. No VTI crate, no network stack, no MLS |
| `vtc` | The VTC room side (`vtc::VtcRoom` over `VtaClient`), the fjall `BridgeStore`, key custody, sealed-at-rest state, the supervisor |
| `geb-live` | The Nostr relay client and an in-process test relay (`ws://` only for 127.0.0.1) |
| `geb-mls` | The Geb MLS group over OpenMLS 0.9, tested only against an in-process second client |
| `keyring` | The OS keyring as the secret store (implies `vtc`) |
| `cli` | The `vti-geb-bridge` binary; implies `vtc geb-live geb-mls` |
| `harness` | Tests against a real `room-host` and a fake VTA (implies `vtc`; see above) |

## CLI

Build with `--features cli`. Every command takes `--config <path>` (default `config.toml`).

| Command | Purpose |
|---|---|
| `setup --setup-key-out <path>` then `setup --from <setup.toml>` | Two-phase provisioning against the operator's VTA: mint the Geb device keys, store them, write the config |
| `link add\|list\|pause\|resume\|remove` | Manage links. `add` mints keys and starts paused. `pause` stops a running `run` within one poll interval (see DESIGN section 9), `resume` lets it continue |
| `link clear-halt <id> [--yes] [--i-have-been-readmitted]` | Clear a persisted halt after reading why it happened |
| `geb connect --link <id> <did>` | Open a dyad with a Geb member's device DID |
| `geb stock-kps --link <id>` | Stock KeyPackages with the link's peers (consent to be added) |
| `status [--link <id>]` | Cursors, outbox depth, last relayed post, halt state (stop `run` first) |
| `run` | Supervise every link until SIGINT or SIGTERM (a paused link idles) |

A link needs the room owner's explicit opt-in (`tier_optin = true`), and `private` rooms are
refused. Logs go to stderr; set `RUST_LOG` (default `info`). Config shape: `docs/DESIGN.md`,
section 9.

## Repository layout

```
src/               core: foreign.rs (the seam), model, mapping, pump, store, room, halt, config, atrest
src/geb/           the Geb adapter: wire, crypto, dyad, room, settle, policy, vrc, nostr, mls/
src/vtc/           the VTC room side and HTTPS delivery to the room host
src/{custody,run,wiring,ops,cli,service,main}.rs   key custody, supervision, operator shell
tests/             vectors (Geb's), harness, e2e, geb_live, custody, cli; fixtures/ holds the vectors
docs/              DESIGN.md, geb-bridge-plan.md, geb-bridge-companion-notes.md
```

## Documents

- `docs/DESIGN.md`: what is being built and why, how the pieces fit, the Geb protocol as
  implemented, key custody, threat model, failure handling, operations, tests, open questions.
- `docs/geb-bridge-plan.md` and `docs/geb-bridge-companion-notes.md`: the original plan, rationale
  and threat analysis. Written inside the VTI repository ("the workspace" means that repository);
  a note at the top of the plan lists details that have since changed.
- `CLAUDE.md`: guidance for working in this crate: boundary rules, fail-closed rules, the current
  Geb pins, open questions and the not-built list.

## Origin

Extracted from the VTI repository (crate `vti-geb-bridge`, branch `feat/geb-bridge`) as a fresh
import without history; the first commit message names the source commit. It depends on published
VTI crates by version, except `room-host`.

## Contributing

Read `CONTRIBUTING.md` and `CLAUDE.md` first. Every commit needs a `Signed-off-by:` trailer
(`git commit -s`, the Developer Certificate of Origin) and should be cryptographically signed.
Commit subjects follow `<type>(<scope>): <subject>`.

## License

Apache-2.0, see `LICENSE`.
