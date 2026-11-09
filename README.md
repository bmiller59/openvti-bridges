# vti-geb-bridge

An experimental bridge between a Verifiable Trust Infrastructure (VTI) community data
room and a foreign room. The first (and only real) foreign adapter is Geb, over its
"path B" wire (Nostr relay plus MLS), pinned to Geb substrate commit `fdf804d`
(release 0.5.15; path B version 0.1). A second, trivial `loopback` adapter keeps the core adapter-neutral.

The bridge carries content both ways between the two rooms. It signs as itself, and
content that crosses the bridge is never presented as verified by either side.

## Status

Experimental. Not published (`publish = false`), not a dependency of anything, and never
run against a live relay, Geb node or VTA. Geb's path B has no versioned specification;
details not settled by Geb's answers are marked `// UNVERIFIED:` in the source. Tests
prove self-consistency and the vendored Geb vectors, not byte-compatibility with real Geb.

Read `CLAUDE.md` for the boundary rules and `docs/` for the plan and companion notes
(threat model, decisions, open questions for Geb). Those documents were written inside the
VTI repository and mean that repository when they say "the workspace".

## Origin

Extracted from the VTI repository, crate `vti-geb-bridge`, branch `feat/geb-bridge`, as a
fresh import without history. The exact source commit is in the first commit message.
It depends on the published VTI crates `vta-sdk`, `vti-common`, `vti-secrets`, `vti-specs`,
`vtc-client`, `vti-rooms` and `vti-rooms-dtg`, by version.

## Features

| Feature | Adds |
|---|---|
| (default) | the Geb core and adapter-neutral core: codec, crypto, dyad, pump, store and room traits, loopback. No VTI crate, no network. |
| `vtc` | the VTC room side (`vtc::VtcRoom` over `VtaClient`), the fjall `BridgeStore`, key custody, sealed-at-rest state |
| `geb-live` | the Nostr relay client and an in-process loopback test relay (`ws://` only for 127.0.0.1) |
| `geb-mls` | the Geb MLS group over OpenMLS 0.9, tested only against an in-process second client |
| `keyring` | the OS keyring as the secret store (implies `vtc`) |
| `cli` | the `vti-geb-bridge` binary (`setup`, `link`, `geb`, `status`, `run`); implies `vtc geb-live geb-mls` |
| `harness` | tests against a real `room-host` and a fake VTA sink (implies `vtc`) |

## Running the tests

All offline-capable once dependencies are in the cargo cache:

```sh
cargo test
cargo test --features "cli geb-live geb-mls"
cargo test --features "cli harness geb-live geb-mls"   # needs room-host, see below
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features "cli geb-live geb-mls" -- -D warnings
```

No test reaches a real relay, Geb node or VTA.

### The harness feature

`room-host` is a service binary in the VTI repository and is not published, so
`Cargo.toml` takes it as an optional git dependency under a **placeholder URL**
(`https://example.invalid/...`) pinned by `rev`. Replace the URL with the real location of
the VTI repository before enabling `harness` in CI. Because even optional dependencies must
resolve, the placeholder also stops `Cargo.lock` from being created for everyone, so
`Cargo.lock` is git-ignored for now; commit it once the URL is real.

For local or offline runs, put an uncommitted `.cargo/config.toml` (git-ignored) next to
`Cargo.toml`:

```toml
[patch."https://example.invalid/verifiable-trust-infrastructure.git"]
room-host = { path = "/path/to/verifiable-trust-infrastructure/room-host" }

# Only needed when the published crates are not in the cargo cache:
[patch.crates-io]
vta-sdk = { path = "/path/to/verifiable-trust-infrastructure/vta-sdk" }
# ... and the other VTI crates named above
```

## Before any live run

All of these need a person or Geb; none has been done.

1. Geb to confirm: KeyPackage wire form (bare vs MLSMessage-wrapped), Welcome and commit
   framing, whether exporter keys match, VRC encoding (`issuerPublicKey`, object shape of
   `vrc`), the `rs` frame body, commit-hash framing.
2. Build persona cards and signed leaves (Geb persona code / leave code) so Remove and
   policy commits can be merged. Until then the bridge halts (persisted) on any undecidable
   commit; Add-only commits merge (`geb-mls` only).
3. Run `setup` / `link add` against a real VTA (untested); confirm the printed pnm grant
   text and the exportable-key flow.
4. Real-VTA end-to-end on the sealed tier with an MLS group; wss/TLS soak; compatibility
   soak against the Geb CLI on a test relay.
5. Choose a `vti-secrets` backend (plaintext is dev-only).
6. Not built: leave, re-seat after a fork, `fc` fragments, a peer index, repair of a sealed
   record left at the wrong version.
7. Record in the VTI specification's divergence register (Appendix F): `room-host` answers
   a refused create-only put as a bare `taskFailed`, where the specification names
   `rooms/records/put:versionConflict`.

## License

Apache-2.0, see `LICENSE`. Contributions: see `CONTRIBUTING.md`.
