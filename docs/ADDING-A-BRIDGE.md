# Adding a bridge

A bridge joins one VTC room to one foreign room, with one persona, per link. The core
(`openvti-bridge-core`) owns ordering, deduplication, the outbox, replay after a crash, the pause and
halt gates, size cuts and notice fallbacks, provenance fencing, echo suppression, the author deny
list, per-link isolation, sealing adapter state at rest, supervisor backoff and derived health. An
adapter supplies the foreign side and nothing else.

## 1. Write the decision record first

Write `docs/bridges/<kind>.md` before any code and have it reviewed. It covers: purpose and
non-goals; the foreign protocol and the exact pin it was read at; the mapping (what crosses, what is
lossy); a capabilities table; identity and custody; state keys and files; halt codes; failure
handling; **a threat model** (assets, trust boundaries, adversaries: a foreign member, the foreign
operator or relay, a VTI member, the host, the network; what the foreign side can cause: injection
into a VTI room, impersonating a VTI author, denial of service, key exposure, metadata leaks; what
the bridge reveals to the foreign side; residual risks and what is UNVERIFIED); the test inventory;
an operational runbook; open questions. See `docs/bridges/geb.md`.

## 2. Checklist

- [ ] Choose `kind` (lower-kebab). It is permanent: the config key, the state prefix, the secret tag and the halt-code prefix.
- [ ] `crates/openvti-bridge-<kind>`, depending on `openvti-bridge-core` only (plus transport and crypto crates). Not on `openvti-bridge-vtc` or `vta-sdk`: mint keys through the core's `KeyMinter` trait.
- [ ] Implement `ForeignRoom` (`foreign.rs`), `BridgeKind` and `AdapterHandle` (`adapter.rs`). Every `BridgeKind` method after `validate_link` and `foreign_room_key` has a default.
- [ ] Declare honest `RoomCapabilities`: `Verifiability::None` when authors cannot be checked; the size limit as a `SizeUnit` and a count.
- [ ] Map errors to the four the core understands: `Refused` (halts), `Foreign` (transient, retried), `Wire` (permanent, dead-lettered), `AdapterHalt { code }`.
- [ ] Declare halt codes (`<kind>.<reason>`, stable, never reused), return them from `halt_codes()`, document them in `docs/bridges/<kind>.md`, and add a census test like Geb's `census_every_halt_code_is_in_the_table`.
- [ ] Config: a `[links.<kind>]` struct with `deny_unknown_fields`, `foreign_room_key`, and `[bridges.<kind>]` if the kind has global settings (the default accepts none).
- [ ] Secrets: `mint_link_secrets` returns the core's `LinkSecrets` with your payload under your kind; `Debug` is redacted; sealed files go in the link directory through `SealedFile`.
- [ ] State goes only through `BridgeStore::state_get/put("<kind>/...")` and is durable before an acknowledgement or a post. Ask of every mutation: the process dies on the next line, then what?
- [ ] Pass the conformance suite from `tests/conformance.rs` (see `crates/openvti-bridge-geb/tests/conformance.rs`). A case the adapter cannot stage is `Unsupported` with a written reason; cap how many.
- [ ] Vectors, pinning and a status line (below).
- [ ] Register in `crates/openvti-bridges/src/registry.rs` behind a feature named for the kind, and add the CI rows (clippy and test) for the crate. The census test `every_registered_kind_has_a_conformance_run` fails if the conformance file is missing.
- [ ] The isolation CI job still passes: `cargo tree -p openvti-bridge-core` shows no adapter crate, no MLS or websocket stack and no VTI client.
- [ ] A `CLAUDE.md` in the crate, a row in the README bridges table, a row in `docs/bridges/README.md`.

Files: `crates/openvti-bridge-<kind>/{Cargo.toml, src/lib.rs, src/adapter.rs, src/room.rs, tests/conformance.rs, tests/vectors.rs, tests/fixtures/, CLAUDE.md}`.

## 3. What each trait guarantees, and what it asks

| Piece | The core guarantees | The adapter must |
|---|---|---|
| `ForeignRoom::join/leave` | calls `join` again to check a pending seating; stops everything on `Refused` and persists the halt | make `join` idempotent; return `Pending` until seated; return `Refused` for a refusal or removal |
| `ForeignRoom::poll` | journals before it acts; deduplicates; reads oldest first and resumes from the saved cursor | return events after the cursor, oldest first, opaque cursor bytes, `link` empty; repeats at or before the cursor are fine |
| `ForeignRoom::post` | journals the event first (outbox) and replays after a crash with one visible effect | post an event already shaped to the capabilities; return `Accepted` unless a read-back proved more; never report `Delivered` without an acknowledgement |
| `capabilities()` | cuts to the size limit and falls back to notices for edit, delete and reply the room lacks | declare them truthfully |
| `identity()` | suppresses the bridge's own posts read back | name the identity the bridge presents |
| `BridgeKind::build` | hands a `LinkCtx` with the link's secrets, the sealed store, the link directory | build the room and an `AdapterHandle`; no network at build time unless needed |
| `AdapterHandle::verb` | the shell refuses a verb while the link is paused or halted, before the adapter runs | implement only the verbs listed in `verbs()`; return lines to print and values to remember in `[links.<kind>]` |
| `status_lines`, `describe_cursor`, `pinned_reading` | `status` reads the store alone, with no keys | read only the store |

## 4. Must not

Reviewed in the pull request and partly enforced by the isolation job.

- Touch `openvti-bridge-core`, `openvti-bridge-vtc`, `mapping`, `pump` or the halt semantics from an adapter pull request. If the seam is wrong, fix the seam in its own pull request, with the loopback kind proving it.
- Weaken pause or halt: never swallow `Refused`, never clear a halt automatically, never retry past a halt, never post while paused, never add a setting that turns a safety gate off.
- Name another bridge or use another adapter's constants.
- Derive keys with a path or label the caller can choose, or export the persona key (it is never exported).
- Log or `Debug` a secret, or write one to the data directory unsealed. No `reqwest::Client::new()` (the VTI workspace rule R1.2).
- Treat `post() == Ok` as delivered (R1.1).
- Infer author verification: `AuthorCheck::Verified` only on a successful signature check.
- Accept a plaintext transport except `127.0.0.1` in tests.
- Accept unrecognised wire input: fail closed with `Error::Wire`.

## 5. Vectors and pinning

Use the foreign protocol's own vectors, from its authors or generated by their reference code,
recorded with the commit and date, in `tests/fixtures/`, plus a test that reproduces them byte for
byte. Invented vectors are not accepted (`CONTRIBUTING.md`). If none exist, say so in the design
document, keep the adapter experimental and list what is unverified.

The adapter states the exact foreign protocol version or commit it was read at in one constant,
returns it from `pinned_reading()` (printed by `status` and logged), and changes it only with a
vectors regeneration. A foreign version it does not recognise fails closed. The adapter's version is
not the foreign version, and no compatibility is claimed beyond the pin.

## 6. Review gate

A second reader reproduces the vectors and runs the conformance suite before the kind is registered
outside the experimental state.
