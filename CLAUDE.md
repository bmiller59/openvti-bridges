# CLAUDE.md — vti-geb-bridge

Crate guidance for the experimental …
foreign room (first adapter: Geb). This crate was extracted from the VTI
repository (see README); "the workspace `CLAUDE.md`" below means that
repository's root `CLAUDE.md`, whose rules still bind this code.
Status: **experimental** (`publish = false`). Geb path B
reading: version `0.1`, pinned to Geb substrate commit `fdf804d` (release 0.5.15;
round 1 of the answers was read at release 0.5.14, the fixture vectors were
generated at release 0.5.14 (round 1) and the round 2 reading (round 2), none at `fdf804d`)
(`geb::PATH_B_VERSION`, `geb::PATH_B_PINNED_COMMIT`, `geb::status_line()`).

## Purpose

Carry content both ways between a VTC data room and a foreign room, with the
bridge signing as itself and bridged content never presented as verified.
Plan: `docs/geb-bridge-plan.md` and `docs/geb-bridge-companion-notes.md`.

## Boundary rules

- **Nothing else depends on this crate, and no VTI crate gains Geb code.**
  Do not depend on `vti-rooms`.
- **The core never names a foreign system.** `config`, `model`, `foreign`,
  `mapping`, `room`, `store`, `pump` depend only on `foreign::ForeignRoom` and
  `foreign::RoomCapabilities`. Behaviour that varies by room (retraction as a
  notice line, size limit) is chosen from the capabilities, never from an
  adapter's name. Everything Geb-specific lives under `geb/`; `loopback` is
  the second, trivial adapter that keeps the core honest.
- **Geb is a foreign-protocol interface** (workspace `CLAUDE.md`, exceptions
  to "every remote operation is a Trust Task"). Its wire has no versioned spec:
  pin to Geb's authoritative answers `Geb's path B answers, round 1` (code at
  release 0.5.14), round 2 (release 0.5.15, `fdf804d`; the 0.5.15 paragraphs are
  the current rules; they supersede `Geb's implementer's guide (2026-11-07)` where they differ)
  round 3 (round 3, 2026-11-09, read at `fdf804d`; see "Round 3 answers") and
  round 4 (round 4, 2026-11-09, `fdf804d`; see "Round 4 answers"), keep
  changes behind `GebCodec` and the other `geb::traits`, and mark anything the
  answers do not settle `// UNVERIFIED:`. Remaining markers: the `did:peer`
  purpose-element order, a few `parsePolicy` details (see `geb/policy.rs`), the
  VRC acceptance by a live Geb (`geb/vrc.rs`: the v2 shape matches Geb's vector byte for byte; `ieee7012Agreed` is a required boolean whose value Geb never checks, round 4 Q18, so `false` is sent and accepted: no longer UNVERIFIED) and the dyad's
  unstated choices (list at the top of `geb/dyad.rs`). The Nostr event id and
  BIP-340 signature are resolved (`geb/event.rs`, bound to the published
  BIP-340 vectors).
- **Fail closed.** Unknown envelope, frame or plaintext types are errors. An
  unreadable mailbox event is dropped and logged, never acted on. Without the
  `geb-mls` group a Geb commit (`mc`) stops the poll (the default
  `GebGroup::hold_commit` refuses): skipping a commit forks the epoch
  silently. Geb's `validCommit` needs local knowledge in two places: persona
  cards (persona code, which we do NOT hold: no persona-card intake is built) and
  signed leaves (`{t:"lv"}` lines and dyad `leave` frames, leave code, which
  we take: `geb::leave`). The production inputs are
  `geb::policy::NoLocalKnowledge` (`can_evaluate() == false`) plus the held
  signed leaves. A Remove passes (Geb's exact rule, answers
  round 4 Q6) when ANY of: (1) every removed DID is the sender's person (without
  a persona store: the sender's own DID); (2) …
  … we hold, no adds, no policy change; (3) a re-seat (removed and
  added DIDs the same non-empty set, no policy change) by any member with a
  bound leaf; (4) the sender is root or an admin (EXACT DID compare, never
  widened, Q4) or the room's policy is v1 (`p.v !== 2`). A Remove or policy
  change needs a sender whose leaf is bound BEFORE the commit, except
  `selfHeal` (Q2: an unbound sender whose Remove has no policy change, removes
  only leaves naming its own DID, adds at least one leaf and …
  … signature). **Geb refuses
  anything else and goes on; it never halts a room.** The ONE residue the bridge
  cannot decide is a Remove of ANOTHER DID by a non-root non-admin sender in a v2
  room with no signed leave we hold and not a re-seat: a Geb device holding a
  persona card linking the two DIDs would merge it. Only that case (and a
  direct-room Add of a DID that is not exactly one of the pair) is neither merged
  nor skipped: the poll errors with `Error::UndecidableCommit` (epoch and commit
  hash in the text, and the reason: no persona store, no signed leave) and the
  link halts, persisted, `HaltReason::UndecidableCommit` (see "Halts"). **That
  halt is a deliberate bridge-side choice, the honest alternative to silently
  forking; Geb itself refuses and continues.** The reason it exists is that the
  bridge holds no persona store. A card-free refusal in the same commit wins over
  the undecidable part. To turn ALL commit merging off, leave `geb-mls` off.
- **MLS wire strictness** (answers round 2, sections 1-2; `geb/mls/commit.rs`):
  every MLS object we read is a full RFC 9420 `MLSMessage`. `mc` / `ml` `m` must
  be an `MLSMessage` whose body is a PrivateMessage (a PublicMessage, a bare
  PrivateMessage and trailing bytes are refused; a refused commit is recorded
  `failed`, a refused line is dropped). A Welcome `w` must be an `MLSMessage`
  whose body is a Welcome ("not a Welcome" otherwise). A KeyPackage is the bare
  TLS `KeyPackage` (`KeyPackageIn::tls_deserialize_exact`, trailing bytes and a
  wrapper fail) in standard base64 matching `^[A-Za-z0-9+/=]+$`; base64url
  strings are dropped, in our `kp` / `kp-stock` frames (`Frame::validate`) and
  in `geb::mls::parse_key_package`.
- **Unknown group ops are ignored, unknown kinds are not** (`wire::parse_frame`).
  A dyad frame `{k:"g", op:<not kp-stock|kp-req|rs|rc|seat-ask|kp|welcome|kp-low|seat-check|leave>}` (Geb's
  `rq`, `rl`, or anything newer) parses as `GroupOp::Ignored`, is
  logged, recorded done and ACKED, and never reaches the consumer. An unknown
  frame kind `k`, a `g` frame without a string `op`, or a known op with a bad
  body still fails and is dropped unacked (a kind may carry authority).
  Confirmed (round 4 Q7): an unacked frame never blocks Geb's ratchet (Geb acks
  a frame the moment it opens it, before reading its op; an unacked frame is
  kept at most 15 minutes, 256 frames, 2 MB); ack-and-ignore is safe for `rc`,
  `seat-ask` and unknown ops (Geb drops unknown ops too). **`leave` is the
  exception: it is a real op** (`GroupOp::Leave`, `{k:"g", op:"leave", room:{id},
  by, at, sig}`), handed to the group, verified, and still acked; a malformed one
  is acked and ignored. See "Signed leaves". `rs`, `rc` and `seat-ask` are real
  ops now (`GroupOp::Rs/Rc/SeatAsk`): see "Room status, catch-up and re-seat".
  A `seat-ask` from a peer needs nothing from us (we are never the healer): acked,
  no action.
- **Signed leaves (receive only)** (answers round 2 section 8, round 4 Q7;
  `geb/leave.rs`). Ignoring a leave is safe only if we take the signed room
  line, or a device with …
  … leaver that every Geb device merges. Taken two ways, one payload:
  `leavePayload(room, by, at) = JCS {t:"leave", v:1, room, by, at}` signed by the
  leaver's device DID Ed25519 key (verified against the key in the `did:peer`):
  (a) a room line `{t:"lv", at, ls, sg}` (read in `GebRoom::poll`; the line's
  `sg` must verify for its MLS sender, then `ls` is verified for `by` = that
  sender); (b) the dyad frame above (`by` is a field; any peer may relay a
  leave, the signature is what counts). Kept: the NEWEST leave per signer per
  room, persisted in the sealed MLS snapshot (`Snapshot.leaves`), at most 1024
  signers; a leave whose signature does not verify, or that names another room,
  is dropped. A held leave covers its signer's EXACT DID in `valid_commit` rule
  (2). We do not send a leave, elect a healer or commit a Remove (follower
  only). UNVERIFIED: the `lv` line's `sg` is read as the usual
  `{v:1, room, author, body}` wrapper over the plaintext without `sg`; a held
  leave is never expired.
- **0.5.15 commit and tree rules** (answers round 2 sections 2, 7, 8, round 4
  Q1-Q6; `geb/mls/commit.rs`, `geb::policy::valid_commit`). Refused (staged by
  MLS, then failed `leafAuth` / `validCommit`): an update-path leaf naming
  another DID than its sender (`leafAuth`) or carrying a forged binding, an
  unbound added leaf naming the root, an admin or a seated DID (`unboundClaim`;
  `seated` is the list BEFORE the commit and nothing exempts a DID the same
  commit removes, Q5), and a remove, re-seat or policy change from a sender whose
  leaf (as it stood before the commit, Q2) is not bound (exception: `selfHeal`).
  Failed (MLS cannot process it): replay, wrong branch, unparsable, a standalone
  Proposal in an `mc` (Geb's binding never stores one; in an `ml` it is dropped
  as non-line) and a commit with a proposal by reference (UNVERIFIED which of
  failed and refused fires there; both are skipped). **The walk NEVER stops on
  any candidate** (Q1): both refused and failed skip to the next hash and the
  first that passes is merged. They differ only after the walk: if NOTHING
  merged and one failed, the cursor stays before it (a later replay is judged
  again) and ONE `rs` goes out; if one merged, a failed candidate changes
  nothing. A `heal` (path-only self-update whose new leaf carries the sender's
  binding) is valid and need not keep the same signature key (Q3; whether
  OpenMLS 0.8.2 accepts a new key in an update path is unconfirmed). At join a
  Welcome whose … with one
  unbound, is refused (`treeRefusal`: the group `into_group` stored is deleted,
  we stay pending). Leaf verdicts: bound = binding verifies
  (`BindingStatus::Verified`), unbound = no `0xF002` (`Missing`), forged = present
  and wrong (`Forged`); `k` is derived from the leaf's own signature key, so a
  bad-`k` binding is simply a signature that does not verify.
- **No new message kinds.** Geb has no edit, delete or retract on the wire. A
  retraction (or a supersede, since edit is unsupported) is an ordinary signed
  `{t:"l"}` line whose `re` is the original line's *derived* id
  (`geb::crypto::line_id`); the xref therefore stores that derived id for each
  bridged record. Notice wording is configurable per link (`[links.notices]`).
- **Capabilities.** The bridge sends `cap` `{k:"cap", dm:0, fc:0}`: `fc` is
  stated because an UNKNOWN `fc` makes Geb hold a large frame back until it
  hears from us; `rv` and `wp` stay unset (a …
  … which is what we want); it never claims `dm >= 1`,
  `fc: 1` or `rv: 1`. KNOWN LIMITATION: with `fc:0` Geb sends a frame too big
  for one 120,000-byte event whole and the relay refuses it, so …
  … in it) NEVER reaches us and joining a
  large room fails. Fragment reassembly (`{k:"fc", id, i, n, d}`, `n` <= 64)
  is not built (open item).
- **Refusal stops the link.** If seating is refused or the leaf is removed
  (`Error::Refused`), the link halts, alerts and is never retried; the halt is
  persisted. An "ask" room may leave seating `JoinState::Pending`, which is a
  state (the link idles and re-checks each tick), not an error.
- **Bridge identity.** Bridges are welcome unmarked by default. `display_name`
  is optional (1-40 characters) and the join announcement line is optional
  (`announce`, default off). Geb will later define room-level bridge policy
  (not welcome / welcome automatically / ask, and whether to show a mark) and a
  signed "bridge" role badge; shapes are not shared yet and are not implemented.
- **Receipts are evidence, not delivery** (R1.1). Geb can only ever return
  `Relayed`, after reading our own event back.
- **No invented test vectors.** Geb's vectors are vendored at
  `tests/fixtures/geb-path-b-vectors.json` (fixed labelled test keys and public
  outputs only) and bound in `tests/vectors.rs`; round 2
  (`geb-path-b-vectors-2.json`: commit hash and settle winner, exporter, signed
  leaf, persona card, VRC v2) is bound in `tests/vectors2.rs`. Of those, the exporter
  is re-derived by a test-only RFC 9420 implementation (our code derives it only
  through OpenMLS) and the persona card by a test-only verifier (this crate has no
  card type). Other tests are round-trips
  and re-derivations and say so; never present this crate's own output as
  Geb's.
- Inbound foreign text is untrusted: records are `basis: "observed"`, with a
  provenance block, and the text sits in a fence longer than any backtick run
  in it.

## Features (M1)

- **default (none)**: the Geb core and the adapter-neutral core build and test
  without `vta-sdk`, the generated Trust Task crates, fjall or `room-host`
  (186 lib tests plus `tests/vectors.rs` 11 and `tests/vectors2.rs` 9, seconds; the other test
  targets need a feature and run 0 tests). The pump needs none of them: it speaks the
  `room::RoomSide` and `store::BridgeStore` traits only.
- **`vtc`**: `vtc::VtcRoom` (`RoomSide` over `VtaClient`, HTTPS delivery in
  `vtc::host`) and `fjall_store::FjallStore` (`BridgeStore` over
  `vti_common::store`, keyspaces `links cursors journal_in outbox_out xref
  geb_mls ratchets`, journal fsync after every write the crash argument leans
  on). Kept behind a feature so the Geb work (M2/M3) never waits on the
  VTI build graph, and so nothing Geb-shaped is pulled into it. Only the
  features that need it enable it: `cli`, `keyring` and `harness`
  (`geb-live` and `geb-mls` do not).
- **`harness`** (implies `vtc`): test support only, no room host:
  `HostDelivery::for_loopback_tests`, the in-process MLS `sim`, and
  `vta-sdk/test-loopback` for `tests/custody.rs` and `tests/cli.rs`.
  The tests that need a real `room-host` are the **separate `harness/` package**
  (`harness/tests/harness.rs`, `harness/tests/e2e.rs`; not a workspace member,
  its own git-ignored lock). `room-host` is not published, so `harness/Cargo.toml`
  takes it by git under a placeholder URL; that dependency must never go back into
  the root manifest, because cargo resolves optional dependencies too and the
  root crate would stop resolving for everyone.

**What CI can run** (`.github/workflows/ci.yml`; none of it has run yet, there is no
remote): fmt; clippy and tests for default, `cli geb-live geb-mls` and
`cli harness geb-live geb-mls`; `cargo deny check`; a Signed-off-by check on PRs. CI
generates `Cargo.lock` first because none is committed (a lock produced here has
path-patched sources). The `harness/` package stays manual until the URL is real. Do not
write "verified in CI" for anything.

Run everything locally: the root crate needs the local-only `.cargo/config.toml` override
(git-ignored; `[patch.crates-io]` for VTI crates not in the cargo cache, plus a `[patch]` for
`room-host`). `cargo test --offline --features "cli harness geb-live geb-mls" --no-fail-fast`
in the root gives 273 lib, `cli` 5, `custody` 5, `geb_live` 9, `vectors` 11, `vectors2` 9. For
the room-host tests, `cd harness && cargo test --offline`: `e2e` 3, `harness` 8. A `[patch]` on
a git source still has to fetch it on a fresh resolve (no lock), so offline either point
`room-host` at a path in `harness/Cargo.toml` temporarily (do not commit that) or keep a lock.

- **`geb-live`**: `geb::nostr::NostrRelay` (a `GebRelay` over one websocket per
  identity: wss only, `ws://` only for 127.0.0.1, capped jittered reconnect,
  every event verified; posts refused over 120,000 bytes, reads over the
  relay's 131,072 dropped; relay manners, see "Round 3 answers") and `geb::test_relay::TestRelay` (an
  in-process loopback relay for tests). `tests/geb_live.rs` runs the dyad over
  it. No test may reach a real relay or Geb node. The wss/TLS path is not
  exercised by any test.

- **`geb-mls`**: `geb::mls::MlsGroupClient`, the `GebGroup` over OpenMLS 0.9
  (own provider, no `vti-rooms`; OpenMLS 0.9.x, Geb pins 0.8.2: see "OpenMLS version"): KeyPackages with `[0xF001, 0xF002]` and the
  leaf binding signed through `GebSigner`, seating over the dyad (`kp-stock`,
  `kp-req`/`kp`, `welcome`), per-epoch relay keys from the exporter, sealed
  lines, and the settle rule. The pure settle queue (`geb::settle`) and
  `validCommit` (`geb::policy::valid_commit`) are in every build. Tests run
  against an in-process second OpenMLS client playing a Geb member
  (`geb/mls/sim.rs`): they prove self-consistency, NOT byte-compatibility with
  real Geb MLS. The `// UNVERIFIED:` list is at the top of `geb/mls/mod.rs`.
  A PrivateMessage can be decrypted once, so a commit candidate's verdict is
  cached (`GroupJudge`), never re-processed.

## Geb dyad (M2)

`geb::dyad::StatefulDyad` is the `GebDyad`: connect-when-apart (`invite`,
`invitations`, `accept`, then `sync` completes the handshake) and ratcheted
messaging (`send`, `recv`, `retransmit`). State goes through
`BridgeStore::state_get/state_put` (`links/dyad/<peer>` and `ratchets/<peer>`);
a received frame is queued durably before its ack is posted, and a sent
frame's counter is persisted before the post. It sends `cap` with `dm:0` and
`fc:0` and refuses to send `dm>=1`, `fc` or `rv` of 1. The state is leased, not locked: a
second concurrent call fails with "dyad busy".

## VTC room side rules

- The bridge never holds the persona key. Reads (`rooms/keys/browse/0.4`,
  `rooms/keys/read/0.2`) are VTA-side tasks: the VTA fetches from the host as
  the member, so the bridge delivers nothing for a read. Writes are
  `rooms/keys/act/0.11` (and `rooms/keys/seal/0.3` with `signAsPrincipal` on
  the sealed tier); the returned document is POSTed unaltered and
  unauthenticated to `{host}/trust-tasks` over HTTPS (`vtc::host`), because the
  host authenticates by the document's proof alone.
- Never loop a `VtaClient` call. The only repeat is the sealed put's re-seal at
  the version the host assigned (a different request, bounded at three).
- Typed errors stay typed: `permissionDenied`, `...:actionNotHeld`,
  `...:notAMember` and a VTA `Forbidden` become `Error::Refused` (the pump
  halts the link); everything else is `Error::Room { code, retryable, .. }`.
- A refused create-only put is resolved by reading the key back, never by
  parsing a message: this workspace's `room-host` answers a bare `taskFailed`
  where the specification says `rooms/records/put:versionConflict`.
- The host URL is guarded (https only, no private ranges unless the operator
  opted in) and the HTTP client is the shared foreign-fetch client.

## Operational shell (custody, sealed state, CLI)

- **Custody** (`custody`, feature `vtc`): the VTA mints two key records in the
  `geb-bridge` context (Ed25519, and a separately derived X25519), the bridge
  exports each once (`keys/export-secret/0.1`), builds `did:peer:2.A.V.E`
  itself (no `.S`) and keeps the secrets only in its `vti-secrets` store
  (`SecretStore`, one blob: `BridgeSecrets`). The room persona is only
  recorded, never exported. One device DID and one persona per link, enforced
  in the store and in `Config::validate`. `config_seed` is refused.
- **Sealed at rest** (`atrest`): XChaCha20-Poly1305, key = HKDF of the store
  key per purpose, record name as AAD. `EncryptedState` wraps a `BridgeStore`
  (dyad/ratchet state); `SealedFile` holds the MLS signature key and the
  OpenMLS key-store snapshot. `MlsGroupClient::with_state_store` resumes
  seated; it saves before a KeyPackage leaves, after joining, before a sealed
  line is returned and after a merged commit. A restart still loses the settle
  queue (re-read from the relay: the cursor barrier holds the position) and the
  dedup window (the journal covers it). Cursors, journal, outbox and xref are
  not secrets and stay in clear.
- **CLI** (`--features cli`, `src/main.rs`, `cli`, `service`; not a default
  feature): two-phase `setup`
  (`--setup-key-out`, then `--from`), `link add|list|pause|resume|remove`,
  `geb connect|stock-kps`, `status`, `run`. One fjall store per link under
  `<data_dir>/links/<id>/`. `run` supervises each pump, paused links included (idle; kill switch: `pause.rs`, `ConfigFilePause` re-reads the config on every check, anything unreadable counts as PAUSED, the pump checks before every post and room write; DESIGN section 9) (`run`: stop observed at
  every wait, `close` on every exit, backoff reset only after a healthy session,
  `Refused` and `UndecidableCommit` halt for good and the halt is persisted, health derived from the
  time of the last good tick). Config load reads one file and contacts nothing.
- **Fork marker** (`geb::forkmark`, store cursor `fork`, unsealed, numbers only): the MLS client
  mirrors a recorded split (`heal::Split`, sealed snapshot) so `status` can show it without
  keys: `waiting-for-reseat` / `branch-won` -> `reseated` when a re-seat Welcome is accepted
  (`MlsGroupClient::with_fork_marker`, `sync_fork_marker`). Never add a secret to it.
- `wiring::assemble` builds a link; the end-to-end test (`harness/tests/e2e.rs`) uses the same assembly. Its header says
  what it does not prove (byte-compatibility with real Geb).
- **Edit and retraction are decided by the record KEY, never by `version`**
  (the host's version is room-wide arrival order). `xref` holds
  `vtkey:<key>` -> `origin_id` of the newest bridged version of that key
  (written after the post, before the outbox entry is marked posted) and
  `vtc:<origin_id>` -> the foreign line id. A content record whose key was
  bridged is a `Supersede` of that `origin_id`, otherwise a plain `Post` at any
  version. A room tombstone (`RoomRecord::retracted`) of a bridged key is a
  `Retract` of it (an ordinary signed `{t:"l"}` with `re`, notice wording from
  `[links.notices]`); a tombstone of a key never bridged is ignored.

## Halts

A halt is persisted in the link's `halt` cursor (`halt::HaltReason`, JSON; a
bare string from before kinds existed reads as `Refused`) so a restart stays
halted without touching the foreign room. The alert (`security_alert = true`)
is raised once, when the halt is recorded; later ticks answer from the record.
The supervisor ends `End::Halted` for both kinds and never retries.

- `HaltReason::Refused`: seating refused or our leaf removed by a merged
  commit (`Error::Refused`). Permanent.
- `HaltReason::UndecidableCommit`: a Remove of ANOTHER DID by a non-root,
  non-admin sender in a v2 room, with no signed leave we hold and not a
  re-seat, or a direct-room Add of a non-exact DID. A Geb device that holds a
  persona card linking the two DIDs would merge it; the bridge holds no persona
  store (persona-card intake is not built), cannot know, and neither merging
  nor skipping is safe. **This halt is a deliberate bridge-side choice, the
  honest alternative to silently forking: Geb itself refuses such a commit and
  continues, and never halts a room.** The reason text says so. The record names
  the commit's epoch and hash. Clearing makes the link read the commit again, so
  it halts again at once unless something changed (a signed leave arrived, or
  the room moved on).
- `status` shows the halt and its reason. `link clear-halt <link>` prints what
  the halt was, then clears it only with `--yes`; a `Refused` halt also needs
  `--i-have-been-readmitted` (the bridge has been admitted to the room again).
  Neither starts the link; `run` does.
- **fjall locks its directory**: `status`, `geb connect`, `geb stock-kps` and
  `link clear-halt` open the link's store, so `run` must be stopped first.
  They fail with "the store at ... is in use by another process" rather than
  the engine's lock error (`fjall_store::open_err`; `config`-only commands such
  as `link list` do not open it).
- Not covered: too many held commits (`Error::Unsupported` from
  `hold_commit`) and a build without `geb-mls` (the default `UnsupportedGroup`
  refuses every commit each tick) still fail per tick with backoff.

## OpenMLS version (UNVERIFIED, needs a live run)

We build on OpenMLS **0.9.x** (`Cargo.lock` resolves 0.9.2); Geb pins
**0.8.2** (`Cargo.lock:3292-3293` there). The 0.8.2 source is not on the
development machine, so no source diff was possible. Every behaviour Geb quotes
for 0.8.2 (default PURE_CIPHERTEXT wire-format policy, `add_members` returning
`(MlsMessageOut, MlsMessageOut, Option<GroupInfo>)`, the RFC 9420 section 8.5
exporter, suite 0x0001 first in the default capability list, the ratchet-tree
extension) was checked against the **0.9.2 source only**; they agree. The wire
encodings we depend on are RFC 9420 ones that did not change between the two
(0.9 changed the storage format, past-epoch timestamping and draft features). So
wire compatibility is **inferred, not shown**: only the live compatibility run
against a Geb 0.5.15 CLI (0.8.2) can show it. A Welcome that 0.9.2 rejects
surfaces as `welcome: ...` / `treeRefusal: ...` in the warn log
(`ignoring a welcome`). Also unknown: whether Geb's OpenMLS carries a
`[patch]`. Confirmed (round 4 Q19): Geb's 0.8.2 is stock from crates.io, no `[patch]`, no
`.cargo` folder, features `["js"]`. We use 0.9-only API (`StagedCommit::update_path_leaf_node`,
`QueuedProposal::proposal_or_ref_type`); the cost of moving to 0.8.2 is a
second MLS stack plus a storage-snapshot rework, and is not recommended before
the live run says it is needed.

## Open questions for Geb (round 2 follow-ups)

ANSWERED by round 4 (see "Round 4 answers"): 1 (stock 0.8.2, no patch), 2
(exact), 3 (skip either way; which fires for by-reference is still
unconfirmed), 4 (`forkMineWins`, `askReseat`, `e`), 5 (never blocks; `leave` is
not safe to ignore), 6 (before the commit; key not required; OpenMLS 0.8.2's
own acceptance unconfirmed), 7 (refused). Kept below as asked.

1. Is Geb's build stock OpenMLS 0.8.2, with no `[patch]`?
2. In `validCommit` (Geb's source), is the root / admin test an exact DID
   compare, or can persona cards (`same`) widen it to a sibling device? (Decides
   whether our card-free verdicts can fork.)
3. In the settle walk, is a standalone-Proposal, by-reference or
   `leafAuth`-violating commit "refused" (next hash, cursor moves) exactly like a
   `validCommit` failure, or "failed" (cursor stays, `rs`)? We implement
   refused.
4. (ANSWERED, round 4 Q9, built) `rs` / `rc` / `seat-ask` details: `forkMineWins`,
   when a client `askReseat`s, `rc`'s `e` is the from-epoch.
5. Does an unacked dyad frame block or only repeat on Geb's ratchet, and is a
   reply required to `rs` / `rc` / `leave`? (We ack and ignore unknown ops.)
6. Does the heal need the same signature key, and does "bound sender" read the
   leaf before or after the commit's own update path? (We: before; key not
   required.)
7. Is a re-seat's added unbound leaf (naming a DID the same commit removes)
   refused as an `unboundClaim`? (We refuse it.)

## Open questions for Geb (round 3 follow-ups)

ANSWERED by round 4: 1 (an `rs` with no valid `s` is DROPPED), 4 (`n:0` is
valid, gen + 1), 5 (a lifetime of exactly 84 d + 1 h is not refused); 2 and 3
only partly (relay figures now UNCONFIRMED, see "Round 4 answers").

1. (ANSWERED, round 4 Q8: dropped; we now send the full body.)
2. With `fc:0`, is a Welcome over 120,000 bytes really never delivered, or is
   there a fallback (a re-send in pieces, a smaller tree)? What room size is the
   practical limit?
3. Is the live relay's per-event cap 131,072 or 256 KB, and is the 900 s future
   limit and 20-subscription limit still as in the repo copy?
4. `kp-low {gen, n}`: can `n` be 0, and what should we answer when we have lost our
   per-contact state (we use `their gen + 1`)?
5. Does Geb reject a KeyPackage whose lifetime range is exactly 84 days + 1 h
   (OpenMLS 0.8.2 defines a maximum range of that size but does not call it)?

## Not built (blocked or later)

M3 remainder: persona-card intake (`geb::policy::CommitCheckInputs` has no
persona implementation; the card-dependent Remove halts the link); SENDING a
leave, the healer election and Remove commits (we only RECEIVE signed leaves);
a peer index (the dyad is driven per peer DID, peers are listed per link in
`geb_peers`); `fc` fragments; healer duty (electing, committing a re-seat or Remove, we
only follow: see "Room status, catch-up and re-seat"); `status` shows only the
non-secret fork marker of a recorded split, not the split itself (sealed MLS snapshot).
Also not built on the room side: recovery of a sealed record left at a wrong
version by a crash mid-race (it is reported as a typed read error).

## Round 3 answers (2026-11-09, read at `fdf804d`): summary notes

Summary in our own words. Geb's answers are private and are not reproduced here. Nothing below has been
checked against a live Geb; the status of each point is stated.

- **OpenMLS (UNVERIFIED).** Geb is on stock OpenMLS 0.8.2 and has not compared its rooms with any other
  version or library, so this bridge (on 0.9.x) is the first such comparison. Where the bridge relies on
  an OpenMLS default (leaf capabilities, KeyPackage lifetime, ciphertext-only wire format, no padding, no
  retained past epochs, the standard exporter, no last-resort packages), check it against the live run.
  A line that loses an epoch race is recovered by the line self-heal, not by MLS. Whether a Welcome or
  Commit carrying … accepted is not known.
  See "OpenMLS version".
- **Release facts (implemented: pin only).** The bridge builds to release 0.5.15. The release metadata
  carries a wire number that is not a compatibility signal; there is no changelog and no release event,
  and Geb says breaking changes are announced to implementers before they ship. This crate reads none
  of that metadata. Whether 0.5.15 still counts as path B 0.1 is not decided on Geb's side.
- **Decisions Geb has not made yet (not assumed).** Staying on OpenMLS 0.8.2; a path B compatibility
  policy; a room member cap; bridge and agent room settings and how a member declares itself a bridge;
  … devices; the live relay limits.
- **KeyPackages (implemented).** One mint path: always bound (leaf extension `0xF002`), with an explicit
  lifetime (back-dated one hour, valid 84 days). `gen` counts the stocks we sent to one contact, never
  packages and never globally; a stock is 6 packages (receivers keep at most 16) and a receiver replaces
  its set only for a higher `gen`. A `kp-low` is answered with `max(our last gen to them, theirs) + 1`;
  a contact whose last stock is over 7 days old is re-stocked while its link waits for a Welcome.
  Private keys are kept for the newest two stock gens per contact plus anything minted in the last hour,
  and for single packages (`kp` answers) for 7 days. Bridge-side choices: a `kp-low` is answered at most
  once a minute per contact; the newest batch of a gen is the one kept. A `seat-check` is answered with
  `rs` when seated.
- **Limits and relay manners (implemented; live values UNVERIFIED).** A line is at most 20,000 UTF-16
  code units (refused on post, dropped on read). We post events of at most 120,000 bytes (an error naming
  the size, never truncated) and never one dated more than 900 s ahead. Catch-up reads page by `limit`
  and `until`, at most 8 at once, re-reading a little behind the newest delivered event; the first read
  starts at the 7-day retention floor, never unbounded. Dyad frames are planned at 36,000 bytes of
  plaintext. The `mapping` layer cuts outbound text at `RoomCapabilities::max_message_units` (20,000 units
  for Geb, `mapping::truncate_utf16`: char boundary, `[truncated]` marker inside the limit, never over).
  The relay's live limits are unconfirmed (see "Round 4 answers").
- **Room plaintext kinds (implemented).** A newer interop-announcement kind `{t:"wp", ...}` may arrive
  inside a share and older builds drop it. We drop every unknown `t` (and a reaction) without effect, halt
  or any log above debug (`codec::is_not_a_line`); a batch share is never opened by the bridge.
- **Direct rooms (implemented, OPEN at link time).** A bridge cannot sit in a direct room: Geb's commit
  check refuses an … persons. A Welcome into one is refused
  before the group is stored (`Error::Refused`, the link halts; `declares_direct` reads the policy JSON
  raw). `link add` is config-only and contacts nothing, so it cannot detect this beforehand. The leaf the
  adder made for us stays in that room (leaving is not built).
- **Persona cards, heal, leave, `rs`, `seat-ask` (implemented as a follower).** A persona card is needed
  only with two or more devices per person. A heal is path-only and bound leaves need no card. A new
  device DID is a new member; a wiped store sends a `seat-ask` with a fresh bound package. Silence never
  commits.

### Room status, catch-up and re-seat (built; the bridge stays a follower)

Code: `geb/status.rs` (pure: body, `cleanStatus`, `compareStatus`,
`forkMineWins`), `geb/mls/client/heal.rs` (the client side), `geb/room.rs`
(re-read, re-post). Built strictly to Geb 0.5.15 as written; nothing assumes an
alignment change.

- **`rs` sent**: `{k:"g", op:"rs", room:{id}, s:{e, a, chain, lines?, ls?}, via?}`.
  `e` = our MLS epoch, `a` = first 16 hex of the OpenMLS epoch authenticator,
  `chain` = persisted settled Commits `{e: epoch the Commit MADE, h: winner
  SHA-256 (16 hex), a: authenticator there}` (sealed snapshot field `heal`;
  an older snapshot loads with an empty chain), newest 300 only (a dyad frame
  must fit one event; we say `fc:0`). `lines` / `ls`: only our own lines
  (up to 100 kept) and our join time, omitted until we hold one. Sent: after
  joining, after each settle that applied a Commit (to member peers except a
  newly added one), once after a Commit failed to process, at start (1.5 s and
  8 s after the first settle pass), when a dyad answers for the first time or
  again after an error, in answer to a status, and to a seat-check. **Minimum
  interval per peer: 5 s for an unchanged (epoch, authenticator)**; a changed one
  goes at once; the same answer to the same status at most once a minute; so the
  1.5 s start send is usually absorbed by the join send.
- **`rs` received** (from a member's exact device DID only; a non-member's is
  dropped; no valid `s` is dropped, never a fork signal): `compare_status`:
  equal, nothing; they lag: each Commit we hold from their epoch as `{op:"rc",
  room, e: from-epoch, c}` (newest 64 kept, in memory only) then our status;
  behind: re-read from the start of the relay's retention (`SettleReport.reread`,
  at most every 30 s), our status, and the same (mine, theirs) pair seen again a
  settle window later is `askReseat` (`seat-ask` WITHOUT `kp`, once per 600 s,
  then our `rs` is quiet 600 s); fork: lowest common epoch with differing
  authenticators, lower wins, adjusted by `fork_mine_wins` (Q9 rules). The split
  is recorded (`MlsGroupClient::split()`, persisted, WARN log). A winner marks the
  loser asked for the elected healer; a loser does NOT askReseat and waits. We
  never commit.
- **`rc` received**: `e` below our epoch dropped, equal judged at once, later held
  (at most 64), all through the settle queue (`validCommit` and `leafAuth` apply).
- **`seat-ask` with `kp`** (always a freshly minted BOUND package, backed off 600 s;
  its keys are kept 7 days): a Welcome whose KeyPackage we no longer hold; a
  local copy that is missing/evicted (snapshot says we were seated, group gone); a
  `seat-check` while we hold nothing; a re-seat Welcome that has not come 120 s
  after the re-seat Commit merged.
- **Re-seat**: a Welcome while seated (or while `Reseating`) replaces the group:
  only from a current member's device, after `treeRefusal`, the direct-policy
  refusal and the other Welcome checks, and only if our own leaf names our DID,
  is bound and carries the key we hold. The old group is deleted from storage
  first (OpenMLS refuses `GroupAlreadyExists` otherwise); any refusal restores a
  copy of the old store. State reset: settle queue, chain, heard epochs; relay keys
  re-derive from the new group and the room is re-read. A merged re-seat Commit
  that removes our leaf and adds our DID is NOT a removal: state `Reseating`
  until its Welcome arrives.
- **Dead-branch re-post**: our own sent text lines are kept (at most 100, 256 KiB,
  in the sealed snapshot; never others'). After a re-seat those sent at an epoch
  at or above the recorded split's epoch (else our old epoch) are re-posted,
  re-signed, `{t:"l", ..., fk:1, id}` with the original `at` and the derived id,
  directly through the group (not the pump). Our own leaf is skipped on read, so
  nothing is re-bridged; an incoming `fk` line whose id we already hold is dropped.
- **UNVERIFIED**: `compareStatus` exact algorithm; empty-vs-truncated chain
  behaviour at Geb; a chain that starts at our join (no entry for the Welcome's
  epoch); authenticator truncation; `via` meaning; `every` over an empty `others`
  list (we read it as true); whether `fk` lines are signed over `fk`/`id`; which
  dead-branch lines Geb expects; when Geb counts us seen; `cleanStatus` on a bad
  chain entry (we drop the whole status).

### Open items (recorded, not built)

- `fc` fragments (large-room joins fail; see Capabilities).
- Healer duty (re-seating a fork loser, electing, committing): not built, the bridge
  only follows. `status` shows the non-secret fork marker.
- Re-stocking a SEATED member every 7 days (re-seat needs it; there is no natural
  place until the dyad is driven while seated; we do read it every 30 s while
  seated for `kp-low` / `seat-check`).
- A `link add` check for direct rooms (needs a network read).
- An oversize outbox entry (cannot come out of the mapping layer, which cuts at
  the room's unit limit) is a permanent journalled failure (xref `failed:<key>`,
  `status` shows `oversize_failed`), never retried.
- Sending a leave, healer duty, persona-card intake, fork choice.

### UNVERIFIED points that still stand

Round 4 settled most of the round 2 and 3 follow-ups (see "Round 4 answers").
Still open: OpenMLS 0.8.2's own acceptance of …
… path; which of failed and refused fires for a by-reference
commit; the live relay limits (see below); whether the `lv` line's `sg` uses the
usual wrapper; and, from round 3:

- **`kp-low` / `seat-check` frames:** field types are read from the answers
  (`gen`, `n` integers; `e` an epoch integer), not from a vector.
- **`fc:0` in `cap`:** Geb reads `fc` only when exactly `1`; `0` is "stated, not
  fragments". An over-budget frame is sent to an `fc:0` peer WHOLE (round 4 Q11),
  so a Welcome above the relay's per-event cap is never delivered; no fallback.
- **Event and line limits:** 120,000 / 20,000 come from the answers; the live
  relay's per-event cap is UNCONFIRMED (131,072 in the repo copy, raised to
  256 KB on 2026-11-02 per Geb's record).

## Round 4 answers (2026-11-09, read at `fdf804d`): summary notes

Summary in our own words; Geb's answers are private and not reproduced. Nothing here is checked against
a live Geb. Four of our earlier readings would have forked us (the settle walk, the heal rule, the
removes rule and signed leaves); all four are fixed (`git log`).

**Acted on.**
- The settle walk never stops on any candidate: refused and failed both skip, and the cursor and `rs`
  move only if nothing merged.
- The heal rule (`selfHeal`) is implemented for an unbound sender.
- The removes rule follows Geb's exact rule, with the persisted halt kept only for the card-dependent
  residue (a deliberate bridge-side choice).
- Signed leaves are received (room line and dyad frame) and feed rule (2) of the removes rule.

**Confirmed (no longer UNVERIFIED).**
- A heal needs the same DID and, if a binding is present, a valid one; the new key is not compared with
  the old.
- Root and admin are an exact DID compare; persona cards widen only leave-by-own-person, the devices a
  signed leave covers and direct-room adds. A root's sibling device has no rights.
- A DID removed in the same commit still counts as seated, so an unbound re-seat leaf is refused.
- An unacked dyad frame never blocks the ratchet; ack-and-ignore is safe for `rc`, `seat-ask` and
  unknown ops, not for `leave`.
- An `rs` without a valid status body is dropped: not a fork signal, never marks us seen, earns no `rc`
  or re-seat. An unanswered seat-check commits nothing. (Built since: we send the proper body.)
- `rc` carries the epoch the Commit was made from; receivers judge at once when it equals theirs, keep up
  to 64 for later epochs and drop earlier ones. Fork choice (`fork_mine_wins`): I lose if theirs is above
  mine and every other is above mine; I win if theirs is below mine and every other is above theirs;
  otherwise the lower authenticator at the lowest differing common epoch wins. A fork loser waits and
  does not ask for a re-seat; `askReseat` fires when behind or evicted, at most once per 600 s, sends
  `seat-ask` without `kp`, and keeps our `rs` quiet for 600 s afterwards. Built.
- After a re-seat each device re-posts its own dead-branch lines (original `id` and `at`, at most 100,
  text only). Built; the exact `fk` shape is UNVERIFIED.
- An over-budget frame goes whole to an `fc:0` peer and is not delivered above the relay's per-event cap;
  there is no fallback route. No fragment sample exists yet, and the room size at which a Welcome needs
  fragments is not measured.
- A KeyPackage lifetime of exactly 84 days plus one hour is not refused (receivers check only that now
  lies inside the lifetime). `kp-low` with `n:0` is valid and the gen after a loss is theirs + 1. The
  first 16 `kp-stock` entries passing the pattern and length filter are kept. `ieee7012Agreed` is a
  required boolean whose value is not checked, so `false` is accepted. Geb's OpenMLS is the stock registry
  release.

**Relay figures are UNCONFIRMED.** Geb's own copy of its relay config is out of date; the per-event cap,
subscriptions per connection and expiry handling may differ live, and Geb has said it will check. We plan
to 120,000 bytes either way and keep our 8 concurrent catch-up reads.

**Decisions Geb has not made yet.** Which test cases the compatibility run uses and whether test switches
run on throwaway nodes; a fragmented-frame sample; publishing the live relay settings; …
… joining. The fixed transcript for the compatibility cases follows
separately; each case can be staged from Geb's own CLI.

### Remaining questions for Geb (rs / re-seat round)

1. How exactly does Geb compare status chains with no common epoch, or a chain that does not reach back to
   the peer's epoch?
2. What does a joiner's chain hold for epochs before its join and for the epoch its Welcome gave it (we
   send no entry, only the epoch and authenticator)?
3. Is `a` the first 16 hex of the epoch authenticator bytes?
4. Does a receiver cap the chain it accepts per frame (we send the newest 300)?
5. Is a re-post signed over its fork marker and id (we sign the whole plaintext without `sg`), and is the
   id the derived 32-hex id?
6. Which dead-branch lines does Geb re-post (we: those sent at or after the split epoch, else at our old
   epoch)?
7. For the fork choice, is the "every" over an empty list of others true (we read it so)?
