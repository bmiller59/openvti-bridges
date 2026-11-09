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
  A dyad frame `{k:"g", op:<not kp-stock|kp-req|rs|kp|welcome|kp-low|seat-check|leave>}` (Geb's `rc`,
  `seat-ask`, or anything newer) parses as `GroupOp::Ignored`, is
  logged, recorded done and ACKED, and never reaches the consumer. An unknown
  frame kind `k`, a `g` frame without a string `op`, or a known op with a bad
  body still fails and is dropped unacked (a kind may carry authority).
  Confirmed (round 4 Q7): an unacked frame never blocks Geb's ratchet (Geb acks
  a frame the moment it opens it, before reading its op; an unacked frame is
  kept at most 15 minutes, 256 frames, 2 MB); ack-and-ignore is safe for `rc`,
  `seat-ask` and unknown ops (Geb drops unknown ops too). **`leave` is the
  exception: it is a real op** (`GroupOp::Leave`, `{k:"g", op:"leave", room:{id},
  by, at, sig}`), handed to the group, verified, and still acked; a malformed one
  is acked and ignored. See "Signed leaves". No reply to `rc` / `seat-ask` is
  built.
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
  (about 110 tests, seconds). The pump needs none of them: it speaks the
  `room::RoomSide` and `store::BridgeStore` traits only.
- **`vtc`**: `vtc::VtcRoom` (`RoomSide` over `VtaClient`, HTTPS delivery in
  `vtc::host`) and `fjall_store::FjallStore` (`BridgeStore` over
  `vti_common::store`, keyspaces `links cursors journal_in outbox_out xref
  geb_mls ratchets`, journal fsync after every write the crash argument leans
  on). Kept behind a feature so the Geb work (M2/M3) never waits on the
  VTI build graph, and so nothing Geb-shaped is pulled into it. Nothing
  else enables it.
- **`harness`** (implies `vtc`): optional dependencies on `room-host`,
  `vti-rooms-dtg` test support and `vtc-client`, for `tests/harness.rs`. They
  are optional rather than dev-dependencies so a default `cargo test` does not
  compile the room host.

Run the harness: `cargo test --features harness` (needs the `room-host` git dependency, see README).

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
  `<data_dir>/links/<id>/`. `run` supervises each pump (`run`: stop observed at
  every wait, `close` on every exit, backoff reset only after a healthy session,
  `Refused` and `UndecidableCommit` halt for good and the halt is persisted, health derived from the
  time of the last good tick). Config load reads one file and contacts nothing.
- `wiring::assemble` builds a link; the end-to-end test (`tests/e2e.rs`,
  features `harness geb-live geb-mls`) uses the same assembly. Its header says
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
4. `rs` / `rc` / `seat-ask` details (P1): `forkMineWins`, when a client is
   behind long enough to `askReseat`, and whether `rc`'s `e` is the epoch it was
   made from.
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

1. Does Geb accept (or silently ignore) an `rs` with no status body `s`, and is a
   seat-check answered by anything short of a full `rs`? (We send the minimal one.)
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
a re-seat after a fork (`rs` is sent, a replacement Welcome is not processed);
a peer index (the dyad is driven per peer DID, peers are listed per link in
`geb_peers`); `fc` fragments; the `rs` status body and its fork repair (`rs` is
sent minimal, and Geb DROPS it: see "Round 4 answers"); `seat-ask` and `rc`
handling; accepting a re-seat Welcome; dead-branch line re-post; fork choice.
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

### Open items (recorded, not built)

- `fc` fragments (large-room joins fail; see Capabilities).
- A proper `rs` status body `s:{e, a, chain, ...}` (THE NEXT TASK: Geb drops our
  minimal `rs`, so it currently has no effect at all), `rc`, `seat-ask`, and
  accepting a re-seat Welcome (P1). Until then our `rs` is the minimal
  `{k:"g", op:"rs", room:{id}}`.
- Re-stocking a SEATED member every 7 days (re-seat needs it; there is no natural
  place until the dyad is driven while seated; we do read it every 30 s while
  seated for `kp-low` / `seat-check`).
- A `link add` check for direct rooms (needs a network read).
- An oversize outbox entry (cannot come out of the mapping layer, which cuts at
  20,000 bytes) would be retried every tick, not dropped.
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

## Round 4 answers (2026-11-09, `Geb's path B answers, round 4`, read at `fdf804d`)

Geb's word as written; none checked against a live Geb. Four of our readings
would have forked us (Q1, Q2, Q6, Q7); all four are fixed (`git log`).

**Acted on.** Q1: the settle walk never stops on any candidate (refused and
failed both skip; cursor and `rs` only if nothing merged). Q2: `selfHeal`. Q6:
Geb's exact removes rule, with the persisted halt kept ONLY for the
card-dependent residue (a deliberate bridge-side choice). Q7: signed leaves are
received (room line and dyad frame) and feed rule (2).

**Confirmed (no longer UNVERIFIED).**
- Q3: a heal needs the same DID and, if a binding is present, a valid one; the
  new key is not compared with the old.
- Q4: root and admin are an EXACT DID compare (`roleOf`, `mayRemove`,
  `mayChangePolicy`, `unboundClaim`); persona cards widen only …
  … adds. A root's sibling
  device has no rights.
- Q5: a DID removed in the same commit still counts as seated: an unbound
  re-seat leaf is refused (`unboundClaim`).
- Q7: an unacked dyad frame never blocks the ratchet; ack-and-ignore is safe for
  `rc`, `seat-ask` and unknown ops, not for `leave`.
- Q8: an `rs` with no valid body `s` is DROPPED (`cleanStatus`, then `return
  null`): never a fork signal, never marks us "seen", never gets us `rc` or a
  re-seat. **So our current minimal `rs` has no effect at all; the proper `rs`
  status body is the next task.** An unanswered seat-check commits nothing
  ("silence alone never commits").
- Q9 (for the `rs`/re-seat task, not built): `rc`'s …
  … (receivers judge at once when `e` equals theirs, keep up to 64
  for later epochs, drop below). `forkMineWins(hashWins, mine, theirs, others)`:
  (1) `theirs > mine` and every `other > mine`: I lose; (2) `theirs < mine` and
  every `other > theirs`: I win; else `hashWins` (at the lowest common epoch where
  authenticators differ, the lower authenticator wins). …
  … when behind (same `(mine, theirs)` pair seen
  again a settle window later) or when evicted/missing, at most once per 600 s;
  it sends `seat-ask` with no `kp`, after which our `rs` stays quiet 600 s.
- Q10: after a re-seat each device re-posts ITS OWN dead-branch lines (original
  `id` and `at`, `{t:"l", ..., fk:1, id}`, at most 100, text only); we cannot
  leave it to others. Not built.
- Q11: an over-budget frame is sent whole to an `fc:0` peer; Geb's sender sets
  it aside only above 258,048 bytes; no fallback route; members per room before
  a Welcome needs fragments is not measured.
- Q12: no fragment sample exists yet (owed).
- Q15: a KeyPackage lifetime of exactly 84 d + 1 h is NOT refused (receivers
  check only that now is in `[not_before, not_after]`; Geb adds no check).
- Q16: `kp-low` with `n:0` is valid (`n` from 0 to `STOCK_N - 1`); the gen after
  a loss is `max(last gen sent, their gen) + 1`, i.e. theirs + 1 as implemented.
- Q17: more than 16 `kp-stock` entries: the first 16 that pass the pattern and
  length filter are kept.
- Q18: `ieee7012Agreed` is a required boolean whose value is never checked;
  `false` is accepted.
- Q19: Geb's OpenMLS 0.8.2 is stock (registry source, no `[patch]`, no `.cargo`).

**Relay figures are now UNCONFIRMED (Q13, Q14).** Geb's repo copy of the strfry
config is out of date: per-event 131,072 there, raised to 256 KB on 2026-11-02 per
Geb's record (and); subscriptions per connection 20 there,
raised to 200 on 2026-11-04 (round 3's "20" was stale); future `created_at`
900 s, no change recorded; NIP-40 deletion vs hiding unconfirmed. Geb will read
the live config. We keep planning to 120,000 bytes either way and keep our 8
concurrent catch-up reads.

**Not decided yet (Geb, Geb's maintainers decide):** which of seven cases the compatibility
run uses and whether test switches run on throwaway Geb nodes; a fragmented
frame sample; publishing the live relay config; …
… joining.

**Q20/Q21.** The fixed transcript follows separately. Every case in Q21 can be
staged from the `geb` CLI today (bound add, unbound add, heal with
`GEB_TEST_NO_BINDING=1`, forced fork + re-seat, `geb group leave`, a line over
20,000 characters, a Commit Geb refuses).
