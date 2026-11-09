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
  and round 3 (round 3, 2026-11-09, read at `fdf804d`; see "Round 3 answers"), keep
  changes behind `GebCodec` and the other `geb::traits`, and mark anything the
  answers do not settle `// UNVERIFIED:`. Remaining markers: the `did:peer`
  purpose-element order, a few `parsePolicy` details (see `geb/policy.rs`), the
  VRC acceptance by a live Geb (`geb/vrc.rs`: the v2 shape matches Geb's vector byte for byte; `ieee7012Agreed` is sent `false`) and the dyad's
  unstated choices (list at the top of `geb/dyad.rs`). The Nostr event id and
  BIP-340 signature are resolved (`geb/event.rs`, bound to the published
  BIP-340 vectors).
- **Fail closed.** Unknown envelope, frame or plaintext types are errors. An
  unreadable mailbox event is dropped and logged, never acted on. Without the
  `geb-mls` group a Geb commit (`mc`) stops the poll (the default
  `GebGroup::hold_commit` refuses): skipping a commit forks the epoch
  silently. Geb's `validCommit` needs local knowledge in exactly two cases (persona cards
  from persona code, signed leaves `{t:"lv", at, ls}` from leave code), which
  we do not have; the only production inputs are `geb::policy::NoLocalKnowledge`
  (`can_evaluate() == false`). Everything else is decided without them
  (round 2 section 7): ordinary adds, exact-DID root or admin removes, a bound
  sender removing or re-seating its own DID, other re-seats, root policy
  changes, a direct-room add of an exact pair member, and every 0.5.15 bound-leaf
  refusal. Only (1) a Remove of a DIFFERENT DID by a sender who is neither root
  nor admin and (2) a direct-room Add of a DID that is not exactly one of the
  pair are neither merged nor skipped: the poll errors with
  `Error::UndecidableCommit` (epoch and commit hash in the text) and the link
  halts, persisted, `HaltReason::UndecidableCommit` (see "Halts"). A card-free
  refusal in the same commit wins over the undecidable part. UNVERIFIED (open
  question 2): the root / admin test is an exact DID compare; if Geb's test also
  accepts a root's sibling device through persona cards, a commit from one is
  refused here and merged by Geb (a fork), and a non-root policy change is
  refused rather than halted. To turn ALL commit merging off,
  leave `geb-mls` off.
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
  A dyad frame `{k:"g", op:<not kp-stock|kp-req|rs|kp|welcome>}` (Geb's `rc`,
  `seat-ask`, `leave`, or anything newer) parses as `GroupOp::Ignored`, is
  logged, recorded done and ACKED, and never reaches the consumer. An unknown
  frame kind `k`, a `g` frame without a string `op`, or a known op with a bad
  body still fails and is dropped unacked (a kind may carry authority).
  UNVERIFIED: whether an unacked frame blocks Geb's ratchet or only repeats.
  Our own receive chain cannot stall (opening a frame commits the chain, and the
  skipped-key window heals gaps), but without an ack the sender would repost
  the frame for ever, so ack is the safe choice either way. Geb's expected
  reply to `rc` / `seat-ask` / `leave` (P1/P2) is not built.
- **0.5.15 commit and tree rules** (answers round 2 sections 2, 7, 8;
  `geb/mls/commit.rs`, `geb::policy::valid_commit`). Refusals, never failures:
  a commit with any proposal by reference, a standalone Proposal in an `mc`
  (never stored), an update-path leaf naming another DID than its sender
  (`leafAuth`) or carrying a forged binding, an unbound added leaf naming the
  root, an admin or a seated DID (`unboundClaim`), and a remove, re-seat or
  policy change from a sender whose leaf is not bound (exception: …
  … leaf). A `heal` (path-only self-update
  whose new leaf carries the sender's binding) is valid. At join a Welcome whose
  … with one unbound, is
  refused (`treeRefusal`: the group `into_group` stored is deleted, we stay
  pending). Leaf verdicts: bound = binding verifies (`BindingStatus::Verified`),
  unbound = no `0xF002` (`Missing`), forged = present and wrong (`Forged`); `k`
  is derived from the leaf's own signature key, so a bad-`k` binding is simply a
  signature that does not verify. Refused vs failed in the walk: refused = drop
  and try the next hash; failed (`Unprocessable`: replay, wrong branch,
  unparsable) = stop, keep the cursor, send `rs` once.
  UNVERIFIED (Geb's walk label for the MLS-layer refusals is "refused", which
  we read as the same as a `validCommit` failure, matching the forged-binding
  precedent in round 1; the answers do not say it outright, and the reading
  "failed" would stop the walk instead; open question 3): standalone Proposal,
  by-reference, `leafAuth`. UNVERIFIED: the "bound sender" is the sender's leaf
  before the commit; the unboundClaim "seated" set includes a DID the same
  commit removes (a re-seat onto an unbound leaf is refused); a heal need not
  keep the same signature key.
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
- `HaltReason::UndecidableCommit`: with production inputs
  (`NoLocalKnowledge`) a Remove of a different DID by a sender who is neither
  root nor admin, or a direct-room Add of a non-exact DID, cannot be decided
  without persona cards or signed leaves, and neither merging nor skipping is
  safe. The record names the commit's epoch and hash. Clearing
  makes the link read the commit again, so it halts again at once unless
  something changed.
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
`[patch]`. We use 0.9-only API (`StagedCommit::update_path_leaf_node`,
`QueuedProposal::proposal_or_ref_type`); the cost of moving to 0.8.2 is a
second MLS stack plus a storage-snapshot rework, and is not recommended before
the live run says it is needed.

## Open questions for Geb (round 2 follow-ups)

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

M3 remainder: persona cards and signed leaves (`geb::policy::CommitCheckInputs`
has only the `NoLocalKnowledge` production implementation), so the two
card-dependent commit kinds halt the link; leaving a room (a signed `{t:"lv"}`); a
re-seat after a fork (`rs` is sent, a replacement Welcome is not processed);
a peer index (the dyad is driven per peer DID, peers are listed per link in
`geb_peers`); `fc` fragments; the `rs` status body and its fork repair (`rs` is
sent minimal, see "Round 3 answers"); `seat-ask` and `rc` handling; accepting a
re-seat Welcome; persona-card intake; fork choice. Also not
built on the room side: recovery of a sealed record left at a wrong version
by a crash mid-race (it is reported as a typed read error).

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
- A proper `rs` status body `s:{e, a, chain, ...}`, `rc`, `seat-ask`, and
  accepting a re-seat Welcome (P1). Until then our `rs` is the minimal
  `{k:"g", op:"rs", room:{id}}`.
- Re-stocking a SEATED member every 7 days (re-seat needs it; there is no natural
  place until the dyad is driven while seated; we do read it every 30 s while
  seated for `kp-low` / `seat-check`).
- A `link add` check for direct rooms (needs a network read).
- An oversize outbox entry (cannot come out of the mapping layer, which cuts at
  20,000 bytes) would be retried every tick, not dropped.
- Leave, persona-card intake, fork choice.

### UNVERIFIED points that still stand

The seven round-2 follow-ups under "Open questions for Geb" are all still open;
round 3 narrows only the first (Geb pins 0.8.2 as stated; whether it carries a
`[patch]` is still unanswered). Added by round 3:

- **`rs` for `seat-check`:** our `rs` has no status body, which Geb's
  `cleanStatus` requires, so it most likely does NOT satisfy a seat-check
  (nothing worse follows: silence never commits). `geb/mls/client.rs`.
- **`kp-low` / `seat-check` frames:** field types are read from the answers
  (`gen`, `n` integers; `e` an epoch integer), not from a vector.
- **`fc:0` in `cap`:** Geb reads `fc` only when exactly `1`; `0` is "stated, not
  fragments". The effect on large Welcomes is as Geb describes, unobserved.
- **Event and line limits:** 120,000 / 20,000 come from the answers; whether
  the live relay (256 KB claim vs 131,072 in the repo copy) still takes 131,072
  is unconfirmed.
