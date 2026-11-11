# Geb (path B): design

Status: experimental. Everything in this document describes the Geb adapter crate
(`crates/openvti-bridge-geb`) and rests on Geb's written answers, Geb's test vectors (run locally; the committed ones are stand-ins, see the crate's `CLAUDE.md`) and our own
tests; none of it has been run against a live Geb node or relay. The markers are the ones
explained in [`../core.md`](../core.md) (Built, Not built, UNVERIFIED). The core, the
ForeignRoom seam, the data model and the operations that are not Geb's are in
[`../core.md`](../core.md); the rules for working in the crate are in
`crates/openvti-bridge-geb/CLAUDE.md`.

## 5. Geb path B, as implemented

Pinned reading: **path B version `0.1`** (our own label; Geb has not decided whether 0.5.15 is
still 0.1, see section 11) against **Geb release 0.5.15, substrate commit `fdf804d`**
(`geb::PATH_B_VERSION`, `geb::PATH_B_PINNED_COMMIT`, `geb::status_line()`). Round 1 of Geb's
answers was read at release 0.5.14; rounds 2 to 4 were read at `fdf804d`. The fixture vectors were
generated at release 0.5.14 (round 1) and at the round 2 reading; none at `fdf804d`. The sources are
Geb's implementer's guide (2026-11-07) and Geb's path B answers, rounds 1 to 4 (all private, none
stored here); the 0.5.15 paragraphs of round 2 supersede the guide where they differ. None of it is
checked against live Geb.

**Identity (built).** A device DID `did:peer:2.A<ed>.V<ed>.E<x>`: the same Ed25519 key under `.A`
and `.V`, a separately generated X25519 key under `.E`, no `.S`. The order of the purpose elements
is UNVERIFIED.

**Dyad (connect-when-apart, built).** Two devices that are not yet related run: invitation to a
derived inbox (kind 4178), response, completion, with a VRC in each direction; then a pair mailbox
(kind 4177) carries ratcheted frames. States: Invited, Responded, Connected, Expired (7 days). The
dyad keeps a per-peer ratchet (a receiver keeps 512 skipped keys and heals jumps up to 65,536),
frame ids, acks, retransmit. A received frame is queued durably before its ack is posted, and a
sent frame's counter is persisted before the post, so a crash can lose a post but never reuse a
counter. The state is leased, not locked: a second concurrent call fails with "dyad busy".
`cap` is sent as `{k:"cap", dm:0, fc:0}`; the bridge never claims `dm >= 1`, `fc: 1` or `rv: 1`.
Dyad frames are planned at 36,000 bytes of plaintext (conservative).

**VRC v2 (built, UNVERIFIED against live Geb).** W3C VC 2.0 with the DTG context, an
`eddsa-jcs-2022` DataIntegrityProof, `credentialSubject.issuerPublicKey`, a 32-hex `nonce`,
`issuerEndpoint`, `subjectEndpoint` and `ieee7012Agreed` (always sent `false`: the bridge makes no
such claim; round 4 Q18 confirms the field is a required boolean whose value Geb never checks, so
`false` is accepted). The output reproduces Geb's round 2 vector byte for byte; whether a live Geb
accepts one we issue in full is open.

**Mailbox envelopes (built).** `{t:"f"|"ack"|"ml"|"mc"|response|completion}` sealed into Nostr
events of kind 4177 (pair and room mailboxes) and 4178 (inboxes), each with a NIP-40 `expiration`
tag (7 days). Event id and BIP-340 signature are bound to the published BIP-340 vectors. An
unreadable event is dropped and logged, never acted on. An unknown envelope or frame kind is an
error (a kind may carry authority); an unknown group `op` is acked and ignored.

**MLS rooms (built behind `geb-mls`, self-consistent only).** OpenMLS 0.9.x; ciphersuite 0x0001;
group id is the room id as UTF-8; `BasicCredential` is the device DID; the ratchet tree comes in
the Welcome; external joins are never used. The KeyPackage declares extensions `[0xF001, 0xF002]`.

- `0xF001` is the room policy (a GroupContext extension of JSON: `{v:2, committer, settleWindowMs,
  root, admins, direct?}`). `parse_policy` mirrors Geb's parser; malformed reads as the v1
  default. Only `root` can change policy.
- `0xF002` is the **leaf binding**, a LeafNode extension: the device DID key's signature over
  `JCS({"did", "k", "t":"leaf", "v":1})` where `k` is the hex of the leaf's MLS signature key,
  as base64url (86 characters). It proves the leaf belongs to the DID. A missing binding is
  "unbound"; a present wrong one is "forged".
- Every KeyPackage we hand out is bound, with an explicit lifetime (not before now minus 1 h, not
  after now plus 84 days).
- Seating over the dyad: `kp-stock` (6 packages per stock, at most 16 kept by receivers,
  per-contact `gen`), `kp-req` / `kp`, `welcome`, `kp-low`, `seat-check`.
- **Relay keys from the exporter.** Per epoch, labels `geb/room/v2/nostr` and `geb/room/v2/aead`
  with context equal to the room id bytes give the room mailbox's Nostr key and AEAD key. We
  resubscribe after every merged commit and post under the keys of the epoch a line is sealed in.
- Framing is strict (answers round 2): a room line `m` is a full `MLSMessage` holding a
  PrivateMessage; a Welcome is an `MLSMessage` holding a Welcome; a KeyPackage is a bare TLS
  `KeyPackage` in standard base64. Other forms are refused or dropped.

**Settle rule and `validCommit` (built).** The bridge never commits in either group.
Every `mc` is held for the room's `settleWindowMs` (read from the policy, default 3000, clamped to
0 to 60,000). Candidates for one parent epoch are tested in ascending SHA-256 of the commit
bytes, each against `validCommit` before it can win; the first valid one is merged. **The walk
never stops on any candidate** (round 4 Q1). *Refused* (MLS staged it, then it failed `leafAuth` /
`validCommit`: drop it) and *failed* (MLS cannot process it: replay, other branch, unparsable, a
standalone Proposal in an `mc`, a proposal by reference) both go on to the next hash. They differ
only after the walk: if nothing merged and one failed, the cursor stays before it and one `rs`
goes out; if one merged, a failed candidate changes nothing. The 0.5.15 rules are applied: refuse
an update-path leaf naming another DID than its sender, an unbound added leaf naming the root, an
admin or a seated DID (the DID a same commit removes still counts as seated), and a remove,
re-seat or policy change from a sender whose leaf, as it stood before the commit, is not bound
(`selfHeal` excepted: an unbound sender may remove leaves naming only its own DID if it adds at
least one leaf, each added leaf names the sender and carries a binding signed by the sender's own key,
and there is no policy change). A
path-only self-update carrying the sender's binding (a "heal") is valid and need not keep its key.
At join a Welcome is refused if a leaf in its tree carries a forged binding, or if one DID sits
in two leaves and one of them is unbound.

A **Remove** passes (Geb's exact rule, round 4 Q6) when any of: (1) every
removed DID is the sender's person (no persona store here, so the sender's own DID only); (2) every
removed leaf is covered by a held signed leave, with no adds and no policy change; (3) a re-seat: the same non-empty DID set removed and added, policy untouched, by any member with a
bound leaf; (4) the sender is root or an admin (exact DID compare, never widened by persona cards) or the
room's policy is v1. Geb **refuses anything else and goes on; it never halts a room.**

**The one deliberate difference.** The bridge holds no persona store (persona-card intake is not
built). A Remove of another DID by a non-root, non-admin sender in a v2 room, with no signed leave
we hold and not a re-seat, is the only commit whose verdict depends on a card: a Geb device holding
a card that links the two DIDs would merge it, and we cannot know. The bridge therefore **halts**
(persisted, `UndecidableCommit`) rather than silently fork. That halt is a bridge-side choice, the
honest alternative to a silent fork; Geb itself refuses and continues. The same halt covers a
direct-room Add of a DID that is not exactly one of the pair.

**Signed leaves (received, never sent).** Ignoring a leave is safe only if the signed room line is
taken (round 4 Q7): a device lacking the signed leave would refuse the healer's Remove of the
leaver while every Geb device merges it, and we would fork. The payload is `JCS {t:"leave", v:1, room, by, at}` signed by
the leaver's device DID key. It arrives as a room line `{t:"lv", at, ls, sg}` (the line's `sg` must
verify for its MLS sender, then `ls` for that sender) and as a dyad frame `leave` carrying the same fields plus `sig` (still acked). The newest leave per signer per room is kept and persisted
in the sealed MLS state; one that does not verify is dropped. A held leave covers its signer's exact
DID in rule (2). The bridge does not send a leave, elect a healer or commit a Remove.

**Limits (built).** A line's text is at most 20,000 UTF-16 code units: refused on post, dropped on
read. Every event we post is at most 120,000 bytes (an error naming the size, never truncated);
we read at most 131,072. We refuse to post an event dated more than 900 s ahead. Catch-up reads
page with `limit: 200` and `until`, at most 8 at once (the repo copy of the relay config allows 20
subscriptions, but that copy is stale: 200 per Geb's record, live config UNCONFIRMED, round 4 Q13);
the first read starts at the 7-day retention floor, never unbounded.

### What is built and what is not

| Geb feature | State here | Consequence of the gap |
|---|---|---|
| Identity, dyad, VRC v2, mailbox envelopes, ratchet | Built; vectors bind the primitives; the whole flow only against our own test relay | Interop with a live Geb is unproven |
| MLS seating, lines, settle rule, 0.5.15 commit rules | Built behind `geb-mls`; tested only against an in-process second OpenMLS client | Wire compatibility with Geb's OpenMLS 0.8.2 is inferred, not shown |
| Healer duty (electing, committing a re-seat or Remove) | Not built, deliberately: the bridge follows | A fork the bridge wins needs a Geb member to heal the loser; the bridge only marks the loser "asked". The recorded split is in the sealed MLS snapshot; `status` shows its non-secret fork marker (section 8) |
| `rs`, `rc`, `seat-ask`, re-seat Welcome, dead-branch re-post | Built (round 2 sections 5 and 8, round 4 Q8-Q10): proper `rs` body, `compareStatus` and `forkMineWins`, `rc` both ways, `seat-ask` (no `kp` when behind, bound `kp` otherwise), group replacement from a re-seat Welcome, own-line re-post | Several details are UNVERIFIED (CLAUDE.md "Room status, catch-up and re-seat"): the exact `compareStatus`, the chain before our join (empty), authenticator truncation, the `fk` shape. Tested only against the in-process second client, never a Geb node. Commit bytes for `rc` are memory-only |
| Signed leave, receiving (`{t:"lv", at, ls}`, dyad `leave`) | Built (`geb/leave.rs`) | Feeds `validCommit` rule (2) |
| Signed leave, sending; healer duty; Remove commits | Not built; `leave` fails closed | The bridge cannot leave a room cleanly; the leaf stays until someone removes it. Also, a refused direct-room Welcome leaves the adder's leaf in that room |
| Persona-card intake | Not built; only `NoLocalKnowledge` plus held signed leaves exists | One card-dependent Remove halts the link (section 8); Geb itself would refuse and continue |
| Fork choice | Not built | A real fork is not detected or resolved by the bridge |
| `fc` fragments (`{k:"fc", id, i, n, d}`) | Not built; we say `fc:0` | A frame too big for one 120,000-byte event, notably a Welcome for a large room, never reaches us: joining a large room fails. The practical room size limit is unknown |
| `rq` / `rl` line-sharing, history | Not built; acked and ignored | No lines from before joining (Geb gives none) and no gap healing after joining |
| Bridge role badge, per-room bridge policy | Not built; Geb has not shared shapes | The bridge is unmarked unless `display_name` and `announce` are set |
| Direct rooms | Refused at join time (a Welcome into one is refused, the link halts) | `link add` cannot detect it ahead of time |
| Peer index | Not built; dyads are driven per configured peer DID | Peers are listed per link in `geb_peers` |
| Re-stocking a seated member every 7 days | Not built | A re-seat later may find no fresh packages |


## 11. Open questions and the pre-live-run checklist

### Open questions for Geb

Rounds 2 and 3 left a list of follow-ups; **round 4** (Geb's path B answers, round 4,
2026-11-09, read at `fdf804d`) answered nearly all of them. Four of our readings would have forked
us and are fixed (Q1 walk, Q2 `selfHeal`, Q6 removes, Q7 signed leaves).

Answered and confirmed (no longer UNVERIFIED):

- Geb's OpenMLS 0.8.2 is stock from crates.io, no `[patch]` (Q19).
- Root and admin are an exact DID compare; persona cards widen the match only for a person's own leave, the devices a signed leave covers and direct-room
  adds (Q4).
- A heal needs the same DID and a valid binding if present; the new key is not compared (Q3).
  Whether OpenMLS 0.8.2 itself accepts a new key in an update path is unconfirmed.
- A DID removed in the same commit still counts as seated for `unboundClaim` (Q5).
- An unacked frame never blocks the ratchet; ack-and-ignore is safe except for `leave` (Q7).
- An `rs` with no valid status body is dropped (Q8); ours carries the body now.
- `rc`'s `e` is the from-epoch; `forkMineWins` and `askReseat` as in round 4 Q9 (built). After a
  re-seat each device re-posts its own dead-branch lines (Q10, built; the `fk` shape is
  UNVERIFIED).
- A KeyPackage lifetime of exactly 84 d + 1 h is not refused (Q15); `kp-low` `n:0` is valid and
  the gen after a loss is theirs + 1 (Q16); the first 16 `kp-stock` entries that pass the filter
  are kept (Q17); `ieee7012Agreed` is a required boolean, value never checked (Q18).
- An over-budget frame goes whole to an `fc:0` peer and is never delivered above the relay's cap;
  no fallback (Q11); no fragment sample yet (Q12).

Still open:

- The live relay limits (Q13, Q14): per-event cap (131,072 in the stale repo copy, 256 KB per
  Geb's record), subscriptions (20 stale, 200 per record), future limit (900 s), NIP-40 handling.
  Geb will read the live config. We plan to 120,000 bytes either way.
- Which of "failed" and "refused" fires for a by-reference commit (both are skipped).
- Geb's "Not decided yet" lists (rounds 3 and 4): OpenMLS 0.8.2 versus 0.9.x; whether 0.5.15 is
  path B 0.1 or 0.2; a compatibility policy; a room member cap and a recommended size for clients
  without fragment joining; bridge and agent room settings; linking a bridge as a person's own
  device; the live relay limits; which of the seven round 4 cases the compatibility run uses and
  whether test switches run on throwaway Geb nodes; a fragmented-frame sample; the fixed transcript
  (Q20, following separately).

Other UNVERIFIED points: the `did:peer` purpose-element order; a few `parsePolicy` details
(`geb/policy.rs`); VRC acceptance by a live Geb in full; the dyad's unstated choices (list at the
top of `geb/dyad.rs`); whether `kp-low` and `seat-check` field types match (read from prose, no
vector); whether the `lv` line's `sg` uses the usual `{v:1, room, author, body}` wrapper; the
settle window's start (local first sight of the earliest commit); the OpenMLS 0.9.x versus 0.8.2
difference (every behaviour Geb quotes for 0.8.2 was checked against 0.9.2 source only; the 0.8.2
source was not available).

### Before any live run

All of these need a person or Geb. None has been done.

1. Settle the remaining open points above with Geb, and build the proper `rs` status body (Geb
   drops ours; it is needed to answer `seat-check` and for fork repair).
2. Implement persona-card intake (Geb's persona code) so the one card-dependent Remove can be
   decided like Geb. Signed leaves are already received. Until then the link halts, persisted, on
   that Remove; every other commit is decided and merged or skipped as Geb does (with `geb-mls`).
3. Run `setup` and `link add` against a real VTA (untested); confirm the printed `pnm` grant text,
   the role name and capability set, and the exportable-key flow.
4. A real-VTA end to end on the sealed tier with an MLS group; a `wss://` and TLS soak; a
   compatibility run against the Geb CLI on a test relay (not Geb's live room).
5. Choose a `vti-secrets` backend (plaintext is for development only).
6. Decide what to do about the not-built list in section 5, in particular `fc` fragments (large-room
   joins fail), `rs` body and re-seat Welcome acceptance, sending a leave, and gap records.
7. Record in the VTI specification's divergence register (Appendix F): `room-host` answers a
   refused create-only put as a bare `taskFailed`, where the specification names
   `rooms/records/put:versionConflict`.
8. Replace the placeholder `room-host` git URL, commit the lock file, and exercise the build against
   published crates.

### Where documents here are stale

- `docs/bridges/geb/plan.md` and the companion notes were written before rounds 2 and 3. Superseded
  details are listed in a note at the top of the plan: the file layout, the task versions
  (`browse/0.3` and `seal/0.2` are now `0.4` and `0.3`), "any `mc` stops the poll" (now only the
  undecidable cases halt, with `geb-mls`), the 65,536-byte event limit (now 120,000), and gap
  records (not built).
- Some source comments (`geb/dyad.rs` `MAX_FRAME_PLAINTEXT`, `geb/event.rs` size doc) still mention
  the old 65,536-byte event size.


## Halt codes

An adapter halt carries a stable `<kind>.<reason>` code (`Error::AdapterHalt`, stored as
`HaltReason::Adapter`). The table is `geb::HALT_CODES`; a census test holds every code written in
the sources to it and holds this section to the table.

| Code | Meaning |
|---|---|
| `geb.undecidable-commit` | A commit can be neither merged nor skipped without a persona card this bridge cannot hold. The link halts, persisted, and stays halted until an operator clears it (`link clear-halt <id> --yes`); clearing makes it read the commit again and it halts again at once if the commit is still undecidable. The detail names the commit's epoch and hash. |
