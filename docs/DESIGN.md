# vti-geb-bridge: design

Status: experimental, `publish = false`. Nothing in this document has been verified against a
live Geb node, a real VTA, a real room host or a real Nostr relay. Every test in this repository
runs offline against test doubles (section 10). Where a claim rests on Geb's written answers
rather than on a vector or a live run, it is marked UNVERIFIED, as in `CLAUDE.md` and in the
`// UNVERIFIED:` comments in the source.

How to read the markers used here:

- **Built**: the code exists and is exercised by an offline test.
- **Not built**: the code does not exist; the consequence is stated.
- **UNVERIFIED**: built from Geb's word or from our own reading, with no vector and no live run to
  confirm it.

This document explains what the crate is and why it is shaped as it is. The rules a contributor
must follow are in `CLAUDE.md`; the original plan and its rationale are in
`docs/geb-bridge-plan.md` and `docs/geb-bridge-companion-notes.md` (both were written inside the
VTI repository, and "the workspace" in them means that repository; some details in them have been
superseded, see the note at the top of the plan and section 11 below).

## 1. Purpose and non-goals

**Purpose.** Carry content both ways between a VTC data room (a Verifiable Trust Infrastructure
room: key/value records on a room host) and a Geb room (an MLS group whose members exchange signed
chat lines over a Nostr relay). The bridge is a member of both rooms. It signs as itself on each
side, and content that crosses it is never presented as verified by the other side.

**Non-goals.**

- Not a general-purpose Geb client. It implements the parts of Geb "path B" a read-and-post room
  member needs, and refuses or ignores the rest (section 5).
- No Geb agreements or CRDT state (Geb says that JSON is not a stable format), and no rooms over
  TSP (Geb has not built it).
- Neither side's cryptography vouches for the other side's members. It cannot.
- No change to any VTI crate. Nothing depends on this crate, and no VTI crate gains Geb code. The
  crate does not depend on `vti-rooms`.
- Not stable. Geb's path B has no versioned specification; this crate pins one reading of it
  (section 5) and will break when Geb does.

**Why a bridge and not a direct join.** Both systems use the MLS ciphersuite
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, which is necessary and not sufficient. A VTI room
holds sealed key/value records, only the owner commits, and the host sequences epochs. A Geb room
holds signed chat lines, any member may commit, and clients hold commits for a settle window. They
differ in admission, transport (Trust Tasks vs Nostr kinds 4177/4178) and signatures (a VTA signing
oracle vs raw Ed25519 over RFC 8785 JCS). Something must hold a leaf in Geb's tree and speak
Geb's framing and settle rule. The VTA does not, so the bridge is a Geb client plus a translation
layer.

## 2. Architecture

The bridge is a separate process (`vti-geb-bridge run`). One link joins one VTC room to one Geb
room; the process supervises every enabled link.

```
                 +-------------------- vti-geb-bridge (one process) --------------------+
                 |                                                                       |
 VTC room host   |  vtc::VtcRoom        pump          geb::GebRoom (ForeignRoom)         |  Nostr relay
 (HTTPS, Trust   |  (RoomSide)  <-->  [per link]  <-->  GebDyad + GebGroup (OpenMLS)    |  (wss, kinds
  Tasks)    <----+--  host.rs         mapping           GebRelay (nostr.rs)             +-> 4177 / 4178)
                 |       ^            store/outbox/       ^                              |
                 |       |            xref/halt            | device keys                  |
                 +-------+-------------------------------- | -----------------------------+
                         | rooms/keys/{browse,read,act,seal}   | exported once at setup
                         v                                     v
                      user's VTA  (room persona never leaves; mints and exports the Geb device keys)
```

What it talks to:

| Peer | Protocol | What for |
|---|---|---|
| The user's VTA | `VtaClient` over REST (`vta-sdk`) with the bridge's own client credential | Read the room as the persona (`rooms/keys/browse/0.4`, `rooms/keys/read/0.2`); produce signed room writes (`rooms/keys/act/0.11`, and `rooms/keys/seal/0.3` with `signAsPrincipal` on the sealed tier); at setup, mint and export the Geb device keys (`keys/export-secret/0.1`) |
| The VTC room host | HTTPS `POST {host_url}/trust-tasks` | Deliver the document the VTA signed, unaltered and unauthenticated, because the host authenticates by the document's proof alone (`vtc::host`). The URL is guarded: https only, and no private ranges unless the operator opted in (`vta_sdk::http` policy). Reads are VTA-side, so nothing is delivered for them |
| A Nostr relay | One websocket per identity (`geb::nostr`), `wss://` only; `ws://` accepted only for `127.0.0.1` (tests) | Geb mailboxes and rooms. The default is `wss://nostr.myceli.al` (`[geb] relay_url`) |

The bridge never reaches Geb "nodes" directly; Geb is the protocol on the relay.

### Module map

Core (default features; names no foreign system):

| Module | Role |
|---|---|
| `foreign.rs` | `ForeignRoom` trait, `RoomCapabilities`, `Cursor`, `JoinState`, `Receipt`, `Posted`: the one seam |
| `model.rs` | `BridgeEvent` (origin, ids, author, text, `EventKind` Post/Supersede/Retract, `Provenance`) |
| `mapping.rs` | Pure: record to event, event to outbound line (quoting, notices, size), foreign event to record (provenance block, fence), deterministic record key, `DedupWindow` |
| `room.rs` | `RoomSide` trait (`browse`, create-only `put`), `MemoryRoom`, the provenance marker |
| `store.rs` | `BridgeStore` trait (cursors, journal, outbox, xref, adapter state), `MemoryStore` |
| `pump.rs` | The per-link pump, written against `ForeignRoom`, `RoomSide`, `BridgeStore` only |
| `halt.rs` | `HaltReason` (persisted), clear confirmation |
| `config.rs` | TOML config, `deny_unknown_fields`, validation |
| `atrest.rs` | XChaCha20-Poly1305 sealing of ratchet and MLS state |
| `loopback.rs` | The second, trivial adapter: an in-memory `ForeignRoom` that keeps the core honest |
| `error.rs` | `Error` (including `Refused`, `UndecidableCommit`, `Unsupported`) |

Geb adapter (`geb/`; everything Geb-specific):

| Module | Role |
|---|---|
| `geb/traits.rs` | `GebRelay`, `GebDyad`, `GebGroup`, `GebCodec`, `GebSigner`: the churn boundary |
| `geb/wire/` | Envelopes (`f`, `ack`, `ml`, `mc`, response, completion), frames (`m`, `g`, `cap`), room plaintext (line `l`), limits |
| `geb/codec.rs` | `GuideCodec`, the pinned reading, behind `GebCodec` |
| `geb/crypto/` | `did_peer`, inbox derivation, `sealed` box, `rendezvous` keys, `pair` AES-GCM seal, `ratchet`, `frame_id`, `line_id`, `leaf` binding, `sign` (`sign_json` over JCS), `kdf` |
| `geb/event.rs` | Nostr event id and BIP-340 signature, kinds 4177/4178, NIP-40 expiry tags |
| `geb/vrc.rs` | The v2 relationship credential |
| `geb/dyad.rs` | `StatefulDyad`: connect-when-apart and ratcheted one-to-one frames, durable |
| `geb/room.rs` | `GebRoom`: the `ForeignRoom` implementation; sealing lines, read-back evidence, inbound path, 7-day dedup |
| `geb/settle.rs`, `geb/policy.rs` | Pure settle queue and `validCommit` / room policy |
| `geb/mls/` | (feature `geb-mls`) `MlsGroupClient`, KeyPackage identity, commit tests, in-process second client `sim.rs` |
| `geb/nostr.rs`, `geb/test_relay.rs` | (feature `geb-live`) live relay client, in-process loopback relay for tests |
| `geb/fake.rs` | In-memory relay and group doubles |

VTC side, operations (feature-gated):

| Module | Feature | Role |
|---|---|---|
| `vtc/mod.rs`, `vtc/host.rs` | `vtc` | `VtcRoom` (`RoomSide` over `VtaClient`), HTTPS delivery, typed error reading |
| `fjall_store.rs` | `vtc` | `FjallStore`, the durable `BridgeStore`; keyspaces `links cursors journal_in outbox_out xref geb_mls ratchets`; journal fsync after each write |
| `custody.rs` | `vtc` | Device key minting and export, `BridgeSecrets` in a `vti-secrets` store |
| `run.rs` | `vtc` | `supervise`: shutdown, backoff, halted-stays-halted, derived health |
| `wiring.rs` | `vtc` + `geb-mls` | `assemble`: builds one link from its parts (used by the binary and by `tests/e2e.rs`) |
| `ops.rs` | `vtc` + `geb-mls` | `geb connect`, `geb stock-kps`, the data behind `status` |
| `cli.rs`, `service.rs`, `main.rs` | `cli` | Setup, link management, `run`, `status`, clap definitions |

### Feature flags

| Feature | Pulls in | Notes |
|---|---|---|
| default | the Geb core (codec, crypto, dyad, settle, policy, `GebRoom`, fakes) and the adapter-neutral core | No VTI crate, no network stack, no MLS. Without `geb-mls` the group is `UnsupportedGroup` and fails closed |
| `vtc` | `vta-sdk`, `vti-common`, `vti-specs`, `trust-tasks-rs`, `reqwest`, `chrono`, `tokio`, `vti-secrets` | `VtcRoom`, `FjallStore`, custody, `run` |
| `geb-live` | `tokio-tungstenite`, `futures-util`, `url`, `tokio` | `NostrRelay`, `TestRelay` |
| `geb-mls` | `openmls` 0.9, `openmls_rust_crypto`, `openmls_basic_credential`, `openmls_traits`, `tls_codec` | `MlsGroupClient`, own provider; no `vti-rooms` |
| `keyring` | `vtc`, `vti-secrets/keyring`, `vta-sdk/keyring` | OS keyring as the secret store |
| `cli` | `vtc`, `geb-live`, `geb-mls`, `clap`, `tracing-subscriber`, `vta-sdk/provision-client`, `vta-sdk/crypto-provider` | The `vti-geb-bridge` binary (`required-features = ["cli"]`) |
| `harness` | `vtc`, `room-host`, `vti-rooms`, `vti-rooms-dtg`, `vtc-client`, `dtg-credentials`, `axum`, `chrono`, `vta-sdk/test-loopback` | For `tests/harness.rs` and `tests/e2e.rs`. Optional, not dev-dependencies, so a default `cargo test` does not compile the room host |

`vti-geb-bridge` depends on published VTI crates by version, except `room-host`, which is not
published (section 10).

## 3. The ForeignRoom seam, and adding another adapter

The pump, mapping, outbox and journal know one foreign interface:

```rust
trait ForeignRoom {
    async fn join(&self)  -> Result<JoinState>;          // Seated | Pending; refusal is Error::Refused
    async fn leave(&self) -> Result<()>;
    async fn poll(&self, after: Option<&Cursor>) -> Result<Vec<Polled>>;  // oldest first; may repeat
    async fn post(&self, event: &BridgeEvent) -> Result<Posted>;          // Receipt + foreign id
    fn identity(&self) -> ForeignIdentity;
    fn capabilities(&self) -> RoomCapabilities;
}
// RoomCapabilities { max_message_bytes, supports_edit, supports_delete,
//                    supports_replies, authors_verifiable }
```

Behaviour that varies by room is chosen from `RoomCapabilities`, never from an adapter's name.
Example: `prepare_outbound` turns a retraction into a notice line when `supports_delete` is false,
and cuts the text to `max_message_bytes`. The `Cursor` is opaque bytes that only the adapter can
read; the core stores and returns it.

`loopback::Loopback` is the second adapter. It supports everything and delivers instantly, and
exists so a core change that quietly assumes Geb fails a test.

To add another MLS ecosystem:

1. Add a module (for example `src/other/`) that implements `ForeignRoom`, with its own transport,
   group and identity code behind its own internal traits, as `geb/` does behind `geb/traits.rs`.
2. Return honest `RoomCapabilities`. If authors cannot be checked, say `Verifiability::None`.
3. Put the adapter's pinning and "fail closed" rules in its own `CLAUDE.md` section.
4. Do not touch `pump`, `mapping`, `store` or `model`. If the new adapter needs them changed, that
   shows the seam is wrong; fix the seam, not the adapter.

Known gaps in the seam: `config.rs` has Geb-named fields (`geb_room_id`, `geb_peers`, the `[geb]`
table), `wiring.rs` and `service.rs` assemble only Geb links, and `store.rs` names the adapter
keyspaces `Links` and `Ratchets`. The core types do not name Geb, but the operational shell does.
A second adapter would need those generalised. The plan's "rule of three" applies: no
configurable framework before a second real adapter shows where the boundary falls.

## 4. Data model and mapping

### 4.1 What crosses

A VTC record is a key/value entry in a room with a version, author persona DID, optional title,
body and timestamp. On the sealed tier the record is sealed outside MLS (ChaCha20-Poly1305 under
an exporter key); the VTA opens it on read. A Geb line is a signed `{t:"l", at, text, re?, sg}`
inside an MLS application message. `BridgeEvent` is the neutral form between them.

```
VTC record ---> record_to_event ---> prepare_outbound ---> post (Geb line "> author wrote:\n...")
Geb line   ---> poll (verify sg) ---> foreign_to_record ---> create-only put (basis "observed")
```

### 4.2 VTC to Geb

- **Quoting the original author.** The line is signed by the bridge's Geb device key, so Geb
  members cannot verify the VTC author. The text is `> <author> wrote:\n<title>\n\n<body>`, with
  the author label stripped of control characters and cut to 200 characters, control characters
  other than newline and tab removed from the body, and the whole text cut to
  `max_message_bytes` (20,000 bytes for Geb, which never exceeds Geb's 20,000 UTF-16 unit limit,
  at the cost of cutting multi-byte text early; `post` itself counts units and refuses over the
  limit).
- **Re-signing is inherent.** Geb verifies lines against a Geb device DID key and cannot check our
  credentials or persona signature. The VTA's signing oracle is domain-separated and will not
  emit a signature Geb accepts. So the bridge is always the signer on the Geb side, and the quoted
  author header is an assertion by the bridge, not evidence.
- **Retractions and supersedes as notice lines.** Geb has no edit, delete or retract on the wire.
  A supersede or a retraction becomes an ordinary signed `{t:"l"}` line. Its text begins with a
  configurable notice (`[links.notices]`; defaults `[update to earlier post {target}]` and
  `[retracted: earlier post {target}]`), and where the original's foreign id is known its `re` is
  that line's derived id (first 32 hex of SHA-256 over `JSON.stringify({g,from,at,text})`,
  `geb::crypto::line_id`). No new message kind is invented. A retraction is a notice only: it
  cannot recall text that Geb members already read.
- **Edit and retraction are decided by the record key, never by `version`.** The host's version is
  room-wide arrival order, not a per-key counter. The xref holds `vtkey:<key>` pointing at the
  `origin_id` of the newest bridged version of that key. A record whose key was bridged before is
  a Supersede of that `origin_id`; otherwise it is a plain Post at any version. A room tombstone
  of a bridged key is a Retract; a tombstone of a key never bridged is ignored.
- **Echo suppression (VTC to Geb).** Records authored by the bridge's own persona, and records
  whose body starts with the provenance marker (` ```vti-bridge-provenance`), are never bridged.
  Records already in the xref are skipped.

### 4.3 Geb to VTC

- A line from a member is read from the room, its `sg` checked against the author's device DID
  key, and written as a create-only record (`expectedVersion: 0`) by the bridge's persona.
- The record `basis` is `"observed"`, never declared or verified. The body begins with a
  provenance block (foreign room id, author device DID, signature result `verified` /
  `unverified` / `unsigned`, original timestamp as claimed, message hash), then the text inside a
  fenced block whose fence is longer than any backtick run in the text. Control characters other
  than newline and tab are removed; text is cut to 80,000 bytes with a marker. A forged or
  unsigned line is still bridged, labelled `UNVERIFIED`. A forged name can therefore appear in a
  quoted author header in text; the provenance block's signature result is what to read.
- The record key is `HMAC-SHA256(link_secret, geb_room_id || msg_hash)` in hex: opaque,
  deterministic, so replay is idempotent.
- **Echo suppression (Geb to VTC).** Events whose author is the bridge's own device DID, or whose
  author is in `[geb] deny_list` (other bridges' device DIDs), are skipped. `GebRoom` also skips
  lines from the bridge's own MLS leaf.
- **Unknown plaintext kinds** (reactions, `wp`, anything newer) are dropped without effect, halt,
  or any log above debug. An `rl` share is never opened, so nothing in it has an effect.

### 4.4 Delivery, dedup and durability

- **At-least-once, deduplicated.** The Geb adapter keeps a seen-set of message hashes
  (SHA-256 of the MLS message bytes, `DedupWindow`) for 7 days plus 300 s, Geb's own rule. It is
  in memory and a restart loses it; the journal and the create-only put on a deterministic key
  make a replay harmless.
- **R1.1: an `Ok` is not delivery.** Geb has no receipts for room posts. `GebRoom::post` publishes
  and then reads the event back from the relay; if it is there the receipt is `Relayed`, else
  `Accepted`. It never returns `Delivered`. `status` shows the time of the last read-back.
- **R2.1: remote first.** Ask "the process dies on the next line, then what?" for each step:
  - VTC to Geb: insert into the outbox (key `link|origin_id`), advance the browse cursor, post,
    then write both xref entries (`vtc:<origin_id>` to the foreign line id, `vtkey:<key>` to the
    `origin_id`) before marking the outbox entry posted. A crash between post and mark re-posts
    the same signed line; Geb's own id dedups it. Unposted outbox entries are retried first on
    the next tick.
  - Geb to VTC: insert into the journal before the put, put create-only, write the xref, and
    advance the foreign cursor only after that. A replay finds the key existing and counts it
    skipped.
  - The Geb relay cursor is the newest delivered `created_at`; reads start 300 s earlier.
- **No retry loops around `VtaClient` calls.** The one rewrite is the sealed put's re-seal at the
  version the host assigned (a different request, at most three seals in total). Retry of the
  relay's transport belongs to `geb::nostr` (capped, jittered reconnect); retry of a tick belongs
  to the supervisor.
- **Typed errors stay typed.** `permissionDenied`, `...:actionNotHeld`, `...:notAMember` and a VTA
  `Forbidden` become `Error::Refused`, which halts the link. A refused create-only put is resolved
  by reading the key back, never by parsing a message (the room host answers a bare `taskFailed`
  where the specification names `rooms/records/put:versionConflict`).

Not built: gap records. The plan proposed a record naming a span lost to relay expiry; nothing
writes one. If the bridge is down for longer than the relay's 7-day expiry, Geb lines in that span
are lost without a trace in the room.

## 5. Geb path B, as implemented

Pinned reading: **path B version `0.1`** (our own label; Geb has not decided whether 0.5.15 is
still 0.1, see section 11) against **Geb release 0.5.15, substrate commit `fdf804d`**
(`geb::PATH_B_VERSION`, `geb::PATH_B_PINNED_COMMIT`, `geb::status_line()`). Round 1 of Geb's
answers was read at release 0.5.14 (release 0.5.14); round 2 and 3 were read at `fdf804d`. The fixture
vectors were generated at release 0.5.14 (round 1) and the round 2 reading (round 2); none at `fdf804d`. The
sources are `Geb's implementer's guide (2026-11-07)` (the implementer's guide, 2026-11-07), and
`Geb's path B answers, round 1`, round 2, round 3; the 0.5.15 paragraphs of round 2 supersede
the guide where they differ. All of this is Geb's word, and none of it is checked against live
Geb.

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
least one leaf, … bound, and there is no policy change). A
path-only self-update carrying the sender's binding (a "heal") is valid and need not keep its key.
At join a Welcome whose … with one unbound, is
refused.

A **Remove** passes (Geb's exact rule, round 4 Q6) when any of: (1) every
removed DID is the sender's person (no persona store here, so the sender's own DID only); (2) every
removed leaf is covered by a held signed leave, with no adds and no policy change; (3) a re-seat:
… change, by any member with a bound
leaf; (4) the sender is root or an admin (exact DID compare, never widened by persona cards) or the
room's policy is v1. Geb **refuses anything else and goes on; it never halts a room.**

**The one deliberate difference.** The bridge holds no persona store (persona-card intake is not
built). A Remove of another DID by a non-root, non-admin sender in a v2 room, with no signed leave
we hold and not a re-seat, is the only commit whose verdict depends on a card: a Geb device holding
a card that links the two DIDs would merge it, and we cannot know. The bridge therefore **halts**
(persisted, `UndecidableCommit`) rather than silently fork. That halt is a bridge-side choice, the
honest alternative to a silent fork; Geb itself refuses and continues. The same halt covers a
direct-room Add of a DID that is not exactly one of the pair.

**Signed leaves (received, never sent).** Ignoring a leave is safe only if the signed room line is
taken (round 4 Q7), or a device with …
leaver that every Geb device merges. The payload is `JCS {t:"leave", v:1, room, by, at}` signed by
the leaver's device DID key. It arrives as a room line `{t:"lv", at, ls, sg}` (the line's `sg` must
verify for its MLS sender, then `ls` for that sender) and as …
… (still acked). The newest leave per signer per room is kept and persisted
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
| Healer duty (electing, committing a re-seat or Remove) | Not built, deliberately: the bridge follows | A fork the bridge wins needs a Geb member to heal the loser; the bridge only marks the loser "asked". The recorded split is in the sealed MLS snapshot, not shown by `status` |
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

## 6. Key custody

Two identities per link, never linked:

1. **The room persona** (`P_b`) is held by the user's VTA in a dedicated context (default
   `geb-bridge`) and never leaves it. The bridge records its DID only; there is deliberately no
   export call for it anywhere in this crate. Room writes go through the VTA (`rooms/keys/act`,
   `rooms/keys/seal` with `signAsPrincipal`), and the MLS leaf for `P_b` stays in the VTA.
2. **The Geb device identity** (`G_b`): the VTA mints two key records in the context (an Ed25519
   key and a separately derived X25519 key), the bridge exports each once
   (`keys/export-secret/0.1`), builds the `did:peer:2` itself, and keeps the secrets only in its
   own `vti-secrets` store (`SecretStore`, one blob, `BridgeSecrets`).

**Why the device keys are exported.** The VTA signing oracle frames its signatures
(`OPAQUE_SIGNING_DOMAIN_V1`) and so cannot produce Geb's raw Ed25519 signature over JCS, and there
is no X25519 ECDH oracle for the dyad's key agreement (inferred, not checked against every VTA
surface). The alternative is Geb-specific signing and ECDH code inside `vta-service`. The cost of
exporting: a compromised bridge leaks keys that act only as its Geb identity. They cannot reach the
seed, the VTA or any VTC credential.

**One device DID and one persona per link.** A shared identity correlates every room it sits in.
It is enforced in `Config::validate` (one persona per link, one Geb room per link) and in the
store.

**The MLS leaf signature key** is a random OpenMLS key, held sealed at rest in `mls-sigkey.enc`.
The leaf binding is signed through `GebSigner`.

**At rest** (`atrest`). The secret store also holds a 32-byte store key. `AtRestKey` derives an
independent key per purpose by HKDF-SHA256. Records are XChaCha20-Poly1305 with a random 24-byte
nonce and the record's own name as associated data, so a blob moved to another record fails to
open. `EncryptedState` wraps a `BridgeStore` for dyad and ratchet state. `SealedFile` holds the MLS
signature key and the OpenMLS key-store snapshot (`mls-state.enc`, `mls-sigkey.enc` under
`<data_dir>/links/<id>/`). The state is saved before a KeyPackage leaves, after joining, before a
sealed line is returned and after a merged commit. Not encrypted: cursors, journal, outbox and
xref (bridged text, not secrets). A process holding the store key in memory can read everything:
this protects disks, not a live compromise. (Some older source comments, such as the schema note
at the top of `geb/dyad.rs`, still say the fjall store does not encrypt; the assembled link wraps
it.)

**Secret-store backend.** The backends are those of `vti-secrets` (the same names and feature
flags the VTA, VTC and witness use, including the OS keyring behind feature `keyring`). The
`config_seed` backend is refused, and an inlined `seed` in `[secrets]` is refused. A plaintext
backend exists in `vti-secrets` and is for development only. `setup` warns when the chosen store
does not survive a restart. Choosing a production backend is an operator task not yet done.

**Orphans.** The mint is two creates and two exports before the secrets are saved. A crash between
them leaves key records at the VTA that nothing references; they cost nothing and are listed under
the context for the operator to revoke. The config is written only after the secrets.

**Grants.** Setup uses an ephemeral setup key with a short-lived admin grant on the context. The
bridge's long-term client credential is then narrowed: the printed grant is
`pnm acl create --did <client> --role initiator --contexts <ctx> --capabilities room-present,room-open`.
UNVERIFIED: the role name `initiator` and this capability set come from the community-rooms guide's
example and have not been checked against a VTA. An AI-agent or mediator consumer kind is refused
`act` and `signAsPrincipal`. Revoking the bridge is removing that ACL entry.

## 7. Security and threat model

The analysis is reasoning, not testing. The residual risk is bounded, not eliminated.

| Threat | What exists in code | What does not |
|---|---|---|
| **Plaintext exposure.** The bridge holds plaintext from both sides; bridged room content is readable by every Geb member, irreversibly | `tier_optin` must be true or the config is refused; `private` tier is refused by `Config::validate`; links start with `enabled = false`; `directions` restricts flow | Nothing re-confirms when Geb membership changes; a retraction is a notice and cannot recall text |
| **Bridge compromise.** Attacker gets the exported Geb keys and the bridge's room role | One identity per link; the persona and seed never leave the VTA; at-rest encryption protects disks; revocation is removing the ACL entry | A live compromise reads everything. Key rotation is manual; `link remove` does not revoke the VTA key records. No tested wss/TLS path |
| **Injection from Geb** into the room (prompt injection aimed at agents, misleading text, oversize or malformed input) | Records are `basis: "observed"` with a provenance block; text is fenced longer than any backtick run; control characters stripped; 80,000-byte cap; no action is triggered by bridged content; unknown kinds dropped | Whether the VTI room's existing content handling is sufficient for hostile text from a stranger-populated room was never checked. Anything that reads the room, especially an agent, must treat bridged records as untrusted |
| **Spoofed attribution** | A Geb line's `sg` is verified against the author's device DID; the result is recorded in the provenance block; unsigned and forged lines are still bridged but labelled `UNVERIFIED`. In the other direction the quoted author is the bridge's assertion | Geb members cannot verify the quoted VTC author. A forged name can appear inside quoted text |
| **Epoch fork** on the Geb side (a wrong commit decision silently drops the bridge from the group) | The settle rule and 0.5.15 `validCommit` rules, Geb's exact removes rule, signed leaves received; never skipping a commit silently; without `geb-mls` every commit refuses; the one card-dependent Remove (and a direct-room add of a non-exact DID) halts the link; `rs` sent and compared, `rc` taken, the fork loser waits and accepts a re-seat Welcome | Persona cards are not implemented (section 8); healer duty is not built, so a split needs a Geb member to heal it. Root and admin are an exact DID compare (confirmed, round 4 Q4) |
| **Echo loops and duplication** | Own-persona and provenance-marker skip on the VTC side; own-DID, own-leaf and `deny_list` skip on the Geb side; xref; create-only deterministic keys | A bridge not listed in `deny_list` and with a different device DID is bridged like any member |
| **Relay availability and 7-day expiry** | Capped jittered reconnect, a startup catch-up read from the 7-day floor, relay manners from round 3 | One relay is the only resting place; no gap record; lines lost during a long outage are not noticed in the room |
| **Unstable upstream** (no versioned spec) | Pinned to one release; unknown envelope, frame and plaintext kinds fail closed or are dropped; Geb-specific shapes sit behind `GebCodec` and the other `geb::traits` | Wire compatibility with Geb's OpenMLS 0.8.2 is inferred. Geb `wire: 2` in release metadata is not a compatibility signal; nothing reads it |
| **Metadata** (the relay sees traffic patterns; the host sees read/write timing) | One identity per link limits correlation | Does not remove it |
| **Another process on the host** | Store opens are exclusive (fjall locks the directory) | No hardening of the data directory beyond what the operator provides |

**Non-negotiables** (each is in code unless marked):

- Owner opt-in per link (`tier_optin`), `private` refused (config validation).
- Minimal role: the persona is admitted as an ordinary member with read and write only; no curate,
  no admin. This is an operator and owner action in the VTC room, not enforced by this crate.
  The ACL grant is narrowed to `room-present` and `room-open` (UNVERIFIED, section 6).
- Fail closed on unknown authority-bearing kinds (unknown envelope or frame kind: error, dropped
  unacked). Unknown group ops without authority are acked and ignored.
- Size limits both sides (section 5, section 4.3).
- Kill switch: see section 9. `link pause` stops a link at the next `run`; stopping the process
  stops everything; removing the bridge's ACL entry at the VTA revokes room access.
- Bridged content is never presented as verified.

## 8. Failure handling

A link can **halt**. A halt is persisted in the link's `halt` cursor, so a restart stays halted
without touching the foreign room. The alert (`security_alert = true` in a `tracing` error) is
raised once, when the halt is recorded; later ticks answer from the record. The supervisor ends
with `End::Halted` and never retries.

| Halt | Cause | Meaning |
|---|---|---|
| `Refused` | Seating refused, our leaf removed by a merged commit, a `permissionDenied` / `actionNotHeld` / `notAMember` or VTA `Forbidden` on the room side, or a Welcome into a direct room | Permanent until the bridge is admitted again |
| `UndecidableCommit` | A Remove of another DID by a non-root, non-admin sender in a v2 room, with no signed leave we hold and not a re-seat; or a direct-room Add of a DID that is not exactly one of the pair. The record names the commit's epoch and hash and says the bridge holds no persona store | A Geb device holding a persona card linking the DIDs would merge it and we cannot know, so neither merging nor skipping is safe. **A deliberate bridge-side choice, the honest alternative to a silent fork: Geb itself refuses such a commit and continues.** A card-free refusal in the same commit wins over the undecidable part |

Commits that are decided without a persona store (ordinary adds, removes by exact-DID root or admin
or in a v1 room, a Remove of the sender's own DID, a Remove covered by a held signed leave,
re-seats, root policy changes, every 0.5.15 bound-leaf refusal) are handled normally, and a
refused one is skipped as Geb skips it. A "pending" seating (an "ask" room) is a state,
not an error: the link idles and re-checks each tick.

Not covered by a halt: too many held commits (`Error::Unsupported` from `hold_commit`), and a build
without `geb-mls` (`UnsupportedGroup` refuses each tick), which fail per tick with backoff.

**What `status` shows.** The pinned Geb reading, then per link: enabled or paused, the browse
version, the foreign cursor (seconds), the outbox depth (journalled, not yet posted), the time of
the last relayed post, and `ok` or `HALTED (<reason>)`.

**Clearing a halt.** `link clear-halt <link>` prints what the halt was, then clears it only with
`--yes`. A `Refused` halt also needs `--i-have-been-readmitted`, a statement by the operator that
the room's members have admitted the bridge again. Clearing does not start the link; `run` does.
Clearing an `UndecidableCommit` makes the link read the commit again, so it halts again at once
unless something changed. Both commands open the link's store, so `run` must be stopped first
(they fail with "the store at ... is in use by another process").

**Recovery notes.**

- A sealed record left at a wrong version by a crash mid-race is not repaired; it is reported as a
  typed read error.
- A restart loses the settle queue (re-read from the relay; the cursor barrier holds the position)
  and the dedup window (the journal covers it).
- After a real fork the bridge asks and waits: a Geb member must commit the re-seat (healer duty is not built). A re-seat Welcome is accepted; if it never comes the bridge asks again with a fresh bound package every 600 s.
- An oversize outbox entry cannot come out of the mapping layer (it cuts at 20,000 bytes), but if
  one existed it would be retried every tick rather than dropped.

**Supervision.** `run::supervise` observes the stop signal at every wait, lets a tick in flight
finish, closes on every exit path, doubles the backoff to a cap with jitter and resets it only after
a healthy session that made a successful tick, and derives health from the time of the last good
tick (no latched flag, R6.2).

## 9. Operations

Build the binary with `--features cli`. All commands take `--config <path>` (default
`config.toml`). The log filter is the `RUST_LOG` environment variable, default `info`; logs go to
stderr via `tracing_subscriber`. Security alerts carry `security_alert = true`.

| Command | What it does | Contacts |
|---|---|---|
| `setup --setup-key-out <path> [--context <ctx>]` | Phase 1: mint an ephemeral setup key, store it (0600), print the grant the operator must apply at the VTA | Nothing |
| `setup --from <setup.toml>` | Phase 2: mint and export device keys for each `[[links]]`, store them, write the config. Refuses to overwrite a config or a non-empty secret store | The VTA |
| `link add --setup-key-file ... --id ... --vtc-room ... --host-did ... --host-url ... --persona ... --geb-room-id ... [--directions] [--tier] [--tier-optin] [--poll-secs] [--display-name]` | Mint this link's keys with a fresh granted setup key, then record the link. Starts paused | The VTA |
| `link list` | One line per link | Nothing |
| `link pause <id>` / `link resume <id>` | Set `enabled` in the config. `resume` does not clear a halt. Only read at the start of `run` | Nothing |
| `link remove <id>` | Drop the link and its secrets. Does not revoke the VTA key records and leaves the link's data directory | Secret store |
| `link clear-halt <id> [--yes] [--i-have-been-readmitted]` | See section 8 | Local store |
| `geb connect --link <id> <did>` | Open a dyad with a Geb member's device DID (waits up to 60 s) and add it to `geb_peers` | The relay |
| `geb stock-kps --link <id>` | Stock KeyPackages with the link's peers; counts as consent to be added | The relay |
| `status [--link <id>]` | Local state, see section 8 | Nothing |
| `run` | Supervise every enabled link until SIGINT or SIGTERM | VTA, host, relay |

Typical order: `setup --setup-key-out`, apply the grant at the VTA, write a setup file,
`setup --from`, apply the printed client grant, `link resume`, `geb connect`, `geb stock-kps`, then
`run`. None of these steps has been executed against a real VTA.

**Config file** (`config.rs`; TOML; every table rejects unknown keys):

```toml
data_dir = "data"                 # relative paths resolve against the config file's directory

[vta]
did = "did:webvh:vta.example"
url = "https://vta.example"       # REST base; needed to run
context = "geb-bridge"            # default

[geb]
relay_url = "wss://nostr.myceli.al"   # default
deny_list = []                    # device DIDs of other bridges whose lines are never bridged

[secrets]                         # the vti-secrets table; no seed, no config_seed
backend = "keyring"

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
host_url = "https://host.example" # required to run; https only (http only for 127.0.0.1)
persona = "did:key:z6Mk..."
geb_room_id = "geb-1"
geb_peers = []                    # added by `geb connect`
directions = "both"               # both | to_foreign | from_foreign
tier = "open"                     # open | attributed; private is refused
tier_optin = true                 # required
poll_secs = 10
enabled = false                   # off by default
display_name = "Ada"              # optional, 1 to 40 characters; bridges are unmarked by default
announce = false                  # one join announcement line, off by default
[links.notices]
update  = "[update to earlier post {target}]"
retract = "[retracted: earlier post {target}]"
```

Per-link state lives under `<data_dir>/links/<link id>/`: `store/` (fjall), `mls-state.enc`,
`mls-sigkey.enc`. The config load reads one file and contacts nothing. Note: there is no
`[geb] settle_ms`; a config that names it is rejected (the error says so). The settle window comes
from the room's own `0xF001` policy (`geb/mls/client.rs`).

## 10. Testing

Run (offline once dependencies are cached; run under `nice -n 10` on a shared machine):

```sh
cargo test                                          # default features
cargo test --features "cli geb-live geb-mls"        # what CI runs
cargo test --features "cli harness geb-live geb-mls"  # also needs room-host, see below
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features "cli geb-live geb-mls" -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs fmt, both clippy lines and the first two test lines, on Rust
1.95.0. The `harness` job is manual (`workflow_dispatch`) because `room-host` cannot resolve.

| Test target | What it shows | What it does not |
|---|---|---|
| Unit tests in `src/` | Pure mapping, config rules, settle queue, `validCommit`, pump behaviour against `Loopback`, `MemoryRoom` and `MemoryStore`, dyad and room behaviour against `FakeRelay`, MLS against `sim.rs` | Anything about real Geb |
| `tests/vectors.rs` (round 1) and `tests/vectors2.rs` (round 2) | Our primitives reproduce, or open, bytes that Geb's own code produced from fixed test keys: inbox and rendezvous derivation, sealed box, ratchet, frame id, leaf binding, `sign_json`, `did:peer`, plus commit hash and settle winner, exporter, signed leaf, persona card, VRC v2. The exporter is re-derived by a test-only RFC 9420 implementation and the persona card by a test-only verifier | Round 1 vectors are from release 0.5.14 and round 2 from the round 2 reading; none is a `fdf804d` output. Randomised values (sealed box, ratchet nonces) are "open this" checks. The MLS room cannot be fixed by Geb's API, so that vector is one real run plus its inputs |
| `tests/geb_live.rs` (`geb-live`) | The dyad runs over a real websocket to the in-process `TestRelay` on 127.0.0.1 | Not a real relay; not `wss://` or TLS |
| `tests/custody.rs`, `tests/cli.rs` | Key minting, export and the CLI against a fake VTA that serves only key create and export (our own reading of those tasks), and the offline binary commands | A real VTA |
| `tests/harness.rs` (`harness`) | A real `room-host` on a TCP port (open tier), real room credentials, `VtcRoom` over a real `VtaClient`, HTTPS delivery, `FjallStore`, the pump, against a loopback foreign room and a fake VTA sink; a kill between every pair of store operations | The VTA is a fake; the sealed tier is only covered by scripted `sealed_*` tests |
| `tests/e2e.rs` (`harness`, `geb-live`, `geb-mls`) | The production assembly (`wiring::assemble`) with fjall, sealed state, the real dyad and `MlsGroupClient`, the real `room-host`, the test relay, and a Geb member played by `sim.rs` | Byte compatibility with real Geb; wss/TLS; a real VTA; a sealed-tier room; a mid-step crash (a "kill" is a drop and reboot between steps); persona cards and signed leaves |

Self-consistency is not interoperability. The second OpenMLS client was written by us from the
guide and the answers, so a shared misreading would pass every test. Only a live compatibility run
against a Geb 0.5.15 build can show wire compatibility, and Geb has said its compatibility-run
invitation "follows separately" (round 3, section 14).

**Known gaps in testing.**

- `room-host` is not published. `Cargo.toml` takes it as an optional git dependency under the
  placeholder URL `https://example.invalid/verifiable-trust-infrastructure.git`, pinned by `rev`.
  Because even optional dependencies must resolve, no lock file can be created for everyone, and
  `Cargo.lock` is git-ignored. For a local or offline run, put an uncommitted `.cargo/config.toml`
  (git-ignored) next to `Cargo.toml` with a `[patch."https://example.invalid/..."]` entry pointing
  `room-host` at a local VTI checkout, and a `[patch.crates-io]` entry for each VTI crate that is
  not in the cargo cache. The real URL has to replace the placeholder before the harness can run
  in CI.
- The dependencies on published VTI crates (`vta-sdk`, `vti-common`, `vti-secrets`, `vti-specs`,
  `vtc-client`, `vti-rooms`, `vti-rooms-dtg`, and others) have only been built here against local
  path overrides; building against the crates published on crates.io has not been exercised.
- No test reaches a real relay, Geb node, VTA or room host. The `wss://` path is exercised by no
  test.

## 11. Open questions and the pre-live-run checklist

### Open questions for Geb

Rounds 2 and 3 left a list of follow-ups; **round 4** (`Geb's path B answers, round 4`,
2026-11-09, read at `fdf804d`) answered nearly all of them. Four of our readings would have forked
us and are fixed (Q1 walk, Q2 `selfHeal`, Q6 removes, Q7 signed leaves).

Answered and confirmed (no longer UNVERIFIED):

- Geb's OpenMLS 0.8.2 is stock from crates.io, no `[patch]` (Q19).
- Root and admin are an exact DID compare; persona cards widen only …
  … (Q4).
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

- `docs/geb-bridge-plan.md` and the companion notes were written before rounds 2 and 3. Superseded
  details are listed in a note at the top of the plan: the file layout, the task versions
  (`browse/0.3` and `seal/0.2` are now `0.4` and `0.3`), "any `mc` stops the poll" (now only the
  undecidable cases halt, with `geb-mls`), the 65,536-byte event limit (now 120,000), and gap
  records (not built).
- Some source comments (`geb/dyad.rs` `MAX_FRAME_PLAINTEXT`, `geb/event.rs` size doc) still mention
  the old 65,536-byte event size.

## 12. Glossary

- **VTI**: Verifiable Trust Infrastructure, the workspace and specification this bridge sits beside.
- **VTC**: Verifiable Trust Community service; here, the community whose data room is bridged.
- **VTA**: Verifiable Trust Agent; the user's own agent holding keys and credentials. Holds the room
  persona and mints the Geb device keys.
- **room-host**: the service that stores a data room's records and sequences them. A service binary,
  not published.
- **Data room**: a VTI room of key/value records, in tiers (`open`, `attributed`, `private`).
- **Persona**: the DID the bridge acts as inside the VTC room; held by the VTA, never exported.
- **VMC / VAC**: credentials the room itself issues to a member: the VMC proves membership and the
  VAC states what the holder may do (read and write only, for the bridge).
- **Trust Task**: a typed, signed VTI request/response document; room operations are Trust Tasks
  (`rooms/keys/*`). Geb is a foreign-protocol interface and is not.
- **Geb**: the messaging system on the other side. **Path B** is Geb's name for its route that
  speaks MLS rooms over Nostr (as opposed to the TSP path); it has no versioned specification.
- **Dyad**: a pair of Geb devices with an established relationship (VRCs exchanged, ratchets
  running); the channel on which KeyPackages and Welcomes travel.
- **VRC**: verifiable relationship credential, exchanged in connect-when-apart.
- **KeyPackage**: an MLS object that lets a member be added to a group. Here always bound
  (leaf extension `0xF002`) and given in stocks of 6 (`kp-stock`).
- **Welcome**: the MLS message that brings a new member into a group, carrying the ratchet tree.
- **Settle**: Geb's rule that commits are held for a window and the lowest SHA-256 among those for
  one parent epoch that passes `validCommit` wins.
- **Leaf binding**: the `0xF002` LeafNode extension tying an MLS leaf key to a device DID by a
  signature from that DID.
- **Persona card**: Geb's record that two devices belong to one person; local knowledge needed to
  decide some commits. Not to be confused with the bridge's VTC persona.
- **Signed leave**: Geb's `{t:"lv", at, ls}` plaintext (and dyad `leave` frame), by which a person
  leaves a room. The bridge receives them and never sends one.
- **Echo suppression**: not re-bridging what the bridge itself wrote.
- **Xref**: the store's cross-reference between origin ids and foreign line ids.
- **Halt**: a persisted stop of a link (`Refused` or `UndecidableCommit`).
