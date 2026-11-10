# openvti-bridges: core design

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

This document explains what the core and the shell are and why they are shaped as they are; the Geb
adapter is in [`bridges/geb.md`](bridges/geb.md). The rules a contributor must follow are in the
`CLAUDE.md` of each crate; the original plan and its rationale are in
`docs/bridges/geb/plan.md` and `docs/bridges/geb/companion-notes.md` (both were written inside the
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

The bridge is a separate process (`openvti-bridges run`). One link joins one VTC room to one Geb
room; the process supervises every link (a paused one idles).

```
                 +-------------------- openvti-bridges (one process) --------------------+
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
| `fjall_store.rs` | `vtc` | `FjallStore`, the durable `BridgeStore`; keyspaces `links cursors journal_in outbox_out xref geb_mls ratchets outbox_pending retention`; journal fsync after each write; the pending index and the day-bucketed retention schedule (section 8, Retention) |
| `custody.rs` | `vtc` | Device key minting and export, `BridgeSecrets` in a `vti-secrets` store |
| `run.rs` | `vtc` | `supervise`: shutdown, backoff, halted-stays-halted, derived health |
| `wiring.rs` | `vtc` + `geb-mls` | `assemble`: builds one link from its parts (used by the binary and by `tests/e2e.rs`) |
| `ops.rs` | `vtc` + `geb-mls` | `bridge geb connect`, `bridge geb stock-kps`, the data behind `status` |
| `cli.rs`, `service.rs`, `main.rs` | `cli` | Setup, link management, `run`, `status`, clap definitions |

### Feature flags

| Feature | Pulls in | Notes |
|---|---|---|
| default | the Geb core (codec, crypto, dyad, settle, policy, `GebRoom`, fakes) and the adapter-neutral core | No VTI crate, no network stack, no MLS. Without `geb-mls` the group is `UnsupportedGroup` and fails closed |
| `vtc` | `vta-sdk`, `vti-common`, `vti-specs`, `trust-tasks-rs`, `reqwest`, `chrono`, `tokio`, `vti-secrets` | `VtcRoom`, `FjallStore`, custody, `run` |
| `geb-live` | `tokio-tungstenite`, `futures-util`, `url`, `tokio` | `NostrRelay`, `TestRelay` |
| `geb-mls` | `openmls` 0.9, `openmls_rust_crypto`, `openmls_basic_credential`, `openmls_traits`, `tls_codec` | `MlsGroupClient`, own provider; no `vti-rooms` |
| `keyring` | `vtc`, `vti-secrets/keyring`, `vta-sdk/keyring` | OS keyring as the secret store |
| `cli` | `vtc`, `geb-live`, `geb-mls`, `clap`, `tracing-subscriber`, `vta-sdk/provision-client`, `vta-sdk/crypto-provider` | The `openvti-bridges` binary (`required-features = ["cli"]`) |
| `harness` | `vtc`, `vta-sdk/test-loopback` | Test support: loopback host delivery, the in-process MLS `sim`, the loopback sink for `tests/custody.rs` and `tests/cli.rs`. No room host: the real-`room-host` tests are the separate `harness/` package |

`openvti-bridges` depends on published VTI crates by version. `room-host` is not published; only the
separate `harness/` package takes it, by git (section 10).

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
// RoomCapabilities { max_message_units, supports_edit, supports_delete,
//                    supports_replies, authors_verifiable }
```

Behaviour that varies by room is chosen from `RoomCapabilities`, never from an adapter's name.
Example: `prepare_outbound` turns a retraction into a notice line when `supports_delete` is false,
and cuts the text to `max_message_units`. The `Cursor` is opaque bytes that only the adapter can
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
VTC record ---> record_to_event ---> prepare_outbound ---> post (Geb line "author wrote:\n> ...")
Geb line   ---> poll (verify sg) ---> foreign_to_record ---> create-only put (basis "observed")
```

### 4.2 VTC to Geb

- **Quoting the original author.** The line is signed by the bridge's Geb device key, so Geb
  members cannot verify the VTC author. The text is `<author> wrote:` on its own,
  unquoted first line, then the title and body with EVERY line quoted (`> ` prefix, `>` for an empty
  line), so a VTC member cannot write a second, convincing header: any line they write starts with
  `>`. UNVERIFIED: how Geb clients render the quote (the format is the bridge's own; Geb's
  vectors do not fix it). Untrusted text from both directions goes through `mapping::strip_controls`:
  CRLF, bare CR, NEL, VT, FF, U+2028 and U+2029 become newlines (before quoting), other control
  characters (except newline and tab) and every Unicode format character (Cf: bidi overrides and
  isolates, zero-width space/joiners, BOM, tag characters) are removed (this splits joined emoji
  sequences; accepted). The author label is stripped likewise and cut to 200 characters. The
  transformed text, quote prefixes included, is cut to
  `max_message_units`: UTF-16 code units (JavaScript string length; an emoji counts 2), 20,000
  for Geb. `mapping::truncate_utf16` cuts at a char boundary, never over the limit, and ends with a
  `[truncated]` marker inside it (earlier versions counted bytes and so cut multi-byte text at
  half the limit or less). `post` counts units too and refuses over the limit.
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
  author is in the link's `deny_authors` (other bridges' device DIDs), are skipped. `GebRoom` also skips
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

Moved: the Geb wire, state machines and what is built and not built are in
[`bridges/geb.md`](bridges/geb.md). Nothing in this document depends on them.

## 6. Key custody

Two identities per link, never linked:

1. **The room persona** (`P_b`) is held by the user's VTA in a dedicated context (default
   `openvti-bridges`) and never leaves it. The bridge records its DID only; there is deliberately no
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
sealed line is returned and after a merged commit. `EncryptedState` also seals the **text, title and
author of every journal and outbox event** (purpose `state`, AAD `journal|outbox/<link>/<key>`), so
bridged message text is not on disk in clear. **In clear, exactly:** the events' `origin`,
`origin_id`, `link`, `at`, `kind`, `reply_to`, `record_key` and `provenance` (ids, a timestamp, the
foreign room and device ids, the message hash; no message text); the outbox receipt rank and retired
flag; the xref (`vtc:`, `vtkey:`, `foreign:` and `failed:` keys, holding ids, foreign line ids and
failure reasons that may quote an error message); the cursors; the retention index; and fjall's own
file metadata. Rows written by an earlier version are plaintext and are read as they are until
pruned. Sealing gives confidentiality, not protection against whole-row replacement or rollback.
`status` counts pending entries from the outbox index without opening any body, so it needs no key.
A process holding the store key in memory can read everything: this protects disks, not a live
compromise. (Some older source comments, such as the schema note
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
| **Echo loops and duplication** | Own-persona and provenance-marker skip on the VTC side; own-DID, own-leaf and `deny_authors` skip on the Geb side; xref; create-only deterministic keys | A bridge not listed in `deny_authors` and with a different device DID is bridged like any member |
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
- Kill switch: see section 9. `link pause` stops a RUNNING link within one poll interval (the
  running process re-reads the flag, `pause.rs`); stopping the process stops everything; removing the bridge's ACL entry at the VTA revokes room access.
- Bridged content is never presented as verified.

## 8. Failure handling

A link can **halt**. A halt is persisted in the link's `halt` cursor, so a restart stays halted
without touching the foreign room. The alert (`security_alert = true` in a `tracing` error) is
raised once, when the halt is recorded; later ticks answer from the record. The supervisor ends
with `End::Halted` and never retries.

| Halt | Cause | Meaning |
|---|---|---|
| `Refused` | Seating refused, our leaf removed by a merged commit, a `permissionDenied` / `actionNotHeld` / `notAMember` from the Geb room, or a Welcome into a direct room | Permanent until the bridge is admitted again |
| `VtcRefused` | The VTA or the room host refused the bridge's own write or read (an ACL or room-membership refusal, not Geb's doing) | Permanent until the grant is fixed. Fix the bridge's ACL grant or room membership at the VTA (the grant `link add` printed), then `link clear-halt <id> --yes` (no `--i-have-been-readmitted`: Geb did not remove the bridge) |
| `UndecidableCommit` | A Remove of another DID by a non-root, non-admin sender in a v2 room, with no signed leave we hold and not a re-seat; or a direct-room Add of a DID that is not exactly one of the pair. The record names the commit's epoch and hash and says the bridge holds no persona store | A Geb device holding a persona card linking the DIDs would merge it and we cannot know, so neither merging nor skipping is safe. **A deliberate bridge-side choice, the honest alternative to a silent fork: Geb itself refuses such a commit and continues.** A card-free refusal in the same commit wins over the undecidable part |

Commits that are decided without a persona store (ordinary adds, removes by exact-DID root or admin
or in a v1 room, a Remove of the sender's own DID, a Remove covered by a held signed leave,
re-seats, root policy changes, every 0.5.15 bound-leaf refusal) are handled normally, and a
refused one is skipped as Geb skips it. A "pending" seating (an "ask" room) is a state,
not an error: the link idles and re-checks each tick.

Not covered by a halt: a build without `geb-mls` (`UnsupportedGroup` refuses each tick), which fails
per tick with backoff. Held commits no longer fail a poll: an `mc`'s `e` and bytes are unauthenticated,
so a commit more than 8 epochs ahead is dropped, at most 64 ahead of us are held, at 256 held a failed
one is evicted else the newcomer is dropped (logged, never an error), and only commits from our own
epoch hold the read cursor. A commit with content the check is not described for is refused and
skipped, not a halt (UNVERIFIED against Geb).

**What `status` shows.** The pinned Geb reading, then per link: `enabled` or `PAUSED`, the browse
version, the foreign cursor (seconds), the outbox depth (journalled, not yet posted or retired), the time of
the last relayed post, and `ok` or `HALTED (<reason>)`. When the Geb room has split, a second line
shows the **fork marker** (`geb/forkmark.rs`): state (`waiting-for-reseat` when our branch lost,
`branch-won`, or `reseated` once a re-seat Welcome was accepted), the fork epoch, our and their
epochs at detection and the times. The split itself lives in the sealed MLS snapshot, which `status`
cannot open, so the client mirrors a minimal record in the store's `fork` cursor, unsealed like the
halt record, written when the split is recorded and moved to `reseated` when the Welcome is
accepted. It holds numbers and names only: no key, no plaintext, no commit bytes, no peer identity.

**Kill switch (`link pause` / `link resume`, `pause.rs`).** `link pause` sets `enabled = false` in
the config file (an atomic replace). The store is locked by the running process, so the config is
the one channel a second process can write; `run` re-reads it: `ConfigFilePause` reads and
validates the file and looks at the link's `enabled` on every check, with no cache and no mtime
test (a same-size edit within a clock tick would be missed). **Fail-safe:** anything but a clean
read of `enabled = true` (file missing, unparsable, invalid, link no longer named) is PAUSED, and
the log says why. A broken config therefore pauses a running bridge.

- *Latency.* The pump checks before every outbound post and before every write into the VTC room,
  and the supervisor before every session start and tick. A pause therefore stops posting at the
  next step, which is within one tick; an idle link notices within its `poll_secs`. The message
  `link pause` prints states this with the link's own interval.
- *`bridge geb connect` and `bridge geb stock-kps` obey the same switch*: a paused link (or a config that cannot be
  read, which counts as paused) or a persisted halt makes them refuse before any keys are loaded or
  anything is sent, naming the cause.
- *A paused link* posts nothing to Geb and writes nothing into the room; the tick does not poll
  (so it answers no fork, `rs` or `seat-ask` traffic, sends no frame, and acks nothing); no cursor
  moves; the outbox, journal and xref stay as they were. The process and its connections stay
  alive. It is not a failure: no backoff, no health alert beyond the last good tick ageing.
- *In-flight work.* A step that has begun finishes (one post with its xref and outbox mark; one
  room write): the pump is crash-safe, and a half-posted line is wasted work. A pause between the
  outbox journal and the post leaves the entry unposted in the outbox; the first tick after a
  resume posts it, exactly once. A pause in the middle of an inbound batch leaves the cursor at
  the last handled event; the rest is offered again (the poll may return events at or before the
  cursor and the create-only write dedups).
- *Resume* continues from the preserved cursors with no loss and no duplicate. The supervisor
  starts the session again (the join is idempotent) and ticks.
- *Caveat of a long pause.* Nothing is read from Geb meanwhile. Geb keeps an unacked frame for at
  most 15 minutes, 256 frames or 2 MB (round 4 Q7), and a room can commit meanwhile, so after a
  long pause the bridge may find itself behind the room's epoch; the existing catch-up (`rc`,
  re-seat) deals with that after the resume, and a bridge that was removed meanwhile halts as
  usual. Pausing is the kill switch, not a way to hold a place in the room.
- `run` supervises paused links too (idle), so a `link resume` needs no restart. A paused link
  whose parts cannot be built (no keys) is skipped with a warning; restart `run` after fixing it.
  A `run` started by a build without this mechanism does not read the flag; stop it.
- Tests: `pump::tests::a_pause_*`, `run::tests::link_pause_in_the_config_*` (the supervisor, a
  real pump and the config switch over the loopback adapter), `pause::tests`.

**Clearing a halt.** `link clear-halt <link>` prints what the halt was, then clears it only with
`--yes`. A `Refused` (Geb-side) halt also needs `--i-have-been-readmitted`, a statement by the operator that
the room's members have admitted the bridge again. A `VtcRefused` halt needs `--yes` only; the message tells the operator to fix the ACL grant or room membership at the VTA first. Clearing does not start the link; `run` does.
Clearing an `UndecidableCommit` makes the link read the commit again, so it halts again at once
unless something changed. Both commands open the link's store, so `run` must be stopped first
(they fail with "the store at ... is in use by another process").

**Recovery notes.**

- A sealed record left at a wrong version (a put that ran out of its 3 re-seal attempts, or a crash
  mid-race) is continued from the version the host reports: the next create-only put conflicts, the
  record does not open, and it is rewritten as an update over `currentVersion`.
- A failure that cannot pass (a non-retryable room error such as a key collision, a line that cannot
  be encoded, a record the persona can never read) is dead-lettered: xref `failed:...` with the
  reason, counted (`status` shows `dead_lettered`), and the cursor passes it. Retryable errors stop
  the tick and resume; the two directions run independently, so a stuck one does not starve the other.
- Unacked dyad frames are capped (256 unacked, or a 256-counter span from the oldest): beyond it
  sending to that peer stops with `PEER_BEHIND` and nothing is dropped. Unposted or unacked frames
  are reposted in counter order from the service loop (3 s, then every 60 s until 15 min).
- A replacing Welcome while seated is accepted only when a re-seat is expected (re-seating, a split
  we lost, a lost copy, or a recent `seat-ask` of ours), and not from a lower epoch unless we lost a
  split or our copy; otherwise it is ignored and logged. Signed leaves are kept only for seated signers
  and pruned on removal (UNVERIFIED against Geb).
- A restart loses the settle queue (re-read from the relay; the cursor barrier holds the position)
  and the dedup window (the journal covers it).
- After a real fork the bridge asks and waits: a Geb member must commit the re-seat (healer duty is not built). A re-seat Welcome is accepted; if it never comes the bridge asks again with a fresh bound package every 600 s.
- **Retention and pruning (P1-4).** Nothing the bridge keeps grows without bound. A tick reads only
  the `outbox_pending` index (entries not yet posted or retired), written before the outbox row and
  removed after it is marked, so a crash leaves at worst a stale index entry that the next read
  removes; a store from before the index is indexed once on first use (guarded by a cursor flag).
  Per link, `retention_days` (default 7, at least 1; it matches Geb's seven-day relay retention) sets
  how long the following are kept before `prune` deletes them, run by the pump at most hourly and
  scheduled in day buckets so only days since a persisted floor are scanned: journal rows; outbox
  rows whose remote effect is confirmed (any receipt) or that were retired (dead-lettered); and the
  `foreign:` and `failed:` xref keys. **Never pruned:** an unposted outbox row (re-checked at delete
  time, whatever the schedule says), the `vtc:` and `vtkey:` xref keys (no plaintext; they stop a
  lost browse cursor re-bridging and resolve edits and retractions), the cursors, counters and halt
  record. A store that predates the schedule ages its old rows out one retention period after the
  upgrade. A dead-lettered entry is retired when its `failed:` record is written; once both are
  pruned, a replayed record that was never posted would be attempted (and refused) again.
- **Fetch paging.** A catch-up read stopping at `MAX_FETCH_EVENTS` (5,000) is continued with `until`
  and merged by id, up to `MAX_FETCH_PAGES` (20) reads; beyond that, or when `until` cannot move,
  the read is an error ("more than 20 pages ... not returning a partial result") and the caller's
  cursor is unchanged. A truncated result is never returned as complete, and every `REQ` is closed on
  every exit.
- An oversize outbox entry cannot come out of the mapping layer (it cuts at the room's unit limit),
  but one journalled under another limit could exist. It is a permanent failure: journalled
  (xref `failed:<outbox key>` with the reason), counted (`status` shows `oversize_failed`), logged
  once, never retried, retired (so no longer pending or counted in `outbox_depth`) and pruned after retention; the entries behind it still go out.

**Supervision.** `run::supervise` observes the stop signal at every wait, lets a tick in flight
finish, closes on every exit path, doubles the backoff to a cap with jitter and resets it only after
a healthy session that made a successful tick, and derives health from the time of the last good
tick (no latched flag, R6.2).

## 9. Operations

Build the binary with `cargo build -p openvti-bridges`. All commands take `--config <path>` (default
`config.toml`). The log filter is the `RUST_LOG` environment variable, default `info`; logs go to
stderr via `tracing_subscriber`. Security alerts carry `security_alert = true`.

| Command | What it does | Contacts |
|---|---|---|
| `setup --setup-key-out <path> [--context <ctx>]` | Phase 1: mint an ephemeral setup key, store it (0600), print the grant the operator must apply at the VTA | Nothing |
| `setup --from <setup.toml>` | Phase 2: mint and export device keys for each `[[links]]`, store them, write the config. Refuses to overwrite a config or a non-empty secret store | The VTA |
| `link add --setup-key-file ... --id ... --vtc-room ... --host-did ... --host-url ... --persona ... --geb-room-id ... --directions <to_foreign|from_foreign|both> [--tier] [--tier-optin] [--poll-secs] [--display-name]` | Mint this link's keys with a fresh granted setup key, then record the link. Starts paused | The VTA |
| `link list` | One line per link | Nothing |
| `link pause <id>` / `link resume <id>` | Set `enabled` in the config and print what a running process will do and how soon. `resume` does not clear a halt. A running `run` re-reads the flag (below) | Nothing |
| `link remove <id>` | Drop the link and its secrets. Does not revoke the VTA key records and leaves the link's data directory | Secret store |
| `link clear-halt <id> [--yes] [--i-have-been-readmitted]` | See section 8 | Local store |
| `bridge geb connect --link <id> <did>` | Open a dyad with a Geb member's device DID (waits up to 60 s) and add it to `geb_peers` | The relay |
| `bridge geb stock-kps --link <id>` | Stock KeyPackages with the link's peers; counts as consent to be added | The relay |
| `status [--link <id>]` | Local state, see section 8 | Nothing |
| `run` | Supervise every link until SIGINT or SIGTERM; a paused link idles | VTA, host, relay |

Typical order: `setup --setup-key-out`, apply the grant at the VTA, write a setup file,
`setup --from`, apply the printed client grant, `link resume`, `bridge geb connect`, `bridge geb stock-kps`, then
`run`. None of these steps has been executed against a real VTA.

**Config file** (`config.rs`; TOML; every table rejects unknown keys):

```toml
data_dir = "data"                 # relative paths resolve against the config file's directory

[vta]
did = "did:webvh:vta.example"
url = "https://vta.example"       # REST base; needed to run
context = "openvti-bridges"            # default

[geb]
relay_url = "wss://nostr.myceli.al"   # default

# per link: deny_authors = []     # foreign author ids (other bridges' device DIDs) never bridged

[secrets]                         # the vti-secrets table; no seed, no config_seed
backend = "keyring"

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
host_url = "https://host.example" # required to run; https only (http only for 127.0.0.1)
persona = "did:key:z6Mk..."
geb_room_id = "geb-1"
geb_peers = []                    # added by `bridge geb connect`
directions = "both"               # required, no default (absence is refused): both | to_foreign | from_foreign
tier = "open"                     # open | attributed; private is refused
tier_optin = true                 # required
poll_secs = 10
enabled = false                   # off by default
display_name = "Ada"              # optional, 1 to 40 characters; bridges are unmarked by default
announce = false                  # one join announcement line, off by default
retention_days = 7                # days before posted/journal/expiring-xref rows are pruned; >= 1
[links.notices]
update  = "[update to earlier post {target}]"
retract = "[retracted: earlier post {target}]"
```

Per-link state lives under `<data_dir>/links/<link id>/`: `store/` (fjall), `mls-state.enc`,
`mls-sigkey.enc`. The config load reads one file and contacts nothing. The config file is written
mode `0600`, replaced atomically and fsynced (file and directory); every read-modify-write
(`link add`, `link pause`, ...) holds an exclusive lock on `<config>.lock` (also `0600`, kept beside
the config) around the read and the write, never across a network call. The lock is an OS advisory
lock: it serialises commands on one host; on a filesystem that does not honour it (some network
filesystems) it does not, and that is UNVERIFIED. Note: there is no
`[geb] settle_ms`; a config that names it is rejected (the error says so). The settle window comes
from the room's own `0xF001` policy (`geb/mls/client.rs`).

## 10. Testing

Run (offline once dependencies are cached; run under `nice -n 10` on a shared machine):

```sh
cargo test -p openvti-bridge-core                  # the neutral core alone
cargo test --workspace --no-fail-fast
cargo test --workspace --features harness            # adds tests/custody.rs and tests/cli.rs
(cd harness && cargo test)                          # real room-host: manual, see below
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features harness -- -D warnings
```

CI (`.github/workflows/ci.yml`), on Rust 1.95.0, is configured to run: fmt; clippy and tests for the
default features, `geb-live geb-mls` (now `live mls` on `openvti-bridge-geb`) and `cli harness geb-live geb-mls`; `cargo deny check`; and,
on pull requests, a check that every commit has a `Signed-off-by` trailer. It generates `Cargo.lock`
first because none is committed. **None of this has run**: the repository has no remote yet. The
`harness/` package (real `room-host`) is a manual job (`workflow_dispatch`) that cannot pass until
its placeholder git URL is real.

| Test target | What it shows | What it does not |
|---|---|---|
| Unit tests in `src/` | Pure mapping, config rules, settle queue, `validCommit`, pump behaviour against `Loopback`, `MemoryRoom` and `MemoryStore`, dyad and room behaviour against `FakeRelay`, MLS against `sim.rs` | Anything about real Geb |
| `tests/vectors.rs` (round 1) and `tests/vectors2.rs` (round 2) | Our primitives reproduce, or open, bytes that Geb's own code produced from fixed test keys: inbox and rendezvous derivation, sealed box, ratchet, frame id, leaf binding, `sign_json`, `did:peer`, plus commit hash and settle winner, exporter, signed leaf, persona card, VRC v2. The exporter is re-derived by a test-only RFC 9420 implementation and the persona card by a test-only verifier | Round 1 vectors are from release 0.5.14 and round 2 from the round 2 reading; none is a `fdf804d` output. Randomised values (sealed box, ratchet nonces) are "open this" checks. The MLS room cannot be fixed by Geb's API, so that vector is one real run plus its inputs |
| `tests/geb_live.rs` (`geb-live`) | The dyad runs over a real websocket to the in-process `TestRelay` on 127.0.0.1 | Not a real relay; not `wss://` or TLS |
| `tests/custody.rs`, `tests/cli.rs` (`harness`) | Key minting, export and the CLI against a fake VTA that serves only key create and export (our own reading of those tasks), and the offline binary commands | A real VTA |
| `harness/tests/harness.rs` (separate package) | A real `room-host` on a TCP port (open tier), real room credentials, `VtcRoom` over a real `VtaClient`, HTTPS delivery, `FjallStore`, the pump, against a loopback foreign room and a fake VTA sink; a kill between every pair of store operations | The VTA is a fake; the sealed tier is only covered by scripted `sealed_*` tests |
| `harness/tests/e2e.rs` (separate package) | The production assembly (`wiring::assemble`) with fjall, sealed state, the real dyad and `MlsGroupClient`, the real `room-host`, the test relay, and a Geb member played by `sim.rs` | Byte compatibility with real Geb; wss/TLS; a real VTA; a sealed-tier room; a mid-step crash (a "kill" is a drop and reboot between steps); persona cards and signed leaves |

Self-consistency is not interoperability. The second OpenMLS client was written by us from the
guide and the answers, so a shared misreading would pass every test. Only a live compatibility run
against a Geb 0.5.15 build can show wire compatibility, and Geb has said its compatibility-run
invitation "follows separately" (round 3, section 14).

**Known gaps in testing.**

- `room-host` is not published. `harness/Cargo.toml` takes it as a git dependency under the
  placeholder URL `https://example.invalid/verifiable-trust-infrastructure.git`, pinned by `rev`.
  It lives in a package of its own because cargo resolves even optional dependencies, so in the
  root manifest it broke resolution of this crate (and every CI job but fmt) on a clean checkout.
  For a local or offline run, put an uncommitted `.cargo/config.toml` (git-ignored) in the
  repository root with a `[patch."https://example.invalid/..."]` entry pointing `room-host` at a
  local VTI checkout, and a `[patch.crates-io]` entry for each VTI crate not in the cargo cache.
  The real URL has to replace the placeholder before the harness can run in CI.
- `Cargo.lock` is not committed. A lock made here contains path-patched VTI crates, which is
  wrong for everyone else. Someone with network and no override should run
  `cargo generate-lockfile`, remove `/Cargo.lock` from `.gitignore` and commit it. The VTI crates
  `vta-sdk` 0.85, `vti-common` 0.61, `vti-secrets` 0.34 and `vti-specs` 0.10 resolve from the
  local registry index but their sources are not in the local cache, so they have not been
  built from crates.io, and whether the published `vta-sdk` 0.85 has the `test-loopback`,
  `provision-client` and `crypto-provider` features is unchecked.
- The dependencies on published VTI crates (`vta-sdk`, `vti-common`, `vti-secrets`, `vti-specs`,
  `vtc-client`, `vti-rooms`, `vti-rooms-dtg`, and others) have only been built here against local
  path overrides; building against the crates published on crates.io has not been exercised.
- No test reaches a real relay, Geb node, VTA or room host. The `wss://` path is exercised by no
  test.

## 11. Open questions and the pre-live-run checklist

Geb's open questions and its pre-live-run checklist are in [`bridges/geb.md`](bridges/geb.md), section 11.

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
- **Halt**: a persisted stop of a link (`Refused`, `VtcRefused` or `UndecidableCommit`).

## 13. Upgrading from the pre-restructure state: a clean break

The restructure into `openvti-bridge-core`, `-vtc`, `-geb`, `-conformance` and the shell changed
what is stored and how it is configured, and nothing was deployed, so there is no migration:

- Secret blob `VERSION` 1 became 2 (the core keeps an opaque per-adapter payload; Geb's identity is
  one payload under `geb`). A version 1 blob is refused with a message that says to discard it.
- The at-rest salt is `openvti-bridges/at-rest/v1`; every derived key changed, so old sealed state and
  MLS files do not open.
- Durable state: the keyspaces `links`, `geb_mls` and `ratchets` are replaced by one `adapter_state`
  keyspace keyed `<ns>\0<key>` with `ns` = `<kind>/<name>` (`geb/links`, `geb/ratchets`); records
  are sealed with additional data `state/<link>/<ns>/<key>`. The unsealed fork cursor `fork` is `geb/fork`.
- VTA key labels: `openvti-bridges/geb/<link>/device-*`; context `openvti-bridges`.
- Config: `geb_room_id`/`geb_peers` are `kind = "geb"` plus `[links.geb]`; `[geb]` is `[bridges.geb]`;
  `[geb].deny_list` is `deny_authors` per link (an unknown key, refused).
- CLI: `bridge geb connect|stock-kps` are `bridge geb connect|stock-kps`; `--geb-room-id` is
  `--kind geb --set room_id=`.

Move over by deleting `data/` and the stored secrets, running `setup` again and `link add` for each link.
