> Renamed `vti-geb-bridge` -> `openvti-bridges` and split into crates (core, vtc, geb, shell); the text below is
> the historical plan and keeps its original wording and paths.

> Superseded details (added 2026-11-09, extended 2026-11-09; `docs/core.md` and `docs/bridges/geb.md` are the current state). Where the body
> below disagrees with it, this note wins:
> - File layout (section 3) is the original plan: the code has `cli.rs`, `service.rs`, `run.rs`, `wiring.rs`, `ops.rs`,
>   `custody.rs`, `atrest.rs`, `halt.rs`, `pause.rs` and a `geb/mls/` directory, and no `setup.rs`.
> - Task versions (sections 4 and 6) are `rooms/keys/browse/0.4`, `rooms/keys/read/0.2`, `rooms/keys/act/0.11` and
>   `rooms/keys/seal/0.3`.
> - Section 7's "any `mc` stops the poll" holds only without `geb-mls`; with it only the two undecidable commit kinds
>   halt the link (and Geb itself never halts a room).
> - "Gap" records (section 8) are not built.
> - The event limit is 120,000 bytes to post (131,072 accepted on reading), not 65,536; a line is 20,000 UTF-16 code
>   units, counted as such by the mapping layer (`RoomCapabilities::max_message_units`, was `max_message_bytes`).
> - `[geb] settle_ms` (section 9) no longer exists (a config naming it is rejected); the window comes from the room's
>   0xF001 policy.
> - The kill switch (section 9): `link pause` / `link resume` now take effect on a running `run` (it re-reads the flag
>   from the config; unreadable counts as paused); `status` shows PAUSED, the outbox depth, the oversize-failure
>   count and a fork marker.
> - The Geb pin is release 0.5.15 (`fdf804d`) and answers rounds 1 to 4, not only release 0.5.14.

> Update 2026-11-08: Geb answered the open questions from its code at commit release 0.5.14, now versioned as "path B 0.1" (the pin moved to release 0.5.15, commit `fdf804d`, with round 2 on 2026-11-09)
> (breaking changes are announced in the Geb's announcement channel first). Geb details below are pinned to it. Effects: a retraction
> is an ordinary signed reply line, never a new kind; bridges are welcome by default with no marking; each room will later choose not
> welcome / welcome automatically / ask, and whether to show a mark (same for AI agents), shapes not yet shared; the M3 blocker is now Geb's commit check, which needs persona cards and
> signed leaves held locally (see section 7). Edit and delete are designed but not built.

# Plan: `vti-geb-bridge` — a bidirectional … room

Note: this plan was written inside the VTI repository (a design note) and is kept here as a copy. References to "the workspace", "the VTI repository's root CLAUDE.md" and repository paths (vti-rooms/..., vti-witness/..., docs/...) mean the VTI repository, not this one. Requirement citations (VTI-*) are to the VTI specification.

Status: draft for review. Date: 2026-11-08. Author: BAM session.
Companion: `companion-notes.md` (rationale, threat model, decisions, questions for Geb).

Sources: `Geb's implementer's guide (2026-11-07)` (Geb implementer's guide, code as of 2026-11-07) is the authority for Geb.
VTI facts were checked in this repo by a planning agent. [V] = checked in code, [I] = inferred, not yet checked.

## 1. Goal and non-goals

Goal: a VTC data room controlled through keyring can be joined to a Geb MLS room, with content flowing both ways,
and with no Geb-specific code in any existing crate.

Non-goals (this plan):
- Geb agreements and CRDT state (Geb says the JSON is not a stable format).
- Rooms over TSP (Geb has not built it; if it appears, the transport seam below is where it lands).
- Making either side's cryptography vouch for the other side's members (it cannot; see companion notes).

## 2. Why a bridge and not a direct join

MLS only provides a group key. Everything around it differs between the two systems:

| | VTI rooms | Geb rooms |
|---|---|---|
| Content | key/value records sealed outside MLS (ChaCha20-Poly1305 under an exporter key) | MLS application messages (signed chat lines) |
| Commits | owner only, sequenced by the room host (`rooms/epoch/mint`) | any member; clients hold commits 3 s, lowest SHA-256 wins |
| Admission | VMC + VAC credentials, invitation | Geb dyad relationship, KeyPackage capabilities 0xF001/0xF002 |
| Transport | `rooms/*` Trust Tasks | Nostr kinds 4177/4178, Geb sealing and ratchet |
| Signatures | VTA signing oracle (domain-framed) | raw Ed25519 over RFC 8785 JCS (`sign_json`) |

Same ciphersuite (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) is necessary, not sufficient. Rooms are Geb path B only;
no TSP route to a room exists (guide, "Two paths").

## 3. Architecture

Crate `vti-geb-bridge`, modelled on VTI's `vti-witness`:
- `publish = false`; a standalone repository (originally a non-default member of the VTI workspace); own `CLAUDE.md`.
- Nothing depends on it. No VTI crate gains a Geb line.
- Depends on `vta-sdk`, `vti-common`, `vti-secrets`, `vti-specs`, `trust-tasks-rs`.
- Geb-only deps: `openmls` 0.9 used directly, a Nostr client (behind feature `geb-live`), hkdf / aes-gcm /
  chacha20poly1305 / secp256k1, a JCS canonicaliser.
- Must NOT depend on `vti-rooms`: its ciphersuite constant, storage label and `RoomGroup` are VTI conventions
  (vti-rooms/src/mls.rs:69,76 [V]) and Geb needs different capabilities and extensions.
- Declare the Geb side in crate docs as a foreign-protocol interface (root CLAUDE.md, exceptions to "every remote
  operation is a Trust Task"). The room side stays Trust Tasks.

```
src/
  config.rs    deny_unknown_fields; [[links]], [geb], [vta], [secrets]
  setup.rs     two-phase setup, as vti-witness
  model.rs     BridgeEvent { origin, origin_id, link, author, at, text, kind: Post|Supersede|Retract, provenance }
  foreign.rs   ForeignRoom trait + RoomCapabilities: THE seam the core uses (adapter-agnostic)
  mapping.rs   pure: record <-> BridgeEvent <-> foreign line (no I/O; the conformance target)
  vtc/         RoomSide over VtaClient (browse / read / seal / act, host send)
  geb/         the Geb adapter: GebRoom implements ForeignRoom; everything below is internal to it
    traits.rs  GebRelay, GebDyad, GebGroup, GebCodec, GebSigner   <- the churn boundary
    wire/      envelopes {t:f|ack|ml|mc}, frames {k:m|g|cap}, line {t:l,...,sg}, kp-stock/kp/welcome
    crypto/    inbox derive + sealed box, rendezvous HKDF, AES-GCM pair seal, ratchet, sign_json
    mls.rs     own OpenMLS client: caps 0xF001/0xF002, leaf-binding ext, settle-window resolver
    nostr.rs   relay client (feature geb-live)
    fake.rs    in-memory relay + scripted Geb peer
  store.rs     fjall keyspaces: links, cursors, journal_in, outbox_out, xref, geb_mls, ratchets
  pump.rs      two pumps + supervisor; depends only on ForeignRoom
  loopback.rs  trivial in-memory ForeignRoom (test only): proves the core is adapter-agnostic
```

Top-level seam (adapter-generic): the pump, mapping and outbox/journal depend only on `ForeignRoom`:
join/leave; an inbound poll returning `BridgeEvent`s with an opaque resumable cursor; `post(&BridgeEvent) -> Receipt`
(`Accepted | Relayed | Delivered`; Geb only ever returns `Relayed`); the identity it presents; and
`capabilities() -> RoomCapabilities { max_message_units, supports_edit, supports_delete, supports_replies,
authors_verifiable }`. The core chooses behaviour from capabilities (for example a retraction notice line when delete is
unsupported). A later adapter for another MLS ecosystem implements this trait and nothing else in the core changes.
Adapters stay modules of this one crate until a second real adapter shows where the boundary falls (rule of three:
no configurable framework before then). Per-system trust rules stay in the adapter, which states what it can verify
about its authors.

Geb adapter internals (not seen by the core): `GebCodec` versions every Geb envelope/frame/line shape (Geb path B has no versioned spec);
`GebGroup` hides OpenMLS and the settle rule; `GebRelay` hides Nostr; `GebSigner` hides key custody.

## 4. Identity and key custody

Two identities per link, never linked:

1. Room persona `P_b`. Held by the user's VTA in a dedicated context `geb-bridge`. Never leaves the VTA. All room
   writes go through `rooms/keys/act` and `rooms/keys/seal/0.2` with `signAsPrincipal`; reads through
   `rooms/keys/browse/0.3` and `rooms/keys/read`. The MLS leaf for `P_b` stays in the VTA (existing behaviour).
2. Geb device DID `G_b` = `did:peer:2.A<ed>.V<ed>.E<x>` (same Ed25519 key under .A and .V; separately generated X25519
   under .E; no .S). Keys are minted by the VTA (two key records in the `geb-bridge` context, marked exportable),
   exported once via `keys/export-secret/0.1` [V], and held in the bridge's `vti_secrets` store. The bridge encodes the DID.
   Published only in its own DID (foreign-protocol identity exception, root CLAUDE.md).

Why export: the VTA signing oracle frames signatures (`OPAQUE_SIGNING_DOMAIN_V1`; `ProtocolDefined` is reachable only
inside the VTA — vta-sdk/src/protocols/key_management/sign.rs:57-71 [V]) so it cannot produce Geb's raw JCS signature,
and there is no X25519 ECDH oracle [I]. The alternative puts Geb code in `vta-service`.

3. Geb MLS leaf signature key: random OpenMLS key, stored encrypted in `geb_mls`. Leaf binding ext 0xF002 =
   `sign_json({t:"leaf",v:1,did:G_b,k:hex(mls_sig_pub)})`.

Template gap: no DID template or mint path yields Geb's shape. The VTA did:peer path makes V+E plus a DIDComm `.S`
service (vta-service/src/operations/did_peer.rs:62-82 [V]); the only peer template, `ai-agent-peer`, is DIDComm-only
[V]; nothing reads/writes did:peer:4 [V]. M1 encodes client-side; a generic template-driven did:peer:2 mint is an
optional later upstream change (ask (a)).

Keyring control: grant the bridge's client `did:key` an ACL entry in `geb-bridge` narrowed to
`--capabilities room-present,room-open`. The consumer kind must not be ai-agent or mediator (delegates are refused
`act` and `signAsPrincipal` — data-rooms.md:828-836 [V]). Revoking the bridge = removing that ACL entry.

Recommend one `G_b` and one `P_b` per link (a shared identity correlates every room it sits in).

## 5. Role and policy in the VTC room

- Owner admits `P_b` as an ordinary member (VIC, KeyPackage, Welcome) and issues VMC + VAC conferring read + write only.
  No curate, no admin: the bridge cannot mint epochs, prune or curate others' records.
- One link = one VTC room + one Geb room + one persona.
- Tiers: `open` and `attributed` only with explicit owner opt-in in the link config; `private` refused (not served yet,
  data-rooms.md:81).
- Removal uses existing `rooms/owner/group/remove` and `rooms/owner/revoke`.

## 6. Flows

### VTC -> Geb
1. Poll `rooms/keys/browse/0.3` with `sinceVersion = cursor`; read new records with `rooms/keys/read`.
2. Skip records authored by `P_b`, records carrying the bridge-provenance marker, and records already in `xref`.
3. Map to a Geb line `{t:"l", at, text, re?, sg}`: `text` = quoted header naming the VTC author's persona DID, then
   title and body, truncated to 20,000 chars; `sg` = `G_b` sign_json over `{v:1, room, author:G_b, body}`.
4. Seal as an MLS application message in the current Geb epoch, wrap `{t:"ml"}`, seal with the epoch relay AEAD key,
   post as kind 4177, event <= 120,000 bytes (round 3; it was 65,536).
5. A new version of a record posts a new line with `re` pointing at the earlier line. A retraction posts a notice line
   (Geb has no visible edit/delete).

### Geb -> VTC
1. Fetch kind 4177 by the room pubkey; sort by `created_at`; open `ml` envelopes in epoch order.
2. Hold every `mc` commit for the settle window (3000 ms) and apply the winner (lowest SHA-256 among commits for one
   parent epoch), then check it against room policy.
3. Dedup id = sha256 of the `m` bytes, kept 7 days + 300 s (Geb's own rule).
4. Skip lines from our own leaf and from deny-listed bridge device DIDs.
5. Verify `sg` against the author DID's `.V` key. Unsigned or bad lines are still bridged, marked `unverified`.
6. Write a record: key = HMAC(link_secret, geb_room_id || msg_hash) (opaque, deterministic -> idempotent), author `P_b`,
   `expectedVersion: 0`, `basis: "observed"` (never declared/verified), body with a fenced provenance block (Geb room
   id, author device DID, signature result, original `at`, message hash). Bodies are untrusted; fence and render inert.

Ordering: VTC -> Geb follows host versions; Geb -> VTC follows MLS epoch then relay `created_at`. Host versions record
arrival order at the bridge, not Geb's order; original `at` travels in the body.

Sealed puts: seal for head+1; on conflict re-seal and rewrite (the pnm pattern). If the deterministic key exists, open
it; same author and hash means done.

## 7. MLS on the Geb side

- Own OpenMLS provider and store, suite as above, group id = UTF-8 room id, ratchet tree in the Welcome, BasicCredential
  = `G_b` UTF-8, external joins refused. KeyPackage declares 0xF001 and 0xF002 and carries the binding ext.
- Seating needs a dyad first: connect-when-apart (inbox derive + sealed box, invitation, response, completion, VRCs
  `eddsa-jcs-2022`), then post `kp-stock` (<= 16 KeyPackages, increasing `gen`) or answer `kp-req`, then accept
  `{k:"g",op:"welcome"}`. Never send `cap dm:1`.
- Per-epoch relay keys from the exporter: labels `geb/room/v2/nostr` and `geb/room/v2/aead`, context = room id bytes.
  Resubscribe after every merged commit. … from.
- Geb's commit check (answer 9) walks candidates for one parent epoch in ascending SHA-256 order and tests each with
  `validCommit` before it can win; a failing Commit is dropped and the next is tried. Two inputs are local knowledge:
  persona cards (same-person) and signed leaves (`{t:"lv"}`). A bridge that cannot evaluate them refuses a leave or
  signed-out remove that others accept and forks. So the bridge applies no commit until it implements persona cards and
  signed leaves; until then any `mc` stops the poll. The policy `committer:"owner"` is not enforced by Geb at release 0.5.14.
- Retraction/supersede is an ordinary signed `{t:"l"}` line whose `re` is the original line's derived id (first 32 hex of
  SHA-256 over `JSON.stringify({g,from,at,text})`); today's builds drop unknown kinds, so no new kind.
- Admission is a per-room Geb setting that does not exist yet (not welcome / automatic / ask). The bridge treats a pending
  or refused seat as a distinct join state: refusal or removal stops the link and alerts, no retry. A display name and
  a join announcement are optional config, default off; a signed "bridge" role badge may come later (not implemented).
- The bridge never commits in either group. It must implement the settle rule exactly or its epoch silently forks.

## 8. Delivery, failure, resumption

- R1.1: an `Ok` is not delivery. Geb room posts have no receipts; strongest evidence is reading our own 4177 event back
  from the relay. Record as `relayed`, never `delivered`.
- R2.1 remote-first, with durable stores:
  - VTC -> Geb: insert into `outbox_out` (key `link|key|version`), advance the browse cursor, post, mark `relayed` on
    read-back. Re-posts reuse the same MLS ciphertext so the hash and dedup id are stable.
  - Geb -> VTC: insert into `journal_in` (keyed by msg hash) before advancing the relay cursor (`since = newest - 300`),
    then put, then write `xref`. Replay is safe: the put is create-only on a deterministic key.
- Retry ownership: never wrap `VtaClient` calls in a retry loop (`act`, `seal`, `browse` are RetrySafe — vta-sdk
  retry_safety.rs [V]). The bridge owns retry for the Geb relay domain only: capped backoff with jitter.
  `vti_common::outbox_store` belongs to the messaging layer, not the bridge [V].
- Gaps: Geb mailboxes expire after 7 days. If down longer, write a `gap` record (signed by `P_b`) naming the span.
- Refusals: `permissionDenied` / `actionNotHeld` on the VTC side, or a Geb commit removing our leaf, stops that link and
  raises an alert; no retry. No latched health flags (R6.2).
- Supervision follows vti-witness (graceful shutdown on every error path, minimum healthy session, one socket per DID).

## 9. Config and operations

- Two-phase setup like vti-witness: `vti-geb-bridge setup --setup-key-out`, a pnm or keyring grant, then `setup --from`.
- `[[links]]`: `vtc_room`, `host_did`, `persona`, `geb_room_id`, `directions`, `tier_optin`, `poll_secs`.
- `[geb]`: relay URL (default `wss://nostr.myceli.al`), deny-list of other bridges' device DIDs.
- Keys only in `[secrets]`.
- CLI: `link add|list|pause`, `geb connect <did>`, `geb stock-kps`, `status` (cursors, outbox depth, last relayed).
- Kill switch: pausing a link stops both pumps; removing the ACL entry revokes room access.

## 10. Testing

- Pure: `mapping` round-trips; Geb conformance vectors taken from Geb's source (inbox derivation counter rule, sealed
  box, rendezvous keys, AES-GCM AAD, ratchet lo2hi/hi2lo with skipped keys, frame-id hash at
  sign_json, leaf binding, did:peer:2.A.V.E encode/decode). Ask Geb for published vectors.
- MLS: `GebGroup` against a second in-process OpenMLS client playing a Geb member; competing commits inside the settle
  window, re-seat, removal.
- Harness: real `room-host` + test VTA + `fake.rs` relay; both directions end to end; kill the process between every
  pair of steps to prove resumption and idempotency.
- Live (feature-gated): soak against the Geb CLI on a test relay.
- Hostile-input tests for inbound Geb text: oversize, malformed JSON, forged names, injection strings.

## 11. Milestones

| | Scope | Blocked on |
|---|---|---|
| M0 | skeleton, `ForeignRoom` seam + loopback adapter, Geb traits, fake relay, mapping, config | nothing |
| M1 | VTC side complete against the harness; writes delivered over HTTPS `/v1/trust-tasks` (companion notes, B5) | nothing |
| M2 | Geb identity + dyad (connect-when-apart, VRC, ratchet, acks) | nothing, but pin to a Geb commit hash |
| M3 | Geb MLS seating, line post/receive, settle rule | persona cards + signed leaves so the commit check can be evaluated exactly (Geb's answers on 0xF001, policy, `re`/`m`/`o` are in) |
| M4 | both directions live, gap handling, soak | M1-M3 |
| M5 | keyring surface (grant, link status, "bridged" label); upstream asks (a) template-driven did:peer:2, (b) lift seal-and-retry put logic into `vta-sdk` | user approval of each |

Upstream asks are generic, not Geb-specific, and each needs explicit approval before any existing crate is touched.
