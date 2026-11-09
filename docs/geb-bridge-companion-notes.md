# Companion notes: Geb bridge plan

Date: 2026-11-08. Author: BAM session. Plan: `geb-bridge-plan.md`.
Paths below that are not under `src/` or `docs/` refer to the VTI repository, where this document was first written.
These notes explain the choices, record the threat model, and list what is still open. [V] = checked in code by a
planning agent; [I] = inferred or not yet checked. The threat analysis is reasoning, not testing.

## A. Why a bridge (the core issue)

Same MLS ciphersuite is necessary, not sufficient. MLS gives a group a shared key; the rest differs:
who may commit, how members are admitted, what the content is, how it travels, how things are signed (table in plan
section 2). A group is one cryptographic object: to be in a Geb room something must hold a leaf in Geb's tree and speak
Geb's framing and settle rule. Our VTA speaks none of that. Geb's guide is explicit that rooms need path B and that no
TSP route to a room exists. So a Geb client must exist; the "bridge" part is the translation between key/value records
and chat lines.

Re-signing is inherent. Geb verifies lines against a Geb device DID key; it cannot check our credentials or persona
signature. The bridge therefore signs as itself and carries the original author only as a quoted header. The VTA
signing oracle is domain-separated by design and will not emit a signature Geb accepts.

Ways to avoid a bridge, and why not: (1) rooms speaking Geb natively would put Geb code in core and track an unversioned
protocol; (2) Geb adopting our model is up to them; (3) waiting for convergence on TSP (Geb lists rooms over TSP as
unfinished). The trait seams mean (3), if it happens, replaces the Geb transport and group code and leaves the room side.

Generality: the room-side core (BridgeEvent, mapping, outbox/journal, provenance, link config) is adapter-agnostic. The seam
is `ForeignRoom` plus a capability descriptor, with all Geb concepts (dyads, KeyPackage stocks, the settle rule, Nostr
sealing) internal to the Geb adapter. Another MLS ecosystem differs in admission (x509, central delivery service),
commit sequencing and framing, so only the seam is generalised now; a second adapter will show whether it is right.

## B. Decisions and recommendations

1. Custody: export the Geb device keys to the bridge (recommended).
   Why: oracle cannot sign Geb's format and there is no ECDH oracle [I]; the alternative is Geb signing and ECDH code in
   `vta-service`. Cost: a compromised bridge leaks keys that act only as its Geb identity; they cannot reach the seed,
   the VTA or any VTC credential. Keyring already makes a comparable trade-off with `borrowKey`
   (keyring-wallet docs/plans/openvtc-rooms-plan.md:105-107 [V]). The room persona stays inside the VTA.
2. One Geb device DID and one persona per link (recommended). A shared identity lets anyone in the rooms it sits in
   correlate them. Cost: more setup and keys. Skip only if bridging exactly one room.
3. Bridging is opt-in per link by the room owner; `private` refused (recommended). Bridging hands plaintext to Geb members
   our credentials do not govern. Possible stricter option: confirm again when Geb membership changes; left out of v1.
4. Retractions: post a notice line (recommended). Geb has no visible edit/delete; silence would be worse than a stale
   marker. Switch to a delete if Geb adds one.
5. Sender binding (SETTLED 2026-11-08, read from code by an agent; two points inferred). `act` returns a completed document
   signed as the persona; the bridge delivers it. Over DIDComm/TSP the host refuses a deliverer that is not the issuer
   (`identityMismatch`, room-host/src/didcomm.rs:435-478; spine rule vti-trust-task-server/src/spine.rs:355-385, no
   relaxation). Over HTTPS `POST /v1/trust-tasks` the host authenticates by the document's proof alone
   (room-host/src/lib.rs:197-228, 421-425), which is how the existing CLI delivers act output
   (vta-cli-common/src/commands/rooms.rs:156-195). So M1 delivers over HTTPS. No REST-exception row is needed: that table
   covers only VTA routes (vta-service/src/deprecation.rs:79-147), not the room host's route. Sending over TSP/DIDComm
   would require a session as the persona itself (what keyring's wallet does, inferred). Not checked: the host's
   recipient/audience checks and read-path (browse/read) delivery.
6. Phase with Geb's answers as gates. M0-M2 need only the guide. M3 must not be guessed: a wrong MLS guess forks the
   epoch silently.

## C. Threat model

Bounded, not eliminated. Main points:

1. Plaintext exposure (main risk). The bridge holds plaintext from both sides; bridged room content is readable by every
   Geb room member. Irreversible, and a retraction cannot recall it. Mitigations: owner opt-in per link, no private tier,
   off by default.
2. Bridge compromise. Attacker gets the exported Geb keys and the bridge's read/write role: can impersonate the bridge in
   Geb, exfiltrate room content, inject records. Mitigations: read/write only, one identity per link, fast revocation
   (remove ACL entry), key rotation.
3. Injection from Geb into the room. Any Geb member can write text that lands in a record: prompt-injection aimed at
   agents reading the room, misleading content, oversize or malformed input. Mitigations: `basis: "observed"`, fenced and
   inert rendering (required by data-rooms.md:1637-1641 [V]), size caps, no action triggered by bridged content. Anything
   that reads the room, especially an agent, must treat bridged records as untrusted. NOT YET CHECKED: whether the
   existing content handling is sufficient for hostile text from a stranger-populated room.
4. Spoofed attribution. Geb members see the bridge's signature plus a quoted header; they cannot verify the quoted
   author. Inbound lines with bad/missing signatures are bridged marked `unverified`, so a forged name could appear in a
   quote. Mitigation: always present authors as quoted, show the signature result.
5. MLS epoch fork on the Geb side. A wrong settle rule drops the bridge from the group silently. Availability, not
   confidentiality. Heaviest testing goes here.
6. Echo loops and duplication across two bridges or relayed copies. Own-author skip, provenance marker, deny-list.
7. Relay and availability. One relay is the only resting place for mailboxes; 7-day expiry. Gap records make loss visible.
8. Unstable upstream. Path B has no versioned spec. Pin to a Geb commit, isolate behind trait seams, fail closed on
   unrecognised message types.
9. Metadata. The relay sees traffic patterns and our host sees read/write timing; someone watching both can correlate.
   One identity per link limits, not removes.

Non-negotiables: owner opt-in per link; minimal role; one identity per link; bridged content never trusted as verified;
fail closed on unknown Geb types; size limits both sides; a documented kill switch.

## D. Open questions

For us:
- Which ACL consumer kind can call `act` and `seal` without being treated as a delegate (ai-agent and mediator are
  refused). [V] for the refusal, [I] for the right kind.
- Does the VTA persona resolver recognise a did:peer:2 in `.A` form (persona.rs:29-34)? If yes, `keys/sign-document`
  could sign the VRC as `G_b`. [I]
- Is a generic template-driven did:peer:2 mint wanted upstream (ask a), and lifting the seal-and-retry put logic into
  `vta-sdk` (ask b)? Each needs approval before touching an existing crate.

For Geb (Geb's announcement channel; bring file:line):
1. Payload format of KeyPackage capability/extension 0xF001 (committer policy) and what the group requires of it
   (mls.rs:27-33,48-50).
2. The room `policy` JSON in the `welcome` frame (`room:{v:2,id,name,founder,since,policy…}`):
   schema, and what a read-and-post member must satisfy.
3. Meaning of `re`, `m`, `o` in the `{t:"l"}` line  and in `{k:"m"}` frames.
4. Is there any edit/delete/retract for lines? How do clients show a superseded line?
5. Are bot-style or automated members permitted by room policy? Is there a way to mark a member as a bridge?
6. Published test vectors for: inbox derivation, sealed box, rendezvous keys, AES-GCM AAD, ratchet with skipped keys,
   frame-id hash, sign_json, leaf binding.
7. Policy check after the settle rule: exact rules for rejecting a winning commit, and what a non-committing member does
   when the winner is rejected .
8. Will path B be versioned or pinned to tags? How will breaking changes be announced?

## E. Pointers

- Geb guide: `Geb's implementer's guide (2026-11-07)`.
- VTI rooms: docs/02-vta/data-rooms.md, docs/05-design-notes/data-rooms*.md, vti-rooms/src/mls.rs, sealed.rs,
  room-host/src/lib.rs.
- Template for the crate: vti-witness (Cargo.toml, CLAUDE.md, src/{setup,run,messaging}.rs).
- The VTI repository's root CLAUDE.md sections that bind this work: foreign-protocol identity exception, key custody, Trust Task rules,
  retry ownership, R1.1, R2.1, R6.2.

## F. Geb's answers (2026-11-08, code at release 0.5.14 = path B 0.1)

Settled: test vectors exist (`geb-path-b-vectors.json`, not yet received here; sealed box, mailbox envelope and ratchet
nonces are "open this" checks); inbox IKM is the raw 32-byte X25519 key; no AAD except on the mailbox envelope; ratchet
labels are HKDF info strings; frame id and leaf binding are specified; `0xF001` is a GroupContext extension holding policy
JSON; field types for lines, acks, `mc.e`, `cap`, reactions.
Still open: the wire shape of edit and delete (a design ruling, not built; a deletion is a request and attested).
Policy answers (corrected): by default bridges are welcome with no marking; each room will choose not welcome /
welcome automatically / ask, and whether to show a mark, for bridges and AI agents alike (settings not built, shape shared
before they ship); path B is versioned (0.1) with breaking changes announced in Geb's announcement channel first.
Caution carried into the design: the commit check depends on persona cards and signed leaves held locally; do not touch a
live room until the bridge can evaluate them (plan section 7).
