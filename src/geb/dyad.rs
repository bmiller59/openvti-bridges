//! The stateful Geb dyad: connect-when-apart (guide, "Connecting" 2, steps
//! 1-8) and path B one-to-one messaging (guide, "One-to-one messages").
//!
//! Everything durable goes through [`BridgeStore::state_put`]: a connection's
//! handshake state under `links` (`dyad/<peer DID>`) and its ratchets, unacked
//! frames, inbound queue and duplicate guards under `ratchets` (`<peer DID>`).
//! A received frame is opened, queued and persisted in ONE record before its
//! ack is posted, so an ack never outruns the state it vouches for. A sent
//! frame's counter is persisted (with the frame, as pending) before the frame
//! is posted, so a crash can lose a post but never reuse a counter; the
//! pending record lets [`StatefulDyad::retransmit`] repost it.
//!
//! Concurrency: the whole state is *leased* (taken out of a `std` mutex and put
//! back on drop), so no lock is held across an await. A second concurrent
//! operation fails fast with "dyad busy"; one task drives a dyad.
//!
//! Schema notes (records are JSON, version `v`):
//! - `links/dyad/<peer>`: [`ConnRecord`].
//! - `ratchets/<peer>`: [`RatchetRecord`]. It holds chain keys in clear, so the
//!   store is trusted to protect them like key material (the fjall store here
//!   does not encrypt at rest).
//!
//! UNVERIFIED (the guide and the answers are silent; each is a choice, not
//! Geb's behaviour):
//! - whether a receiver re-acks a frame it has already opened (we do);
//! - whether an authenticated frame of an unknown kind or non-JSON text is acked
//!   (we drop it unacked; Geb shows non-JSON text);
//! - the inbox is read from the start (no `since`) because inbox events expire
//!   after 7 days; a processed invitation is remembered by its connection;
//! - a second invitation from a peer we already hold a connection record for
//!   is ignored;
//! - whether the pair mailbox is also where a response/completion for an
//!   *existing* dyad would travel again (we accept them only in the matching
//!   handshake phase);
//! - `fc` fragments are not supported, so a frame must fit one event (about
//!   36,000 bytes of plaintext);
//! - retransmission policy (callers decide when; we never loop).

use super::codec::GuideCodec;
use super::crypto::ratchet::{RecvChain, RecvState, SendChain, SendState, channel_key, my_side};
use super::crypto::rendezvous::pair_keys;
use super::crypto::{b64_decode, did_peer, ecdh, frame_id, inbox, pair, sealed, sign};
use super::event::{KIND_INBOX, KIND_MAILBOX, standard_tags};
use super::room::{Clock, EXPIRY_SECS, SINCE_SLACK_SECS};
use super::traits::{GebCodec, GebDyad, GebRelay, GebSigner, RelayEvent};
use super::vrc;
use super::wire::{
    COMPLETION_TYPE, Envelope, Frame, INVITATION_TYPE, Invitation, InvitePayload, MAX_ACK_IDS,
    MAX_EVENT_BYTES, RESPONSE_TYPE, VrcCompletion, VrcResponse, is_nonce,
};
use crate::store::{BridgeStore, StateSpace};
use crate::{Error, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Largest frame plaintext that still fits one 65,536-byte event once the
/// ratchet frame, two base64 layers and the AEAD overhead are added.
pub const MAX_FRAME_PLAINTEXT: usize = 36_000;
/// Most recent frame ids remembered for duplicate suppression.
const DONE_FRAMES: usize = 1024;
/// A display name sent in an invitation is cut to this many characters.
const NAME_CHARS: usize = 40;

/// The bridge's Geb device identity: the DID, its Ed25519 key (`.A` = `.V`)
/// and the X25519 `.E` secret.
pub struct GebIdentity {
    did: String,
    signing: SigningKey,
    e_secret: Zeroizing<[u8; 32]>,
}

impl GebIdentity {
    /// Build the identity and its `did:peer:2.A.V.E`.
    pub fn new(signing: SigningKey, e_secret: [u8; 32]) -> Result<Self> {
        let did = did_peer::encode(
            &signing.verifying_key().to_bytes(),
            &super::crypto::x25519_public(&e_secret),
            None,
        )?;
        Ok(Self {
            did,
            signing,
            e_secret: Zeroizing::new(e_secret),
        })
    }
    /// The public `.E` key.
    pub fn e_public(&self) -> [u8; 32] {
        super::crypto::x25519_public(&self.e_secret)
    }
}

impl GebSigner for GebIdentity {
    fn did(&self) -> &str {
        &self.did
    }
    fn sign_json(&self, value: &Value) -> Result<String> {
        sign::sign_json(&self.signing, value)
    }
}

/// Who started the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// We sent the invitation.
    Inviter,
    /// We answered one.
    Invitee,
}

/// Where a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Inviter: invitation posted, no response yet.
    Invited,
    /// Invitee: response posted, no completion yet.
    Responded,
    /// Both VRCs exchanged; the ratchets exist.
    Connected,
    /// The 7-day window passed without an answer. Terminal.
    Expired,
}

/// Handshake state for one peer (`links/dyad/<peer>`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnRecord {
    /// Schema version, 1.
    pub v: u32,
    /// The peer's DID.
    pub peer: String,
    /// Who invited.
    pub role: Role,
    /// Handshake phase.
    pub phase: Phase,
    /// The invitation nonce.
    pub nonce: String,
    /// Seconds: when the invitation was sent or received.
    pub since: u64,
    /// The peer's display name, if it sent one.
    pub peer_name: Option<String>,
    /// The VRC the peer issued about us.
    pub their_vrc: Option<Value>,
    /// The VRC we issued about the peer.
    pub our_vrc: Option<Value>,
    /// Inviter: the completion has been posted.
    pub completion_sent: bool,
    /// Our `cap` frame has been sent on the ratchet.
    pub cap_sent: bool,
    /// The peer's last `cap` frame.
    pub peer_cap: Option<Value>,
    /// Newest `created_at` processed on the pair mailbox.
    pub newest: u64,
    /// Pair-mailbox event ids already processed, with their `created_at`.
    pub seen: BTreeMap<String, u64>,
}

/// Ratchets and queues for a connected peer (`ratchets/<peer>`). Deliberately
/// not `Debug`: it holds chain keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct RatchetRecord {
    /// Schema version, 1.
    pub v: u32,
    /// Sending chain.
    pub send: SendState,
    /// Receiving chain.
    pub recv: RecvState,
    /// Sent, not yet acked: frame id to frame base64.
    pub pending: BTreeMap<String, String>,
    /// Opened frames not yet handed to the caller, with their ratchet counter
    /// (handed over in counter order: equal `created_at` seconds sort by
    /// event id, which is not send order).
    pub inbound: Vec<(u32, Frame)>,
    /// Frame ids already opened (re-acked, never re-opened).
    pub done: VecDeque<String>,
}

/// An invitation read from our inbox, not yet answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedInvitation {
    /// The inviter's DID (checked against the signature).
    pub from: String,
    /// The invitation nonce.
    pub nonce: String,
    /// The inviter's display name, if sent.
    pub name: Option<String>,
    /// The inbox event's `created_at`, seconds.
    pub created_at: u64,
}

/// What one [`StatefulDyad::sync`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Frames opened and queued.
    pub frames: usize,
    /// Acks processed (ids removed from pending).
    pub acked: usize,
    /// Events dropped (unreadable, wrong direction, duplicate, forged).
    pub dropped: usize,
    /// Phase after the sync, if a record exists.
    pub phase: Option<Phase>,
}

struct Peer {
    conn: ConnRecord,
    ratchet: Option<RatchetRecord>,
}

type Core = HashMap<String, Peer>;

struct Lease<'a> {
    owner: &'a StatefulDyad,
    core: Option<Core>,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.owner.core.lock() {
            *g = self.core.take();
        }
    }
}

/// The stateful dyad.
pub struct StatefulDyad {
    id: Arc<GebIdentity>,
    relay: Arc<dyn GebRelay>,
    store: Arc<dyn BridgeStore>,
    codec: Arc<dyn GebCodec>,
    clock: Clock,
    core: Mutex<Option<Core>>,
}

fn to_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|e| Error::Store(format!("encode: {e}")))
}

fn hex_nonce() -> String {
    let mut n = [0u8; 16];
    rand::fill(&mut n);
    hex::encode(n)
}

fn e_pub_of(did: &str) -> Result<[u8; 32]> {
    did_peer::decode(did)?
        .key_agreement
        .ok_or_else(|| Error::Wire("peer DID has no .E key".into()))
}

impl StatefulDyad {
    /// Compose the dyad.
    pub fn new(
        id: Arc<GebIdentity>,
        relay: Arc<dyn GebRelay>,
        store: Arc<dyn BridgeStore>,
        clock: Clock,
    ) -> Self {
        Self {
            id,
            relay,
            store,
            codec: Arc::new(GuideCodec),
            clock,
            core: Mutex::new(Some(HashMap::new())),
        }
    }

    /// Our DID.
    pub fn did(&self) -> &str {
        &self.id.did
    }

    fn now(&self) -> u64 {
        (self.clock)() / 1000
    }

    fn lease(&self) -> Result<Lease<'_>> {
        let core = self
            .core
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))?
            .take()
            .ok_or_else(|| Error::Foreign("dyad busy: another operation is running".into()))?;
        Ok(Lease {
            owner: self,
            core: Some(core),
        })
    }

    async fn load(&self, core: &mut Core, peer: &str) -> Result<()> {
        if core.contains_key(peer) {
            return Ok(());
        }
        let Some(raw) = self
            .store
            .state_get(StateSpace::Links, &format!("dyad/{peer}"))
            .await?
        else {
            return Ok(());
        };
        let conn: ConnRecord = serde_json::from_slice(&raw)
            .map_err(|e| Error::Store(format!("connection record does not decode: {e}")))?;
        let ratchet = match self.store.state_get(StateSpace::Ratchets, peer).await? {
            Some(r) => Some(
                serde_json::from_slice(&r)
                    .map_err(|e| Error::Store(format!("ratchet record does not decode: {e}")))?,
            ),
            None => None,
        };
        core.insert(peer.to_string(), Peer { conn, ratchet });
        Ok(())
    }

    async fn save_conn(&self, c: &ConnRecord) -> Result<()> {
        self.store
            .state_put(
                StateSpace::Links,
                &format!("dyad/{}", c.peer),
                &to_bytes(c)?,
            )
            .await
    }

    async fn save_ratchet(&self, peer: &str, r: &RatchetRecord) -> Result<()> {
        self.store
            .state_put(StateSpace::Ratchets, peer, &to_bytes(r)?)
            .await
    }

    /// Seal `payload` to the invitee's inbox and post it (kind 4178, signed by
    /// the inbox key, 7-day expiry).
    async fn post_invitation(
        &self,
        invitee_did: &str,
        nonce: &str,
        name: Option<&str>,
    ) -> Result<()> {
        let invitation = Invitation {
            kind: INVITATION_TYPE.into(),
            did: self.id.did.clone(),
            endpoint: self.id.did.clone(),
            nonce: nonce.into(),
        };
        let sig = self.id.sign_json(
            &serde_json::to_value(&invitation).map_err(|e| Error::Wire(e.to_string()))?,
        )?;
        let payload = InvitePayload {
            v: 1,
            from: self.id.did.clone(),
            invitation,
            sig,
            name: name.map(|n| n.chars().take(NAME_CHARS).collect()),
        };
        let invitee_e = e_pub_of(invitee_did)?;
        let content = sealed::seal(
            &invitee_e,
            &serde_json::to_vec(&payload).map_err(|e| Error::Wire(e.to_string()))?,
        )?;
        let now = self.now();
        let ev = RelayEvent::sign(
            &inbox::inbox_secret(&invitee_e)?,
            KIND_INBOX,
            now,
            standard_tags(now),
            content,
        )?;
        self.publish(ev).await
    }

    async fn publish(&self, ev: RelayEvent) -> Result<()> {
        if ev.json_len() > MAX_EVENT_BYTES {
            return Err(Error::Foreign("event over 65,536 bytes".into()));
        }
        self.relay.publish(ev).await
    }

    /// Post an envelope on the pair mailbox shared with `peer`.
    async fn post_envelope(&self, peer: &str, env: &Envelope) -> Result<()> {
        let keys = pair_keys(&self.id.e_secret, &e_pub_of(peer)?)?;
        let content = pair::seal(&keys, KIND_MAILBOX, &self.codec.encode_envelope(env)?)?;
        let now = self.now();
        let ev = RelayEvent::sign(
            &keys.nostr_secret,
            KIND_MAILBOX,
            now,
            standard_tags(now),
            content,
        )?;
        self.publish(ev).await
    }

    /// Invite `invitee_did` (connect-when-apart steps 1-3). Idempotent while
    /// the invitation is outstanding: a repeat reposts the same invitation
    /// (same nonce), so a failed post is resumable. Returns the nonce.
    pub async fn invite(&self, invitee_did: &str, name: Option<&str>) -> Result<String> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, invitee_did).await?;
        if invitee_did == self.id.did {
            return Err(Error::Foreign("cannot invite ourselves".into()));
        }
        e_pub_of(invitee_did)?;
        let nonce = match core.get(invitee_did) {
            Some(p) if p.conn.role == Role::Inviter && p.conn.phase == Phase::Invited => {
                p.conn.nonce.clone()
            }
            Some(_) => return Err(Error::Foreign("a connection with this peer exists".into())),
            None => {
                let conn = ConnRecord {
                    v: 1,
                    peer: invitee_did.into(),
                    role: Role::Inviter,
                    phase: Phase::Invited,
                    nonce: hex_nonce(),
                    since: self.now(),
                    peer_name: None,
                    their_vrc: None,
                    our_vrc: None,
                    completion_sent: false,
                    cap_sent: false,
                    peer_cap: None,
                    newest: 0,
                    seen: BTreeMap::new(),
                };
                // Intent is durable before the post, so a failed post resumes.
                self.save_conn(&conn).await?;
                let n = conn.nonce.clone();
                core.insert(
                    invitee_did.into(),
                    Peer {
                        conn,
                        ratchet: None,
                    },
                );
                n
            }
        };
        self.post_invitation(invitee_did, &nonce, name).await?;
        Ok(nonce)
    }

    /// Read our inbox (kind 4178): invitations that open, verify and are not
    /// already answered. Anything else is dropped and logged.
    pub async fn invitations(&self) -> Result<Vec<ReceivedInvitation>> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        let inbox_pub = hex::encode(inbox::inbox_pubkey(&self.id.e_public())?);
        let mut events = self.relay.fetch(KIND_INBOX, &inbox_pub, None).await?;
        events.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let now = self.now();
        let mut out: Vec<ReceivedInvitation> = Vec::new();
        for ev in events {
            if ev.pubkey != inbox_pub || ev.kind != KIND_INBOX || ev.verify().is_err() {
                tracing::warn!(event = %ev.id, "dropping an inbox event that does not verify");
                continue;
            }
            if ev.is_expired(now) {
                continue;
            }
            let inv = match self.read_invitation(&ev) {
                Ok(i) => i,
                Err(e) => {
                    tracing::warn!(event = %ev.id, error = %e, "dropping an unreadable invitation");
                    continue;
                }
            };
            self.load(core, &inv.from).await?;
            if core.contains_key(&inv.from) || out.iter().any(|o| o.nonce == inv.nonce) {
                continue;
            }
            out.push(inv);
        }
        Ok(out)
    }

    fn read_invitation(&self, ev: &RelayEvent) -> Result<ReceivedInvitation> {
        let plain = sealed::open(&self.id.e_secret, &ev.content)?;
        let p: InvitePayload =
            serde_json::from_slice(&plain).map_err(|e| Error::Wire(format!("invitation: {e}")))?;
        if p.v != 1 || p.invitation.kind != INVITATION_TYPE || !is_nonce(&p.invitation.nonce) {
            return Err(Error::Wire("malformed invitation".into()));
        }
        // Guide step 3: … signature.
        if p.invitation.did != p.from {
            return Err(Error::Crypto("invitation.did is not from".into()));
        }
        if p.from == self.id.did {
            return Err(Error::Wire("invitation from ourselves".into()));
        }
        let key = did_peer::decode(&p.from)?.verifying_key()?;
        let doc = serde_json::to_value(&p.invitation).map_err(|e| Error::Wire(e.to_string()))?;
        sign::verify_json(&key, &doc, &p.sig)?;
        e_pub_of(&p.from)?;
        Ok(ReceivedInvitation {
            from: p.from,
            nonce: p.invitation.nonce,
            name: p.name,
            created_at: ev.created_at,
        })
    }

    /// Answer an invitation (steps 4 and 6): record the intent, issue our VRC
    /// about the inviter and post `{t:"response"}` on the pair mailbox. A
    /// repeat for the same invitation reposts it.
    pub async fn accept(&self, inv: &ReceivedInvitation) -> Result<()> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, &inv.from).await?;
        let now = self.now();
        if inv.created_at.saturating_add(EXPIRY_SECS) <= now {
            return Err(Error::Foreign("the invitation has expired".into()));
        }
        match core.get(&inv.from) {
            Some(p) if p.conn.role == Role::Invitee && p.conn.nonce == inv.nonce => {}
            Some(_) => return Err(Error::Foreign("a connection with this peer exists".into())),
            None => {
                let our_vrc = vrc::issue(&self.id.did, &self.id.signing, &inv.from, now)?;
                let conn = ConnRecord {
                    v: 1,
                    peer: inv.from.clone(),
                    role: Role::Invitee,
                    phase: Phase::Responded,
                    nonce: inv.nonce.clone(),
                    since: now,
                    peer_name: inv.name.clone(),
                    their_vrc: None,
                    our_vrc: Some(our_vrc),
                    completion_sent: false,
                    cap_sent: false,
                    peer_cap: None,
                    newest: 0,
                    seen: BTreeMap::new(),
                };
                self.save_conn(&conn).await?;
                core.insert(
                    inv.from.clone(),
                    Peer {
                        conn,
                        ratchet: None,
                    },
                );
            }
        }
        let peer = core
            .get(&inv.from)
            .ok_or_else(|| Error::Foreign("connection vanished".into()))?;
        let vrc = peer
            .conn
            .our_vrc
            .clone()
            .ok_or_else(|| Error::Foreign("no VRC recorded".into()))?;
        let env = Envelope::Response {
            response: VrcResponse {
                kind: RESPONSE_TYPE.into(),
                did: self.id.did.clone(),
                endpoint: self.id.did.clone(),
                vrc,
                nonce: inv.nonce.clone(),
            },
            name: None,
        };
        self.post_envelope(&inv.from, &env).await
    }

    /// The phase of the connection with `peer`, if any.
    pub async fn phase(&self, peer: &str) -> Result<Option<Phase>> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, peer).await?;
        Ok(core.get(peer).map(|p| p.conn.phase))
    }

    /// Frames sent and not yet acked.
    pub async fn unacked(&self, peer: &str) -> Result<usize> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, peer).await?;
        Ok(core
            .get(peer)
            .and_then(|p| p.ratchet.as_ref())
            .map_or(0, |r| r.pending.len()))
    }

    /// The peer's last `cap` frame, if it sent one.
    pub async fn peer_cap(&self, peer: &str) -> Result<Option<Value>> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, peer).await?;
        Ok(core.get(peer).and_then(|p| p.conn.peer_cap.clone()))
    }

    fn start_ratchets(&self, peer: &str) -> Result<RatchetRecord> {
        let shared = ecdh(&self.id.e_secret, &e_pub_of(peer)?)?;
        let ck = channel_key(&shared)?;
        let mine = my_side(&self.id.did, peer)?;
        Ok(RatchetRecord {
            v: 1,
            send: SendChain::new(&ck, mine)?.snapshot(),
            recv: RecvChain::new(&ck, mine.other())?.snapshot(),
            pending: BTreeMap::new(),
            inbound: Vec::new(),
            done: VecDeque::new(),
        })
    }

    /// Read the pair mailbox and advance: complete the handshake, open frames
    /// (queued durably, then acked), process acks. Safe to call as often as
    /// the caller likes; re-reads `newest - 300` seconds and skips what it has
    /// seen.
    pub async fn sync(&self, peer: &str) -> Result<SyncReport> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.sync_inner(core, peer).await
    }

    async fn sync_inner(&self, core: &mut Core, peer: &str) -> Result<SyncReport> {
        self.load(core, peer).await?;
        let mut report = SyncReport::default();
        let Some(p) = core.get_mut(peer) else {
            return Err(Error::Foreign("no connection with this peer".into()));
        };
        let now = self.now();
        if matches!(p.conn.phase, Phase::Invited | Phase::Responded)
            && p.conn.since.saturating_add(EXPIRY_SECS) <= now
        {
            p.conn.phase = Phase::Expired;
            self.save_conn(&p.conn).await?;
        }
        report.phase = Some(p.conn.phase);
        if p.conn.phase == Phase::Expired {
            return Ok(report);
        }
        let peer_e = e_pub_of(peer)?;
        let keys = pair_keys(&self.id.e_secret, &peer_e)?;
        let mailbox = keys.pubkey_hex()?;
        let since = (p.conn.newest > 0).then(|| p.conn.newest.saturating_sub(SINCE_SLACK_SECS));
        let mut events = self.relay.fetch(KIND_MAILBOX, &mailbox, since).await?;
        // Relays return newest first; open oldest first.
        events.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let mine = my_side(&self.id.did, peer)?;

        // Decode everything first. Handshake envelopes run before frames, so a
        // frame sorted ahead of its connection's completion is not lost.
        let mut handshake = Vec::new();
        let mut rest = Vec::new();
        let mut rest_ids: Vec<String> = Vec::new();
        let mut newly_seen: Vec<(String, u64)> = Vec::new();
        for ev in events {
            if p.conn.seen.contains_key(&ev.id) {
                continue;
            }
            if ev.pubkey != mailbox || ev.kind != KIND_MAILBOX || ev.verify().is_err() {
                tracing::warn!(event = %ev.id, "dropping a relay event that does not verify");
                report.dropped += 1;
                continue;
            }
            newly_seen.push((ev.id.clone(), ev.created_at));
            if ev.is_expired(now) {
                report.dropped += 1;
                continue;
            }
            let env = match pair::open(&keys, KIND_MAILBOX, &ev.content)
                .and_then(|b| self.codec.decode_envelope(&b))
            {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(event = %ev.id, error = %e, "dropping unreadable mailbox event");
                    report.dropped += 1;
                    continue;
                }
            };
            match env {
                Envelope::Response { .. } | Envelope::Completion { .. } => handshake.push(env),
                _ => {
                    rest_ids.push(ev.id.clone());
                    rest.push(env);
                }
            }
        }

        let mut post_completion = false;
        for env in handshake {
            match (env, p.conn.role, p.conn.phase) {
                (Envelope::Response { response, name }, Role::Inviter, Phase::Invited) => {
                    let ok = response.nonce == p.conn.nonce
                        && response.did == peer
                        && vrc::verify(&response.vrc, peer, &self.id.did).is_ok();
                    if !ok {
                        tracing::warn!(
                            "dropping a response that fails the nonce, DID or VRC check"
                        );
                        report.dropped += 1;
                        continue;
                    }
                    let ours = vrc::issue(&self.id.did, &self.id.signing, peer, now)?;
                    let r = self.start_ratchets(peer)?;
                    // Ratchets first, then the connection that points at them.
                    self.save_ratchet(peer, &r).await?;
                    p.ratchet = Some(r);
                    p.conn.their_vrc = Some(response.vrc);
                    p.conn.our_vrc = Some(ours);
                    p.conn.peer_name = name.or(p.conn.peer_name.take());
                    p.conn.phase = Phase::Connected;
                    self.save_conn(&p.conn).await?;
                }
                (Envelope::Completion { completion }, Role::Invitee, Phase::Responded) => {
                    let ok = completion.nonce == p.conn.nonce
                        && vrc::verify(&completion.vrc, peer, &self.id.did).is_ok();
                    if !ok {
                        tracing::warn!("dropping a completion that fails the nonce or VRC check");
                        report.dropped += 1;
                        continue;
                    }
                    let r = self.start_ratchets(peer)?;
                    self.save_ratchet(peer, &r).await?;
                    p.ratchet = Some(r);
                    p.conn.their_vrc = Some(completion.vrc);
                    p.conn.phase = Phase::Connected;
                    p.conn.completion_sent = true;
                    self.save_conn(&p.conn).await?;
                }
                _ => {
                    tracing::warn!("dropping a handshake envelope that does not fit the phase");
                    report.dropped += 1;
                }
            }
        }
        if p.conn.role == Role::Inviter
            && p.conn.phase == Phase::Connected
            && !p.conn.completion_sent
        {
            post_completion = true;
        }

        // Frames and acks, only with ratchets.
        let mut to_ack: Vec<String> = Vec::new();
        if let Some(r) = p.ratchet.as_mut() {
            let mut rc = RecvChain::restore(&r.recv)?;
            for env in rest {
                match env {
                    Envelope::Frame { f, d } => {
                        if d == mine {
                            // Our own echo (guide: Geb drops an envelope whose `d` is its side).
                            report.dropped += 1;
                            continue;
                        }
                        let id = frame_id::frame_id(&f);
                        if r.done.contains(&id) {
                            to_ack.push(id);
                            report.dropped += 1;
                            continue;
                        }
                        let frame = rc
                            .open_b64(&f)
                            .and_then(|b| {
                                serde_json::from_slice::<Frame>(&b)
                                    .map_err(|e| Error::Wire(format!("frame: {e}")))
                            })
                            .and_then(|fr| fr.validate().map(|()| fr));
                        match frame {
                            Ok(Frame::Cap { dm, fc, rv, wp }) => {
                                p.conn.peer_cap = Some(serde_json::json!(
                                    {"k":"cap","dm":dm,"fc":fc,"rv":rv,"wp":wp}
                                ));
                                r.done.push_back(id.clone());
                                to_ack.push(id);
                            }
                            Ok(fr) => {
                                let n = b64_decode(&f)
                                    .ok()
                                    .and_then(|b| {
                                        b.get(..4)
                                            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                                    })
                                    .unwrap_or(u32::MAX);
                                r.inbound.push((n, fr));
                                r.done.push_back(id.clone());
                                to_ack.push(id);
                                report.frames += 1;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "dropping a frame that did not open or parse");
                                report.dropped += 1;
                            }
                        }
                    }
                    Envelope::Ack { a } => {
                        for id in a {
                            if r.pending.remove(&id).is_some() {
                                report.acked += 1;
                            }
                        }
                    }
                    // Room envelopes do not belong on a pair mailbox.
                    _ => report.dropped += 1,
                }
            }
            while r.done.len() > DONE_FRAMES {
                r.done.pop_front();
            }
            r.recv = rc.snapshot();
            // Durable before any ack leaves.
            self.save_ratchet(peer, r).await?;
        } else if !rest.is_empty() {
            // Frames before the handshake finished: not ours to open yet.
            // Marking them seen would lose them, so they are left unseen.
            let unseen: std::collections::BTreeSet<&str> =
                rest_ids.iter().map(String::as_str).collect();
            newly_seen.retain(|(id, _)| !unseen.contains(id.as_str()));
            report.dropped += rest.len();
        }

        for (id, at) in newly_seen {
            p.conn.seen.insert(id, at);
            p.conn.newest = p.conn.newest.max(at);
        }
        let floor = p.conn.newest.saturating_sub(2 * SINCE_SLACK_SECS);
        p.conn.seen.retain(|_, at| *at >= floor);
        self.save_conn(&p.conn).await?;
        report.phase = Some(p.conn.phase);

        if post_completion {
            let env = Envelope::Completion {
                completion: VrcCompletion {
                    kind: COMPLETION_TYPE.into(),
                    vrc: p
                        .conn
                        .our_vrc
                        .clone()
                        .ok_or_else(|| Error::Foreign("no VRC recorded".into()))?,
                    nonce: p.conn.nonce.clone(),
                },
            };
            self.post_envelope(peer, &env).await?;
            p.conn.completion_sent = true;
            self.save_conn(&p.conn).await?;
        }
        for chunk in to_ack.chunks(MAX_ACK_IDS) {
            self.post_envelope(peer, &Envelope::Ack { a: chunk.to_vec() })
                .await?;
        }
        if p.conn.phase == Phase::Connected && !p.conn.cap_sent {
            self.send_inner(p, peer, &Frame::bridge_cap()).await?;
            p.conn.cap_sent = true;
            self.save_conn(&p.conn).await?;
        }
        Ok(report)
    }

    async fn send_inner(&self, p: &mut Peer, peer: &str, frame: &Frame) -> Result<()> {
        frame.validate()?;
        // The bridge claims no capability it lacks (guide: never dm:1 without
        // rooms; never fc or rv = 1 without reassembling them).
        if let Frame::Cap { dm, fc, rv, .. } = frame {
            let one = |v: &Option<Value>| v.as_ref().is_some_and(|x| x == &Value::from(1));
            if dm.as_f64().is_none_or(|n| n >= 1.0) || one(fc) || one(rv) {
                return Err(Error::Foreign(
                    "the bridge sends cap with dm:0 and never fc or rv".into(),
                ));
            }
        }
        if p.conn.phase != Phase::Connected {
            return Err(Error::Foreign("not connected to this peer".into()));
        }
        let r = p
            .ratchet
            .as_mut()
            .ok_or_else(|| Error::Foreign("no ratchet for this peer".into()))?;
        let plain = serde_json::to_vec(frame).map_err(|e| Error::Wire(e.to_string()))?;
        if plain.len() > MAX_FRAME_PLAINTEXT {
            return Err(Error::Foreign(
                "frame too large for one event (fragments are not supported)".into(),
            ));
        }
        let mut sc = SendChain::restore(&r.send)?;
        let f = sc.seal_b64(&plain)?;
        let id = frame_id::frame_id(&f);
        r.send = sc.snapshot();
        r.pending.insert(id, f.clone());
        // The counter and the pending frame are durable before the post.
        self.save_ratchet(peer, r).await?;
        let mine = my_side(&self.id.did, peer)?;
        self.post_envelope(peer, &Envelope::Frame { f, d: mine })
            .await
    }

    /// Repost every sent-but-unacked frame, unchanged (same ratchet frame, a
    /// new event). The receiver opens it once and re-acks duplicates. One
    /// attempt each; the caller decides when to call again.
    pub async fn retransmit(&self, peer: &str) -> Result<usize> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, peer).await?;
        let p = core
            .get(peer)
            .ok_or_else(|| Error::Foreign("no connection with this peer".into()))?;
        let Some(r) = p.ratchet.as_ref() else {
            return Ok(0);
        };
        let mine = my_side(&self.id.did, peer)?;
        let frames: Vec<String> = r.pending.values().cloned().collect();
        for f in &frames {
            self.post_envelope(
                peer,
                &Envelope::Frame {
                    f: f.clone(),
                    d: mine,
                },
            )
            .await?;
        }
        Ok(frames.len())
    }
}

#[async_trait]
impl GebDyad for StatefulDyad {
    async fn send(&self, peer_did: &str, frame: &Frame) -> Result<()> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.load(core, peer_did).await?;
        let p = core
            .get_mut(peer_did)
            .ok_or_else(|| Error::Foreign("no connection with this peer".into()))?;
        self.send_inner(p, peer_did, frame).await
    }

    /// Sync, then hand over (and durably clear) the opened frames. The caller
    /// must journal what it receives before it asks again.
    async fn recv(&self, peer_did: &str) -> Result<Vec<Frame>> {
        let mut lease = self.lease()?;
        let core = lease.core.get_or_insert_with(HashMap::new);
        self.sync_inner(core, peer_did).await?;
        let Some(p) = core.get_mut(peer_did) else {
            return Ok(Vec::new());
        };
        let Some(r) = p.ratchet.as_mut() else {
            return Ok(Vec::new());
        };
        if r.inbound.is_empty() {
            return Ok(Vec::new());
        }
        let held = std::mem::take(&mut r.inbound);
        let mut sorted = held.clone();
        sorted.sort_by_key(|(n, _)| *n);
        if let Err(e) = self.save_ratchet(peer_did, r).await {
            r.inbound = held;
            return Err(e);
        }
        Ok(sorted.into_iter().map(|(_, f)| f).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geb::fake::FakeRelay;
    use crate::store::MemoryStore;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const T0: u64 = 1_700_000_000;

    struct World {
        relay: Arc<FakeRelay>,
        now: Arc<AtomicU64>,
        a_store: Arc<MemoryStore>,
        b_store: Arc<MemoryStore>,
        a: StatefulDyad,
        b: StatefulDyad,
    }

    fn ident(seed: u8) -> Arc<GebIdentity> {
        Arc::new(GebIdentity::new(SigningKey::from_bytes(&[seed; 32]), [seed + 100; 32]).unwrap())
    }

    fn clock(now: &Arc<AtomicU64>) -> Clock {
        let n = now.clone();
        Arc::new(move || n.load(Ordering::SeqCst) * 1000)
    }

    fn dyad(
        id: Arc<GebIdentity>,
        relay: Arc<dyn GebRelay>,
        store: Arc<dyn BridgeStore>,
        now: &Arc<AtomicU64>,
    ) -> StatefulDyad {
        StatefulDyad::new(id, relay, store, clock(now))
    }

    fn world() -> World {
        let relay = Arc::new(FakeRelay::new());
        let now = Arc::new(AtomicU64::new(T0));
        let (a_store, b_store) = (Arc::new(MemoryStore::new()), Arc::new(MemoryStore::new()));
        World {
            a: dyad(ident(1), relay.clone(), a_store.clone(), &now),
            b: dyad(ident(2), relay.clone(), b_store.clone(), &now),
            relay,
            now,
            a_store,
            b_store,
        }
    }

    fn msg(text: &str) -> Frame {
        Frame::Message {
            d: text.into(),
            id: hex_nonce(),
            re: None,
            nr: None,
            o: None,
        }
    }

    fn text(f: &Frame) -> String {
        match f {
            Frame::Message { d, .. } => d.clone(),
            other => format!("{other:?}"),
        }
    }

    async fn connect(w: &World) {
        w.a.invite(w.b.did(), Some("alice")).await.unwrap();
        let inv = w.b.invitations().await.unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(inv[0].from, w.a.did());
        assert_eq!(inv[0].name.as_deref(), Some("alice"));
        w.b.accept(&inv[0]).await.unwrap();
        w.now.fetch_add(1, Ordering::SeqCst);
        let r = w.a.sync(w.b.did()).await.unwrap();
        assert_eq!(r.phase, Some(Phase::Connected));
        w.now.fetch_add(1, Ordering::SeqCst);
        let r = w.b.sync(w.a.did()).await.unwrap();
        assert_eq!(r.phase, Some(Phase::Connected));
    }

    fn envelopes(w: &World) -> Vec<Envelope> {
        let keys = pair_keys(&w.a.id.e_secret, &e_pub_of(w.b.did()).unwrap()).unwrap();
        w.relay
            .all()
            .iter()
            .filter(|e| e.kind == KIND_MAILBOX)
            .filter_map(|e| pair::open(&keys, KIND_MAILBOX, &e.content).ok())
            .filter_map(|b| GuideCodec.decode_envelope(&b).ok())
            .collect()
    }

    #[tokio::test]
    async fn connect_when_apart_then_acked_messages_both_ways() {
        let w = world();
        connect(&w).await;
        // Both sent cap (dm:0, no fc/rv) as the first frame on the ratchet.
        w.now.fetch_add(1, Ordering::SeqCst);
        w.a.sync(w.b.did()).await.unwrap();
        let cap = w.a.peer_cap(w.b.did()).await.unwrap().unwrap();
        assert_eq!(cap["dm"], 0);
        assert!(cap["fc"].is_null() && cap["rv"].is_null());
        assert!(w.b.peer_cap(w.a.did()).await.unwrap().is_some());
        for t in ["one", "two", "three"] {
            w.a.send(w.b.did(), &msg(t)).await.unwrap();
        }
        assert_eq!(w.a.unacked(w.b.did()).await.unwrap(), 3, "cap was acked");
        w.now.fetch_add(1, Ordering::SeqCst);
        let got: Vec<_> =
            w.b.recv(w.a.did())
                .await
                .unwrap()
                .iter()
                .map(text)
                .collect();
        assert_eq!(got, ["one", "two", "three"]);
        assert!(
            w.b.recv(w.a.did()).await.unwrap().is_empty(),
            "drained once"
        );
        w.b.send(w.a.did(), &msg("back")).await.unwrap();
        w.now.fetch_add(1, Ordering::SeqCst);
        let r = w.a.sync(w.b.did()).await.unwrap();
        assert_eq!(r.frames, 1);
        assert_eq!(r.acked, 3);
        assert_eq!(w.a.unacked(w.b.did()).await.unwrap(), 0);
        // The VRCs are kept on both sides and verify.
        let ra = w
            .a_store
            .state_get(StateSpace::Links, &format!("dyad/{}", w.b.did()))
            .await
            .unwrap()
            .unwrap();
        let c: ConnRecord = serde_json::from_slice(&ra).unwrap();
        vrc::verify(c.their_vrc.as_ref().unwrap(), w.b.did(), w.a.did()).unwrap();
        vrc::verify(c.our_vrc.as_ref().unwrap(), w.a.did(), w.b.did()).unwrap();
    }

    #[tokio::test]
    async fn out_of_order_duplicate_and_reposted_events_open_each_frame_once() {
        let w = world();
        connect(&w).await;
        w.b.recv(w.a.did()).await.unwrap();
        // Later frames carry earlier created_at: the relay order and the
        // ratchet order disagree, so skipped keys are used.
        for (i, t) in [(10u64, "m0"), (5, "m1"), (0, "m2")] {
            w.now.store(T0 + 100 - i, Ordering::SeqCst);
            w.a.send(w.b.did(), &msg(t)).await.unwrap();
        }
        // A duplicate delivery of the same event.
        let dup = w.relay.all().last().unwrap().clone();
        w.relay.inject(dup);
        w.now.store(T0 + 200, Ordering::SeqCst);
        let mut got: Vec<_> =
            w.b.recv(w.a.did())
                .await
                .unwrap()
                .iter()
                .map(text)
                .collect();
        got.sort();
        assert_eq!(got, ["m0", "m1", "m2"]);
        // A retransmission is a new event with the same frame: re-acked, not re-delivered.
        assert_eq!(w.a.retransmit(w.b.did()).await.unwrap(), 4);
        w.now.store(T0 + 201, Ordering::SeqCst);
        assert!(w.b.recv(w.a.did()).await.unwrap().is_empty());
        w.now.store(T0 + 202, Ordering::SeqCst);
        w.a.sync(w.b.did()).await.unwrap();
        assert_eq!(w.a.unacked(w.b.did()).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn our_own_echo_a_forged_event_and_an_expired_event_are_dropped() {
        let w = world();
        connect(&w).await;
        w.b.recv(w.a.did()).await.unwrap();
        w.a.send(w.b.did(), &msg("hello")).await.unwrap();
        // A reads the mailbox it just wrote: its own `d` side, dropped, no frame.
        w.now.fetch_add(1, Ordering::SeqCst);
        let r = w.a.sync(w.b.did()).await.unwrap();
        assert_eq!(r.frames, 0);
        assert!(r.dropped >= 1);
        // A forged signature on a copy of a valid event.
        let mut forged = w.relay.all().last().unwrap().clone();
        forged.sig = "11".repeat(64);
        w.relay.inject(forged);
        let got = w.b.recv(w.a.did()).await.unwrap();
        assert_eq!(got.iter().map(text).collect::<Vec<_>>(), ["hello"]);
        // An event that expired before B read it.
        w.a.send(w.b.did(), &msg("late")).await.unwrap();
        w.now.fetch_add(8 * 86_400, Ordering::SeqCst);
        assert!(w.b.recv(w.a.did()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn restart_resumes_the_ratchets_and_never_reuses_a_counter() {
        let w = world();
        connect(&w).await;
        w.a.send(w.b.did(), &msg("before")).await.unwrap();
        w.now.fetch_add(1, Ordering::SeqCst);
        // B restarts over the same store halfway.
        let b2 = dyad(ident(2), w.relay.clone(), w.b_store.clone(), &w.now);
        let got = b2.recv(w.a.did()).await.unwrap();
        assert_eq!(got.iter().map(text).collect::<Vec<_>>(), ["before"]);
        let a2 = dyad(ident(1), w.relay.clone(), w.a_store.clone(), &w.now);
        a2.send(w.b.did(), &msg("after")).await.unwrap();
        w.now.fetch_add(1, Ordering::SeqCst);
        let b3 = dyad(ident(2), w.relay.clone(), w.b_store.clone(), &w.now);
        let got = b3.recv(w.a.did()).await.unwrap();
        assert_eq!(got.iter().map(text).collect::<Vec<_>>(), ["after"]);
        assert_eq!(a2.phase(w.b.did()).await.unwrap(), Some(Phase::Connected));
    }

    #[tokio::test]
    async fn hostile_invitations_are_dropped() {
        let w = world();
        let eve = ident(7);
        let b_e = w.b.id.e_public();
        let post = |payload: &InvitePayload| {
            let content = sealed::seal(&b_e, &serde_json::to_vec(payload).unwrap()).unwrap();
            w.relay.inject(
                RelayEvent::sign(
                    &inbox::inbox_secret(&b_e).unwrap(),
                    KIND_INBOX,
                    T0,
                    standard_tags(T0),
                    content,
                )
                .unwrap(),
            );
        };
        let inv = |did: &str, nonce: &str| Invitation {
            kind: INVITATION_TYPE.into(),
            did: did.into(),
            endpoint: did.into(),
            nonce: nonce.into(),
        };
        let sign = |i: &Invitation| eve.sign_json(&serde_json::to_value(i).unwrap()).unwrap();
        let n = hex_nonce();
        // did != from.
        let i = inv(w.a.did(), &n);
        post(&InvitePayload {
            v: 1,
            from: eve.did().into(),
            invitation: i.clone(),
            sig: sign(&i),
            name: None,
        });
        // Signed by eve but claiming to be A.
        post(&InvitePayload {
            v: 1,
            from: w.a.did().into(),
            invitation: i.clone(),
            sig: sign(&i),
            name: None,
        });
        // Bad nonce and bad version.
        let i2 = inv(eve.did(), "short");
        post(&InvitePayload {
            v: 1,
            from: eve.did().into(),
            invitation: i2.clone(),
            sig: sign(&i2),
            name: None,
        });
        let i3 = inv(eve.did(), &n);
        post(&InvitePayload {
            v: 2,
            from: eve.did().into(),
            invitation: i3.clone(),
            sig: sign(&i3),
            name: None,
        });
        // Garbage sealed content.
        w.relay.inject(
            RelayEvent::sign(
                &inbox::inbox_secret(&b_e).unwrap(),
                KIND_INBOX,
                T0,
                vec![],
                "AAAA".into(),
            )
            .unwrap(),
        );
        assert!(w.b.invitations().await.unwrap().is_empty());
        // The genuine one from eve herself is read.
        post(&InvitePayload {
            v: 1,
            from: eve.did().into(),
            invitation: i3.clone(),
            sig: sign(&i3),
            name: None,
        });
        let got = w.b.invitations().await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].from, eve.did());
    }

    #[tokio::test]
    async fn a_response_with_the_wrong_nonce_issuer_or_subject_is_refused() {
        let w = world();
        w.a.invite(w.b.did(), None).await.unwrap();
        let nonce = w.a.invite(w.b.did(), None).await.unwrap(); // idempotent
        let mallory = ident(9);
        let post = |vrc_v: Value, nonce: &str, did: &str| {
            let env = Envelope::Response {
                response: VrcResponse {
                    kind: RESPONSE_TYPE.into(),
                    did: did.into(),
                    endpoint: did.into(),
                    vrc: vrc_v,
                    nonce: nonce.into(),
                },
                name: None,
            };
            let keys = pair_keys(&w.b.id.e_secret, &w.a.id.e_public()).unwrap();
            let content = pair::seal(
                &keys,
                KIND_MAILBOX,
                &GuideCodec.encode_envelope(&env).unwrap(),
            )
            .unwrap();
            w.relay.inject(
                RelayEvent::sign(
                    &keys.nostr_secret,
                    KIND_MAILBOX,
                    T0,
                    standard_tags(T0),
                    content,
                )
                .unwrap(),
            );
        };
        let b = w.b.did().to_string();
        let a = w.a.did().to_string();
        let good = vrc::issue(&b, &w.b.id.signing, &a, T0).unwrap();
        post(good.clone(), &hex_nonce(), &b); // wrong nonce
        post(
            vrc::issue(w.b.did(), &w.b.id.signing, mallory.did(), T0).unwrap(),
            &nonce,
            &b,
        ); // subject not us
        post(
            vrc::issue(mallory.did(), &mallory.signing, &a, T0).unwrap(),
            &nonce,
            &b,
        ); // issuer not responder
        let r = w.a.sync(&b).await.unwrap();
        assert_eq!(r.phase, Some(Phase::Invited));
        assert!(r.dropped >= 3);
        post(good, &nonce, &b);
        w.now.fetch_add(1, Ordering::SeqCst);
        assert_eq!(w.a.sync(&b).await.unwrap().phase, Some(Phase::Connected));
    }

    #[tokio::test]
    async fn the_bridge_never_claims_capabilities_and_refuses_oversize() {
        let w = world();
        assert!(
            w.a.send(w.b.did(), &msg("x")).await.is_err(),
            "not connected"
        );
        connect(&w).await;
        for (dm, fc, rv) in [(1, None, None), (0, Some(1), None), (0, None, Some(1))] {
            let cap = Frame::Cap {
                dm: dm.into(),
                fc: fc.map(Value::from),
                rv: rv.map(Value::from),
                wp: None,
            };
            assert!(w.a.send(w.b.did(), &cap).await.is_err());
        }
        let big = msg(&"x".repeat(MAX_FRAME_PLAINTEXT));
        assert!(w.a.send(w.b.did(), &big).await.is_err());
        // Nothing was consumed by the refusals.
        assert_eq!(w.a.unacked(w.b.did()).await.unwrap(), 1, "only the cap");
        // The biggest allowed frame fits one event.
        w.a.send(w.b.did(), &msg(&"y".repeat(MAX_FRAME_PLAINTEXT - 200)))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_unanswered_invitation_expires_after_seven_days() {
        let w = world();
        w.a.invite(w.b.did(), None).await.unwrap();
        let inv = w.b.invitations().await.unwrap();
        w.now.fetch_add(EXPIRY_SECS + 1, Ordering::SeqCst);
        assert!(w.b.accept(&inv[0]).await.is_err());
        assert_eq!(
            w.a.sync(w.b.did()).await.unwrap().phase,
            Some(Phase::Expired)
        );
        assert!(w.a.invite(w.b.did(), None).await.is_err(), "terminal");
    }

    struct Flaky {
        inner: Arc<FakeRelay>,
        fail: AtomicBool,
    }
    #[async_trait]
    impl GebRelay for Flaky {
        async fn publish(&self, e: RelayEvent) -> Result<()> {
            if self.fail.swap(false, Ordering::SeqCst) {
                return Err(Error::Foreign("connection reset".into()));
            }
            self.inner.publish(e).await
        }
        async fn fetch(&self, k: u32, a: &str, s: Option<u64>) -> Result<Vec<RelayEvent>> {
            self.inner.fetch(k, a, s).await
        }
    }

    #[tokio::test]
    async fn a_failed_invitation_post_resumes_with_the_same_nonce() {
        let relay = Arc::new(Flaky {
            inner: Arc::new(FakeRelay::new()),
            fail: AtomicBool::new(true),
        });
        let now = Arc::new(AtomicU64::new(T0));
        let a = dyad(ident(1), relay.clone(), Arc::new(MemoryStore::new()), &now);
        let b = dyad(ident(2), relay.clone(), Arc::new(MemoryStore::new()), &now);
        assert!(a.invite(b.did(), None).await.is_err());
        assert!(b.invitations().await.unwrap().is_empty());
        let n = a.invite(b.did(), None).await.unwrap();
        assert_eq!(b.invitations().await.unwrap()[0].nonce, n);
    }

    struct FailRatchets {
        inner: MemoryStore,
        fail: AtomicBool,
    }
    #[async_trait]
    impl BridgeStore for FailRatchets {
        async fn cursor(&self, n: &str) -> Result<Option<Vec<u8>>> {
            self.inner.cursor(n).await
        }
        async fn set_cursor(&self, n: &str, v: &[u8]) -> Result<()> {
            self.inner.set_cursor(n, v).await
        }
        async fn journal_insert(&self, k: &str, e: &crate::model::BridgeEvent) -> Result<bool> {
            self.inner.journal_insert(k, e).await
        }
        async fn outbox_insert(&self, k: &str, e: &crate::model::BridgeEvent) -> Result<bool> {
            self.inner.outbox_insert(k, e).await
        }
        async fn outbox_mark(&self, k: &str, r: crate::foreign::Receipt) -> Result<()> {
            self.inner.outbox_mark(k, r).await
        }
        async fn outbox_receipt(&self, k: &str) -> Result<Option<crate::foreign::Receipt>> {
            self.inner.outbox_receipt(k).await
        }
        async fn outbox_unposted(&self) -> Result<Vec<(String, crate::model::BridgeEvent)>> {
            self.inner.outbox_unposted().await
        }
        async fn xref_set(&self, a: &str, b: &str) -> Result<()> {
            self.inner.xref_set(a, b).await
        }
        async fn xref_has(&self, a: &str) -> Result<bool> {
            self.inner.xref_has(a).await
        }
        async fn xref_get(&self, a: &str) -> Result<Option<String>> {
            self.inner.xref_get(a).await
        }
        async fn state_get(&self, s: StateSpace, k: &str) -> Result<Option<Vec<u8>>> {
            self.inner.state_get(s, k).await
        }
        async fn state_put(&self, s: StateSpace, k: &str, v: &[u8]) -> Result<()> {
            if s == StateSpace::Ratchets && self.fail.load(Ordering::SeqCst) {
                return Err(Error::Store("disk full".into()));
            }
            self.inner.state_put(s, k, v).await
        }
    }

    #[tokio::test]
    async fn no_ack_leaves_before_the_state_it_vouches_for_is_durable() {
        let relay = Arc::new(FakeRelay::new());
        let now = Arc::new(AtomicU64::new(T0));
        let a = dyad(ident(1), relay.clone(), Arc::new(MemoryStore::new()), &now);
        let bs = Arc::new(FailRatchets {
            inner: MemoryStore::new(),
            fail: AtomicBool::new(false),
        });
        let b = dyad(ident(2), relay.clone(), bs.clone(), &now);
        let w = World {
            relay: relay.clone(),
            now: now.clone(),
            a_store: Arc::new(MemoryStore::new()),
            b_store: Arc::new(MemoryStore::new()),
            a,
            b,
        };
        connect(&w).await;
        w.b.recv(w.a.did()).await.unwrap();
        w.a.send(w.b.did(), &msg("durable?")).await.unwrap();
        let acks = |w: &World| {
            envelopes(w)
                .iter()
                .filter(|e| matches!(e, Envelope::Ack { .. }))
                .count()
        };
        let before = acks(&w);
        bs.fail.store(true, Ordering::SeqCst);
        now.fetch_add(1, Ordering::SeqCst);
        assert!(w.b.recv(w.a.did()).await.is_err());
        assert_eq!(acks(&w), before, "no ack when the state could not be saved");
        // The failure is recoverable: the lease came back, and a retry works.
        bs.fail.store(false, Ordering::SeqCst);
        let b2 = dyad(ident(2), relay.clone(), bs.clone(), &now);
        assert_eq!(
            b2.recv(w.a.did())
                .await
                .unwrap()
                .iter()
                .map(text)
                .collect::<Vec<_>>(),
            ["durable?"]
        );
        assert!(acks(&w) > before);
    }
}
