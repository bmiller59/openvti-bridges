//! The churn boundary for the Geb adapter: Geb path B has no versioned spec,
//! so everything that may change sits behind one of these traits.

use super::crypto::rendezvous::RelayKeys;
use super::wire::{Envelope, LineBody};
use crate::Result;
use async_trait::async_trait;
use serde_json::Value;

/// A Nostr event as the adapter handles it (NIP-01). The id and the BIP-340
/// signature are real: build one with [`RelayEvent::sign`], check one with
/// [`RelayEvent::verify`] (see `geb::event`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvent {
    /// Event id: lowercase hex sha256 of the NIP-01 serialisation.
    pub id: String,
    /// Mailbox pubkey, hex (x-only).
    pub pubkey: String,
    /// Kind (4177 mailbox, 4178 inbox).
    pub kind: u32,
    /// Seconds since the epoch.
    pub created_at: u64,
    /// Sealed content.
    pub content: String,
    /// Tags, including `["v","1"]` and `["expiration", ..]`.
    pub tags: Vec<Vec<String>>,
    /// BIP-340 Schnorr signature over the id, lowercase hex (128 chars).
    pub sig: String,
}

/// A Nostr relay.
#[async_trait]
pub trait GebRelay: Send + Sync {
    /// Publish an event.
    async fn publish(&self, event: RelayEvent) -> Result<()>;
    /// Events of `kind` by `author`, optionally `created_at >= since`. Relays
    /// return newest first; callers sort.
    async fn fetch(&self, kind: u32, author: &str, since: Option<u64>) -> Result<Vec<RelayEvent>>;
}

/// The dyad (path B one-to-one) channel. M2 builds the pure pieces; the
/// stateful dyad needs a store and is not wired.
#[async_trait]
pub trait GebDyad: Send + Sync {
    /// Send a frame to a peer.
    async fn send(&self, peer_did: &str, frame: &super::wire::Frame) -> Result<()>;
    /// Frames received from a peer.
    async fn recv(&self, peer_did: &str) -> Result<Vec<super::wire::Frame>>;
}

/// A message opened from the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    /// The sending leaf's BasicCredential identity (the device DID).
    pub sender_did: String,
    /// The application-message plaintext.
    pub plaintext: Vec<u8>,
}

/// What a settle pass did, as `GebRoom` needs to know it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettleReport {
    /// A commit was merged: the relay keys changed, read again under them.
    pub epoch_changed: bool,
    /// Commits are still held (or one is recorded failed): the read cursor
    /// must not pass this relay `created_at` (seconds).
    pub cursor_barrier_secs: Option<u64>,
}

/// The MLS room membership. Hides OpenMLS and the settle rule. The real
/// implementation is `geb::mls::MlsGroupClient` (feature `geb-mls`); the
/// default is `UnsupportedGroup`, which fails closed.
#[async_trait]
pub trait GebGroup: Send + Sync {
    /// Be seated in the room: stock KeyPackages or answer `kp-req` over a
    /// dyad, then accept the Welcome. Idempotent once seated.
    async fn ensure_seated(&self) -> Result<crate::foreign::JoinState>;
    /// Leave.
    async fn leave(&self) -> Result<()>;
    /// Relay keys of the current epoch.
    fn relay_keys(&self) -> Result<RelayKeys>;
    /// Seal plaintext as an MLS application message in the current epoch.
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Open an application message.
    fn open(&self, message: &[u8]) -> Result<OpenedMessage>;
    /// A signed leave `{t:"lv", at, ls}` read from the room (the line's `sg`
    /// already verified by the caller) by `by`, the MLS sender. The group
    /// verifies `ls` and keeps the newest per signer. Returns whether it was
    /// new. The default keeps nothing.
    fn note_signed_leave(&self, _by: &str, _at: u64, _sig: &str) -> Result<bool> {
        Ok(false)
    }
    /// Hold a commit read from the room (`mc`): `parent_epoch` is `mc.e`,
    /// `event_secs` the relay event's `created_at`, `now_ms` the local clock.
    /// Never applies it. The default fails closed: a group that cannot run the
    /// settle rule must not skip a commit.
    async fn hold_commit(
        &self,
        _parent_epoch: u64,
        _commit: &[u8],
        _event_secs: u64,
        _now_ms: u64,
    ) -> Result<()> {
        Err(crate::Error::Unsupported(
            "a Geb commit needs the settle rule (feature geb-mls); stopping instead of forking the epoch",
        ))
    }
    /// Run the settle rule for the current epoch at `now_ms`.
    async fn settle(&self, _now_ms: u64) -> Result<SettleReport> {
        Ok(SettleReport::default())
    }
}

/// Encodes and decodes every Geb shape, so a format change touches one
/// implementation.
pub trait GebCodec: Send + Sync {
    /// Parse a mailbox envelope. Unknown types are errors.
    fn decode_envelope(&self, bytes: &[u8]) -> Result<Envelope>;
    /// Serialise an envelope.
    fn encode_envelope(&self, envelope: &Envelope) -> Result<Vec<u8>>;
    /// Parse a room plaintext. Anything but a line is an error.
    fn decode_line(&self, bytes: &[u8]) -> Result<LineBody>;
    /// Serialise a line.
    fn encode_line(&self, line: &LineBody) -> Result<Vec<u8>>;
}

/// Holds the Geb device key and signs for it.
pub trait GebSigner: Send + Sync {
    /// The device DID (`did:peer:2...`).
    fn did(&self) -> &str;
    /// `sign_json` over a value.
    fn sign_json(&self, value: &Value) -> Result<String>;
}
