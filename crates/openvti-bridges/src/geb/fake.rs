//! Test doubles for the Geb adapter. Nothing here is Geb: `FakeRelay` is an
//! in-memory event list and `FakeGroup` is a NOT-MLS stand-in that provides no
//! confidentiality; it exists to drive the adapter's own code (envelopes,
//! sealing, signatures, dedup) without network access.

use super::crypto::rendezvous::RelayKeys;
use super::traits::{GebGroup, GebRelay, OpenedMessage, RelayEvent};
use crate::foreign::JoinState;
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::Mutex;

/// In-memory relay.
#[derive(Default)]
pub struct FakeRelay {
    events: Mutex<Vec<RelayEvent>>,
    /// When true, `publish` succeeds but stores nothing (a relay that drops).
    drop_all: Mutex<bool>,
}

impl FakeRelay {
    /// Empty relay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the relay accept and silently lose events.
    pub fn set_dropping(&self, dropping: bool) {
        if let Ok(mut g) = self.drop_all.lock() {
            *g = dropping;
        }
    }

    /// Everything stored.
    pub fn all(&self) -> Vec<RelayEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Store an event as another client would have posted it.
    pub fn inject(&self, event: RelayEvent) {
        if let Ok(mut g) = self.events.lock() {
            g.push(event);
        }
    }
}

#[async_trait]
impl GebRelay for FakeRelay {
    async fn publish(&self, event: RelayEvent) -> Result<()> {
        // A real relay checks the id and the signature; so does this one.
        event.verify()?;
        if *self
            .drop_all
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))?
        {
            return Ok(());
        }
        self.events
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))?
            .push(event);
        Ok(())
    }

    async fn fetch(&self, kind: u32, author: &str, since: Option<u64>) -> Result<Vec<RelayEvent>> {
        let g = self
            .events
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))?;
        let mut out: Vec<_> = g
            .iter()
            .filter(|e| {
                e.kind == kind && e.pubkey == author && since.is_none_or(|s| e.created_at >= s)
            })
            .cloned()
            .collect();
        // Real relays return newest first; keep that so callers must sort.
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        Ok(out)
    }
}

/// A NOT-MLS group double: fixed relay keys, and "sealing" that only prefixes
/// the sender's DID. Every instance for the same room shares the same keys.
pub struct FakeGroup {
    join: std::sync::Mutex<std::result::Result<JoinState, String>>,
    member_did: String,
    keys: ([u8; 32], [u8; 32]),
}

impl FakeGroup {
    /// A member with the given device DID in a test room.
    pub fn new(member_did: &str) -> Self {
        Self {
            join: std::sync::Mutex::new(Ok(JoinState::Seated)),
            member_did: member_did.into(),
            keys: ([0x11; 32], [0x22; 32]),
        }
    }
}

impl FakeGroup {
    /// Make the next seating checks answer `state`.
    pub fn set_join_state(&self, state: JoinState) {
        if let Ok(mut g) = self.join.lock() {
            *g = Ok(state);
        }
    }

    /// Make seating refused from now on (also: the leaf was removed).
    pub fn refuse(&self, why: &str) {
        if let Ok(mut g) = self.join.lock() {
            *g = Err(why.to_string());
        }
    }
}

#[async_trait]
impl GebGroup for FakeGroup {
    async fn ensure_seated(&self) -> Result<JoinState> {
        match &*self
            .join
            .lock()
            .map_err(|_| Error::Foreign("poisoned".into()))?
        {
            Ok(s) => Ok(*s),
            Err(why) => Err(Error::Refused(why.clone())),
        }
    }
    async fn leave(&self) -> Result<()> {
        Ok(())
    }
    fn relay_keys(&self) -> Result<RelayKeys> {
        Ok(RelayKeys::from_parts(self.keys.0, self.keys.1))
    }
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = self.member_did.as_bytes().to_vec();
        out.push(0);
        out.extend_from_slice(plaintext);
        Ok(out)
    }
    fn open(&self, message: &[u8]) -> Result<OpenedMessage> {
        let split = message
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| Error::Wire("fake group message without sender".into()))?;
        let sender_did = String::from_utf8(message[..split].to_vec())
            .map_err(|_| Error::Wire("sender not utf-8".into()))?;
        Ok(OpenedMessage {
            sender_did,
            plaintext: message[split + 1..].to_vec(),
        })
    }
}
