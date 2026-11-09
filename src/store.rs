//! Durable bridge state, kept abstract and asynchronous (the fjall store in
//! `fjall_store`, behind feature `vtc`, is async). The in-memory store backs
//! the unit tests.
//!
//! Keyspaces named in the plan: cursors, `journal_in`, `outbox_out`, `xref`.
//! (`links`, `geb_mls` and `ratchets` belong to the Geb adapter and arrive
//! with it.)

use crate::foreign::Receipt;
use crate::model::BridgeEvent;
use crate::{Error, Result};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// Adapter-owned keyspaces reachable through [`BridgeStore::state_get`] and
/// [`BridgeStore::state_put`]. The core never interprets the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StateSpace {
    /// Per-link and per-connection state (`links`).
    Links,
    /// Pair ratchets and their queues (`ratchets`).
    Ratchets,
}

/// What the pump persists.
#[async_trait]
pub trait BridgeStore: Send + Sync {
    /// A named cursor.
    async fn cursor(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Set a named cursor.
    async fn set_cursor(&self, name: &str, value: &[u8]) -> Result<()>;
    /// Record an inbound event before it is acted on. `true` when new.
    async fn journal_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool>;
    /// Record an outbound event before it is posted. `true` when new.
    async fn outbox_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool>;
    /// Record how far an outbound event got.
    async fn outbox_mark(&self, key: &str, receipt: Receipt) -> Result<()>;
    /// Receipt of an outbound event, if posted.
    async fn outbox_receipt(&self, key: &str) -> Result<Option<Receipt>>;
    /// Outbound events never posted, in insertion-key order.
    async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>>;
    /// Read an adapter-owned record. A store that does not provide adapter
    /// state refuses rather than pretending.
    async fn state_get(&self, _space: StateSpace, _key: &str) -> Result<Option<Vec<u8>>> {
        Err(Error::Store("this store keeps no adapter state".into()))
    }
    /// Write an adapter-owned record. When this returns the record is durable
    /// (a ratchet step is persisted before its frame is posted or acked).
    async fn state_put(&self, _space: StateSpace, _key: &str, _value: &[u8]) -> Result<()> {
        Err(Error::Store("this store keeps no adapter state".into()))
    }
    /// Cross-reference: `a` is bridged as `b`.
    async fn xref_set(&self, a: &str, b: &str) -> Result<()>;
    /// Whether `a` has been bridged.
    async fn xref_has(&self, a: &str) -> Result<bool>;
    /// What `a` was bridged as. For an outbound record this is the foreign
    /// room's id of the posted line (empty when the room gave none), so a
    /// later retraction can answer it.
    async fn xref_get(&self, a: &str) -> Result<Option<String>>;
}

#[derive(Default)]
struct Inner {
    cursors: BTreeMap<String, Vec<u8>>,
    journal: BTreeMap<String, BridgeEvent>,
    outbox: BTreeMap<String, (BridgeEvent, Option<Receipt>)>,
    xref: BTreeMap<String, String>,
    state: BTreeMap<(StateSpace, String), Vec<u8>>,
}

/// In-memory [`BridgeStore`].
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))
    }
}

#[async_trait]
impl BridgeStore for MemoryStore {
    async fn cursor(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.lock()?.cursors.get(name).cloned())
    }
    async fn set_cursor(&self, name: &str, value: &[u8]) -> Result<()> {
        self.lock()?.cursors.insert(name.into(), value.to_vec());
        Ok(())
    }
    async fn journal_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        Ok(self
            .lock()?
            .journal
            .insert(key.into(), event.clone())
            .is_none())
    }
    async fn outbox_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        let mut g = self.lock()?;
        if g.outbox.contains_key(key) {
            return Ok(false);
        }
        g.outbox.insert(key.into(), (event.clone(), None));
        Ok(true)
    }
    async fn outbox_mark(&self, key: &str, receipt: Receipt) -> Result<()> {
        let mut g = self.lock()?;
        let entry = g
            .outbox
            .get_mut(key)
            .ok_or_else(|| Error::Store(format!("no outbox entry {key}")))?;
        // Receipts only move forward.
        if entry.1.is_none_or(|r| receipt > r) {
            entry.1 = Some(receipt);
        }
        Ok(())
    }
    async fn outbox_receipt(&self, key: &str) -> Result<Option<Receipt>> {
        Ok(self.lock()?.outbox.get(key).and_then(|e| e.1))
    }
    async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>> {
        Ok(self
            .lock()?
            .outbox
            .iter()
            .filter(|(_, (_, r))| r.is_none())
            .map(|(k, (e, _))| (k.clone(), e.clone()))
            .collect())
    }
    async fn state_get(&self, space: StateSpace, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.lock()?.state.get(&(space, key.to_string())).cloned())
    }
    async fn state_put(&self, space: StateSpace, key: &str, value: &[u8]) -> Result<()> {
        self.lock()?
            .state
            .insert((space, key.to_string()), value.to_vec());
        Ok(())
    }
    async fn xref_set(&self, a: &str, b: &str) -> Result<()> {
        self.lock()?.xref.insert(a.into(), b.into());
        Ok(())
    }
    async fn xref_has(&self, a: &str) -> Result<bool> {
        Ok(self.lock()?.xref.contains_key(a))
    }
    async fn xref_get(&self, a: &str) -> Result<Option<String>> {
        Ok(self.lock()?.xref.get(a).cloned())
    }
}
