//! The durable [`BridgeStore`] over `vti_common::store` (fjall).
//!
//! Keyspaces are the plan's section 3: `links`, `cursors`, `journal_in`,
//! `outbox_out`, `xref`, `geb_mls`, `ratchets`. The pump's [`BridgeStore`]
//! uses the middle four; `links` (per-link state), `geb_mls` and `ratchets`
//! belong to the Geb adapter (M2/M3) and are only opened here so a store
//! always has the complete set (a missing keyspace is created on first use by
//! fjall, but naming them keeps the set in one place).
//!
//! Every write that the pump's crash-safety argument leans on (a journal or
//! outbox insert, a cursor move, a receipt, an xref) is followed by a journal
//! fsync (`persist`): "journalled before the post" and "cursor advanced before
//! the post" are only true if they survive the process.
//!
//! One pump writes a given store; `outbox_mark` is a read-then-write that is
//! forward-only and safe under that single writer.

use crate::foreign::Receipt;
use crate::model::BridgeEvent;
use crate::store::{BridgeStore, StateSpace};
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};

/// Per-link state (halt reasons, join state). Adapter-owned from M2.
pub const KS_LINKS: &str = "links";
/// Named cursors (browse version, foreign relay cursor, halt).
pub const KS_CURSORS: &str = "cursors";
/// Inbound events, journalled before they are acted on.
pub const KS_JOURNAL_IN: &str = "journal_in";
/// Outbound events, journalled before they are posted.
pub const KS_OUTBOX_OUT: &str = "outbox_out";
/// Cross-references between the two sides' ids.
pub const KS_XREF: &str = "xref";
/// Geb MLS state (M3).
pub const KS_GEB_MLS: &str = "geb_mls";
/// Geb pair ratchets (M2).
pub const KS_RATCHETS: &str = "ratchets";

/// Every keyspace, in one place.
pub const ALL_KEYSPACES: [&str; 7] = [
    KS_LINKS,
    KS_CURSORS,
    KS_JOURNAL_IN,
    KS_OUTBOX_OUT,
    KS_XREF,
    KS_GEB_MLS,
    KS_RATCHETS,
];

#[derive(Serialize, Deserialize)]
struct OutboxEntry {
    event: BridgeEvent,
    /// 0 accepted, 1 relayed, 2 delivered; `None` while unposted.
    receipt: Option<u8>,
}

fn rank(r: Receipt) -> u8 {
    match r {
        Receipt::Accepted => 0,
        Receipt::Relayed => 1,
        Receipt::Delivered => 2,
    }
}

fn unrank(n: u8) -> Receipt {
    match n {
        0 => Receipt::Accepted,
        1 => Receipt::Relayed,
        2 => Receipt::Delivered,
        // An unknown rank never reads as more delivered than it is: a receipt
        // is evidence, and an unreadable one is the weakest.
        _ => Receipt::Accepted,
    }
}

fn store_err(e: AppError) -> Error {
    Error::Store(e.to_string())
}

/// fjall takes an exclusive lock on its directory, so a second process (a
/// `status` or `geb` command while `run` is up) cannot open it. Say that,
/// instead of surfacing the engine's raw lock error.
fn open_err(dir: &Path, e: AppError) -> Error {
    let raw = e.to_string();
    if raw.to_lowercase().contains("lock") {
        return Error::Store(format!(
            "the store at {} is in use by another process (a running `vti-geb-bridge run`?). \
             Stop it, then repeat this command",
            dir.display()
        ));
    }
    Error::Store(raw)
}

/// fjall-backed [`BridgeStore`].
pub struct FjallStore {
    _store: Store,
    cursors: KeyspaceHandle,
    journal_in: KeyspaceHandle,
    outbox_out: KeyspaceHandle,
    xref: KeyspaceHandle,
    links: KeyspaceHandle,
    geb_mls: KeyspaceHandle,
    ratchets: KeyspaceHandle,
}

impl FjallStore {
    /// Open (or create) the store under `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let store = Store::open(&StoreConfig {
            data_dir: data_dir.to_path_buf(),
        })
        .map_err(|e| open_err(data_dir, e))?;
        let ks = |n: &str| store.keyspace(n).map_err(store_err);
        Ok(Self {
            cursors: ks(KS_CURSORS)?,
            journal_in: ks(KS_JOURNAL_IN)?,
            outbox_out: ks(KS_OUTBOX_OUT)?,
            xref: ks(KS_XREF)?,
            links: ks(KS_LINKS)?,
            geb_mls: ks(KS_GEB_MLS)?,
            ratchets: ks(KS_RATCHETS)?,
            _store: store,
        })
    }

    /// The `links` keyspace (adapter-owned from M2).
    pub fn links(&self) -> &KeyspaceHandle {
        &self.links
    }

    /// The `geb_mls` keyspace (M3).
    pub fn geb_mls(&self) -> &KeyspaceHandle {
        &self.geb_mls
    }

    /// The `ratchets` keyspace (M2).
    pub fn ratchets(&self) -> &KeyspaceHandle {
        &self.ratchets
    }
}

async fn sync(ks: &KeyspaceHandle) -> Result<()> {
    ks.persist().await.map_err(store_err)
}

#[async_trait]
impl BridgeStore for FjallStore {
    async fn cursor(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.cursors.get_raw(name).await.map_err(store_err)
    }

    async fn set_cursor(&self, name: &str, value: &[u8]) -> Result<()> {
        self.cursors
            .insert_raw(name, value.to_vec())
            .await
            .map_err(store_err)?;
        sync(&self.cursors).await
    }

    async fn journal_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        let new = self
            .journal_in
            .insert_if_absent(key, event)
            .await
            .map_err(store_err)?;
        sync(&self.journal_in).await?;
        Ok(new)
    }

    async fn outbox_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        let entry = OutboxEntry {
            event: event.clone(),
            receipt: None,
        };
        let new = self
            .outbox_out
            .insert_if_absent(key, &entry)
            .await
            .map_err(store_err)?;
        sync(&self.outbox_out).await?;
        Ok(new)
    }

    async fn outbox_mark(&self, key: &str, receipt: Receipt) -> Result<()> {
        let mut entry: OutboxEntry = self
            .outbox_out
            .get(key)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Store(format!("no outbox entry {key}")))?;
        // Receipts only move forward.
        if entry.receipt.is_none_or(|r| rank(receipt) > r) {
            entry.receipt = Some(rank(receipt));
            self.outbox_out
                .insert(key, &entry)
                .await
                .map_err(store_err)?;
            sync(&self.outbox_out).await?;
        }
        Ok(())
    }

    async fn outbox_receipt(&self, key: &str) -> Result<Option<Receipt>> {
        let entry: Option<OutboxEntry> = self.outbox_out.get(key).await.map_err(store_err)?;
        Ok(entry.and_then(|e| e.receipt).map(unrank))
    }

    async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>> {
        let mut out = Vec::new();
        for (k, v) in self
            .outbox_out
            .prefix_iter_raw(Vec::new())
            .await
            .map_err(store_err)?
        {
            let entry: OutboxEntry = serde_json::from_slice(&v)
                .map_err(|e| Error::Store(format!("outbox entry does not decode: {e}")))?;
            if entry.receipt.is_none() {
                out.push((String::from_utf8_lossy(&k).into_owned(), entry.event));
            }
        }
        Ok(out)
    }

    async fn state_get(&self, space: StateSpace, key: &str) -> Result<Option<Vec<u8>>> {
        let ks = match space {
            StateSpace::Links => &self.links,
            StateSpace::Ratchets => &self.ratchets,
        };
        ks.get_raw(key).await.map_err(store_err)
    }

    async fn state_put(&self, space: StateSpace, key: &str, value: &[u8]) -> Result<()> {
        let ks = match space {
            StateSpace::Links => &self.links,
            StateSpace::Ratchets => &self.ratchets,
        };
        ks.insert_raw(key, value.to_vec())
            .await
            .map_err(store_err)?;
        sync(ks).await
    }

    async fn xref_set(&self, a: &str, b: &str) -> Result<()> {
        self.xref
            .insert_raw(a, b.as_bytes().to_vec())
            .await
            .map_err(store_err)?;
        sync(&self.xref).await
    }

    async fn xref_has(&self, a: &str) -> Result<bool> {
        Ok(self.xref.get_raw(a).await.map_err(store_err)?.is_some())
    }

    async fn xref_get(&self, a: &str) -> Result<Option<String>> {
        Ok(self
            .xref
            .get_raw(a)
            .await
            .map_err(store_err)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EventKind, Origin};

    fn ev(id: &str) -> BridgeEvent {
        BridgeEvent {
            origin: Origin::Vtc,
            origin_id: id.into(),
            link: "l".into(),
            author: "a".into(),
            at: 1,
            title: None,
            text: "t".into(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: None,
        }
    }

    #[test]
    fn an_unknown_receipt_rank_never_reads_as_delivered() {
        assert_eq!(unrank(2), Receipt::Delivered);
        assert_eq!(unrank(1), Receipt::Relayed);
        assert_eq!(unrank(200), Receipt::Accepted);
    }

    #[test]
    fn a_second_opener_gets_a_clear_message_not_a_raw_lock_error() {
        let dir = tempfile::tempdir().unwrap();
        let _first = FjallStore::open(dir.path()).unwrap();
        let Err(e) = FjallStore::open(dir.path()) else {
            panic!("a second open of a locked store must fail");
        };
        let msg = e.to_string();
        assert!(msg.contains("in use by another process"), "{msg}");
        assert!(msg.contains("Stop it"), "{msg}");
    }

    #[tokio::test]
    async fn state_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = FjallStore::open(dir.path()).unwrap();
            s.set_cursor("browse", &7u64.to_be_bytes()).await.unwrap();
            assert!(s.outbox_insert("k1", &ev("a")).await.unwrap());
            assert!(!s.outbox_insert("k1", &ev("a")).await.unwrap());
            assert!(s.outbox_insert("k2", &ev("b")).await.unwrap());
            s.outbox_mark("k1", Receipt::Relayed).await.unwrap();
            s.outbox_mark("k1", Receipt::Accepted).await.unwrap();
            assert!(s.journal_insert("j", &ev("a")).await.unwrap());
            assert!(!s.journal_insert("j", &ev("a")).await.unwrap());
            s.xref_set("vtc:a", "").await.unwrap();
            s.state_put(StateSpace::Ratchets, "p", b"r1").await.unwrap();
            s.state_put(StateSpace::Links, "p", b"l1").await.unwrap();
        }
        let s = FjallStore::open(dir.path()).unwrap();
        assert_eq!(
            s.state_get(StateSpace::Ratchets, "p")
                .await
                .unwrap()
                .unwrap(),
            b"r1"
        );
        assert_eq!(
            s.cursor("browse").await.unwrap().unwrap(),
            7u64.to_be_bytes()
        );
        assert_eq!(
            s.outbox_receipt("k1").await.unwrap(),
            Some(Receipt::Relayed)
        );
        let unposted = s.outbox_unposted().await.unwrap();
        assert_eq!(unposted.len(), 1);
        assert_eq!(unposted[0].0, "k2");
        assert_eq!(
            s.state_get(StateSpace::Links, "p").await.unwrap().unwrap(),
            b"l1"
        );
        assert!(s.xref_has("vtc:a").await.unwrap());
        assert_eq!(s.xref_get("vtc:a").await.unwrap().as_deref(), Some(""));
        assert_eq!(s.xref_get("nope").await.unwrap(), None);
    }
}
