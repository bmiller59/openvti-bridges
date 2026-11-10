//! The durable [`BridgeStore`] over `vti_common::store` (fjall).
//!
//! Keyspaces are the plan's section 3: `links`, `cursors`, `journal_in`,
//! `outbox_out`, `xref`, `geb_mls`, `ratchets`. The pump's [`BridgeStore`]
//! uses the middle four; `links` (per-link state), `geb_mls` and `ratchets`
//! belong to the Geb adapter (M2/M3) and are only opened here so a store
//! always has the complete set (a missing keyspace is created on first use by
//! fjall, but naming them keeps the set in one place).
//!
//! Two further keyspaces keep the store bounded (P1-4). `outbox_pending` indexes
//! the outbox entries not yet posted or retired, so a tick reads only those,
//! never the history. `retention` is a day-bucketed schedule
//! (`d{day:08}/{kind}/{key}`) of what [`BridgeStore::prune`] may delete once the
//! retention period has passed: `j` a journal row, `o` an outbox row (written
//! only when its remote effect is confirmed or it is retired), `x` an expiring
//! xref key. Each index entry is written BEFORE the row it describes and
//! removed AFTER the row is updated, so a crash leaves a stale index entry
//! (tolerated and cleaned) and never an unindexed pending row.
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
use crate::store::{BridgeStore, PruneStats, StateSpace};
use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Index of outbox entries not yet posted or retired (key to a marker).
pub const KS_OUTBOX_PENDING: &str = "outbox_pending";
/// Day-bucketed schedule of what may be pruned.
pub const KS_RETENTION: &str = "retention";

/// Every keyspace, in one place.
pub const ALL_KEYSPACES: [&str; 9] = [
    KS_LINKS,
    KS_CURSORS,
    KS_JOURNAL_IN,
    KS_OUTBOX_OUT,
    KS_XREF,
    KS_GEB_MLS,
    KS_RATCHETS,
    KS_OUTBOX_PENDING,
    KS_RETENTION,
];

/// Cursor set once the pending index and the retention schedule were built for
/// a store that predates them.
const FLAG_INDEX: &str = "outbox_index_v1";
/// Cursor: the first day bucket not yet pruned (big-endian u64).
const PRUNE_FLOOR: &str = "prune_floor";
const DAY: u64 = 86_400;
/// Most day buckets one prune visits (a clock jump cannot make it unbounded).
const MAX_DAYS_PER_PRUNE: u64 = 4_000;
/// Which xref keys may expire: nothing else is ever deleted from the xref.
const EXPIRING_XREF: [&str; 2] = ["foreign:", "failed:"];

fn retention_key(day: u64, kind: char, key: &str) -> String {
    format!("d{day:08}/{kind}/{key}")
}

/// Unix seconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize, Deserialize)]
struct OutboxEntry {
    event: BridgeEvent,
    /// 0 accepted, 1 relayed, 2 delivered; `None` while unposted.
    receipt: Option<u8>,
    /// Given up on for good (dead-lettered): not pending, prunable after
    /// retention. Absent in rows written before P1-4.
    #[serde(default)]
    retired: bool,
}

impl OutboxEntry {
    fn pending(&self) -> bool {
        self.receipt.is_none() && !self.retired
    }
    fn prunable(&self) -> bool {
        !self.pending()
    }
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
            "the store at {} is in use by another process (a running `openvti-bridges run`?). \
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
    outbox_pending: KeyspaceHandle,
    retention: KeyspaceHandle,
    clock: Clock,
    migrated: tokio::sync::OnceCell<()>,
    decodes: AtomicUsize,
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
            outbox_pending: ks(KS_OUTBOX_PENDING)?,
            retention: ks(KS_RETENTION)?,
            clock: Arc::new(system_secs),
            migrated: tokio::sync::OnceCell::new(),
            decodes: AtomicUsize::new(0),
            _store: store,
        })
    }

    /// Use `clock` (Unix seconds) to date retention entries. Tests only need
    /// this; the default is the system clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// How many outbox rows this store has JSON-decoded since it was opened:
    /// the measure of the work a tick does over the outbox.
    pub fn decode_count(&self) -> usize {
        self.decodes.load(Ordering::Relaxed)
    }

    fn decode(&self, raw: &[u8]) -> Result<OutboxEntry> {
        self.decodes.fetch_add(1, Ordering::Relaxed);
        serde_json::from_slice(raw)
            .map_err(|e| Error::Store(format!("outbox entry does not decode: {e}")))
    }

    /// Schedule `key` for pruning in today's bucket. Written before the thing
    /// it schedules, so a crash leaves a schedule entry for nothing (pruning
    /// it is a no-op), never a row that is never pruned.
    async fn schedule(&self, kind: char, key: &str) -> Result<()> {
        let k = retention_key((self.clock)() / DAY, kind, key);
        self.retention
            .insert_raw(k, vec![1])
            .await
            .map_err(store_err)?;
        sync(&self.retention).await
    }

    async fn unindex(&self, key: &str) -> Result<()> {
        self.outbox_pending.remove(key).await.map_err(store_err)?;
        sync(&self.outbox_pending).await
    }

    /// Build the pending index and the retention schedule for a store that
    /// predates them, once (guarded by a cursor flag; safe to repeat after a
    /// crash). Rows already posted are scheduled in today's bucket, so they
    /// age out a full retention period after the upgrade.
    async fn ensure_migrated(&self) -> Result<()> {
        self.migrated
            .get_or_try_init(|| self.migrate())
            .await
            .map(|_| ())
    }

    async fn migrate(&self) -> Result<()> {
        if self
            .cursors
            .get_raw(FLAG_INDEX)
            .await
            .map_err(store_err)?
            .is_some()
        {
            return Ok(());
        }
        let today = (self.clock)() / DAY;
        for (k, v) in self
            .outbox_out
            .prefix_iter_raw(Vec::new())
            .await
            .map_err(store_err)?
        {
            let key = String::from_utf8_lossy(&k).into_owned();
            if self.decode(&v)?.pending() {
                self.outbox_pending
                    .insert_raw(key, vec![1])
                    .await
                    .map_err(store_err)?;
            } else {
                self.retention
                    .insert_raw(retention_key(today, 'o', &key), vec![1])
                    .await
                    .map_err(store_err)?;
            }
        }
        for k in self
            .journal_in
            .prefix_keys(Vec::new())
            .await
            .map_err(store_err)?
        {
            let key = String::from_utf8_lossy(&k).into_owned();
            self.retention
                .insert_raw(retention_key(today, 'j', &key), vec![1])
                .await
                .map_err(store_err)?;
        }
        for prefix in EXPIRING_XREF {
            for k in self.xref.prefix_keys(prefix).await.map_err(store_err)? {
                let key = String::from_utf8_lossy(&k).into_owned();
                self.retention
                    .insert_raw(retention_key(today, 'x', &key), vec![1])
                    .await
                    .map_err(store_err)?;
            }
        }
        if self
            .cursors
            .get_raw(PRUNE_FLOOR)
            .await
            .map_err(store_err)?
            .is_none()
        {
            self.cursors
                .insert_raw(PRUNE_FLOOR, today.to_be_bytes().to_vec())
                .await
                .map_err(store_err)?;
        }
        sync(&self.outbox_pending).await?;
        sync(&self.retention).await?;
        sync(&self.cursors).await?;
        self.cursors
            .insert_raw(FLAG_INDEX, vec![1])
            .await
            .map_err(store_err)?;
        sync(&self.cursors).await
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
        self.ensure_migrated().await?;
        if self
            .journal_in
            .get_raw(key)
            .await
            .map_err(store_err)?
            .is_some()
        {
            return Ok(false);
        }
        self.schedule('j', key).await?;
        let new = self
            .journal_in
            .insert_if_absent(key, event)
            .await
            .map_err(store_err)?;
        sync(&self.journal_in).await?;
        Ok(new)
    }

    async fn outbox_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        self.ensure_migrated().await?;
        if self
            .outbox_out
            .get_raw(key)
            .await
            .map_err(store_err)?
            .is_some()
        {
            return Ok(false);
        }
        // Index first, then the row: a crash between leaves an index entry
        // for no row, which `outbox_unposted` removes.
        self.outbox_pending
            .insert_raw(key, vec![1])
            .await
            .map_err(store_err)?;
        sync(&self.outbox_pending).await?;
        let entry = OutboxEntry {
            event: event.clone(),
            receipt: None,
            retired: false,
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
        self.ensure_migrated().await?;
        let mut entry: OutboxEntry = self
            .outbox_out
            .get(key)
            .await
            .map_err(store_err)?
            .ok_or_else(|| Error::Store(format!("no outbox entry {key}")))?;
        // Receipts only move forward.
        if entry.receipt.is_none_or(|r| rank(receipt) > r) {
            if entry.receipt.is_none() {
                // The remote effect is now confirmed: from here the row may
                // be pruned after retention (never before: no schedule entry
                // exists for an unposted row).
                self.schedule('o', key).await?;
            }
            entry.receipt = Some(rank(receipt));
            self.outbox_out
                .insert(key, &entry)
                .await
                .map_err(store_err)?;
            sync(&self.outbox_out).await?;
        }
        // Remove from the index after the row says posted (also cleans an
        // entry a crash left behind).
        self.unindex(key).await
    }

    async fn outbox_receipt(&self, key: &str) -> Result<Option<Receipt>> {
        let entry: Option<OutboxEntry> = self.outbox_out.get(key).await.map_err(store_err)?;
        Ok(entry.and_then(|e| e.receipt).map(unrank))
    }

    async fn outbox_retire(&self, key: &str) -> Result<()> {
        self.ensure_migrated().await?;
        let Some(mut entry) = self
            .outbox_out
            .get::<OutboxEntry>(key)
            .await
            .map_err(store_err)?
        else {
            return self.unindex(key).await;
        };
        if !entry.retired && entry.receipt.is_none() {
            self.schedule('o', key).await?;
            entry.retired = true;
            self.outbox_out
                .insert(key, &entry)
                .await
                .map_err(store_err)?;
            sync(&self.outbox_out).await?;
        }
        self.unindex(key).await
    }

    async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>> {
        self.ensure_migrated().await?;
        let mut out = Vec::new();
        let mut stale = Vec::new();
        // Only the index is walked: the work is the pending entries, not the
        // history. An index entry whose row is gone or no longer pending is
        // what a crash leaves; it is removed here.
        for k in self
            .outbox_pending
            .prefix_keys(Vec::new())
            .await
            .map_err(store_err)?
        {
            let key = String::from_utf8_lossy(&k).into_owned();
            match self.outbox_out.get_raw(k).await.map_err(store_err)? {
                Some(v) => {
                    let entry = self.decode(&v)?;
                    if entry.pending() {
                        out.push((key, entry.event));
                    } else {
                        stale.push(key);
                    }
                }
                None => stale.push(key),
            }
        }
        if !stale.is_empty() {
            for k in &stale {
                self.outbox_pending
                    .remove(k.as_str())
                    .await
                    .map_err(store_err)?;
            }
            sync(&self.outbox_pending).await?;
        }
        Ok(out)
    }

    async fn outbox_pending_keys(&self) -> Result<Vec<String>> {
        self.ensure_migrated().await?;
        let mut out = Vec::new();
        for k in self
            .outbox_pending
            .prefix_keys(Vec::new())
            .await
            .map_err(store_err)?
        {
            let key = String::from_utf8_lossy(&k).into_owned();
            if let Some(v) = self.outbox_out.get_raw(k).await.map_err(store_err)?
                && self.decode(&v)?.pending()
            {
                out.push(key);
            }
        }
        Ok(out)
    }

    async fn prune(&self, now_secs: u64, retention_secs: u64) -> Result<PruneStats> {
        self.ensure_migrated().await?;
        let mut stats = PruneStats::default();
        // A day bucket is prunable once the whole day is older than the
        // retention period.
        let end = now_secs.saturating_sub(retention_secs) / DAY;
        let mut day = self
            .cursors
            .get_raw(PRUNE_FLOOR)
            .await
            .map_err(store_err)?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(end);
        let stop = end.min(day.saturating_add(MAX_DAYS_PER_PRUNE));
        while day < stop {
            let prefix = format!("d{day:08}/");
            for k in self
                .retention
                .prefix_keys(prefix.as_str())
                .await
                .map_err(store_err)?
            {
                let full = String::from_utf8_lossy(&k).into_owned();
                let rest = &full[prefix.len()..];
                let (kind, key) = rest.split_once('/').unwrap_or((rest, ""));
                match kind {
                    "j" => {
                        self.journal_in.remove(key).await.map_err(store_err)?;
                        stats.journal += 1;
                    }
                    "o" => {
                        // Re-check the row: only a confirmed or retired one
                        // is ever deleted (R2.1), whatever the schedule says.
                        if let Some(v) = self.outbox_out.get_raw(key).await.map_err(store_err)?
                            && self.decode(&v)?.prunable()
                        {
                            self.outbox_out.remove(key).await.map_err(store_err)?;
                            stats.outbox += 1;
                        }
                    }
                    "x" if EXPIRING_XREF.iter().any(|p| key.starts_with(p)) => {
                        self.xref.remove(key).await.map_err(store_err)?;
                        stats.xref += 1;
                    }
                    _ => {}
                }
                self.retention.remove(k).await.map_err(store_err)?;
            }
            sync(&self.journal_in).await?;
            sync(&self.outbox_out).await?;
            sync(&self.xref).await?;
            sync(&self.retention).await?;
            day += 1;
            self.cursors
                .insert_raw(PRUNE_FLOOR, day.to_be_bytes().to_vec())
                .await
                .map_err(store_err)?;
            sync(&self.cursors).await?;
        }
        Ok(stats)
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

    async fn xref_set_expiring(&self, a: &str, b: &str) -> Result<()> {
        self.ensure_migrated().await?;
        self.schedule('x', a).await?;
        self.xref_set(a, b).await
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

    // --- P1-4: bounded work, pruning, sealing -------------------------------

    use crate::atrest::{AtRestKey, EncryptedState};
    use std::sync::atomic::AtomicU64;

    const DAYS: u64 = 86_400;

    fn store_at(dir: &Path, now: Arc<AtomicU64>) -> FjallStore {
        FjallStore::open(dir)
            .unwrap()
            .with_clock(Arc::new(move || now.load(Ordering::Relaxed)))
    }

    fn clock(secs: u64) -> Arc<AtomicU64> {
        Arc::new(AtomicU64::new(secs))
    }

    /// Rows as the steady state leaves them, written without the per-row
    /// fsync so five thousand of them do not take minutes.
    async fn seed_posted(s: &FjallStore, n: usize) {
        for i in 0..n {
            let e = OutboxEntry {
                event: ev(&format!("old{i}")),
                receipt: Some(1),
                retired: false,
            };
            s.outbox_out.insert(format!("k{i:05}"), &e).await.unwrap();
        }
        sync(&s.outbox_out).await.unwrap();
    }

    #[tokio::test]
    async fn a_tick_decodes_only_the_pending_entries_not_the_history() {
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path(), clock(10 * DAYS));
        // Open (and index) the empty store, then grow the history.
        assert!(s.outbox_unposted().await.unwrap().is_empty());
        seed_posted(&s, 5_000).await;
        for k in ["p1", "p2", "p3"] {
            assert!(s.outbox_insert(k, &ev(k)).await.unwrap());
        }
        let before = s.decode_count();
        let pending = s.outbox_unposted().await.unwrap();
        assert_eq!(pending.len(), 3);
        assert_eq!(
            s.decode_count() - before,
            3,
            "work must follow pending, not history"
        );
        // `status` is bounded the same way.
        let before = s.decode_count();
        assert_eq!(crate::ops::status(&s).await.unwrap().outbox_depth, 3);
        assert_eq!(s.decode_count() - before, 3);
    }

    #[tokio::test]
    async fn status_counts_pending_entries_without_any_key() {
        let dir = tempfile::tempdir().unwrap();
        {
            let raw = Arc::new(FjallStore::open(dir.path()).unwrap());
            let key = AtRestKey::derive(&[7u8; 32], "state").unwrap();
            let enc = EncryptedState::new(raw.clone(), key, "l1");
            let mut e = ev("a");
            e.text = "a secret bridged sentence".into();
            e.author = "did:key:zAuthorName".into();
            e.title = Some("a private title".into());
            enc.outbox_insert("l1|a|1", &e).await.unwrap();
            enc.journal_insert("l1|a|1", &e).await.unwrap();
            // The bodies are not on disk in clear.
            for ks in [&raw.outbox_out, &raw.journal_in] {
                let row = ks.get_raw("l1|a|1").await.unwrap().unwrap();
                let row = String::from_utf8_lossy(&row).into_owned();
                for needle in ["secret bridged", "private title", "zAuthorName"] {
                    assert!(!row.contains(needle), "{needle} in clear: {row}");
                }
            }
            // And they come back through the key.
            let back = enc.outbox_unposted().await.unwrap();
            assert_eq!(back[0].1, e);
            // A wrong key does not open them.
            let wrong = EncryptedState::new(
                raw.clone(),
                AtRestKey::derive(&[8u8; 32], "state").unwrap(),
                "l1",
            );
            assert!(wrong.outbox_unposted().await.is_err());
        }
        // The raw store, with no key at all, still reports the count.
        let raw = FjallStore::open(dir.path()).unwrap();
        assert_eq!(crate::ops::status(&raw).await.unwrap().outbox_depth, 1);
    }

    #[tokio::test]
    async fn an_unposted_entry_is_never_pruned_and_a_posted_one_is_after_retention() {
        let dir = tempfile::tempdir().unwrap();
        let now = clock(100 * DAYS);
        let s = store_at(dir.path(), now.clone());
        s.outbox_insert("unposted", &ev("u")).await.unwrap();
        s.outbox_insert("posted", &ev("p")).await.unwrap();
        s.outbox_mark("posted", Receipt::Accepted).await.unwrap();
        s.journal_insert("j1", &ev("j")).await.unwrap();
        s.xref_set_expiring("foreign:x", "k").await.unwrap();
        s.xref_set("vtc:p", "ref").await.unwrap();
        s.xref_set("vtkey:rec", "p").await.unwrap();
        // A schedule entry for the unposted row (a bug elsewhere) still does
        // not delete it: the row is re-checked.
        s.retention
            .insert_raw(retention_key(100, 'o', "unposted"), vec![1])
            .await
            .unwrap();
        // Inside retention: nothing goes.
        let st = s.prune(100 * DAYS + 6 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!(st, PruneStats::default());
        // Past it.
        let st = s.prune(100 * DAYS + 9 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!((st.journal, st.outbox, st.xref), (1, 1, 1));
        assert_eq!(s.outbox_receipt("posted").await.unwrap(), None);
        assert!(s.outbox_out.get_raw("unposted").await.unwrap().is_some());
        assert_eq!(s.outbox_unposted().await.unwrap().len(), 1);
        assert!(!s.xref_has("foreign:x").await.unwrap());
        assert!(s.xref_has("vtc:p").await.unwrap(), "vtc: is never pruned");
        assert!(
            s.xref_has("vtkey:rec").await.unwrap(),
            "vtkey: is never pruned"
        );
        // Even far in the future the unposted entry stays.
        s.prune(100 * DAYS + 900 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!(s.outbox_unposted().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_failed_but_unretired_entry_survives_and_a_retired_one_goes_after_retention() {
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path(), clock(50 * DAYS));
        s.outbox_insert("l|dead|1", &ev("d")).await.unwrap();
        s.outbox_insert("l|stuck|1", &ev("s")).await.unwrap();
        s.xref_set_expiring("failed:l|dead|1", "why").await.unwrap();
        s.xref_set_expiring("failed:l|stuck|1", "why")
            .await
            .unwrap();
        s.outbox_retire("l|dead|1").await.unwrap();
        // Retired entries leave the pending set at once.
        let keys = s.outbox_pending_keys().await.unwrap();
        assert_eq!(keys, vec!["l|stuck|1".to_string()]);
        s.prune(50 * DAYS + 3 * DAYS, 7 * DAYS).await.unwrap();
        assert!(s.outbox_out.get_raw("l|dead|1").await.unwrap().is_some());
        assert!(s.xref_has("failed:l|dead|1").await.unwrap());
        let st = s.prune(50 * DAYS + 9 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!(st.outbox, 1);
        assert!(s.outbox_out.get_raw("l|dead|1").await.unwrap().is_none());
        assert!(!s.xref_has("failed:l|dead|1").await.unwrap());
        // Unretired: kept, still an outbox row.
        assert!(s.outbox_out.get_raw("l|stuck|1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn pruning_never_causes_a_re_post_even_when_the_browse_cursor_is_lost() {
        use crate::config::Directions;
        use crate::loopback::Loopback;
        use crate::pump::{CURSOR_BROWSE as BROWSE_CURSOR, LinkRuntime, Pump};
        use crate::room::MemoryRoom;
        let dir = tempfile::tempdir().unwrap();
        // The pump prunes by the real clock (an hour after start, never within
        // the test), so the store is dated by it too.
        let t0 = system_secs();
        let store = Arc::new(store_at(dir.path(), clock(t0)));
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(Loopback::new("bridge-id"));
        let link = || LinkRuntime::new("l1", "did:key:persona", b"s".to_vec(), Directions::Both);
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        for i in 0..5 {
            room.add("did:alice", None, &format!("m{i}"), i + 1)
                .unwrap();
        }
        pump.tick().await.unwrap();
        assert_eq!(lb.posted().len(), 5);
        let st = store.prune(t0 + 30 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!(st.outbox, 5);
        assert!(st.journal == 0);
        // Lose the browse cursor: the whole room is offered again.
        store.set_cursor(BROWSE_CURSOR, &[]).await.unwrap();
        let again = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        let r = again.tick().await.unwrap();
        assert_eq!(
            r.posted, 0,
            "the vtc: cross-reference outlives the outbox row"
        );
        assert_eq!(lb.posted().len(), 5);
    }

    #[tokio::test]
    async fn a_store_from_before_the_index_is_rebuilt_once_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let now = clock(200 * DAYS);
        {
            let s = store_at(dir.path(), now.clone());
            // The old layout: rows with no `retired` field, no index.
            let old = |receipt: serde_json::Value| {
                serde_json::to_vec(&serde_json::json!({
                    "event": ev("o"), "receipt": receipt
                }))
                .unwrap()
            };
            s.outbox_out
                .insert_raw("a-pending", old(serde_json::Value::Null))
                .await
                .unwrap();
            s.outbox_out
                .insert_raw("b-posted", old(1.into()))
                .await
                .unwrap();
            s.outbox_out
                .insert_raw("c-posted", old(0.into()))
                .await
                .unwrap();
            s.journal_in.insert("j-old", &ev("j")).await.unwrap();
            s.xref
                .insert_raw("foreign:old", b"k".to_vec())
                .await
                .unwrap();
            s.xref
                .insert_raw("failed:in:old", b"why".to_vec())
                .await
                .unwrap();
            s.xref.insert_raw("vtc:b", b"r".to_vec()).await.unwrap();
            sync(&s.outbox_out).await.unwrap();
        }
        let s = store_at(dir.path(), now.clone());
        let before = s.decode_count();
        let pending = s.outbox_unposted().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "a-pending");
        // One pass over the history to build the index (3 rows), once.
        assert_eq!(s.decode_count() - before, 3 + 1);
        let again = s.decode_count();
        s.outbox_unposted().await.unwrap();
        assert_eq!(s.decode_count() - again, 1);
        drop(s);
        // Reopened: the flag stops a second rebuild.
        let s = store_at(dir.path(), now.clone());
        let before = s.decode_count();
        s.outbox_unposted().await.unwrap();
        assert_eq!(s.decode_count() - before, 1);
        // Old history ages out one retention period after the upgrade.
        let st = s.prune(200 * DAYS + 3 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!(st, PruneStats::default());
        let st = s.prune(200 * DAYS + 9 * DAYS, 7 * DAYS).await.unwrap();
        assert_eq!((st.journal, st.outbox, st.xref), (1, 2, 2));
        assert!(s.xref_has("vtc:b").await.unwrap());
        assert_eq!(s.outbox_unposted().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_crash_between_the_index_and_the_row_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let s = store_at(dir.path(), clock(5 * DAYS));
        // Index entry written, row never: the pending set ignores it and
        // removes it.
        s.outbox_pending.insert_raw("ghost", vec![1]).await.unwrap();
        assert!(s.outbox_unposted().await.unwrap().is_empty());
        assert!(
            s.outbox_pending
                .prefix_keys(Vec::new())
                .await
                .unwrap()
                .is_empty()
        );
        // The insert after such a crash works and is pending.
        s.outbox_pending.insert_raw("real", vec![1]).await.unwrap();
        assert!(s.outbox_insert("real", &ev("r")).await.unwrap());
        assert_eq!(s.outbox_unposted().await.unwrap().len(), 1);
        // Row marked posted, index entry not yet removed: not pending, and
        // cleaned.
        let e = OutboxEntry {
            event: ev("r"),
            receipt: Some(0),
            retired: false,
        };
        s.outbox_out.insert("real", &e).await.unwrap();
        assert!(s.outbox_unposted().await.unwrap().is_empty());
        assert!(
            s.outbox_pending
                .prefix_keys(Vec::new())
                .await
                .unwrap()
                .is_empty()
        );
    }
}
