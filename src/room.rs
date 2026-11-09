//! The VTC data-room side as the core sees it. The real implementation over
//! `VtaClient` is M1; [`MemoryRoom`] is the test double.

use crate::{Error, Result};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// First line of a bridged record's body. A record starting with it was
/// written by a bridge and is never bridged again.
pub const PROVENANCE_OPEN: &str = "```vti-bridge-provenance";

/// A record read from the room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRecord {
    /// Record key.
    pub key: String,
    /// Host version (arrival order at the host).
    pub version: u64,
    /// Author persona DID.
    pub author: String,
    /// Optional title.
    pub title: Option<String>,
    /// Body.
    pub body: String,
    /// Timestamp in ms.
    pub at: u64,
    /// A tombstone: the record was retracted in the room. It carries no
    /// content (`title` and `body` are empty); `version` is the version of
    /// the retraction, `key` the record retracted.
    pub retracted: bool,
}

impl RoomRecord {
    /// Whether a bridge wrote this record.
    pub fn is_bridged(&self) -> bool {
        self.body.starts_with(PROVENANCE_OPEN)
    }
}

/// A create-only record write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordWrite {
    /// Deterministic opaque key.
    pub key: String,
    /// Body with the provenance block.
    pub body: String,
    /// Epistemic basis; always `observed` for bridged content.
    pub basis: &'static str,
    /// Always 0: create only.
    pub expected_version: u64,
}

/// Result of a create-only put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// Written now.
    Created,
    /// The deterministic key already existed (a safe replay).
    AlreadyExists,
}

/// The room, as the pump uses it.
#[async_trait]
pub trait RoomSide: Send + Sync {
    /// Records with a version above `since_version`, in version order.
    async fn browse(&self, since_version: u64) -> Result<Vec<RoomRecord>>;
    /// Create-only write.
    async fn put(&self, write: &RecordWrite) -> Result<PutOutcome>;
}

/// In-memory room for tests.
#[derive(Default)]
pub struct MemoryRoom {
    inner: Mutex<MemoryRoomInner>,
}

#[derive(Default)]
struct MemoryRoomInner {
    next_version: u64,
    records: Vec<RoomRecord>,
    written: BTreeMap<String, RecordWrite>,
}

impl MemoryRoom {
    /// Empty room.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a record as a human member would; returns its version.
    pub fn add(&self, author: &str, title: Option<&str>, body: &str, at: u64) -> Result<u64> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?;
        g.next_version += 1;
        let version = g.next_version;
        let key = format!("r{version}");
        g.records.push(RoomRecord {
            key,
            version,
            author: author.into(),
            title: title.map(Into::into),
            body: body.into(),
            at,
            retracted: false,
        });
        Ok(version)
    }

    /// Write `key` (new, or a new version of an existing one) as a human
    /// member would. The version is the room-wide arrival counter, like the
    /// host's, so it says nothing about how many times `key` was written.
    pub fn edit(&self, key: &str, author: &str, body: &str, at: u64) -> Result<u64> {
        self.push(key, author, Some(body), at)
    }

    /// Retract `key`: a tombstone arrives at the next room-wide version.
    pub fn retract(&self, key: &str, author: &str, at: u64) -> Result<u64> {
        self.push(key, author, None, at)
    }

    /// Move the room-wide counter forward, as other keys' writes would.
    pub fn advance_to(&self, version: u64) -> Result<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?;
        g.next_version = g.next_version.max(version);
        Ok(())
    }

    fn push(&self, key: &str, author: &str, body: Option<&str>, at: u64) -> Result<u64> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?;
        g.next_version += 1;
        let version = g.next_version;
        g.records.push(RoomRecord {
            key: key.into(),
            version,
            author: author.into(),
            title: None,
            body: body.unwrap_or_default().into(),
            at,
            retracted: body.is_none(),
        });
        Ok(version)
    }

    /// Writes the bridge made, by key.
    pub fn writes(&self) -> Vec<RecordWrite> {
        self.inner
            .lock()
            .map(|g| g.written.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl RoomSide for MemoryRoom {
    async fn browse(&self, since_version: u64) -> Result<Vec<RoomRecord>> {
        let g = self
            .inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?;
        Ok(g.records
            .iter()
            .filter(|r| r.version > since_version)
            .cloned()
            .collect())
    }

    async fn put(&self, write: &RecordWrite) -> Result<PutOutcome> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| Error::Store("poisoned".into()))?;
        if g.written.contains_key(&write.key) {
            return Ok(PutOutcome::AlreadyExists);
        }
        g.next_version += 1;
        let version = g.next_version;
        g.written.insert(write.key.clone(), write.clone());
        // The bridge's own write is also a record, authored by the persona.
        g.records.push(RoomRecord {
            key: write.key.clone(),
            version,
            author: "did:key:persona".into(),
            title: None,
            body: write.body.clone(),
            at: 0,
            retracted: false,
        });
        Ok(PutOutcome::Created)
    }
}
