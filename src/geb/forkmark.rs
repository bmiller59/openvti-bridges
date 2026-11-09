//! A minimal, NON-SECRET marker that the Geb room has split, kept where
//! `status` can read it.
//!
//! The split itself is recorded in the sealed MLS snapshot
//! (`Snapshot.heal.split`), which `status` cannot open: it reads the store
//! without keys. So the client also writes this record, the same way the halt
//! record is stored: a named cursor of the link's store, in clear (an empty
//! value reads as none). It says only that a split happened, between which
//! epochs, when, and where it stands. **No key, no plaintext, no commit or
//! message bytes, no secret, and no peer identity**: a field is added here only
//! if it is safe to print on a terminal and to keep unencrypted.
//!
//! States:
//! - `waiting-for-reseat`: our branch lost; we wait for the elected healer's
//!   re-seat Welcome (we never heal, and never ask to be re-seated from a fork);
//! - `branch-won`: our branch won; the other side must be re-seated, by the
//!   healer, not by us;
//! - `reseated`: a re-seat Welcome was accepted and our group replaced. The
//!   record stays, in this state, until a later split replaces it, so `status`
//!   shows that the last split was resolved and when.

use crate::store::BridgeStore;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// The marker's name (a cursor of the link's store).
pub const FORK: &str = "fork";

/// Where a split stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForkState {
    /// Our branch lost: waiting for a re-seat Welcome.
    WaitingForReseat,
    /// Our branch won: the other side is to be re-seated.
    BranchWon,
    /// A re-seat Welcome was accepted.
    Reseated,
}

impl std::fmt::Display for ForkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WaitingForReseat => "waiting-for-reseat",
            Self::BranchWon => "branch-won",
            Self::Reseated => "reseated",
        })
    }
}

/// The record. Epoch numbers and milliseconds only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForkMarker {
    /// Record version.
    pub v: u32,
    /// The link.
    pub link: String,
    /// Where the split stands.
    pub state: ForkState,
    /// The lowest epoch at which the two branches differ.
    pub fork_epoch: u64,
    /// Our epoch when the split was detected.
    pub our_epoch: u64,
    /// The other branch's epoch when it was detected.
    pub their_epoch: u64,
    /// When it was detected (ms).
    pub detected_at_ms: u64,
    /// When a re-seat resolved it (ms), once it did.
    pub reseated_at_ms: Option<u64>,
}

impl ForkMarker {
    /// Bytes for the store.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Store(format!("encode fork marker: {e}")))
    }

    /// Read a stored marker; a record that does not parse is `None` (the
    /// marker is informational, never an authority).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }

    /// One line for `status`.
    pub fn describe(&self) -> String {
        let mut s = format!(
            "fork {} (epoch {}, ours {} theirs {}, detected {} ms)",
            self.state, self.fork_epoch, self.our_epoch, self.their_epoch, self.detected_at_ms
        );
        if let Some(t) = self.reseated_at_ms {
            s.push_str(&format!(", re-seated at {t} ms"));
        }
        s
    }
}

/// The marker recorded in `store`, if any (an empty record reads as none).
pub async fn read(store: &dyn BridgeStore) -> Result<Option<ForkMarker>> {
    Ok(store
        .cursor(FORK)
        .await?
        .filter(|b| !b.is_empty())
        .and_then(|b| ForkMarker::decode(&b)))
}

/// Record a marker.
pub async fn write(store: &dyn BridgeStore, m: &ForkMarker) -> Result<()> {
    store.set_cursor(FORK, &m.encode()?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn marker(state: ForkState) -> ForkMarker {
        ForkMarker {
            v: 1,
            link: "l1".into(),
            state,
            fork_epoch: 7,
            our_epoch: 9,
            their_epoch: 8,
            detected_at_ms: 1_700_000_000_000,
            reseated_at_ms: None,
        }
    }

    #[tokio::test]
    async fn a_marker_round_trips_and_an_empty_record_is_none() {
        let s = MemoryStore::new();
        assert_eq!(read(&s).await.unwrap(), None);
        let m = marker(ForkState::WaitingForReseat);
        write(&s, &m).await.unwrap();
        assert_eq!(read(&s).await.unwrap(), Some(m));
        s.set_cursor(FORK, &[]).await.unwrap();
        assert_eq!(read(&s).await.unwrap(), None);
        s.set_cursor(FORK, b"not json").await.unwrap();
        assert_eq!(read(&s).await.unwrap(), None, "informational, never fatal");
    }

    #[test]
    fn the_record_carries_numbers_and_names_only() {
        let v: serde_json::Value =
            serde_json::from_slice(&marker(ForkState::Reseated).encode().unwrap()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "detectedAtMs",
                "forkEpoch",
                "link",
                "ourEpoch",
                "reseatedAtMs",
                "state",
                "theirEpoch",
                "v"
            ]
        );
        assert_eq!(v["state"], "reseated");
        assert!(
            marker(ForkState::BranchWon)
                .describe()
                .contains("branch-won")
        );
    }
}
