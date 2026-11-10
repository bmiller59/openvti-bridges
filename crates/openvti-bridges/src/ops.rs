//! The data behind `status`: a link's state read from its store alone.

use crate::Result;
use openvti_bridge_core::adapter::BridgeKind;
use openvti_bridge_core::halt::HaltReason;
use openvti_bridge_core::pump::{CURSOR_BROWSE, CURSOR_FOREIGN, LAST_RELAYED};
use openvti_bridge_core::store::BridgeStore;

/// A link's state as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Last VTC room version read.
    pub browse_version: u64,
    /// The raw foreign cursor, if any; the kind renders it
    /// ([`BridgeKind::describe_cursor`]).
    pub foreign_cursor: Option<Vec<u8>>,
    /// Outbound events journalled but not yet posted (entries given up on for
    /// good are not pending and are counted in `oversize_failed`).
    pub outbox_depth: usize,
    /// Outbound entries given up on for good because they could not be made to
    /// fit the foreign room's size limit (journalled, never retried).
    pub oversize_failed: u64,
    /// Entries dead-lettered because they failed for a reason that cannot pass
    /// (a non-retryable room error, a line that cannot be encoded, a record
    /// the persona can never read), inbound and outbound; each is journalled
    /// in the xref as `failed:...` with its reason.
    pub dead_lettered: u64,
    /// When a post was last read back from the relay (unix seconds).
    pub last_relayed_secs: Option<u64>,
    /// Why the link is halted, if it is.
    pub halted: Option<HaltReason>,
    /// What the link's kind adds ([`BridgeKind::status_lines`]), one line each.
    pub adapter_lines: Vec<String>,
}

fn be8(b: Option<Vec<u8>>) -> Option<u64> {
    b.and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// Read a link's status from its store alone: no network, no keys.
pub async fn status(store: &dyn BridgeStore, kind: &dyn BridgeKind) -> Result<Status> {
    let outbox_depth = openvti_bridge_core::pump::outbox_depth(store).await?;
    Ok(Status {
        browse_version: be8(store.cursor(CURSOR_BROWSE).await?).unwrap_or(0),
        foreign_cursor: store.cursor(CURSOR_FOREIGN).await?,
        outbox_depth,
        oversize_failed: be8(store
            .cursor(openvti_bridge_core::pump::OVERSIZE_FAILED)
            .await?)
        .unwrap_or(0),
        dead_lettered: be8(store
            .cursor(openvti_bridge_core::pump::DEAD_LETTERED)
            .await?)
        .unwrap_or(0),
        last_relayed_secs: be8(store.cursor(LAST_RELAYED).await?),
        halted: openvti_bridge_core::halt::read(store).await?,
        adapter_lines: kind.status_lines(store).await?,
    })
}
