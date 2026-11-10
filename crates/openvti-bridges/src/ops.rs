//! Operator operations on an assembled link (features `vtc`, `geb-mls`):
//! `geb connect`, `geb stock-kps` and the data behind `status`.

use crate::foreign::JoinState;
use crate::geb::dyad::Phase;
use crate::geb::traits::GebGroup;
use crate::halt::HaltReason;
use crate::pump::{CURSOR_BROWSE, CURSOR_FOREIGN, LAST_RELAYED};
use crate::store::BridgeStore;
use crate::wiring::LinkParts;
use crate::{Error, Result};
use std::time::Duration;

/// Invite `peer_did` and drive the handshake until it connects or `timeout`
/// passes. Safe to repeat: the invitation is resumable (same nonce), and a
/// connected peer returns at once. Returns the phase reached.
pub async fn connect(
    parts: &LinkParts,
    peer_did: &str,
    display_name: Option<&str>,
    timeout: Duration,
    step: Duration,
) -> Result<Phase> {
    match parts.dyad.phase(peer_did).await? {
        // Nothing yet: answer an invitation they sent first, else send ours.
        None => {
            let mut answered = false;
            for inv in parts.dyad.invitations().await? {
                if inv.from == peer_did {
                    parts.dyad.accept(&inv).await?;
                    answered = true;
                }
            }
            if !answered {
                parts.dyad.invite(peer_did, display_name).await?;
            }
        }
        // Ours is outstanding: repost it (same nonce) in case the post failed.
        Some(Phase::Invited) => {
            parts.dyad.invite(peer_did, display_name).await?;
        }
        Some(_) => {}
    }
    let started = std::time::Instant::now();
    loop {
        parts.dyad.sync(peer_did).await?;
        match parts.dyad.phase(peer_did).await? {
            Some(Phase::Connected) => return Ok(Phase::Connected),
            Some(Phase::Expired) => {
                return Err(Error::Foreign(
                    "the invitation expired unanswered (7 days)".into(),
                ));
            }
            p if started.elapsed() >= timeout => {
                return Ok(p.unwrap_or(Phase::Invited));
            }
            _ => tokio::time::sleep(step).await,
        }
    }
}

/// Stock KeyPackages with the configured peers (and take a Welcome if one has
/// already arrived). The stock counts as consent to be added to the room.
pub async fn stock_kps(parts: &LinkParts) -> Result<JoinState> {
    parts.group.ensure_seated().await
}

/// A link's state as `status` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Last VTC room version read.
    pub browse_version: u64,
    /// Newest Geb relay `created_at` read (seconds), if any.
    pub foreign_cursor_secs: Option<u64>,
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
    /// The Geb room's last recorded fork split and where it stands, if any
    /// (a non-secret marker; the split itself is in the sealed MLS snapshot).
    pub fork: Option<crate::geb::forkmark::ForkMarker>,
    /// The pinned Geb reading.
    pub geb: String,
}

fn be8(b: Option<Vec<u8>>) -> Option<u64> {
    b.and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// Read a link's status from its store alone: no network, no keys.
pub async fn status(store: &dyn BridgeStore) -> Result<Status> {
    let outbox_depth = crate::pump::outbox_depth(store).await?;
    Ok(Status {
        browse_version: be8(store.cursor(CURSOR_BROWSE).await?).unwrap_or(0),
        foreign_cursor_secs: be8(store.cursor(CURSOR_FOREIGN).await?),
        outbox_depth,
        oversize_failed: be8(store.cursor(crate::pump::OVERSIZE_FAILED).await?).unwrap_or(0),
        dead_lettered: be8(store.cursor(crate::pump::DEAD_LETTERED).await?).unwrap_or(0),
        last_relayed_secs: be8(store.cursor(LAST_RELAYED).await?),
        halted: crate::halt::read(store).await?,
        fork: crate::geb::forkmark::read(store).await?,
        geb: crate::geb::status_line(),
    })
}
