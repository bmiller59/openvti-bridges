//! The two pumps, written against [`ForeignRoom`] only.
//!
//! Remote-first (R2.1): an outbound event is journalled in the outbox and the
//! browse cursor advanced before the post; a crash between the two is
//! repaired by retrying the outbox first. An inbound event is journalled
//! before the record is written, and the foreign cursor advances only after
//! the write; the write is create-only on a deterministic key, so replay is
//! safe. A receipt is evidence of how far a post got, never more (R1.1).
//!
//! Retry of the foreign domain's transport belongs to the supervisor (M4);
//! a failed tick returns its error and the next tick resumes.

use crate::config::Directions;
use crate::foreign::{Cursor, ForeignRoom, JoinState};
use crate::halt::HaltReason;
use crate::mapping::{
    Notices, foreign_to_record, origin_id_for, prepare_outbound, record_to_event,
};
use crate::model::{BridgeEvent, EventKind, Origin};
use crate::pause::{NeverPaused, PauseSource};
use crate::room::{PutOutcome, RoomSide};
use crate::store::BridgeStore;
use crate::{Error, Result};
use std::sync::{Arc, Mutex};

const BROWSE_CURSOR: &str = "browse";
const FOREIGN_CURSOR: &str = "foreign";
/// Set (with the reason, see [`crate::halt`]) when the foreign room refused or
/// removed the bridge, or a commit cannot be decided. A stopped link is never
/// retried; an operator clears it deliberately (`link clear-halt`).
const HALT: &str = crate::halt::HALT;
/// Prefix of the xref entry that says a VTC record KEY was bridged: its value
/// is the `origin_id` of the newest version of that key posted (the line id
/// is the value of `vtc:<origin_id>`).
const XREF_KEY: &str = "vtkey:";
/// Unix seconds of the last post the foreign room read back (`status` shows it).
pub const LAST_RELAYED: &str = "last_relayed";
/// Browse cursor name, for `status`.
pub const CURSOR_BROWSE: &str = BROWSE_CURSOR;
/// Foreign cursor name, for `status`.
pub const CURSOR_FOREIGN: &str = FOREIGN_CURSOR;
/// Halt record name, for `status`.
pub const CURSOR_HALT: &str = HALT;
/// Count (big-endian u64) of outbox entries given up on for good because they
/// could not be made to fit the foreign room's size limit; `status` shows it.
pub const OVERSIZE_FAILED: &str = "oversize_failed";
/// Prefix of the xref entry that journals such a permanent failure, keyed by
/// the outbox key; its value is the reason. An entry with one is never posted
/// again and no longer counts as pending.
pub const FAILED_PREFIX: &str = "failed:";

/// Outbound events journalled, not yet posted and not dead-lettered. Bounded by
/// the pending index, so it decodes only pending entries and opens no body.
pub async fn outbox_depth(store: &dyn BridgeStore) -> Result<usize> {
    let mut depth = 0;
    for key in store.outbox_pending_keys().await? {
        if !store.xref_has(&format!("{FAILED_PREFIX}{key}")).await? {
            depth += 1;
        }
    }
    Ok(depth)
}
/// Count (big-endian u64) of entries dead-lettered because they failed for a
/// reason that cannot pass (a non-retryable room error, a line that cannot be
/// encoded, a record the room will never let the persona read); `status`
/// shows it. Each is journalled in the xref (`failed:...`) with its reason.
pub const DEAD_LETTERED: &str = "dead_lettered";

/// What a link needs at run time.
#[derive(Debug, Clone)]
pub struct LinkRuntime {
    /// Link id.
    pub id: String,
    /// The bridge's persona DID in the VTC room.
    pub persona: String,
    /// Secret for deterministic record keys.
    pub link_secret: Vec<u8>,
    /// Allowed flow.
    pub directions: Directions,
    /// Foreign authors whose messages are never bridged.
    pub deny_list: Vec<String>,
    /// The name used in the join announcement, if any.
    pub display_name: Option<String>,
    /// Post a one-time join announcement line when seated.
    pub announce: bool,
    /// Wording of retraction and update notices.
    pub notices: Notices,
    /// Days a confirmed outbox row, a journal row and an expiring xref key are
    /// kept before they are pruned. At least 1.
    pub retention_days: u32,
}

/// The default retention: it matches Geb's relay retention (seven days), so
/// nothing is forgotten that the foreign relay could still replay.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// The pump prunes at most this often.
const PRUNE_EVERY_SECS: u64 = 3_600;
/// Cursor: Unix seconds of the last successful prune.
pub const LAST_PRUNE: &str = "last_prune";

impl LinkRuntime {
    /// A link with no display name, no announcement and default notices.
    pub fn new(id: &str, persona: &str, link_secret: Vec<u8>, directions: Directions) -> Self {
        Self {
            id: id.into(),
            persona: persona.into(),
            link_secret,
            directions,
            deny_list: Vec::new(),
            display_name: None,
            announce: false,
            notices: Notices::default(),
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }

    fn announcement(&self) -> String {
        let what = "a bridge connects this room to a VTC data room; messages are relayed between the two and quoted with their author";
        match &self.display_name {
            Some(n) => format!("{n}: {what}."),
            None => format!("Note: {what}."),
        }
    }
}

/// Counts from one tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickReport {
    /// Posted to the foreign room.
    pub posted: usize,
    /// Records written to the VTC room.
    pub written: usize,
    /// Events skipped (echo, deny-list, already bridged, already journalled).
    pub skipped: usize,
    /// Outbound entries given up on for good this tick (over the room's size
    /// limit and not postable): journalled, never retried.
    pub failed: usize,
}

/// What became of one outbox entry.
enum Step {
    /// Posted.
    Posted,
    /// The kill switch is on: nothing was done; stop the tick.
    Paused,
    /// Permanently failed (journalled): carry on with the next one.
    Failed,
}

/// One link's pump.
pub struct Pump {
    link: LinkRuntime,
    room: Arc<dyn RoomSide>,
    foreign: Arc<dyn ForeignRoom>,
    store: Arc<dyn BridgeStore>,
    /// Seating is awaiting approval ("ask" rooms): nothing is read or posted.
    pending: Mutex<bool>,
    /// The kill switch (see [`crate::pause`]). Consulted at the start of a
    /// tick, before every outbound post and before every write into the VTC
    /// room; a step already begun finishes.
    pause: Arc<dyn PauseSource>,
}

/// A failure that stops the link (see [`HaltReason`]) rather than one tick.
fn is_halting(e: &Error) -> bool {
    matches!(
        e,
        Error::Refused(_) | Error::VtcRefused(_) | Error::UndecidableCommit(_)
    )
}

/// A failure no later try can pass: the room refused the write for good (a
/// non-retryable typed room error, such as a key collision) or the content
/// cannot be encoded for its destination. Retryable and transport errors are
/// not permanent, and a refusal that stops the link is handled by the guard.
fn is_permanent(e: &Error) -> bool {
    matches!(
        e,
        Error::Room {
            retryable: false,
            ..
        } | Error::Wire(_)
    )
}

async fn version_cursor(store: &dyn BridgeStore) -> Result<u64> {
    Ok(store
        .cursor(BROWSE_CURSOR)
        .await?
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0))
}

impl Pump {
    /// Build a pump.
    pub fn new(
        link: LinkRuntime,
        room: Arc<dyn RoomSide>,
        foreign: Arc<dyn ForeignRoom>,
        store: Arc<dyn BridgeStore>,
    ) -> Self {
        Self {
            link,
            room,
            foreign,
            store,
            pending: Mutex::new(false),
            pause: Arc::new(NeverPaused),
        }
    }

    /// Put the link behind a kill switch. A pump built without one never
    /// pauses.
    pub fn with_pause(mut self, pause: Arc<dyn PauseSource>) -> Self {
        self.pause = pause;
        self
    }

    /// Whether the kill switch is on (read fresh; unreadable counts as on).
    pub fn is_paused(&self) -> bool {
        self.pause.is_paused()
    }

    /// Whether seating is still pending approval.
    pub fn is_pending(&self) -> bool {
        self.pending.lock().map(|g| *g).unwrap_or(false)
    }

    fn set_pending(&self, p: bool) {
        if let Ok(mut g) = self.pending.lock() {
            *g = p;
        }
    }

    /// The reason the link was stopped, if it was.
    pub async fn halted(&self) -> Result<Option<HaltReason>> {
        crate::halt::read(self.store.as_ref()).await
    }

    /// The link must stop for good: persist why and alert, once (a halted link
    /// answers every later tick from the record without raising this again).
    /// No retry; a restart stays stopped.
    async fn halt(&self, reason: HaltReason) -> Error {
        match &reason {
            HaltReason::Refused { detail } => tracing::error!(
                link = %self.link.id,
                reason = %detail,
                security_alert = true,
                "the Geb room refused or removed the bridge; link stopped, not retrying"
            ),
            HaltReason::VtcRefused { detail } => tracing::error!(
                link = %self.link.id,
                reason = %detail,
                security_alert = true,
                "the VTA or room host refused the bridge (not Geb); link stopped, not \
                 retrying: fix the bridge's ACL grant, then `link clear-halt --yes`"
            ),
            HaltReason::UndecidableCommit { detail } => tracing::error!(
                link = %self.link.id,
                reason = %detail,
                security_alert = true,
                "a Geb commit cannot be decided with the knowledge this bridge has; link \
                 stopped, not retrying (see `link clear-halt`)"
            ),
        }
        match crate::halt::write(self.store.as_ref(), &reason).await {
            Ok(()) => reason.raised_error(),
            Err(e) => e,
        }
    }

    async fn guard<T>(&self, r: Result<T>) -> Result<T> {
        match r {
            Err(Error::Refused(why)) => Err(self.halt(HaltReason::refused(why)).await),
            Err(Error::VtcRefused(why)) => Err(self.halt(HaltReason::vtc_refused(why)).await),
            Err(Error::UndecidableCommit(why)) => {
                Err(self.halt(HaltReason::undecidable(why)).await)
            }
            other => other,
        }
    }

    /// Run both directions once. A stopped link errors without touching the
    /// foreign room; a pending seating is checked again and, while still
    /// pending, the tick does nothing.
    pub async fn tick(&self) -> Result<TickReport> {
        if let Some(why) = self.halted().await? {
            return Err(why.stopped_error());
        }
        let mut report = TickReport::default();
        // Paused: nothing is read, posted or written, no cursor moves, no
        // frame is sent (the poll answers fork and seat-ask traffic), and
        // nothing is acked. State is exactly as it was, so a resume carries on
        // from it.
        if self.is_paused() {
            return Ok(report);
        }
        if self.is_pending() && !self.join_and_announce().await? {
            return Ok(report);
        }
        let r = self.run_directions(&mut report).await;
        self.guard(r).await?;
        self.maybe_prune().await?;
        Ok(report)
    }

    /// Prune what is past retention, at most once an hour. A failure of the
    /// prune itself is housekeeping (logged, tried again next tick); the
    /// cursor reads and writes are the store's own and are errors like any
    /// other store error.
    async fn maybe_prune(&self) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let last = self
            .store
            .cursor(LAST_PRUNE)
            .await?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes);
        if last.is_some_and(|l| now.saturating_sub(l) < PRUNE_EVERY_SECS) {
            return Ok(());
        }
        let keep = u64::from(self.link.retention_days.max(1)) * 86_400;
        match self.store.prune(now, keep).await {
            Ok(st) => {
                if st.journal + st.outbox + st.xref > 0 {
                    tracing::info!(link = %self.link.id, journal = st.journal,
                        outbox = st.outbox, xref = st.xref, "pruned past retention");
                }
                self.store
                    .set_cursor(LAST_PRUNE, &now.to_be_bytes())
                    .await?;
            }
            Err(e) => {
                tracing::warn!(link = %self.link.id, error = %e, "pruning failed; will retry")
            }
        }
        Ok(())
    }

    /// Run both directions, each with its own cursor, even when one fails: a
    /// stuck direction must not starve the other. The first error is returned
    /// afterwards (a halting one wins, and stops the tick before the second
    /// direction touches the foreign room again).
    async fn run_directions(&self, report: &mut TickReport) -> Result<()> {
        let mut first: Option<Error> = None;
        if self.link.directions != Directions::FromForeign
            && let Err(e) = self.push_foreign(report).await
        {
            if is_halting(&e) {
                return Err(e);
            }
            first = Some(e);
        }
        if self.link.directions != Directions::ToForeign
            && !self.is_paused()
            && let Err(e) = self.pull_foreign(report).await
        {
            match first {
                Some(ref prev) if !is_halting(&e) => {
                    tracing::warn!(link = %self.link.id, error = %e, first = %prev,
                        "the inbound direction failed as well");
                }
                _ => first = Some(e),
            }
        }
        first.map_or(Ok(()), Err)
    }

    /// Join; when seated, post the one-time announcement if configured.
    /// `false` when seating is still pending.
    async fn join_and_announce(&self) -> Result<bool> {
        let joined = self.foreign.join().await;
        match self.guard(joined).await? {
            JoinState::Pending => {
                self.set_pending(true);
                Ok(false)
            }
            JoinState::Seated => {
                self.set_pending(false);
                let r = self.announce_once().await;
                self.guard(r).await?;
                Ok(true)
            }
        }
    }

    /// The optional join announcement: an ordinary signed line, posted once
    /// (the xref guards it; an unposted outbox entry is resumed by `tick`).
    async fn announce_once(&self) -> Result<()> {
        if !self.link.announce || self.link.directions == Directions::FromForeign {
            return Ok(());
        }
        let origin_id = format!("announce|{}", self.link.id);
        if self.store.xref_has(&format!("vtc:{origin_id}")).await? {
            return Ok(());
        }
        let ev = BridgeEvent {
            origin: Origin::Vtc,
            origin_id,
            link: self.link.id.clone(),
            author: self.link.persona.clone(),
            at: 0,
            title: None,
            text: self.link.announcement(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: None,
        };
        let key = format!("{}|{}", self.link.id, ev.origin_id);
        if self.store.outbox_insert(&key, &ev).await? {
            self.post_one(&key, &ev, &mut TickReport::default()).await?;
        }
        Ok(())
    }

    /// Give up on an outbox entry for good: journal why (xref `failed:<key>`),
    /// count it for `status` and log it. The entry is never posted again and
    /// is not retried every tick; the browse cursor is already past it.
    async fn fail_permanently(&self, key: &str, why: &str, r: &mut TickReport) -> Result<()> {
        self.store
            .xref_set_expiring(&format!("{FAILED_PREFIX}{key}"), why)
            .await?;
        self.store.outbox_retire(key).await?;
        let n = self
            .store
            .cursor(OVERSIZE_FAILED)
            .await?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        self.store
            .set_cursor(OVERSIZE_FAILED, &(n + 1).to_be_bytes())
            .await?;
        tracing::error!(link = %self.link.id, entry = %key, reason = %why,
            "an outbound entry cannot be made to fit the foreign room; given up on, not retried");
        r.failed += 1;
        Ok(())
    }

    /// Dead-letter one thing that failed for a reason that cannot pass:
    /// journal why in the xref under `xref_key` (once: a repeat does not count
    /// again), count it (`status` shows [`DEAD_LETTERED`]) and log it. The
    /// caller then lets its cursor pass.
    async fn dead_letter(
        &self,
        xref_key: &str,
        what: &str,
        err: &Error,
        r: &mut TickReport,
    ) -> Result<()> {
        if self.store.xref_has(xref_key).await? {
            return Ok(());
        }
        self.store
            .xref_set_expiring(xref_key, &err.to_string())
            .await?;
        let n = self
            .store
            .cursor(DEAD_LETTERED)
            .await?
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0);
        self.store
            .set_cursor(DEAD_LETTERED, &(n + 1).to_be_bytes())
            .await?;
        tracing::error!(link = %self.link.id, entry = %what, error = %err,
            "failed for a reason that cannot pass; dead-lettered, not retried");
        r.failed += 1;
        Ok(())
    }

    /// Post one journalled event. [`Step::Paused`] when the kill switch is on:
    /// nothing is posted and nothing is marked, so the entry stays unposted in
    /// the outbox and the next tick after a resume posts it exactly once. An
    /// entry over the room's size limit (it should have come out of the
    /// mapping layer smaller; an entry journalled under another limit may not)
    /// is a permanent, journalled failure rather than a retry every tick.
    async fn post_one(
        &self,
        key: &str,
        ev: &crate::model::BridgeEvent,
        r: &mut TickReport,
    ) -> Result<Step> {
        if self.is_paused() {
            return Ok(Step::Paused);
        }
        if self
            .store
            .xref_has(&format!("{FAILED_PREFIX}{key}"))
            .await?
        {
            // Journalled as failed before (possibly by an earlier version,
            // which did not retire it): make sure it leaves the pending set.
            self.store.outbox_retire(key).await?;
            return Ok(Step::Failed);
        }
        let limit = self.foreign.capabilities().max_message_units;
        let units = crate::mapping::utf16_units(&ev.text);
        if units > limit {
            self.fail_permanently(
                key,
                &format!("oversize: {units} UTF-16 code units, the room's limit is {limit}"),
                r,
            )
            .await?;
            return Ok(Step::Failed);
        }
        let posted = match self.foreign.post(ev).await {
            Ok(p) => p,
            // A line that cannot be encoded never will be: dead-letter it so
            // the browse cursor (already past it) and the outbox move on.
            Err(e) if is_permanent(&e) => {
                self.dead_letter(&format!("{FAILED_PREFIX}{key}"), key, &e, r)
                    .await?;
                self.store.outbox_retire(key).await?;
                return Ok(Step::Failed);
            }
            Err(e) => return Err(e),
        };
        // Keep the foreign id of the line: a later retraction answers it.
        // Both cross-references are written before the outbox entry is marked
        // posted, so a crash between the post and the mark re-posts (the
        // foreign room's own id dedups) rather than leaving a bridged line
        // that a later edit or retraction cannot find.
        self.store
            .xref_set(
                &format!("vtc:{}", ev.origin_id),
                posted.foreign_ref.as_deref().unwrap_or(""),
            )
            .await?;
        if let Some(k) = &ev.record_key {
            // The record KEY has now been bridged; this is the newest version
            // of it that was.
            self.store
                .xref_set(&format!("{XREF_KEY}{k}"), &ev.origin_id)
                .await?;
        }
        self.store.outbox_mark(key, posted.receipt).await?;
        if posted.receipt >= crate::foreign::Receipt::Relayed {
            let secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            self.store
                .set_cursor(LAST_RELAYED, &secs.to_be_bytes())
                .await?;
        }
        r.posted += 1;
        Ok(Step::Posted)
    }

    async fn push_foreign(&self, report: &mut TickReport) -> Result<()> {
        // Resume anything journalled but never posted.
        for (key, ev) in self.store.outbox_unposted().await? {
            if matches!(self.post_one(&key, &ev, report).await?, Step::Paused) {
                return Ok(());
            }
        }
        let caps = self.foreign.capabilities();
        let since = version_cursor(self.store.as_ref()).await?;
        let records = self.room.browse(since).await?;
        // Records the room will never let the persona read: journalled and
        // counted once each, then the cursor passes them (below).
        let mut passed = since;
        for sk in self.room.take_skipped() {
            let err = Error::Wire(sk.reason.clone());
            self.dead_letter(
                &format!("{}browse:{}@{}", FAILED_PREFIX, sk.key, sk.version),
                &sk.key,
                &err,
                report,
            )
            .await?;
            passed = passed.max(sk.version);
        }
        for rec in records {
            // Before anything for this record is journalled or the cursor
            // moves: a record not yet reached is browsed again after a resume.
            if self.is_paused() {
                return Ok(());
            }
            let done = self
                .store
                .xref_has(&format!("vtc:{}", origin_id_for(&rec)))
                .await?;
            // Whether this KEY was bridged before decides edit versus new
            // post (and whether a tombstone means anything): never `version`,
            // which is the room-wide arrival order.
            let prior = self
                .store
                .xref_get(&format!("{XREF_KEY}{}", rec.key))
                .await?
                .filter(|p| !p.is_empty());
            let ev = record_to_event(
                &rec,
                &self.link.id,
                &self.link.persona,
                |_| done,
                prior.as_deref(),
            );
            match ev {
                None => {
                    report.skipped += 1;
                    self.store
                        .set_cursor(BROWSE_CURSOR, &rec.version.to_be_bytes())
                        .await?;
                }
                Some(ev) => {
                    // Resolve the original's foreign id before the (sync) mapping.
                    let target = match &ev.kind {
                        EventKind::Supersede { replaces } => Some(replaces.clone()),
                        EventKind::Retract { target } => Some(target.clone()),
                        EventKind::Post => None,
                    };
                    let resolved = match target {
                        Some(t) => self
                            .store
                            .xref_get(&format!("vtc:{t}"))
                            .await?
                            .filter(|r| !r.is_empty())
                            .map(|r| (t, r)),
                        None => None,
                    };
                    let prepared = prepare_outbound(&ev, &caps, &self.link.notices, |id| {
                        resolved
                            .as_ref()
                            .filter(|(t, _)| t == id)
                            .map(|(_, r)| r.clone())
                    });
                    let key = format!("{}|{}", self.link.id, prepared.origin_id);
                    self.store.outbox_insert(&key, &prepared).await?;
                    self.store
                        .set_cursor(BROWSE_CURSOR, &rec.version.to_be_bytes())
                        .await?;
                    // Paused between the journal and the post: the entry is
                    // unposted in the outbox and goes out first after a resume.
                    if matches!(self.post_one(&key, &prepared, report).await?, Step::Paused) {
                        return Ok(());
                    }
                }
            }
        }
        if passed > version_cursor(self.store.as_ref()).await? {
            self.store
                .set_cursor(BROWSE_CURSOR, &passed.to_be_bytes())
                .await?;
        }
        Ok(())
    }

    async fn pull_foreign(&self, report: &mut TickReport) -> Result<()> {
        let me = self.foreign.identity().id;
        let after = self.store.cursor(FOREIGN_CURSOR).await?.map(Cursor);
        for p in self.foreign.poll(after.as_ref()).await? {
            // Paused mid-batch: nothing more is written into the VTC room and
            // the cursor stays where it was, so the rest is offered again (the
            // poll may return events at or before the cursor; the create-only
            // write dedups).
            if self.is_paused() {
                return Ok(());
            }
            let mut ev = p.event;
            ev.link = self.link.id.clone();
            let skip = ev.author == me || self.link.deny_list.contains(&ev.author);
            if skip {
                report.skipped += 1;
            } else {
                // Journal first; then the create-only put, which is attempted
                // even for a journalled event because a crash may have
                // separated the two. AlreadyExists makes the replay a no-op.
                self.store.journal_insert(&ev.origin_id, &ev).await?;
                let stored = async {
                    let write = foreign_to_record(&ev, &self.link.link_secret)?;
                    let outcome = self.room.put(&write).await?;
                    Ok::<_, Error>((write, outcome))
                }
                .await;
                match stored {
                    Ok((write, outcome)) => {
                        match outcome {
                            PutOutcome::Created => report.written += 1,
                            PutOutcome::AlreadyExists => report.skipped += 1,
                        }
                        self.store
                            .xref_set_expiring(&format!("foreign:{}", ev.origin_id), &write.key)
                            .await?;
                    }
                    // A write the room refuses for good (a collision, content
                    // it cannot take): dead-lettered, and the cursor passes it
                    // so it cannot hold every later message behind it.
                    Err(e) if is_permanent(&e) => {
                        self.dead_letter(
                            &format!("{FAILED_PREFIX}in:{}", ev.origin_id),
                            &ev.origin_id,
                            &e,
                            report,
                        )
                        .await?;
                    }
                    Err(e) => return Err(e),
                }
            }
            self.store.set_cursor(FOREIGN_CURSOR, &p.cursor.0).await?;
        }
        Ok(())
    }

    /// Join the foreign room. Kept here so callers need only the pump.
    /// `Pending` is returned as a state (the link idles until approved); a
    /// refusal stops the link and is an error. A previously stopped link
    /// stays stopped.
    pub async fn start(&self) -> Result<JoinState> {
        if self.link.persona.is_empty() {
            return Err(Error::Config("persona is empty".into()));
        }
        if let Some(why) = self.halted().await? {
            return Err(why.stopped_error());
        }
        // Paused: no join, no announcement. The supervisor starts again after
        // a resume.
        if self.is_paused() {
            return Ok(JoinState::Pending);
        }
        Ok(if self.join_and_announce().await? {
            JoinState::Seated
        } else {
            JoinState::Pending
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loopback::Loopback;
    use crate::room::MemoryRoom;
    use crate::store::MemoryStore;

    fn link() -> LinkRuntime {
        LinkRuntime {
            deny_list: vec!["did:evil".into()],
            ..LinkRuntime::new(
                "l1",
                "did:key:persona",
                b"secret".to_vec(),
                Directions::Both,
            )
        }
    }

    #[tokio::test]
    async fn loopback_both_directions_and_idempotent() {
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(Loopback::new("bridge-id"));
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();

        room.add("did:alice", Some("Title"), "hello foreign", 1)
            .unwrap();
        lb.inject("did:bob", "hello vtc", 2).unwrap();
        lb.inject("bridge-id", "my own echo", 3).unwrap();
        lb.inject("did:evil", "denied", 4).unwrap();

        let r = pump.tick().await.unwrap();
        assert_eq!((r.posted, r.written, r.skipped), (1, 1, 2));
        assert_eq!(lb.posted().len(), 1);
        assert!(lb.posted()[0].text.contains("hello foreign"));
        assert_eq!(room.writes().len(), 1);

        // The bridge's own write comes back through browse and is not echoed.
        let r2 = pump.tick().await.unwrap();
        assert_eq!((r2.posted, r2.written), (0, 0));
        assert_eq!(lb.posted().len(), 1);
    }

    #[tokio::test]
    async fn replay_after_losing_the_foreign_cursor_is_safe() {
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(Loopback::new("bridge-id"));
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.inject("did:bob", "once", 2).unwrap();
        pump.tick().await.unwrap();
        store.set_cursor(FOREIGN_CURSOR, &[]).await.unwrap();
        // Cursor lost: the same message is offered again; no second write.
        let fresh_store_cursor = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        let r = fresh_store_cursor.tick().await.unwrap();
        assert_eq!(r.written, 0);
        assert_eq!(room.writes().len(), 1);
    }

    #[tokio::test]
    async fn unposted_outbox_entries_are_resumed() {
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(Loopback::new("bridge-id"));
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        room.add("did:alice", None, "survives a crash", 1).unwrap();
        // Not joined: the post fails after the outbox insert and cursor advance.
        assert!(pump.tick().await.is_err());
        assert!(lb.posted().is_empty());
        pump.start().await.unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!(r.posted, 1);
        assert_eq!(lb.posted().len(), 1);
        // And exactly once.
        assert_eq!(pump.tick().await.unwrap().posted, 0);
    }

    #[tokio::test]
    async fn directions_are_honoured() {
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(Loopback::new("bridge-id"));
        let store = Arc::new(MemoryStore::new());
        let mut l = link();
        l.directions = Directions::ToForeign;
        let pump = Pump::new(l, room.clone(), lb.clone(), store);
        pump.start().await.unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        lb.inject("did:bob", "y", 2).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!((r.posted, r.written), (1, 0));
    }

    fn parts() -> (Arc<MemoryRoom>, Arc<Loopback>, Arc<MemoryStore>) {
        (
            Arc::new(MemoryRoom::new()),
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        )
    }

    #[tokio::test]
    async fn the_xref_keeps_the_foreign_line_id() {
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        pump.tick().await.unwrap();
        assert_eq!(
            store.xref_get("vtc:r1|1").await.unwrap().as_deref(),
            Some("lbline0")
        );
    }

    #[tokio::test]
    async fn pending_seating_is_a_state_not_an_error() {
        let (room, lb, store) = parts();
        lb.set_pending(true).unwrap();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store);
        assert_eq!(pump.start().await.unwrap(), JoinState::Pending);
        assert!(pump.is_pending());
        room.add("did:alice", None, "waits", 1).unwrap();
        lb.inject("did:bob", "ignored for now", 2).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!((r.posted, r.written, r.skipped), (0, 0, 0));
        assert!(lb.posted().is_empty());
        // Approved: the next tick seats the bridge and carries the backlog.
        lb.set_pending(false).unwrap();
        let r = pump.tick().await.unwrap();
        assert!(!pump.is_pending());
        assert_eq!((r.posted, r.written), (1, 1));
    }

    #[tokio::test]
    async fn refusal_stops_the_link_for_good() {
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.refuse("leaf removed").unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        assert!(matches!(pump.tick().await, Err(Error::Refused(_))));
        assert_eq!(
            pump.halted().await.unwrap(),
            Some(HaltReason::refused("leaf removed"))
        );
        // No retry: even after the room would accept us, the link stays down
        // and the foreign room is not touched.
        let lb2 = Arc::new(Loopback::new("bridge-id"));
        let again = Pump::new(link(), room, lb2.clone(), store);
        assert!(matches!(again.tick().await, Err(Error::Refused(_))));
        assert!(matches!(again.start().await, Err(Error::Refused(_))));
        assert!(lb2.posted().is_empty());
    }

    #[tokio::test]
    async fn refused_at_start_stops_the_link() {
        let (room, lb, store) = parts();
        lb.refuse("not welcome").unwrap();
        let pump = Pump::new(link(), room, lb, store);
        assert!(matches!(pump.start().await, Err(Error::Refused(_))));
        assert_eq!(
            pump.halted().await.unwrap(),
            Some(HaltReason::refused("not welcome"))
        );
    }

    #[tokio::test]
    async fn the_announcement_is_optional_and_posted_once() {
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        assert!(lb.posted().is_empty(), "off by default");

        let (room, lb, store) = parts();
        let mut l = link();
        l.announce = true;
        l.display_name = Some("Ada".into());
        let pump = Pump::new(l.clone(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        assert_eq!(lb.posted().len(), 1);
        assert!(lb.posted()[0].text.starts_with("Ada: a bridge connects"));
        pump.tick().await.unwrap();
        // A restart does not announce again.
        let pump2 = Pump::new(l, room, lb.clone(), store);
        pump2.start().await.unwrap();
        assert_eq!(lb.posted().len(), 1);
    }

    #[tokio::test]
    async fn the_announcement_waits_for_seating() {
        let (room, lb, store) = parts();
        lb.set_pending(true).unwrap();
        let mut l = link();
        l.announce = true;
        let pump = Pump::new(l, room, lb.clone(), store);
        pump.start().await.unwrap();
        pump.tick().await.unwrap();
        assert!(lb.posted().is_empty());
        lb.set_pending(false).unwrap();
        pump.tick().await.unwrap();
        assert_eq!(lb.posted().len(), 1);
        assert!(lb.posted()[0].text.starts_with("Note: a bridge connects"));
    }

    /// A loopback that, like Geb, can only reply: no native edit or delete.
    struct ReplyOnly(Loopback, std::sync::atomic::AtomicBool);
    #[async_trait::async_trait]
    impl ForeignRoom for ReplyOnly {
        async fn join(&self) -> Result<JoinState> {
            self.0.join().await
        }
        async fn leave(&self) -> Result<()> {
            self.0.leave().await
        }
        async fn poll(&self, a: Option<&Cursor>) -> Result<Vec<crate::foreign::Polled>> {
            self.0.poll(a).await
        }
        async fn post(&self, e: &BridgeEvent) -> Result<crate::foreign::Posted> {
            if self.1.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::Foreign("down".into()));
            }
            self.0.post(e).await
        }
        fn identity(&self) -> crate::foreign::ForeignIdentity {
            self.0.identity()
        }
        fn capabilities(&self) -> crate::foreign::RoomCapabilities {
            crate::foreign::RoomCapabilities {
                supports_edit: false,
                supports_delete: false,
                ..self.0.capabilities()
            }
        }
    }

    fn reply_parts() -> (Arc<MemoryRoom>, Arc<ReplyOnly>, Arc<MemoryStore>, Pump) {
        let room = Arc::new(MemoryRoom::new());
        let lb = Arc::new(ReplyOnly(Loopback::new("bridge-id"), Default::default()));
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        (room, lb, store, pump)
    }

    #[tokio::test]
    async fn an_edit_of_a_bridged_key_replies_to_the_earlier_line() {
        let (room, lb, _store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "first", 1).unwrap();
        // Other keys move the room-wide counter before the edit lands.
        room.add("did:alice", None, "other", 2).unwrap();
        pump.tick().await.unwrap();
        room.edit("r1", "did:alice", "first, revised", 3).unwrap();
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        let posted = lb.0.posted();
        assert_eq!(posted.len(), 3);
        assert_eq!(posted[2].reply_to.as_deref(), Some("lbline0"));
        assert!(posted[2].text.contains("[update to earlier post r1|1]"));
        assert!(posted[2].text.contains("first, revised"));
        // A second edit answers the newest earlier line.
        room.edit("r1", "did:alice", "third", 4).unwrap();
        pump.tick().await.unwrap();
        let posted = lb.0.posted();
        assert_eq!(posted[3].reply_to.as_deref(), Some("lbline2"));
    }

    #[tokio::test]
    async fn a_new_key_at_a_high_version_is_a_plain_post() {
        let (room, lb, _store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.advance_to(39).unwrap();
        let v = room.edit("brand-new", "did:alice", "hello", 1).unwrap();
        assert_eq!(v, 40);
        pump.tick().await.unwrap();
        let posted = lb.0.posted();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].kind, EventKind::Post);
        assert_eq!(posted[0].reply_to, None);
        assert!(!posted[0].text.contains("update to"));
    }

    #[tokio::test]
    async fn a_key_never_bridged_at_version_above_one_is_a_plain_post() {
        let (room, lb, _store, pump) = reply_parts();
        pump.start().await.unwrap();
        // The bridge only ever sees the key's newest version (an edit made
        // before it was linked): nothing was bridged before, so nothing is
        // replied to.
        room.advance_to(1).unwrap();
        let v = room
            .edit("edited-before-linking", "did:alice", "x2", 2)
            .unwrap();
        assert_eq!(v, 2);
        pump.tick().await.unwrap();
        let posted = lb.0.posted();
        assert_eq!(posted.len(), 1);
        assert_eq!(posted[0].reply_to, None);
        assert!(!posted[0].text.contains("update to"));
    }

    #[tokio::test]
    async fn pruning_runs_at_most_hourly_and_the_cursor_records_it() {
        let (room, _lb, store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        pump.tick().await.unwrap();
        let first = store
            .cursor(LAST_PRUNE)
            .await
            .unwrap()
            .expect("pruned once");
        // Within the hour: not again (the cursor is untouched).
        store
            .set_cursor(LAST_PRUNE, &u64::MAX.to_be_bytes())
            .await
            .unwrap();
        pump.tick().await.unwrap();
        assert_eq!(
            store.cursor(LAST_PRUNE).await.unwrap().unwrap(),
            u64::MAX.to_be_bytes()
        );
        // An hour on: again.
        store
            .set_cursor(LAST_PRUNE, &1u64.to_be_bytes())
            .await
            .unwrap();
        pump.tick().await.unwrap();
        assert_ne!(
            store.cursor(LAST_PRUNE).await.unwrap().unwrap(),
            1u64.to_be_bytes()
        );
        assert_eq!(first.len(), 8);
    }

    #[tokio::test]
    async fn replaying_the_browse_does_not_double_post_or_forget_the_key() {
        let (room, lb, store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "first", 1).unwrap();
        pump.tick().await.unwrap();
        room.edit("r1", "did:alice", "again", 2).unwrap();
        pump.tick().await.unwrap();
        assert_eq!(lb.0.posted().len(), 2);
        // The browse cursor is lost (a crash before it was saved, or a
        // restore): the whole room is offered again.
        store.set_cursor(BROWSE_CURSOR, &[]).await.unwrap();
        let again = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        let r = again.tick().await.unwrap();
        assert_eq!(r.posted, 0);
        assert_eq!(lb.0.posted().len(), 2);
    }

    #[tokio::test]
    async fn a_failed_post_is_replayed_once_and_only_then_is_the_key_bridged() {
        let (room, lb, store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "first", 1).unwrap();
        // Journalled and cursor advanced, then the post fails (a crash at
        // that point looks the same to the next process).
        lb.1.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(pump.tick().await.is_err());
        assert!(!store.xref_has("vtkey:r1").await.unwrap());
        let next = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        assert_eq!(next.tick().await.unwrap().posted, 1);
        assert_eq!(next.tick().await.unwrap().posted, 0);
        assert_eq!(lb.0.posted().len(), 1);
        assert_eq!(
            store.xref_get("vtkey:r1").await.unwrap().as_deref(),
            Some("r1|1")
        );
        // The edit now finds the line.
        room.edit("r1", "did:alice", "second", 2).unwrap();
        next.tick().await.unwrap();
        assert_eq!(lb.0.posted()[1].reply_to.as_deref(), Some("lbline0"));
    }

    #[tokio::test]
    async fn a_room_retraction_of_a_bridged_key_becomes_a_notice_reply() {
        let (room, lb, _store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "doomed", 1).unwrap();
        pump.tick().await.unwrap();
        room.retract("r1", "did:alice", 2).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!(r.posted, 1);
        let posted = lb.0.posted();
        assert_eq!(posted[1].kind, EventKind::Post, "never a new kind");
        assert_eq!(posted[1].reply_to.as_deref(), Some("lbline0"));
        assert!(posted[1].text.contains("[retracted: earlier post r1|1]"));
        // Not twice.
        assert_eq!(pump.tick().await.unwrap().posted, 0);
    }

    #[tokio::test]
    async fn a_tombstone_of_a_never_bridged_key_is_ignored() {
        let (room, lb, _store, pump) = reply_parts();
        pump.start().await.unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        room.retract("r1", "did:alice", 2).unwrap();
        room.retract("never-seen", "did:alice", 3).unwrap();
        let r = pump.tick().await.unwrap();
        // The first tick sees r1 only as its tombstone (the listing keeps one
        // row per key in the host; here both rows are offered): the content
        // row posts, the tombstone retracts it, the unknown key is ignored.
        assert_eq!(lb.0.posted().len(), 2, "{r:?}");
        assert!(r.skipped >= 1);
    }

    /// A foreign room whose poll cannot decide a commit.
    struct Undecidable(Loopback, std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl ForeignRoom for Undecidable {
        async fn join(&self) -> Result<JoinState> {
            self.0.join().await
        }
        async fn leave(&self) -> Result<()> {
            self.0.leave().await
        }
        async fn poll(&self, _: Option<&Cursor>) -> Result<Vec<crate::foreign::Polled>> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(Error::UndecidableCommit(
                "epoch 7, commit ab12: blocked".into(),
            ))
        }
        async fn post(&self, e: &BridgeEvent) -> Result<crate::foreign::Posted> {
            self.0.post(e).await
        }
        fn identity(&self) -> crate::foreign::ForeignIdentity {
            self.0.identity()
        }
        fn capabilities(&self) -> crate::foreign::RoomCapabilities {
            self.0.capabilities()
        }
    }

    #[tokio::test]
    async fn an_undecidable_commit_is_a_persisted_distinct_halt_that_survives_restart() {
        let room = Arc::new(MemoryRoom::new());
        let fr = Arc::new(Undecidable(Loopback::new("bridge-id"), Default::default()));
        let store = Arc::new(MemoryStore::new());
        let pump = Pump::new(link(), room.clone(), fr.clone(), store.clone());
        pump.start().await.unwrap();
        let e = pump.tick().await.unwrap_err();
        assert!(matches!(e, Error::UndecidableCommit(_)), "{e:?}");
        assert_eq!(
            pump.halted().await.unwrap(),
            Some(HaltReason::undecidable("epoch 7, commit ab12: blocked"))
        );
        // Every later tick answers from the record: the room is not polled
        // again (so nothing re-evaluates or re-alerts).
        for _ in 0..3 {
            let e = pump.tick().await.unwrap_err();
            assert!(matches!(e, Error::UndecidableCommit(ref w) if w.contains("link stopped")));
        }
        assert_eq!(fr.1.load(std::sync::atomic::Ordering::SeqCst), 1);
        // A new process over the same store stays halted, from start on.
        let again = Pump::new(link(), room, fr.clone(), store.clone());
        assert!(matches!(
            again.start().await,
            Err(Error::UndecidableCommit(_))
        ));
        assert!(matches!(
            again.tick().await,
            Err(Error::UndecidableCommit(_))
        ));
        assert_eq!(fr.1.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Clearing lets it run (and poll) again.
        crate::halt::clear(
            store.as_ref(),
            crate::halt::ClearConfirmation {
                yes: true,
                readmitted: false,
            },
        )
        .await
        .unwrap();
        assert!(again.halted().await.unwrap().is_none());
        assert!(matches!(
            again.tick().await,
            Err(Error::UndecidableCommit(_))
        ));
        assert_eq!(fr.1.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    // ---- the kill switch (`crate::pause`) ----

    use crate::pause::PauseSwitch;

    /// A store that flips the kill switch the moment the browse cursor moves:
    /// the pause lands between the outbox journal and the post.
    struct PauseOnBrowseCursor {
        inner: MemoryStore,
        switch: Arc<PauseSwitch>,
    }
    #[async_trait::async_trait]
    impl BridgeStore for PauseOnBrowseCursor {
        async fn cursor(&self, n: &str) -> Result<Option<Vec<u8>>> {
            self.inner.cursor(n).await
        }
        async fn set_cursor(&self, n: &str, v: &[u8]) -> Result<()> {
            self.inner.set_cursor(n, v).await?;
            if n == BROWSE_CURSOR {
                self.switch.set(true);
            }
            Ok(())
        }
        async fn journal_insert(&self, k: &str, e: &BridgeEvent) -> Result<bool> {
            self.inner.journal_insert(k, e).await
        }
        async fn outbox_insert(&self, k: &str, e: &BridgeEvent) -> Result<bool> {
            self.inner.outbox_insert(k, e).await
        }
        async fn outbox_mark(&self, k: &str, r: crate::foreign::Receipt) -> Result<()> {
            self.inner.outbox_mark(k, r).await
        }
        async fn outbox_receipt(&self, k: &str) -> Result<Option<crate::foreign::Receipt>> {
            self.inner.outbox_receipt(k).await
        }
        async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>> {
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
    }

    /// A foreign room that pauses the link right after its first post: the
    /// pause lands in the middle of a tick that has more to send.
    struct PauseAfterFirstPost {
        inner: Arc<Loopback>,
        switch: Arc<PauseSwitch>,
    }
    #[async_trait::async_trait]
    impl ForeignRoom for PauseAfterFirstPost {
        async fn join(&self) -> Result<JoinState> {
            self.inner.join().await
        }
        async fn leave(&self) -> Result<()> {
            self.inner.leave().await
        }
        async fn poll(&self, a: Option<&Cursor>) -> Result<Vec<crate::foreign::Polled>> {
            self.inner.poll(a).await
        }
        async fn post(&self, e: &BridgeEvent) -> Result<crate::foreign::Posted> {
            let r = self.inner.post(e).await;
            self.switch.set(true);
            r
        }
        fn identity(&self) -> crate::foreign::ForeignIdentity {
            self.inner.identity()
        }
        fn capabilities(&self) -> crate::foreign::RoomCapabilities {
            self.inner.capabilities()
        }
    }

    fn gated(
        switch: &Arc<PauseSwitch>,
    ) -> (Pump, Arc<MemoryRoom>, Arc<Loopback>, Arc<MemoryStore>) {
        let (room, lb, store) = parts();
        let pump =
            Pump::new(link(), room.clone(), lb.clone(), store.clone()).with_pause(switch.clone());
        (pump, room, lb, store)
    }

    #[tokio::test]
    async fn a_pause_stops_outbound_posts_and_a_resume_posts_the_pending_one_once() {
        let sw = Arc::new(PauseSwitch::new(false));
        let (pump, room, lb, store) = gated(&sw);
        pump.start().await.unwrap();
        room.add("did:alice", None, "first", 1).unwrap();
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        let browse_before = store.cursor(BROWSE_CURSOR).await.unwrap();

        sw.set(true);
        room.add("did:alice", None, "second", 2).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!(r, TickReport::default(), "a paused tick does nothing");
        assert_eq!(lb.posted().len(), 1, "the post after the pause is not made");
        assert_eq!(
            store.cursor(BROWSE_CURSOR).await.unwrap(),
            browse_before,
            "the cursor does not advance"
        );
        assert!(
            store.outbox_unposted().await.unwrap().is_empty(),
            "nothing journalled"
        );

        sw.set(false);
        assert_eq!(
            pump.tick().await.unwrap().posted,
            1,
            "the pending one goes out"
        );
        assert_eq!(lb.posted().len(), 2);
        assert_eq!(pump.tick().await.unwrap().posted, 0, "exactly once");
        assert_eq!(lb.posted().len(), 2);
    }

    #[tokio::test]
    async fn a_pause_in_the_middle_of_a_tick_keeps_the_rest_for_the_resume() {
        let sw = Arc::new(PauseSwitch::new(false));
        let (room, lb, store) = parts();
        let foreign = Arc::new(PauseAfterFirstPost {
            inner: lb.clone(),
            switch: sw.clone(),
        });
        let pump = Pump::new(link(), room.clone(), foreign, store.clone()).with_pause(sw.clone());
        pump.start().await.unwrap();
        for (i, t) in ["alpha", "bravo", "charlie"].iter().enumerate() {
            room.add("did:alice", None, t, i as u64 + 1).unwrap();
        }
        // The step in flight (the first post) finishes; nothing after it goes.
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        assert_eq!(lb.posted().len(), 1);
        sw.set(false);
        // The switch flips again after the next post: one more per tick.
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        sw.set(false);
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        sw.set(false);
        assert_eq!(pump.tick().await.unwrap().posted, 0);
        let texts: Vec<_> = lb.posted().iter().map(|e| e.text.clone()).collect();
        assert_eq!(texts.len(), 3, "no loss, no duplicate: {texts:?}");
        for t in ["alpha", "bravo", "charlie"] {
            assert_eq!(
                texts.iter().filter(|x| x.contains(t)).count(),
                1,
                "{texts:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_pause_between_the_journal_and_the_post_leaves_the_entry_for_the_resume() {
        let sw = Arc::new(PauseSwitch::new(false));
        let (room, lb) = (
            Arc::new(MemoryRoom::new()),
            Arc::new(Loopback::new("bridge-id")),
        );
        let store = Arc::new(PauseOnBrowseCursor {
            inner: MemoryStore::new(),
            switch: sw.clone(),
        });
        let pump =
            Pump::new(link(), room.clone(), lb.clone(), store.clone()).with_pause(sw.clone());
        pump.start().await.unwrap();
        room.add("did:alice", None, "journalled first", 1).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!(r.posted, 0, "paused before the post");
        assert!(lb.posted().is_empty());
        assert_eq!(
            store.outbox_unposted().await.unwrap().len(),
            1,
            "the journalled entry waits in the outbox"
        );
        sw.set(false);
        assert_eq!(pump.tick().await.unwrap().posted, 1);
        assert_eq!(lb.posted().len(), 1);
        assert_eq!(pump.tick().await.unwrap().posted, 0, "exactly once");
        assert_eq!(lb.posted().len(), 1);
    }

    #[tokio::test]
    async fn a_pause_writes_nothing_into_the_room_and_keeps_the_foreign_cursor() {
        let sw = Arc::new(PauseSwitch::new(false));
        let (pump, room, lb, store) = gated(&sw);
        pump.start().await.unwrap();
        lb.inject("did:bob", "one", 1).unwrap();
        assert_eq!(pump.tick().await.unwrap().written, 1);
        let cursor = store.cursor(FOREIGN_CURSOR).await.unwrap();

        sw.set(true);
        lb.inject("did:bob", "two", 2).unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!(r, TickReport::default());
        assert_eq!(room.writes().len(), 1, "nothing written into the room");
        assert_eq!(store.cursor(FOREIGN_CURSOR).await.unwrap(), cursor);

        sw.set(false);
        assert_eq!(pump.tick().await.unwrap().written, 1);
        assert_eq!(room.writes().len(), 2);
        assert_eq!(pump.tick().await.unwrap().written, 0, "no duplicate");
        assert_eq!(room.writes().len(), 2);
    }

    #[tokio::test]
    async fn start_while_paused_joins_nothing_and_a_later_start_does() {
        let sw = Arc::new(PauseSwitch::new(true));
        let (pump, room, lb, _store) = gated(&sw);
        assert_eq!(pump.start().await.unwrap(), JoinState::Pending);
        room.add("did:alice", None, "x", 1).unwrap();
        assert!(lb.posted().is_empty());
        sw.set(false);
        assert_eq!(pump.start().await.unwrap(), JoinState::Seated);
        assert_eq!(pump.tick().await.unwrap().posted, 1);
    }

    // ---- an entry that cannot fit is a permanent, journalled failure ----

    /// A room that caps a line far below what the outbox holds: a stand-in for
    /// an entry journalled under a bigger limit than today's.
    struct SmallRoom(Arc<Loopback>, usize);
    #[async_trait::async_trait]
    impl ForeignRoom for SmallRoom {
        async fn join(&self) -> Result<JoinState> {
            self.0.join().await
        }
        async fn leave(&self) -> Result<()> {
            self.0.leave().await
        }
        async fn poll(&self, a: Option<&Cursor>) -> Result<Vec<crate::foreign::Polled>> {
            self.0.poll(a).await
        }
        async fn post(&self, e: &BridgeEvent) -> Result<crate::foreign::Posted> {
            self.0.post(e).await
        }
        fn identity(&self) -> crate::foreign::ForeignIdentity {
            self.0.identity()
        }
        fn capabilities(&self) -> crate::foreign::RoomCapabilities {
            crate::foreign::RoomCapabilities {
                max_message_units: self.1,
                ..self.0.capabilities()
            }
        }
    }

    fn event_of(text: &str) -> BridgeEvent {
        BridgeEvent {
            origin: Origin::Vtc,
            origin_id: "big|1".into(),
            link: "l1".into(),
            author: "did:alice".into(),
            at: 1,
            title: None,
            text: text.into(),
            kind: EventKind::Post,
            reply_to: None,
            record_key: None,
            provenance: None,
        }
    }

    #[tokio::test]
    async fn an_oversize_outbox_entry_fails_once_for_good_and_is_not_retried() {
        let (room, lb, store) = parts();
        // The room takes 100 units; the outbox holds a 500-unit entry and a
        // fitting one behind it.
        let small = Arc::new(SmallRoom(lb.clone(), 100));
        let pump = Pump::new(link(), room.clone(), small, store.clone());
        pump.start().await.unwrap();
        store
            .outbox_insert("l1|big|1", &event_of(&"x".repeat(500)))
            .await
            .unwrap();
        let mut ok = event_of("fits");
        ok.origin_id = "ok|1".into();
        store.outbox_insert("l1|ok|1", &ok).await.unwrap();

        let r = pump.tick().await.unwrap();
        assert_eq!(
            (r.failed, r.posted),
            (1, 1),
            "the next entry still goes out"
        );
        assert_eq!(lb.posted().len(), 1);
        assert!(lb.posted()[0].text.contains("fits"));
        let why = store.xref_get("failed:l1|big|1").await.unwrap().unwrap();
        assert!(why.contains("500") && why.contains("100"), "{why}");
        let count = |s: Option<Vec<u8>>| u64::from_be_bytes(s.unwrap().try_into().unwrap());
        assert_eq!(count(store.cursor(OVERSIZE_FAILED).await.unwrap()), 1);

        // Many ticks later: no second failure, no post, no growth of the counter.
        for _ in 0..5 {
            let r = pump.tick().await.unwrap();
            assert_eq!((r.failed, r.posted), (0, 0));
        }
        assert_eq!(count(store.cursor(OVERSIZE_FAILED).await.unwrap()), 1);
        assert_eq!(lb.posted().len(), 1);
        // And it is not bridged: nothing claims it was.
        assert!(!store.xref_has("vtc:big|1").await.unwrap());
    }

    // ---- P0-4: dead letters, direction independence ----------------------------

    use crate::room::{RecordWrite, RoomRecord, SkippedRecord};
    use std::collections::VecDeque;

    /// A room whose writes fail on demand and which reports skipped records.
    struct ScriptedRoom {
        inner: MemoryRoom,
        put_errors: Mutex<VecDeque<Error>>,
        always: Mutex<Option<fn() -> Error>>,
        skipped: Mutex<Vec<SkippedRecord>>,
    }

    impl ScriptedRoom {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryRoom::new(),
                put_errors: Mutex::default(),
                always: Mutex::default(),
                skipped: Mutex::default(),
            })
        }
    }

    #[async_trait::async_trait]
    impl RoomSide for ScriptedRoom {
        async fn browse(&self, since: u64) -> Result<Vec<RoomRecord>> {
            self.inner.browse(since).await
        }
        fn take_skipped(&self) -> Vec<SkippedRecord> {
            std::mem::take(&mut *self.skipped.lock().unwrap())
        }
        async fn put(&self, w: &RecordWrite) -> Result<PutOutcome> {
            if let Some(e) = self.put_errors.lock().unwrap().pop_front() {
                return Err(e);
            }
            if let Some(f) = *self.always.lock().unwrap() {
                return Err(f());
            }
            self.inner.put(w).await
        }
    }

    fn collision() -> Error {
        Error::Room {
            code: "keyCollision".into(),
            message: "exists with another author".into(),
            retryable: false,
            details: None,
        }
    }

    fn transient() -> Error {
        Error::Room {
            code: "sealedVersionRace".into(),
            message: "busy".into(),
            retryable: true,
            details: None,
        }
    }

    async fn counter(store: &MemoryStore, name: &str) -> u64 {
        store
            .cursor(name)
            .await
            .unwrap()
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }

    /// P1-6: a refusal from the VTI side (the VTA's 403, the host's
    /// `permissionDenied`) is not "the foreign room removed the bridge".
    #[tokio::test]
    async fn a_vtc_side_refusal_halts_with_its_own_reason_and_remediation() {
        use crate::halt::{ClearConfirmation, Cleared, clear};
        let room = ScriptedRoom::new();
        *room.always.lock().unwrap() = Some(|| {
            // What `vtc::host::from_vta` returns for a `Forbidden` (pinned in host.rs).
            Error::VtcRefused("the VTA refused the bridge: no grant".into())
        });
        let (lb, store) = (
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        );
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.inject("did:bob", "hello", 2).unwrap();
        assert!(pump.tick().await.is_err());
        let why = pump.halted().await.unwrap().expect("halted");
        let text = why.to_string();
        assert!(
            text.contains("VTA or room host") && !text.contains("foreign room"),
            "{text}"
        );
        // Clearing needs --yes only: Geb has not removed us, so there is no
        // re-admission to attest to; the fix is the ACL grant.
        let e = clear(store.as_ref(), ClearConfirmation::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("ACL") && !e.contains("--i-have-been-readmitted"),
            "{e}"
        );
        let yes = ClearConfirmation {
            yes: true,
            readmitted: false,
        };
        assert!(matches!(
            clear(store.as_ref(), yes).await.unwrap(),
            Cleared::Cleared(_)
        ));
    }

    /// The other side of P1-6: a Geb-side removal keeps its own reason and the
    /// re-admission flag.
    #[tokio::test]
    async fn a_geb_side_refusal_keeps_the_readmit_requirement() {
        use crate::halt::{ClearConfirmation, clear};
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.refuse("leaf removed").unwrap();
        room.add("did:alice", None, "x", 1).unwrap();
        assert!(pump.tick().await.is_err());
        let text = pump.halted().await.unwrap().unwrap().to_string();
        assert!(
            text.contains("Geb") && text.contains("leaf removed"),
            "{text}"
        );
        let yes = ClearConfirmation {
            yes: true,
            readmitted: false,
        };
        let e = clear(store.as_ref(), yes).await.unwrap_err().to_string();
        assert!(e.contains("--i-have-been-readmitted"), "{e}");
    }

    #[tokio::test]
    async fn a_stuck_inbound_direction_does_not_starve_the_outbound_one() {
        let room = ScriptedRoom::new();
        *room.always.lock().unwrap() = Some(transient);
        let (lb, store) = (
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        );
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.inject("did:bob", "stuck", 2).unwrap();
        room.inner.add("did:alice", None, "goes out", 1).unwrap();
        let err = pump.tick().await.unwrap_err();
        assert!(
            matches!(
                err,
                Error::Room {
                    retryable: true,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(lb.posted().len(), 1, "the outbound direction still ran");
        // The stuck one resumes when it can; nothing was lost or skipped.
        *room.always.lock().unwrap() = None;
        let r = pump.tick().await.unwrap();
        assert_eq!(r.written, 1);
    }

    #[tokio::test]
    async fn a_stuck_outbound_direction_does_not_starve_the_inbound_one() {
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.fail_posts(Some(false)).unwrap();
        room.add("did:alice", None, "stuck out", 1).unwrap();
        lb.inject("did:bob", "comes in", 2).unwrap();
        assert!(matches!(pump.tick().await, Err(Error::Foreign(_))));
        assert_eq!(room.writes().len(), 1, "the inbound direction still ran");
        assert_eq!(counter(&store, FOREIGN_CURSOR).await, 1);
        lb.fail_posts(None).unwrap();
        assert_eq!(pump.tick().await.unwrap().posted, 1);
    }

    #[tokio::test]
    async fn a_non_retryable_write_error_is_dead_lettered_and_the_cursor_advances() {
        let room = ScriptedRoom::new();
        room.put_errors.lock().unwrap().push_back(collision());
        let (lb, store) = (
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        );
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.inject("did:bob", "poison", 2).unwrap();
        lb.inject("did:bob", "fine", 3).unwrap();
        let r = pump
            .tick()
            .await
            .expect("a permanent failure is not a tick error");
        assert_eq!((r.written, r.failed), (1, 1));
        assert_eq!(
            counter(&store, FOREIGN_CURSOR).await,
            2,
            "the cursor passed it"
        );
        assert_eq!(counter(&store, DEAD_LETTERED).await, 1);
        let why = store.xref_get("failed:in:loop0").await.unwrap().unwrap();
        assert!(why.contains("keyCollision"), "{why}");
        // A later tick does not count it again.
        pump.tick().await.unwrap();
        assert_eq!(counter(&store, DEAD_LETTERED).await, 1);
    }

    #[tokio::test]
    async fn a_retryable_write_error_is_not_dead_lettered() {
        let room = ScriptedRoom::new();
        room.put_errors.lock().unwrap().push_back(transient());
        let (lb, store) = (
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        );
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.inject("did:bob", "later", 2).unwrap();
        assert!(pump.tick().await.is_err());
        assert_eq!(counter(&store, FOREIGN_CURSOR).await, 0);
        assert_eq!(counter(&store, DEAD_LETTERED).await, 0);
        assert_eq!(pump.tick().await.unwrap().written, 1);
    }

    #[tokio::test]
    async fn a_post_that_cannot_succeed_is_dead_lettered() {
        let (room, lb, store) = parts();
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        lb.fail_posts(Some(true)).unwrap();
        room.add("did:alice", None, "unpostable", 1).unwrap();
        let r = pump.tick().await.expect("not a tick error");
        assert_eq!((r.posted, r.failed), (0, 1));
        assert_eq!(counter(&store, BROWSE_CURSOR).await, 1);
        assert_eq!(counter(&store, DEAD_LETTERED).await, 1);
        for (k, _) in store.outbox_unposted().await.unwrap() {
            assert!(
                store
                    .xref_has(&format!("{FAILED_PREFIX}{k}"))
                    .await
                    .unwrap()
            );
        }
        // Not retried: the foreign room works again and nothing is posted.
        lb.fail_posts(None).unwrap();
        assert_eq!(pump.tick().await.unwrap().posted, 0);
        assert!(lb.posted().is_empty());
    }

    #[tokio::test]
    async fn a_record_the_browse_could_not_read_is_journalled_and_passed_once() {
        let room = ScriptedRoom::new();
        room.inner.add("did:alice", None, "ok", 1).unwrap();
        room.skipped.lock().unwrap().push(SkippedRecord {
            key: "unreadable".into(),
            version: 5,
            reason: "rooms/keys/read:cannotOpen".into(),
        });
        let (lb, store) = (
            Arc::new(Loopback::new("bridge-id")),
            Arc::new(MemoryStore::new()),
        );
        let pump = Pump::new(link(), room.clone(), lb.clone(), store.clone());
        pump.start().await.unwrap();
        let r = pump.tick().await.unwrap();
        assert_eq!((r.posted, r.failed), (1, 1));
        assert_eq!(
            counter(&store, BROWSE_CURSOR).await,
            5,
            "passed the skipped version"
        );
        assert_eq!(counter(&store, DEAD_LETTERED).await, 1);
        assert!(store.xref_has("failed:browse:unreadable@5").await.unwrap());
        // Reported again (as a host would list it again): counted once.
        room.skipped.lock().unwrap().push(SkippedRecord {
            key: "unreadable".into(),
            version: 5,
            reason: "again".into(),
        });
        pump.tick().await.unwrap();
        assert_eq!(counter(&store, DEAD_LETTERED).await, 1);
    }
}
