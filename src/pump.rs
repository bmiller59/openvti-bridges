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
}

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
                "foreign room refused or removed the bridge; link stopped, not retrying"
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
        Ok(report)
    }

    async fn run_directions(&self, report: &mut TickReport) -> Result<()> {
        if self.link.directions != Directions::FromForeign {
            self.push_foreign(report).await?;
        }
        if self.link.directions != Directions::ToForeign && !self.is_paused() {
            self.pull_foreign(report).await?;
        }
        Ok(())
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

    /// Post one journalled event. `false` when the kill switch is on: nothing
    /// is posted and nothing is marked, so the entry stays unposted in the
    /// outbox and the next tick after a resume posts it exactly once.
    async fn post_one(
        &self,
        key: &str,
        ev: &crate::model::BridgeEvent,
        r: &mut TickReport,
    ) -> Result<bool> {
        if self.is_paused() {
            return Ok(false);
        }
        let posted = self.foreign.post(ev).await?;
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
        Ok(true)
    }

    async fn push_foreign(&self, report: &mut TickReport) -> Result<()> {
        // Resume anything journalled but never posted.
        for (key, ev) in self.store.outbox_unposted().await? {
            if !self.post_one(&key, &ev, report).await? {
                return Ok(());
            }
        }
        let caps = self.foreign.capabilities();
        let since = version_cursor(self.store.as_ref()).await?;
        for rec in self.room.browse(since).await? {
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
                    if !self.post_one(&key, &prepared, report).await? {
                        return Ok(());
                    }
                }
            }
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
                let write = foreign_to_record(&ev, &self.link.link_secret)?;
                match self.room.put(&write).await? {
                    PutOutcome::Created => report.written += 1,
                    PutOutcome::AlreadyExists => report.skipped += 1,
                }
                self.store
                    .xref_set(&format!("foreign:{}", ev.origin_id), &write.key)
                    .await?;
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
}
