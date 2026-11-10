//! The conformance suite for a bridge adapter's [`ForeignRoom`].
//!
//! An adapter supplies a [`Fixture`]: a fresh room the bridge has not joined,
//! a [`Peer`] that speaks in the foreign room as another member, and
//! [`Knobs`] that stage failures. [`run_all`] runs every case and returns one
//! [`Outcome`] per case. A case the adapter cannot stage is reported as
//! [`Outcome::Unsupported`] with a written reason, never skipped silently; the
//! adapter's `tests/conformance.rs` caps how many it may report. A case that
//! fails panics, naming itself.
//!
//! The suite proves the adapter against this repository's own reading of its
//! foreign system, not byte-compatibility with the real one.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use async_trait::async_trait;
use openvti_bridge_core::foreign::{
    Cursor, ForeignRoom, JoinState, Polled, Receipt, SizeLimit, SizeUnit,
};
use openvti_bridge_core::mapping::{measure, truncate};
use openvti_bridge_core::model::{BridgeEvent, EventKind, Origin};
use openvti_bridge_core::{Error, Result};
use std::collections::HashSet;
use std::sync::Arc;

/// A staging an adapter cannot do, with the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported(pub &'static str);

/// What staging a fault returns.
pub type Staged = std::result::Result<(), Unsupported>;

/// The other side: a foreign member speaking in the room.
#[async_trait]
pub trait Peer: Send + Sync {
    /// The peer says `text` in the room (it appears in a later `poll`).
    async fn say(&self, text: &str, at_ms: u64) -> Result<()>;
}

/// Faults an adapter can stage.
pub trait Knobs: Send + Sync {
    /// Seating answers `Pending` until `false`.
    fn set_pending(&self, pending: bool) -> Staged;
    /// Refuse the bridge from now on (seating refused or leaf removed).
    fn refuse(&self, why: &str) -> Staged;
    /// Make every post fail: `Some(true)` permanently (`Error::Wire`),
    /// `Some(false)` transiently (`Error::Foreign`), `None` to stop.
    fn fail_posts(&self, permanent: Option<bool>) -> Staged;
}

/// One fresh room under test.
pub struct Rig {
    /// The adapter's room, the bridge not yet joined.
    pub room: Arc<dyn ForeignRoom>,
    /// The other member.
    pub peer: Box<dyn Peer>,
    /// Fault staging.
    pub knobs: Box<dyn Knobs>,
}

/// What an adapter supplies.
#[async_trait]
pub trait Fixture: Send + Sync {
    /// A clean room.
    async fn fresh(&self) -> Rig;
}

/// What one case did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Ran and held.
    Passed,
    /// Could not be staged by this adapter; the reason is written down.
    Unsupported(&'static str),
}

/// Every case, in order.
pub const CASES: &[&str] = &[
    "join_is_idempotent",
    "pending_seating_then_seated",
    "refused_seating_is_refused",
    "poll_is_oldest_first_and_a_resumed_cursor_loses_nothing",
    "a_post_is_accepted_with_a_receipt_and_is_not_echoed_back",
    "failure_classes",
    "size_limit_is_declared_and_a_cut_fits",
    "identity_and_capabilities_are_declared",
];

fn ev(text: &str, at: u64) -> BridgeEvent {
    BridgeEvent {
        origin: Origin::Vtc,
        origin_id: format!("k|{at}"),
        link: "l1".into(),
        author: "did:key:zAlice".into(),
        at,
        title: None,
        text: text.into(),
        kind: EventKind::Post,
        reply_to: None,
        record_key: None,
        provenance: None,
    }
}

async fn seated(rig: &Rig) -> Result<()> {
    match rig.room.join().await? {
        JoinState::Seated => Ok(()),
        JoinState::Pending => Err(Error::Foreign("expected a seated room".into())),
    }
}

/// Run every case against fresh rigs from `fx`.
pub async fn run_all(fx: &dyn Fixture) -> Vec<(&'static str, Outcome)> {
    let mut out = Vec::new();
    for name in CASES {
        let o = run_case(fx, name).await;
        out.push((*name, o));
    }
    out
}

/// Run one case by name. Panics when the case fails.
pub async fn run_case(fx: &dyn Fixture, name: &str) -> Outcome {
    let rig = fx.fresh().await;
    let r: Result<Outcome> = match name {
        "join_is_idempotent" => join_is_idempotent(&rig).await,
        "pending_seating_then_seated" => pending(&rig).await,
        "refused_seating_is_refused" => refused(&rig).await,
        "poll_is_oldest_first_and_a_resumed_cursor_loses_nothing" => polling(&rig).await,
        "a_post_is_accepted_with_a_receipt_and_is_not_echoed_back" => posting(&rig).await,
        "failure_classes" => failures(&rig).await,
        "size_limit_is_declared_and_a_cut_fits" => sizes(&rig).await,
        "identity_and_capabilities_are_declared" => declared(&rig).await,
        other => panic!("no conformance case {other:?}"),
    };
    match r {
        Ok(o) => o,
        Err(e) => panic!("conformance case {name} failed: {e}"),
    }
}

macro_rules! stage {
    ($e:expr) => {
        if let Err(Unsupported(why)) = $e {
            return Ok(Outcome::Unsupported(why));
        }
    };
}

fn check(ok: bool, what: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Foreign(what.into()))
    }
}

async fn join_is_idempotent(rig: &Rig) -> Result<Outcome> {
    check(
        rig.room.join().await? == JoinState::Seated,
        "first join seats",
    )?;
    check(
        rig.room.join().await? == JoinState::Seated,
        "a second join stays seated",
    )?;
    Ok(Outcome::Passed)
}

async fn pending(rig: &Rig) -> Result<Outcome> {
    stage!(rig.knobs.set_pending(true));
    check(rig.room.join().await? == JoinState::Pending, "pending join")?;
    check(
        rig.room.join().await? == JoinState::Pending,
        "joining again while pending stays pending",
    )?;
    stage!(rig.knobs.set_pending(false));
    check(
        rig.room.join().await? == JoinState::Seated,
        "pending turns seated once the room lets us in",
    )?;
    Ok(Outcome::Passed)
}

async fn refused(rig: &Rig) -> Result<Outcome> {
    stage!(rig.knobs.refuse("removed from the room"));
    check(
        matches!(rig.room.join().await, Err(Error::Refused(_))),
        "a refused seating is Error::Refused",
    )?;
    check(
        matches!(rig.room.join().await, Err(Error::Refused(_))),
        "and keeps refusing",
    )?;
    Ok(Outcome::Passed)
}

fn ids(v: &[Polled]) -> Vec<String> {
    v.iter().map(|p| p.event.origin_id.clone()).collect()
}

async fn polling(rig: &Rig) -> Result<Outcome> {
    seated(rig).await?;
    rig.peer.say("first", 1_700_000_000_000).await?;
    rig.peer.say("second", 1_700_000_001_000).await?;
    let all = rig.room.poll(None).await?;
    check(all.len() == 2, "poll(None) returns both lines")?;
    check(
        all[0].event.text == "first" && all[1].event.text == "second",
        "oldest first",
    )?;
    check(
        all.iter().all(|p| p.event.link.is_empty()),
        "the adapter leaves `link` empty",
    )?;
    let seen: HashSet<String> = ids(&all).into_iter().collect();
    check(seen.len() == 2, "foreign ids are distinct")?;
    // Resume from the last cursor: nothing new, and anything repeated is a
    // line already seen (the core deduplicates those).
    let last: Cursor = all[1].cursor.clone();
    let again = rig.room.poll(Some(&last)).await?;
    check(
        ids(&again).iter().all(|i| seen.contains(i)),
        "a resumed poll yields only lines already seen",
    )?;
    // A line said after the cursor is found by the resumed poll.
    rig.peer.say("third", 1_700_000_002_000).await?;
    let later = rig.room.poll(Some(&last)).await?;
    check(
        later.iter().any(|p| p.event.text == "third"),
        "a resumed poll loses nothing",
    )?;
    Ok(Outcome::Passed)
}

async fn posting(rig: &Rig) -> Result<Outcome> {
    seated(rig).await?;
    let posted = rig.room.post(&ev("hello", 1_700_000_000_000)).await?;
    check(
        posted.receipt >= Receipt::Accepted,
        "a post carries a receipt",
    )?;
    let back = rig.room.poll(None).await?;
    check(
        back.iter().all(|p| p.event.text != "hello"),
        "the bridge's own post is not read back as foreign content",
    )?;
    Ok(Outcome::Passed)
}

async fn failures(rig: &Rig) -> Result<Outcome> {
    seated(rig).await?;
    stage!(rig.knobs.fail_posts(Some(false)));
    check(
        matches!(
            rig.room.post(&ev("x", 1_700_000_000_000)).await,
            Err(Error::Foreign(_))
        ),
        "a transient failure is Error::Foreign (retried)",
    )?;
    stage!(rig.knobs.fail_posts(Some(true)));
    check(
        matches!(
            rig.room.post(&ev("x", 1_700_000_000_000)).await,
            Err(Error::Wire(_))
        ),
        "a permanent failure is Error::Wire (dead-lettered)",
    )?;
    stage!(rig.knobs.fail_posts(None));
    rig.room.post(&ev("y", 1_700_000_001_000)).await?;
    Ok(Outcome::Passed)
}

async fn sizes(rig: &Rig) -> Result<Outcome> {
    let SizeLimit { unit, max } = rig.room.capabilities().size_limit;
    check(max > 0, "the room declares a size limit")?;
    // Multi-unit characters at the boundary: the cut never exceeds the limit
    // and never splits a character.
    let long: String = "a\u{1F600}".repeat(max + 1);
    let cut = truncate(unit, &long, max);
    check(measure(unit, &cut) <= max, "a cut fits the declared limit")?;
    check(
        matches!(unit, SizeUnit::Utf16 | SizeUnit::Chars | SizeUnit::Bytes),
        "a known unit",
    )?;
    Ok(Outcome::Passed)
}

async fn declared(rig: &Rig) -> Result<Outcome> {
    check(
        !rig.room.identity().id.is_empty(),
        "the bridge's identity in the room is named",
    )?;
    Ok(Outcome::Passed)
}
