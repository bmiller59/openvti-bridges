//! Room status, Commit catch-up and re-seat (answers round 2 sections 5 and 8,
//! round 3 section 3, round 4 sections 8-10). A child of `client` so it can
//! read the client's private state; the bridge stays a FOLLOWER here: it sends
//! `rs`, `rc` and `seat-ask`, replaces its group from a re-seat Welcome and
//! re-posts its own lines, and never commits, never elects, never heals.
//!
//! Cadence (ours; Geb's list is round 2 section 5): `rs` goes out after joining,
//! after each settle that applied a Commit (to every member we hold a dyad with
//! except one newly added), after a Commit failed to process (once), twice at
//! start (1.5 s and 8 s after the first settle pass), when a dyad comes up, in
//! answer to a status, and to a seat-check. To keep traffic bounded there is a
//! MINIMUM INTERVAL PER PEER of 5 s for an unchanged (epoch, authenticator); a
//! changed one goes at once (it changes only when a Commit settled). A status of ours answering the same status of
//! theirs is repeated at most once a minute. After an `askReseat` our `rs`
//! stays quiet for 600 s (answers round 4 Q9), except to a seat-check.
//!
//! UNVERIFIED (the answers do not settle; each is a choice):
//! - the chain starts at our join: we know no Commit hash from before it, so
//!   the entry for the epoch the Welcome gave us is omitted (our `s.e` / `s.a`
//!   name it) and the chain is empty until the first Commit we settle;
//! - the `a` we send is the first 16 hex of the OpenMLS epoch authenticator;
//! - `lines` carries only our own lines (n = those we still hold, at most 100)
//!   and `ls` is our join time; both are omitted until we hold one;
//! - Commit bytes for `rc` are kept in memory only (the newest 64); a restart
//!   loses them, the chain is persisted;
//! - when Geb counts us 'seen' (a room line from us, or an `rs` that is not a
//!   fork, round 3 section 3);
//! - `via` is the members we hold a dyad with;
//! - which of our dead-branch lines are re-posted: those we sent at an epoch
//!   at or above the recorded split's epoch, else at or above the epoch we
//!   were at when the re-seat arrived (at most 100).

use super::*;
use crate::geb::settle::Held;
use crate::geb::status::{
    ChainEntry, Comparison, Holding, MAX_CHAIN, MAX_CHAIN_SENT, RoomStatus, compare_status,
    fork_mine_wins,
};
use crate::geb::wire::LineBody;
use std::collections::{BTreeMap, HashSet};

/// Prefix of the error for a Welcome whose KeyPackage we no longer hold.
pub(super) const NO_KP: &str = "welcome: no matching KeyPackage";
/// Minimum gap between two `rs` to one peer when nothing changed.
pub const RS_MIN_INTERVAL_MS: u64 = 5_000;
/// `askReseat` and `seat-ask` backoff, and the quiet time that follows
/// (answers round 4 Q9).
pub const ASK_BACKOFF_MS: u64 = 600_000;
/// Re-read the room at most this often on a `behind` verdict.
pub const REREAD_MIN_MS: u64 = 30_000;
/// The same answer to the same status is repeated at most this often.
const ANSWER_REPEAT_MS: u64 = 60_000;
/// At most one `rc` burst (our stored Commits from the peer's epoch up) to one
/// peer per this long, WHATEVER status it claims: the repeat guard above is
/// keyed on the claimed `(e, a)`, which a member chooses, so it alone lets a
/// member draw a burst of up to [`COMMIT_KEEP`] frames from every `rs`.
/// UNVERIFIED (bridge-side, Geb states no limit): 60 s, the same as the
/// answer repeat.
pub const RC_BURST_MIN_INTERVAL_MS: u64 = 60_000;
/// Across ALL peers, at most this many `rc` frames per
/// [`RC_GLOBAL_WINDOW_MS`]. UNVERIFIED (bridge-side): two full bursts.
pub const RC_GLOBAL_MAX_FRAMES: usize = 2 * COMMIT_KEEP;
/// The window [`RC_GLOBAL_MAX_FRAMES`] is counted in.
pub const RC_GLOBAL_WINDOW_MS: u64 = 60_000;
/// A peer's claim to be ahead of us forces a re-read at most this often, per
/// peer, on top of the global [`REREAD_MIN_MS`]. UNVERIFIED (bridge-side):
/// five minutes; an honest peer that is really ahead is read from the relay by
/// the first re-read, and our own settle loop keeps catching up after it.
pub const REREAD_PEER_MIN_MS: u64 = 300_000;
/// Start-up statuses, after the first settle pass (round 2 section 5).
const START_SENDS_MS: [u64; 2] = [1_500, 8_000];
/// Commit bytes kept for `rc`, and `rc` held for later epochs.
pub const COMMIT_KEEP: usize = 64;
/// Own lines kept for a dead-branch re-post (answers round 4 Q10).
pub const OWN_LINES_MAX: usize = 100;
const OWN_LINES_BYTES: usize = 256 * 1024;
/// How long a re-seat Welcome is awaited before asking with a fresh package.
/// UNVERIFIED: Geb's seat wait is 120 s ; we reuse it.
pub const SEAT_WAIT_MS: u64 = 120_000;
/// How long after a `seat-ask` of ours a replacing Welcome is still expected.
/// UNVERIFIED (not in the answers): a bridge-side window, two ask backoffs.
pub const SEAT_ASK_EXPECT_MS: u64 = 2 * ASK_BACKOFF_MS;
/// Largest `rc` Commit we take (an event is at most 120,000 bytes).
const MAX_RC_BYTES: usize = 100_000;

/// A recorded split: the lowest epoch at which a peer's authenticator differs
/// from ours and who won it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Split {
    /// The lowest epoch where the authenticators differ.
    pub epoch: u64,
    /// The member whose status showed the fork.
    pub peer: String,
    /// Whether our branch won (we then mark the loser "asked" and carry on).
    pub we_won: bool,
    /// `behind-all`, `they-behind-all` or `hash`.
    pub reason: String,
    /// When first seen, ms.
    pub at_ms: u64,
    /// We won and marked the loser for the elected healer (we never heal).
    pub asked: bool,
    /// A re-seat replaced our group since.
    pub resolved: bool,
    /// Our epoch when the split was detected (0 in a snapshot from before
    /// this was kept).
    #[serde(default)]
    pub our_epoch: u64,
    /// The peer's epoch when it was detected (0 likewise).
    #[serde(default)]
    pub their_epoch: u64,
    /// When a re-seat resolved it, ms (`None` until one did).
    #[serde(default)]
    pub resolved_at_ms: Option<u64>,
}

/// One line we sent, kept for a dead-branch re-post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct OwnLine {
    pub epoch: u64,
    pub line: LineBody,
}

/// What survives a restart (inside the sealed snapshot; every field defaults,
/// so an older snapshot loads with an empty chain).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct Persist {
    pub chain: Vec<ChainEntry>,
    pub own_lines: Vec<OwnLine>,
    pub pending_reposts: Vec<LineBody>,
    pub split: Option<Split>,
    pub joined_ms: Option<u64>,
    pub was_seated: bool,
    pub reseating: bool,
    /// Frame id of the last Welcome applied (first join or re-seat). A dyad
    /// frame is redelivered after a crash between its read and our persist
    /// (the two-phase hand-off); a Welcome already applied is then skipped,
    /// never applied twice.
    #[serde(default)]
    pub last_welcome: Option<String>,
}

struct SentRs {
    e: u64,
    a: String,
    at: u64,
}

/// In-memory bookkeeping (and the persisted part, `p`).
#[derive(Default)]
pub(super) struct HealState {
    pub p: Persist,
    pub commit_bytes: BTreeMap<u64, Vec<u8>>,
    pub heard: HashMap<String, u64>,
    last_rs: HashMap<String, SentRs>,
    last_answer: HashMap<String, (u64, String, u64, String, u64)>,
    /// peer -> (our epoch, their epoch, first seen ms) of a `behind` verdict.
    pair: HashMap<String, (u64, u64, u64)>,
    pub announced: HashSet<String>,
    pub reread: bool,
    last_reread_ms: u64,
    /// Per peer: when its claim last forced a re-read (see [`REREAD_PEER_MIN_MS`]).
    last_reread_peer: HashMap<String, u64>,
    /// Per peer: when it was last sent an `rc` burst ([`RC_BURST_MIN_INTERVAL_MS`]).
    last_rc_burst: HashMap<String, u64>,
    /// The global `rc` budget: window start (ms) and frames sent in it.
    rc_window: (u64, usize),
    quiet_until_ms: u64,
    last_ask_ms: Option<u64>,
    last_kp_ask_ms: Option<u64>,
    started_ms: Option<u64>,
    start_sent: usize,
    pub reseating_since_ms: u64,
    pub lost_copy: bool,
    pub reseats: u32,
}

impl HealState {
    /// A Commit settled: made epoch `made` (from `from`) by `winner`.
    pub fn note_settled(
        &mut self,
        from: u64,
        made: u64,
        winner: Option<[u8; 32]>,
        auth: &str,
        bytes: Option<Vec<u8>>,
    ) {
        if let Some(w) = winner {
            self.p.chain.push(ChainEntry {
                e: made,
                h: hex::encode(w)[..16].to_string(),
                a: auth.to_string(),
            });
            if self.p.chain.len() > MAX_CHAIN {
                let extra = self.p.chain.len() - MAX_CHAIN;
                self.p.chain.drain(..extra);
            }
        }
        if let Some(b) = bytes {
            self.commit_bytes.insert(from, b);
            while self.commit_bytes.len() > COMMIT_KEEP {
                self.commit_bytes.pop_first();
            }
        }
    }
}

/// First 16 hex of the epoch authenticator.
pub(super) fn auth_hex(grp: &MlsGroup) -> String {
    hex::encode(grp.epoch_authenticator().as_slice())[..16].to_string()
}

/// Keep a line we are about to send, for a dead-branch re-post. Only text
/// lines (`t:"l"`) and never a re-post itself; never anyone else's.
pub(super) fn record_own_line(p: &mut Persist, epoch: u64, plaintext: &[u8]) {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(plaintext) else {
        return;
    };
    if v.get("t").and_then(|t| t.as_str()) != Some("l") {
        return;
    }
    let Ok(mut line) = serde_json::from_value::<LineBody>(v) else {
        return;
    };
    if line.is_repost() {
        return;
    }
    line.sg = None;
    p.own_lines.push(OwnLine { epoch, line });
    let bytes = |p: &Persist| p.own_lines.iter().map(|l| l.line.text.len()).sum::<usize>();
    while p.own_lines.len() > OWN_LINES_MAX || (p.own_lines.len() > 1 && bytes(p) > OWN_LINES_BYTES)
    {
        p.own_lines.remove(0);
    }
}

fn build_status(me: &str, grp: &MlsGroup, p: &Persist) -> RoomStatus {
    let (lines, ls) = match (p.own_lines.last(), p.joined_ms) {
        (Some(last), Some(joined)) => {
            let mut m = BTreeMap::new();
            m.insert(
                me.to_string(),
                Holding {
                    n: p.own_lines.len() as u64,
                    last: p
                        .own_lines
                        .iter()
                        .map(|l| l.line.at)
                        .max()
                        .unwrap_or(last.line.at),
                },
            );
            (Some(m), Some(joined))
        }
        _ => (None, None),
    };
    RoomStatus {
        e: grp.epoch().as_u64(),
        a: auth_hex(grp),
        chain: p.chain.clone(),
        lines,
        ls,
        cps: None,
    }
}

impl MlsGroupClient {
    /// Our current status, when seated.
    pub fn room_status(&self) -> Option<RoomStatus> {
        let g = self.lock().ok()?;
        match &g.state {
            State::Seated(grp) => Some(build_status(self.device.did(), grp, &g.heal.p)),
            _ => None,
        }
    }

    /// The fork this client last recorded, if any.
    pub fn split(&self) -> Option<Split> {
        self.lock().ok()?.heal.p.split.clone()
    }

    /// How many re-seats replaced our group in this process.
    pub fn reseats(&self) -> u32 {
        self.lock().map(|g| g.heal.reseats).unwrap_or(0)
    }

    /// Tests only: the dead-branch lines still waiting to be re-posted.
    #[cfg(test)]
    pub(crate) fn pending_reposts_for_test(&self) -> Vec<LineBody> {
        self.lock()
            .map(|g| g.heal.p.pending_reposts.clone())
            .unwrap_or_default()
    }

    /// Whether a merged commit re-seated us and its Welcome is awaited.
    pub fn is_reseating(&self) -> bool {
        self.lock()
            .map(|g| matches!(g.state, State::Reseating(_)))
            .unwrap_or(false)
    }

    /// Tests only: switch the unprompted statuses (the two at start and the
    /// one when a dyad comes up) on or off, so a test counts the rest exactly.
    #[cfg(test)]
    pub(crate) fn set_unprompted_statuses(&self, on: bool) {
        let mut g = self.lock().unwrap();
        g.heal.start_sent = if on { 0 } else { START_SENDS_MS.len() };
        if on {
            g.heal.announced.clear();
        } else {
            g.heal.announced.extend(self.cfg.peers.iter().cloned());
        }
    }

    /// Device DIDs we hold a dyad with that are members of the room.
    fn member_peers(&self, g: &Inner) -> Vec<String> {
        let State::Seated(grp) = &g.state else {
            return Vec::new();
        };
        let members: Vec<String> = grp
            .members()
            .filter_map(|m| credential_did(&m.credential))
            .collect();
        self.cfg
            .peers
            .iter()
            .filter(|p| members.contains(p))
            .cloned()
            .collect()
    }

    /// Send our status to every member peer except `except`.
    pub(super) async fn send_rs_all(&self, force: bool, except: &[String]) {
        let peers = match self.lock() {
            Ok(g) => self.member_peers(&g),
            Err(_) => return,
        };
        for p in peers.iter().filter(|p| !except.contains(p)) {
            self.send_rs_to(p, force).await;
        }
    }

    /// Send our status to `peer`. `force` skips the minimum interval and the
    /// post-`askReseat` quiet time (joining, a seat-check).
    pub(crate) async fn send_rs_to(&self, peer: &str, force: bool) {
        let now = (self.clock)();
        let frame = {
            let Ok(mut g) = self.lock() else { return };
            let vias = self.member_peers(&g);
            let Inner { state, heal, .. } = &mut *g;
            let State::Seated(grp) = state else { return };
            let mut s = build_status(self.device.did(), grp, &heal.p);
            if !force {
                if now < heal.quiet_until_ms {
                    return;
                }
                if let Some(l) = heal.last_rs.get(peer) {
                    let gap = now.saturating_sub(l.at);
                    // A changed (epoch, authenticator) goes at once: it can
                    // only change when a Commit settled, which is paced by the
                    // settle window.
                    if l.e == s.e && l.a == s.a && gap < RS_MIN_INTERVAL_MS {
                        return;
                    }
                }
            }
            heal.last_rs.insert(
                peer.to_string(),
                SentRs {
                    e: s.e,
                    a: s.a.clone(),
                    at: now,
                },
            );
            // A dyad frame must fit one event (we say `fc:0`): the newest
            // entries only, fewer still if the frame is still too large.
            let keep = s.chain.len().saturating_sub(MAX_CHAIN_SENT);
            s.chain.drain(..keep);
            let mut frame = Frame::Group(GroupOp::Rs {
                room: Some(RoomRef {
                    id: self.cfg.room_id.clone(),
                    name: None,
                }),
                s: Some(s),
                via: Some(vias),
            });
            loop {
                let len = serde_json::to_vec(&frame)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                let Frame::Group(GroupOp::Rs { s: Some(s), .. }) = &mut frame else {
                    break;
                };
                if len <= 30_000 || s.chain.is_empty() {
                    break;
                }
                let half = s.chain.len() / 2;
                s.chain.drain(..half);
            }
            frame
        };
        if let Err(e) = self.dyad.send(peer, &frame).await {
            tracing::warn!(error = %e, "could not send the room status");
        }
    }

    /// A status from `peer` (answers round 2 section 5, round 4 Q8-Q9).
    pub(crate) async fn on_rs(&self, peer: &str, room: Option<RoomRef>, s: Option<RoomStatus>) {
        let now = (self.clock)();
        if room.as_ref().is_none_or(|r| r.id != self.cfg.room_id) {
            tracing::debug!("rs for another room dropped");
            return;
        }
        // An `rs` with no valid `s` is dropped: not a fork signal, never 'seen'.
        let Some(theirs) = s else {
            tracing::debug!("rs without a valid status dropped");
            return;
        };
        struct Plan {
            rc: Vec<Frame>,
            answer: bool,
            ask: bool,
        }
        let plan = {
            let Ok(mut g) = self.lock() else { return };
            let Inner { state, heal, .. } = &mut *g;
            let State::Seated(grp) = state else { return };
            let me = self.device.did();
            let members: Vec<String> = grp
                .members()
                .filter_map(|m| credential_did(&m.credential))
                .collect();
            // Accepted from a room member (we hold no persona cards, so exactly
            // a member's device DID).
            if !members.iter().any(|m| m == peer) {
                tracing::warn!("rs from a device that is not a member dropped");
                return;
            }
            heal.heard.insert(peer.to_string(), theirs.e);
            let mine = build_status(me, grp, &heal.p);
            let mut plan = Plan {
                rc: Vec::new(),
                answer: false,
                ask: false,
            };
            match compare_status(&mine, &theirs) {
                Comparison::Equal => {
                    heal.pair.remove(peer);
                }
                Comparison::Ahead => {
                    heal.pair.remove(peer);
                    // They lag: each Commit we hold from their epoch on, then
                    // our status again.
                    // Rate-limited per peer and globally, independent of the
                    // claimed (e, a) (P1-8): a member cannot draw a burst from
                    // every status it makes up.
                    let peer_ok = heal
                        .last_rc_burst
                        .get(peer)
                        .is_none_or(|at| now.saturating_sub(*at) >= RC_BURST_MIN_INTERVAL_MS);
                    if now.saturating_sub(heal.rc_window.0) >= RC_GLOBAL_WINDOW_MS {
                        heal.rc_window = (now, 0);
                    }
                    let budget = RC_GLOBAL_MAX_FRAMES.saturating_sub(heal.rc_window.1);
                    if peer_ok && budget > 0 {
                        for (e, bytes) in heal.commit_bytes.range(theirs.e..).take(budget) {
                            plan.rc.push(Frame::Group(GroupOp::Rc {
                                room: RoomRef {
                                    id: self.cfg.room_id.clone(),
                                    name: None,
                                },
                                e: *e,
                                c: STANDARD.encode(bytes),
                            }));
                        }
                        if !plan.rc.is_empty() {
                            heal.last_rc_burst.insert(peer.to_string(), now);
                            heal.rc_window.1 += plan.rc.len();
                        }
                    } else {
                        tracing::debug!(
                            peer_ok,
                            budget,
                            "rc burst withheld (rate limit); our status is still answered"
                        );
                    }
                    plan.answer = true;
                }
                Comparison::Behind => {
                    // Re-read the room from its founding (paged and bounded by
                    // the relay's own manners), then answer.
                    // Bounded globally and per peer (P1-8): a claim to be ahead
                    // costs the peer nothing, so it must not buy a relay read
                    // every 30 s.
                    if (heal.last_reread_ms == 0
                        || now.saturating_sub(heal.last_reread_ms) >= REREAD_MIN_MS)
                        && heal
                            .last_reread_peer
                            .get(peer)
                            .is_none_or(|at| now.saturating_sub(*at) >= REREAD_PEER_MIN_MS)
                    {
                        heal.reread = true;
                        heal.last_reread_ms = now;
                        heal.last_reread_peer.insert(peer.to_string(), now);
                    }
                    let window = u64::from(group_policy(grp).settle_window_ms);
                    match heal.pair.get(peer) {
                        Some((m, t, first))
                            if *m == mine.e
                                && *t == theirs.e
                                && now.saturating_sub(*first) >= window =>
                        {
                            plan.ask = true;
                        }
                        Some((m, t, _)) if *m == mine.e && *t == theirs.e => {}
                        _ => {
                            heal.pair.insert(peer.to_string(), (mine.e, theirs.e, now));
                        }
                    }
                    plan.answer = true;
                }
                Comparison::Fork { epoch, hash_wins } => {
                    heal.pair.remove(peer);
                    let others: Vec<u64> = heal
                        .heard
                        .iter()
                        .filter(|(d, _)| {
                            d.as_str() != me
                                && d.as_str() != peer
                                && members.iter().any(|m| m == *d)
                        })
                        .map(|(_, e)| *e)
                        .collect();
                    let (we_won, why) = fork_mine_wins(hash_wins, mine.e, theirs.e, &others);
                    let reason = match why {
                        crate::geb::status::ForkReason::BehindAll => "behind-all",
                        crate::geb::status::ForkReason::TheyBehindAll => "they-behind-all",
                        crate::geb::status::ForkReason::Hash => "hash",
                    };
                    let at_ms = match &heal.p.split {
                        Some(s) if s.epoch == epoch && s.peer == peer && !s.resolved => s.at_ms,
                        _ => now,
                    };
                    tracing::warn!(
                        fork_epoch = epoch,
                        we_won,
                        reason,
                        "the room has split: {}",
                        if we_won {
                            "our branch wins; the loser is marked asked for the elected healer \
                             (this bridge never heals)"
                        } else {
                            "our branch loses; waiting to be re-seated (no askReseat)"
                        }
                    );
                    heal.p.split = Some(Split {
                        epoch,
                        peer: peer.to_string(),
                        we_won,
                        reason: reason.into(),
                        at_ms,
                        asked: we_won,
                        resolved: false,
                        our_epoch: mine.e,
                        their_epoch: theirs.e,
                        resolved_at_ms: None,
                    });
                    plan.answer = true;
                }
            }
            // Do not ping-pong: the same answer to the same status goes at most
            // once a minute.
            if plan.answer {
                let key = (theirs.e, theirs.a.clone(), mine.e, mine.a.clone());
                match heal.last_answer.get(peer) {
                    Some((te, ta, me_, ma, at))
                        if (*te, ta, *me_, ma) == (key.0, &key.1, key.2, &key.3)
                            && now.saturating_sub(*at) < ANSWER_REPEAT_MS =>
                    {
                        plan.answer = false;
                        plan.rc.clear();
                    }
                    _ => {
                        heal.last_answer
                            .insert(peer.to_string(), (key.0, key.1, key.2, key.3, now));
                    }
                }
            }
            plan
        };
        // The split (if this status showed one) is in the sealed snapshot
        // state now; mirror it where `status` can read it.
        self.sync_fork_marker().await;
        for f in &plan.rc {
            if let Err(e) = self.dyad.send(peer, f).await {
                tracing::warn!(error = %e, "could not send a Commit (rc)");
                break;
            }
        }
        if plan.answer {
            self.send_rs_to(peer, false).await;
        }
        if plan.ask {
            self.ask_reseat(peer).await;
        }
    }

    /// `rc {room, e, c}`: a Commit made from epoch `e` (round 4 Q9). Judged at
    /// once when `e` is our epoch, held (at most 64) for a later one, dropped
    /// below ours. It goes into the settle queue: never around `validCommit`.
    pub(crate) fn on_rc(&self, peer: &str, room: &RoomRef, e: u64, c: &str) {
        if room.id != self.cfg.room_id {
            return;
        }
        let Ok(bytes) = b64_decode(c) else {
            tracing::debug!("rc that is not base64 dropped");
            return;
        };
        if bytes.len() > MAX_RC_BYTES {
            tracing::debug!("rc over the size cap dropped");
            return;
        }
        let Ok(mut g) = self.lock() else { return };
        let Inner { state, queue, .. } = &mut *g;
        let State::Seated(grp) = state else { return };
        if !grp
            .members()
            .filter_map(|m| credential_did(&m.credential))
            .any(|d| d == peer)
        {
            tracing::warn!("rc from a device that is not a member dropped");
            return;
        }
        if e < grp.epoch().as_u64() {
            return;
        }
        // `event_secs == u64::MAX` marks a Commit that came by `rc` (it never
        // holds the relay read cursor back).
        let held = queue
            .held()
            .iter()
            .filter(|c| c.event_secs == u64::MAX)
            .count();
        if held >= COMMIT_KEEP {
            tracing::debug!("more than 64 rc held; one dropped");
            return;
        }
        // first-seen 0: the window is already out, so it is judged at once
        // together with whatever else is held for that epoch.
        let epoch = grp.epoch().as_u64();
        if let Held::Dropped(why) = queue.hold(epoch, e, bytes, u64::MAX, 0) {
            tracing::warn!(why, "dropped an rc instead of holding it");
        }
    }

    /// Why a replacing Welcome would be expected now, and whether it may come
    /// from an epoch below ours. `None`: no re-seat is expected, so a Welcome
    /// would replace our whole group on a member's say-so (any member can mint
    /// a group with the room's id from one of our published KeyPackages).
    ///
    /// Expected when: we merged a commit that re-seats us (`Reseating`); a
    /// recorded split is unresolved and we lost it (the winner's branch may sit
    /// at a lower epoch); we lost our local copy; or a `seat-ask` of ours is
    /// outstanding (sent within [`SEAT_ASK_EXPECT_MS`]).
    ///
    /// UNVERIFIED: Geb's answers say only that a `join` replaces the group
    /// (round 2 section 8); whether a Geb device accepts a replacing Welcome
    /// it did not expect is not stated. This gate, the window and the epoch
    /// rule are bridge-side hardening. The welcomer is NOT restricted to the
    /// elected healer: any member can commit a re-seat (round 2 section 8,
    /// round 4 Q6), and nothing shows Geb requires the healer.
    pub(super) fn reseat_expected(g: &Inner, now: u64) -> Option<(&'static str, bool)> {
        if matches!(g.state, State::Reseating(_)) {
            return Some(("a merged commit re-seats us", false));
        }
        if g.heal
            .p
            .split
            .as_ref()
            .is_some_and(|s| !s.we_won && !s.resolved)
        {
            return Some(("we lost a recorded split", true));
        }
        if g.heal.lost_copy {
            return Some(("we lost our local copy", true));
        }
        let asked = [g.heal.last_ask_ms, g.heal.last_kp_ask_ms]
            .into_iter()
            .flatten()
            .any(|t| now.saturating_sub(t) < SEAT_ASK_EXPECT_MS);
        asked.then_some(("a seat-ask of ours is outstanding", false))
    }

    /// A Welcome while we hold the room: accepted only as a re-seat of OUR
    /// DID (round 2 section 8) that we expect ([`Self::reseat_expected`]).
    /// Anything else is ignored and logged.
    pub(crate) async fn on_reseat_welcome(&self, peer: &str, room: &RoomInfo, w: &str) {
        let now = (self.clock)();
        let joined = {
            let Ok(mut g) = self.lock() else { return };
            if !matches!(g.state, State::Seated(_) | State::Reseating(_)) {
                return;
            }
            let wid = crate::geb::crypto::frame_id::frame_id(w);
            if g.heal.p.last_welcome.as_deref() == Some(wid.as_str()) {
                tracing::debug!("a Welcome already applied came again (redelivery); skipped");
                return;
            }
            let Some((why, lower_ok)) = Self::reseat_expected(&g, now) else {
                tracing::warn!(
                    security_alert = true,
                    "ignoring a replacing Welcome: no re-seat is expected (not split, \
                     not re-seated, no seat-ask outstanding)"
                );
                return;
            };
            tracing::info!(why, "a replacing Welcome is expected; checking it");
            match self.join_from_welcome(&mut g, room, w, Some(peer), lower_ok) {
                Ok(()) => {
                    g.heal.p.last_welcome = Some(wid);
                    match self.persist_state(&g) {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::error!(error = %e, "could not persist after a re-seat");
                            true
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ignoring a welcome while seated (not a re-seat of us)");
                    false
                }
            }
        };
        if joined {
            tracing::warn!("re-seated from a Welcome: the old group was replaced");
            self.sync_fork_marker().await;
            self.send_rs_all(true, &[]).await;
        }
    }

    /// Bring the non-secret fork marker (`geb::forkmark`) in line with the
    /// split the sealed snapshot holds. Cheap and idempotent: it writes only
    /// when the record differs. A failed write is logged and never fails the
    /// caller; the marker is informational.
    pub(super) async fn sync_fork_marker(&self) {
        use crate::geb::forkmark::{self, ForkMarker, ForkState};
        let Some((store, link)) = &self.fork_sink else {
            return;
        };
        let Some(split) = self.split() else { return };
        let state = if split.resolved {
            ForkState::Reseated
        } else if split.we_won {
            ForkState::BranchWon
        } else {
            ForkState::WaitingForReseat
        };
        let marker = ForkMarker {
            v: 1,
            link: link.clone(),
            state,
            fork_epoch: split.epoch,
            our_epoch: split.our_epoch,
            their_epoch: split.their_epoch,
            detected_at_ms: split.at_ms,
            reseated_at_ms: split.resolved_at_ms,
        };
        match forkmark::read(store.as_ref()).await {
            Ok(Some(old)) if old == marker => return,
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "could not read the fork marker"),
        }
        if let Err(e) = forkmark::write(store.as_ref(), &marker).await {
            tracing::warn!(error = %e, "could not write the fork marker");
        }
    }

    /// The new group must be a re-seat of OUR own DID: our DID on a bound leaf
    /// whose signature key is the one we hold the private key for.
    pub(super) fn reseat_consistent(
        &self,
        g: &Inner,
        group: &MlsGroup,
    ) -> std::result::Result<(), String> {
        let leaf = group.own_leaf().ok_or("no own leaf")?;
        if credential_did(leaf.credential()).as_deref() != Some(self.device.did()) {
            return Err("our leaf does not name our DID".into());
        }
        if super::super::commit::binding_status(leaf)
            != super::super::commit::BindingStatus::Verified
        {
            return Err("our leaf is not bound".into());
        }
        let ours = g.ident.leaf_key().map_err(|e| e.to_string())?;
        if leaf.signature_key().as_slice() != ours {
            return Err("our leaf carries a key we do not hold".into());
        }
        Ok(())
    }

    /// After a group was joined (first join or re-seat): reset what described
    /// the old one. A re-seat also queues our own dead-branch lines.
    pub(super) fn after_join(&self, g: &mut Inner, old_epoch: Option<u64>, now: u64) {
        g.queue = SettleQueue::new();
        g.judged.clear();
        let h = &mut g.heal;
        h.p.chain.clear();
        h.commit_bytes.clear();
        h.heard.clear();
        h.pair.clear();
        h.last_answer.clear();
        h.p.joined_ms = Some(now);
        h.p.was_seated = true;
        h.p.reseating = false;
        h.lost_copy = false;
        h.quiet_until_ms = 0;
        h.last_ask_ms = None;
        if let Some(oe) = old_epoch {
            h.reread = true;
            h.reseats += 1;
            let from =
                h.p.split
                    .as_ref()
                    .filter(|s| !s.resolved)
                    .map_or(oe, |s| s.epoch);
            let take: Vec<LineBody> =
                h.p.own_lines
                    .iter()
                    .filter(|l| l.epoch >= from)
                    .map(|l| l.line.clone())
                    .collect();
            let skip = take.len().saturating_sub(OWN_LINES_MAX);
            h.p.pending_reposts = take.into_iter().skip(skip).collect();
            if let Some(s) = h.p.split.as_mut() {
                if !s.resolved {
                    s.resolved_at_ms = Some(now);
                }
                s.resolved = true;
            }
        }
    }

    /// `askReseat` (answers round 4 Q9): a `seat-ask` WITHOUT a package, backed
    /// off to once per 600 s, then our `rs` stays quiet for 600 s.
    pub(super) async fn ask_reseat(&self, peer: &str) {
        let now = (self.clock)();
        let vias = {
            let Ok(mut g) = self.lock() else { return };
            if g.heal
                .last_ask_ms
                .is_some_and(|t| now.saturating_sub(t) < ASK_BACKOFF_MS)
            {
                return;
            }
            let vias = self.member_peers(&g);
            g.heal.last_ask_ms = Some(now);
            g.heal.quiet_until_ms = now.saturating_add(ASK_BACKOFF_MS);
            vias
        };
        tracing::warn!("behind and not catching up: asking to be re-seated");
        let f = Frame::Group(GroupOp::SeatAsk {
            room: RoomRef {
                id: self.cfg.room_id.clone(),
                name: None,
            },
            kp: None,
            via: Some(vias),
        });
        if let Err(e) = self.dyad.send(peer, &f).await {
            tracing::warn!(error = %e, "could not send seat-ask");
        }
    }

    /// `seat-ask` WITH a fresh BOUND KeyPackage (standard base64), backed off
    /// to once per 600 s: for a Welcome we cannot open, a missing local copy,
    /// a seat-check while we hold nothing, or a re-seat Welcome that never
    /// came. Its private keys are kept 7 days like any single package.
    pub(super) async fn seat_ask_with_kp(&self, peer: &str) {
        self.seat_ask_kp(&[peer.to_string()]).await;
    }

    async fn seat_ask_kp(&self, targets: &[String]) {
        let Some(first) = targets.first() else { return };
        let now = (self.clock)();
        let kp = {
            let Ok(mut g) = self.lock() else { return };
            if g.heal
                .last_kp_ask_ms
                .is_some_and(|t| now.saturating_sub(t) < ASK_BACKOFF_MS)
            {
                return;
            }
            let (kp, r) = match self.make_kp(&g, now) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "could not mint a KeyPackage for a seat-ask");
                    return;
                }
            };
            g.contacts
                .entry(first.clone())
                .or_default()
                .singles
                .push(Batch {
                    generation: 0,
                    at_ms: now,
                    refs: vec![r],
                });
            self.prune(&mut g, now);
            if let Err(e) = self.persist_state(&g) {
                tracing::warn!(error = %e, "could not persist a KeyPackage; not sending it");
                return;
            }
            g.heal.last_kp_ask_ms = Some(now);
            kp
        };
        for t in targets {
            let f = Frame::Group(GroupOp::SeatAsk {
                room: RoomRef {
                    id: self.cfg.room_id.clone(),
                    name: None,
                },
                kp: Some(kp.clone()),
                via: None,
            });
            if let Err(e) = self.dyad.send(t, &f).await {
                tracing::warn!(error = %e, "could not send seat-ask");
            }
        }
    }

    /// Timers while we hold or await the room: the two start-up statuses, and
    /// the wait for a re-seat Welcome.
    pub(super) async fn heal_tick(&self, now: u64) {
        enum Do {
            Nothing,
            Start,
            AskKp,
        }
        let act = {
            let Ok(mut g) = self.lock() else { return };
            let reseating = matches!(g.state, State::Reseating(_));
            let h = &mut g.heal;
            if reseating {
                if now.saturating_sub(h.reseating_since_ms) >= SEAT_WAIT_MS {
                    Do::AskKp
                } else {
                    Do::Nothing
                }
            } else {
                let started = *h.started_ms.get_or_insert(now);
                match START_SENDS_MS.get(h.start_sent) {
                    Some(after) if now >= started.saturating_add(*after) => {
                        h.start_sent += 1;
                        Do::Start
                    }
                    _ => Do::Nothing,
                }
            }
        };
        match act {
            Do::Nothing => {}
            Do::Start => self.send_rs_all(false, &[]).await,
            Do::AskKp => self.seat_ask_kp(&self.cfg.peers.clone()).await,
        }
    }

    /// While unseated: a local copy that went missing is asked back with a
    /// fresh bound package (backed off).
    pub(super) async fn heal_unseated_tick(&self) {
        let lost = self
            .lock()
            .map(|g| g.heal.lost_copy && matches!(g.state, State::Unseated))
            .unwrap_or(false);
        if lost {
            self.seat_ask_kp(&self.cfg.peers.clone()).await;
        }
    }
}
