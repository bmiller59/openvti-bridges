//! The settle rule, as a pure component (Geb path B answer 9, read at release
//! 0.5.14; release 0.5.15 is `fdf804d`; guide "Commits").
//!
//! Commits are never applied at once. Every `mc` is **held** for
//! `settleWindowMs` (policy, default 3000, clamped 0-60000). When the window
//! for one parent epoch has run out, the candidates for that epoch are tested
//! in **ascending SHA-256 of the commit bytes**, each against `validCommit`
//! BEFORE it can win:
//!
//! - fails the check (or seats a leaf with a forged binding): dropped (the
//!   staged commit is discarded), reported refused, the next hash is tried;
//! - the first that passes is merged;
//! - all refused: nothing settles, the epoch stays;
//! - MLS cannot process it (a replay, a Commit made on another branch, a
//!   standalone Proposal): recorded **failed** and SKIPPED exactly like a
//!   refusal. The walk NEVER stops on any candidate (answers round 4 Q1):
//!   the first candidate that passes is
//!   merged, whatever failed below it. The two differ only after the walk: if
//!   NOTHING merged and one failed, the read cursor stays before it (so a
//!   later replay is judged again) and the device asks for the room status
//!   (`{k:"g", op:"rs"}`) once; if one merged, a failed candidate changes
//!   nothing.
//!
//! This module knows nothing of MLS. A [`Judge`] tests and merges a candidate;
//! time is an argument (`now_ms`), so tests never sleep.
//!
//! UNVERIFIED (the answers do not say; each is a choice here, not Geb's
//! behaviour):
//! - the window starts at the **local first sight** of the epoch's earliest
//!   held commit, not at the event's `created_at`;
//! - a commit arriving after its epoch's candidates were settled (all refused)
//!   is a new candidate with a new window;
//! - commits made from an epoch ahead of ours are held, never tested. They are
//!   bounded because `e` is unauthenticated: more than [`MAX_EPOCHS_AHEAD`]
//!   ahead is dropped at once, at most [`MAX_HELD_AHEAD`] ahead-of-us commits
//!   are kept (a further one is dropped, newest first), and they never hold the
//!   read cursor back ([`SettleQueue::barrier_secs`]). A dropped commit is
//!   re-read from the relay, or answered by an `rc`, once we are behind enough
//!   for `rs` to say so; Geb's answers state no such cap, so this is a
//!   bridge-side limit and its choice (drop, never halt) is UNVERIFIED;
//! - at most [`MAX_HELD`] commits are held in all. When full, a held commit
//!   already recorded failed is evicted (oldest first) to make room, else the
//!   new commit is dropped (newest first). Dropping a current-epoch candidate
//!   could in principle change the winner, but halting the link on a count
//!   any member can inflate is worse; the drop is logged as a security alert.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Most commits held at once.
pub const MAX_HELD: usize = 256;

/// Most held commits made from an epoch ahead of ours.
pub const MAX_HELD_AHEAD: usize = 64;

/// How far ahead of our epoch a commit's (unauthenticated) `e` may be and
/// still be held. A commit from further ahead cannot be judged until we have
/// merged the epochs between, which we only learn about from the relay or an
/// `rc` again; it is dropped at the door.
pub const MAX_EPOCHS_AHEAD: u64 = 8;

/// What [`SettleQueue::hold`] did with a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Newly held.
    New,
    /// This exact commit is already held or was already settled as refused.
    Duplicate,
    /// Not held, on purpose (the reason is for the log). Never an error: the
    /// `e` and the bytes of an `mc` are unauthenticated until it is judged, so
    /// any member can make a queue limit bite, and a limit must not fail a
    /// poll or stop the link.
    Dropped(&'static str),
}

/// SHA-256 of the commit bytes: the ordering key.
pub type CommitHash = [u8; 32];

/// SHA-256 over the commit bytes.
pub fn commit_hash(bytes: &[u8]) -> CommitHash {
    Sha256::digest(bytes).into()
}

/// A held commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// SHA-256 of `bytes`.
    pub hash: CommitHash,
    /// The epoch the commit says it was made from (`mc.e`).
    pub parent_epoch: u64,
    /// Local time the commit was first seen, ms.
    pub first_seen_ms: u64,
    /// `created_at` (seconds) of the relay event that carried it; used only to
    /// keep the read cursor before it.
    pub event_secs: u64,
    /// The MLS message bytes.
    pub bytes: Vec<u8>,
}

/// What testing one candidate found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// `validCommit` and the binding check pass; it may win.
    Valid,
    /// Fails `validCommit` or seats a forged binding: drop it, try the next.
    Refused(String),
    /// Cannot be processed at all: record failed, keep the cursor before it.
    Unprocessable(String),
    /// The check needs local knowledge this device lacks. Neither merging nor
    /// skipping is safe: stop and alert.
    Undecidable(String),
}

/// Tests and merges candidates. The tester owns whatever staged state a
/// `Valid` verdict leaves behind and drops it when the next candidate is
/// judged.
pub trait Judge {
    /// Test a candidate. Must leave the group unchanged.
    fn judge(&mut self, candidate: &Candidate) -> Verdict;
    /// Merge the candidate that was just judged [`Verdict::Valid`].
    fn merge(&mut self, candidate: &Candidate) -> Result<(), String>;
}

/// What one [`SettleQueue::settle`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing is held for this epoch.
    Idle,
    /// The window has not run out; look again in `wait_ms`.
    Holding { wait_ms: u64 },
    /// `winner` was merged; `refused` and `failed` were tried before it
    /// (ascending) and skipped. A failed one changes nothing once one merged.
    Merged {
        winner: CommitHash,
        refused: Vec<CommitHash>,
        failed: Vec<CommitHash>,
    },
    /// Every candidate was refused; the epoch stays.
    AllRefused { refused: Vec<CommitHash> },
    /// Nothing merged and a candidate could not be processed: recorded
    /// failed, the cursor stays before it. `hash` and `reason` are the lowest
    /// failed one; `failed` lists all. `ask_status` is true when a newly
    /// failed one was recorded, the first time only (the caller sends
    /// `{k:"g",op:"rs"}` once).
    Failed {
        hash: CommitHash,
        reason: String,
        ask_status: bool,
        refused: Vec<CommitHash>,
        failed: Vec<CommitHash>,
    },
    /// A candidate needs knowledge this device lacks: stop.
    Blocked { hash: CommitHash, reason: String },
    /// A candidate passed the test but merging it failed: recorded failed like
    /// an unprocessable one.
    MergeFailed { hash: CommitHash, reason: String },
}

/// The held commits.
#[derive(Debug, Default)]
pub struct SettleQueue {
    held: Vec<Candidate>,
    failed: BTreeSet<CommitHash>,
    refused: BTreeSet<CommitHash>,
}

impl SettleQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of commits held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// The held candidates.
    pub fn held(&self) -> &[Candidate] {
        &self.held
    }

    /// Hashes recorded failed (unprocessable).
    pub fn failed(&self) -> &BTreeSet<CommitHash> {
        &self.failed
    }

    /// The smallest `event_secs` among the held commits the read cursor must
    /// stay before: those made from `epoch` (ours). A commit from an epoch
    /// ahead of ours is not judgeable yet and its `e` is unauthenticated, so
    /// it never holds the cursor (it stays in memory; if the cursor passes it
    /// and we restart, the heal path re-reads or asks for an `rc`; UNVERIFIED
    /// against Geb, which the answers do not describe).
    pub fn barrier_secs(&self, epoch: u64) -> Option<u64> {
        self.held
            .iter()
            .filter(|c| c.parent_epoch <= epoch)
            .map(|c| c.event_secs)
            .min()
    }

    /// Hold a commit made from `parent_epoch` while we are at `epoch`. A
    /// commit that cannot be held is dropped ([`Held::Dropped`]), never an
    /// error; see the module docs for the bounds and why.
    pub fn hold(
        &mut self,
        epoch: u64,
        parent_epoch: u64,
        bytes: Vec<u8>,
        event_secs: u64,
        now_ms: u64,
    ) -> Held {
        let hash = commit_hash(&bytes);
        // Bounded memory: forgetting old refusals only means a re-sent refused
        // commit is tested (and refused) again.
        if self.refused.len() > 4096 {
            self.refused.clear();
        }
        if self.held.iter().any(|c| c.hash == hash) || self.refused.contains(&hash) {
            return Held::Duplicate;
        }
        if parent_epoch > epoch {
            if parent_epoch - epoch > MAX_EPOCHS_AHEAD {
                return Held::Dropped("made from an epoch too far ahead of ours");
            }
            if self.held.iter().filter(|c| c.parent_epoch > epoch).count() >= MAX_HELD_AHEAD {
                return Held::Dropped("too many commits held from epochs ahead of ours");
            }
        }
        if self.held.len() >= MAX_HELD {
            // Make room by evicting a commit already recorded failed (oldest
            // first); otherwise the newcomer is the one dropped.
            let Some(at) = self.held.iter().position(|c| self.failed.contains(&c.hash)) else {
                return Held::Dropped("too many commits held for the settle window");
            };
            let gone = self.held.remove(at);
            self.failed.remove(&gone.hash);
        }
        self.held.push(Candidate {
            hash,
            parent_epoch,
            first_seen_ms: now_ms,
            event_secs,
            bytes,
        });
        Held::New
    }

    /// Forget every held commit made from an epoch below `epoch` (they can no
    /// longer win). Geb receivers ignore such commits at the door as well.
    pub fn prune_below(&mut self, epoch: u64) {
        self.held.retain(|c| c.parent_epoch >= epoch);
    }

    /// Settle the candidates made from `epoch`. `window_ms` is the policy's
    /// settle window (already clamped); `now_ms` is the injectable clock.
    pub fn settle(
        &mut self,
        epoch: u64,
        window_ms: u32,
        now_ms: u64,
        judge: &mut dyn Judge,
    ) -> Outcome {
        let mut mine: Vec<Candidate> = self
            .held
            .iter()
            .filter(|c| c.parent_epoch == epoch)
            .cloned()
            .collect();
        let Some(first) = mine.iter().map(|c| c.first_seen_ms).min() else {
            return Outcome::Idle;
        };
        let due = first.saturating_add(u64::from(window_ms));
        if now_ms < due {
            return Outcome::Holding {
                wait_ms: due - now_ms,
            };
        }
        // Ascending SHA-256 of the commit bytes.
        mine.sort_by_key(|c| c.hash);
        let mut refused = Vec::new();
        let mut failed: Vec<(CommitHash, String)> = Vec::new();
        for c in &mine {
            match judge.judge(c) {
                Verdict::Valid => {
                    return match judge.merge(c) {
                        Ok(()) => {
                            // The winner and every candidate tried before it
                            // are settled; the rest were made from a parent
                            // epoch that no longer exists. A failed candidate
                            // changes nothing once one merged.
                            self.held.retain(|h| h.parent_epoch != epoch);
                            self.refused.extend(refused.iter().copied());
                            let held = &self.held;
                            self.failed.retain(|h| held.iter().any(|c| c.hash == *h));
                            Outcome::Merged {
                                winner: c.hash,
                                refused,
                                failed: failed.into_iter().map(|(h, _)| h).collect(),
                            }
                        }
                        Err(reason) => {
                            self.failed.insert(c.hash);
                            Outcome::MergeFailed {
                                hash: c.hash,
                                reason,
                            }
                        }
                    };
                }
                Verdict::Refused(_) => {
                    refused.push(c.hash);
                }
                // Skipped, the walk goes on to the next hash.
                Verdict::Unprocessable(reason) => failed.push((c.hash, reason)),
                Verdict::Undecidable(reason) => {
                    // Nothing is dropped: the refused ones were refused on
                    // grounds that need no local knowledge, so they stay so.
                    self.drop_refused(&refused);
                    return Outcome::Blocked {
                        hash: c.hash,
                        reason,
                    };
                }
            }
        }
        if let Some((hash, reason)) = failed.first().cloned() {
            // Nothing merged and a candidate failed: the refused ones are
            // dropped; the failed ones stay held, so the cursor stays before
            // them and a later replay is judged again.
            self.drop_refused(&refused);
            let mut ask_status = false;
            for (h, _) in &failed {
                ask_status |= self.failed.insert(*h);
            }
            return Outcome::Failed {
                hash,
                reason,
                ask_status,
                refused,
                failed: failed.into_iter().map(|(h, _)| h).collect(),
            };
        }
        self.held.retain(|h| h.parent_epoch != epoch);
        self.refused.extend(refused.iter().copied());
        Outcome::AllRefused { refused }
    }

    fn drop_refused(&mut self, refused: &[CommitHash]) {
        self.held.retain(|h| !refused.contains(&h.hash));
        self.refused.extend(refused.iter().copied());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Scripted judge: verdict per commit bytes; records the order tested.
    #[derive(Default)]
    struct Script {
        verdicts: HashMap<Vec<u8>, Verdict>,
        tested: Vec<Vec<u8>>,
        merged: Vec<Vec<u8>>,
        merge_fails: bool,
    }

    impl Judge for Script {
        fn judge(&mut self, c: &Candidate) -> Verdict {
            self.tested.push(c.bytes.clone());
            self.verdicts
                .get(&c.bytes)
                .cloned()
                .unwrap_or(Verdict::Valid)
        }
        fn merge(&mut self, c: &Candidate) -> Result<(), String> {
            if self.merge_fails {
                return Err("merge".into());
            }
            self.merged.push(c.bytes.clone());
            Ok(())
        }
    }

    /// Three commit payloads sorted by hash: returns (lowest, middle, highest).
    fn by_hash() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut v: Vec<Vec<u8>> = (0u8..3).map(|i| vec![i, 7, 7]).collect();
        v.sort_by_key(|b| commit_hash(b));
        (v[0].clone(), v[1].clone(), v[2].clone())
    }

    #[test]
    fn nothing_held_is_idle() {
        let mut q = SettleQueue::new();
        assert_eq!(q.settle(0, 3000, 10, &mut Script::default()), Outcome::Idle);
    }

    #[test]
    fn a_commit_is_held_until_the_window_runs_out() {
        let (lo, ..) = by_hash();
        let mut q = SettleQueue::new();
        assert_eq!(q.hold(0, 0, lo.clone(), 5, 1_000), Held::New);
        let mut j = Script::default();
        assert_eq!(
            q.settle(0, 3000, 1_000, &mut j),
            Outcome::Holding { wait_ms: 3000 }
        );
        assert_eq!(
            q.settle(0, 3000, 3_999, &mut j),
            Outcome::Holding { wait_ms: 1 }
        );
        assert!(j.tested.is_empty() && j.merged.is_empty());
        assert!(matches!(
            q.settle(0, 3000, 4_000, &mut j),
            Outcome::Merged { .. }
        ));
        assert_eq!(j.merged, vec![lo]);
        assert!(q.is_empty());
    }

    #[test]
    fn a_zero_window_decides_at_once() {
        let (lo, ..) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, 0, lo, 5, 1_000);
        assert!(matches!(
            q.settle(0, 0, 1_000, &mut Script::default()),
            Outcome::Merged { .. }
        ));
    }

    #[test]
    fn the_lowest_hash_wins_whatever_the_arrival_order() {
        let (lo, mid, hi) = by_hash();
        for order in [
            [&lo, &mid, &hi],
            [&hi, &mid, &lo],
            [&mid, &hi, &lo],
            [&hi, &lo, &mid],
        ] {
            let mut q = SettleQueue::new();
            for (i, c) in order.iter().enumerate() {
                q.hold(4, 4, (*c).clone(), 5, 1_000 + i as u64 * 100);
            }
            let mut j = Script::default();
            let out = q.settle(4, 3000, 5_000, &mut j);
            assert_eq!(
                out,
                Outcome::Merged {
                    winner: commit_hash(&lo),
                    refused: vec![],
                    failed: vec![]
                }
            );
            assert_eq!(j.merged, vec![lo.clone()]);
            // Only the winner was tested: nothing past it is looked at.
            assert_eq!(j.tested, vec![lo.clone()]);
            assert!(q.is_empty(), "losers made from a dead epoch are forgotten");
        }
    }

    #[test]
    fn the_window_runs_from_the_earliest_sight() {
        let (lo, mid, _) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, 0, mid, 5, 1_000);
        q.hold(0, 0, lo, 5, 3_500);
        let mut j = Script::default();
        // 3000 ms after the FIRST sighting.
        assert!(matches!(
            q.settle(0, 3000, 3_999, &mut j),
            Outcome::Holding { .. }
        ));
        assert!(matches!(
            q.settle(0, 3000, 4_000, &mut j),
            Outcome::Merged { .. }
        ));
    }

    #[test]
    fn a_failing_candidate_is_dropped_and_the_next_one_wins() {
        let (lo, mid, hi) = by_hash();
        let mut q = SettleQueue::new();
        for c in [&hi, &lo, &mid] {
            q.hold(0, 0, c.clone(), 5, 0);
        }
        let mut j = Script::default();
        j.verdicts.insert(lo.clone(), Verdict::Refused("x".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Merged {
                winner: commit_hash(&mid),
                refused: vec![commit_hash(&lo)],
                failed: vec![]
            }
        );
        assert_eq!(j.tested, vec![lo.clone(), mid.clone()]);
        assert_eq!(j.merged, vec![mid]);
        // The refused commit coming round again is not a new candidate.
        assert_eq!(q.hold(0, 0, lo, 5, 9), Held::Duplicate);
    }

    #[test]
    fn all_refused_leaves_the_epoch_where_it_was() {
        let (lo, mid, hi) = by_hash();
        let mut q = SettleQueue::new();
        let mut j = Script::default();
        for c in [&lo, &mid, &hi] {
            q.hold(0, 0, c.clone(), 5, 0);
            j.verdicts.insert(c.clone(), Verdict::Refused("no".into()));
        }
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::AllRefused {
                refused: vec![commit_hash(&lo), commit_hash(&mid), commit_hash(&hi)]
            }
        );
        assert!(j.merged.is_empty());
        assert!(q.is_empty());
        assert_eq!(q.settle(0, 0, 0, &mut j), Outcome::Idle);
    }

    /// Answers round 4 Q1: a failed candidate never stops the walk. A lower
    /// hash that fails is skipped and the valid higher hash is merged.
    #[test]
    fn a_failed_candidate_with_a_lower_hash_does_not_stop_the_walk() {
        let (lo, mid, hi) = by_hash();
        let mut q = SettleQueue::new();
        for c in [&hi, &lo, &mid] {
            q.hold(0, 0, c.clone(), 7, 0);
        }
        let mut j = Script::default();
        j.verdicts
            .insert(lo.clone(), Verdict::Unprocessable("replay".into()));
        j.verdicts.insert(mid.clone(), Verdict::Refused("r".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Merged {
                winner: commit_hash(&hi),
                refused: vec![commit_hash(&mid)],
                failed: vec![commit_hash(&lo)]
            }
        );
        assert_eq!(j.tested, vec![lo.clone(), mid.clone(), hi.clone()]);
        assert_eq!(j.merged, vec![hi]);
        // One merged: the failed candidate changes nothing (no rs, no cursor
        // barrier, nothing recorded failed).
        assert!(q.is_empty() && q.barrier_secs(0).is_none());
        assert!(q.failed().is_empty());
    }

    #[test]
    fn with_no_merge_a_failed_candidate_keeps_the_cursor_and_asks_for_status_once() {
        let (lo, mid, _) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, 0, lo.clone(), 7, 0);
        q.hold(0, 0, mid.clone(), 9, 0);
        let mut j = Script::default();
        j.verdicts
            .insert(lo.clone(), Verdict::Unprocessable("replay".into()));
        j.verdicts.insert(mid.clone(), Verdict::Refused("r".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Failed {
                hash: commit_hash(&lo),
                reason: "replay".into(),
                ask_status: true,
                refused: vec![commit_hash(&mid)],
                failed: vec![commit_hash(&lo)]
            }
        );
        assert!(j.merged.is_empty());
        assert_eq!(j.tested, vec![lo.clone(), mid.clone()], "the walk went on");
        // The refused one is dropped; the failed one stays held, so the
        // cursor stays before it.
        assert_eq!(q.len(), 1);
        assert_eq!(q.barrier_secs(0), Some(7));
        assert!(q.failed().contains(&commit_hash(&lo)));
        // Judged again on the next settle, but the status is asked only once.
        let again = q.settle(0, 0, 10, &mut j);
        assert!(matches!(
            again,
            Outcome::Failed {
                ask_status: false,
                ..
            }
        ));
    }

    #[test]
    fn an_undecidable_candidate_blocks_and_nothing_is_merged_or_skipped() {
        let (lo, mid, _) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, 0, lo.clone(), 5, 0);
        q.hold(0, 0, mid.clone(), 5, 0);
        let mut j = Script::default();
        j.verdicts
            .insert(lo.clone(), Verdict::Undecidable("needs persona".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Blocked {
                hash: commit_hash(&lo),
                reason: "needs persona".into()
            }
        );
        assert!(j.merged.is_empty());
        assert_eq!(q.len(), 2, "both stay held");
        // A refusal below the undecidable one stays dropped.
        let (lo2, mid2, hi2) = by_hash();
        let mut q = SettleQueue::new();
        for c in [&lo2, &mid2, &hi2] {
            q.hold(0, 0, c.clone(), 5, 0);
        }
        let mut j = Script::default();
        j.verdicts.insert(lo2.clone(), Verdict::Refused("r".into()));
        j.verdicts
            .insert(mid2.clone(), Verdict::Undecidable("u".into()));
        assert!(matches!(q.settle(0, 0, 0, &mut j), Outcome::Blocked { .. }));
        assert_eq!(q.len(), 2);
        assert!(j.merged.is_empty());
    }

    #[test]
    fn a_failed_merge_is_recorded_not_swallowed() {
        let (lo, ..) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, 0, lo.clone(), 5, 0);
        let mut j = Script {
            merge_fails: true,
            ..Script::default()
        };
        assert!(matches!(
            q.settle(0, 0, 0, &mut j),
            Outcome::MergeFailed { .. }
        ));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn only_the_current_epochs_candidates_are_tested() {
        let (lo, mid, _) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(5, 5, lo, 5, 0); // from the future
        q.hold(3, 3, mid, 5, 0); // from the past
        let mut j = Script::default();
        assert_eq!(q.settle(4, 0, 0, &mut j), Outcome::Idle);
        assert!(j.tested.is_empty());
        q.prune_below(4);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn duplicates_are_not_held_twice_and_a_full_queue_drops_never_fails() {
        let mut q = SettleQueue::new();
        assert_eq!(q.hold(0, 0, vec![1], 1, 0), Held::New);
        assert_eq!(q.hold(0, 0, vec![1], 1, 5), Held::Duplicate);
        for i in 0..(MAX_HELD - 1) {
            q.hold(0, 0, vec![2, (i % 250) as u8, (i / 250) as u8], 1, 0);
        }
        assert_eq!(q.len(), MAX_HELD);
        // Full: the newcomer is dropped, not an error, and nothing grows.
        assert!(matches!(
            q.hold(0, 0, vec![9, 9, 9, 9], 1, 0),
            Held::Dropped(_)
        ));
        assert_eq!(q.len(), MAX_HELD);
    }

    #[test]
    fn a_full_queue_evicts_a_failed_commit_oldest_first_before_dropping_a_newcomer() {
        let mut q = SettleQueue::new();
        let mut j = Script::default();
        for i in 0..MAX_HELD {
            let b = vec![3, (i % 250) as u8, (i / 250) as u8];
            q.hold(0, 0, b.clone(), 1, 0);
            if i < 2 {
                j.verdicts.insert(b, Verdict::Unprocessable("x".into()));
            } else {
                j.verdicts.insert(b, Verdict::Refused("r".into()));
            }
        }
        // Make two of them failed (the others refused and dropped by settle).
        q.settle(0, 0, 0, &mut j);
        assert_eq!(q.len(), 2);
        for i in 0..(MAX_HELD - 2) {
            q.hold(0, 0, vec![4, (i % 250) as u8, (i / 250) as u8], 1, 0);
        }
        assert_eq!(q.len(), MAX_HELD);
        let failed_before = q.failed().len();
        assert_eq!(q.hold(0, 0, vec![5, 5, 5], 1, 0), Held::New);
        assert_eq!(q.len(), MAX_HELD);
        assert_eq!(q.failed().len(), failed_before - 1);
    }

    #[test]
    fn commits_from_far_or_numerous_future_epochs_are_dropped_not_errors() {
        let mut q = SettleQueue::new();
        // Beyond the bound: dropped at once, whatever the count.
        assert!(matches!(
            q.hold(5, 5 + MAX_EPOCHS_AHEAD + 1, vec![1], 1, 0),
            Held::Dropped(_)
        ));
        assert!(matches!(
            q.hold(5, u64::MAX, vec![2], 1, 0),
            Held::Dropped(_)
        ));
        assert!(q.is_empty());
        // Within the bound: held up to MAX_HELD_AHEAD, then dropped newest-first.
        for i in 0..MAX_HELD_AHEAD {
            let b = vec![3, i as u8];
            assert_eq!(q.hold(5, 6, b, 1, 0), Held::New);
        }
        assert!(matches!(q.hold(5, 6, vec![4, 4], 1, 0), Held::Dropped(_)));
        assert_eq!(q.len(), MAX_HELD_AHEAD);
        // The ahead cap does not stop commits made from our own epoch.
        assert_eq!(q.hold(5, 5, vec![6], 1, 0), Held::New);
    }

    #[test]
    fn only_commits_from_our_epoch_or_below_hold_the_cursor() {
        let mut q = SettleQueue::new();
        q.hold(5, 6, vec![1], 3, 0); // ahead, older event
        assert_eq!(q.barrier_secs(5), None, "an ahead commit never pins");
        q.hold(5, 5, vec![2], 9, 0);
        assert_eq!(q.barrier_secs(5), Some(9));
        assert_eq!(q.barrier_secs(6), Some(3), "it pins once it is ours");
    }

    #[test]
    fn hash_order_is_bytewise_ascending() {
        let mut v = [[0u8; 32], [1u8; 32], [0u8; 32]];
        v[2][31] = 1;
        v.sort();
        assert_eq!(v[0], [0u8; 32]);
        assert_eq!(v[2], [1u8; 32]);
        // SHA-256 of the empty string, a published value.
        assert_eq!(
            hex::encode(commit_hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
