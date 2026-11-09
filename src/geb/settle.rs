//! The settle rule, as a pure component (Geb path B answer 9, code at commit
//! release 0.5.14; guide "Commits").
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
//! - …
//!   … **failed**; the read cursor stays before it and the device asks
//!   for the room status (`{k:"g", op:"rs"}`), which starts fork repair.
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
//! - an `unprocessable` candidate stops the walk: higher hashes are not tried
//!   (the read cursor "stays before it", so nothing past it is read);
//! - commits made from an epoch ahead of ours are held, never tested, and at
//!   most [`MAX_HELD`] are kept: more than that is a hard stop, because
//!   dropping a candidate could change the winner.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Most commits held at once.
pub const MAX_HELD: usize = 256;

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
    /// `winner` was merged; `refused` were tried before it (ascending).
    Merged {
        winner: CommitHash,
        refused: Vec<CommitHash>,
    },
    /// Every candidate was refused; the epoch stays.
    AllRefused { refused: Vec<CommitHash> },
    /// A candidate could not be processed: recorded failed. `ask_status` is
    /// true the first time only (the caller sends `{k:"g",op:"rs"}`).
    Failed {
        hash: CommitHash,
        reason: String,
        ask_status: bool,
        refused: Vec<CommitHash>,
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

    /// The smallest `event_secs` among held and failed-held commits: the read
    /// cursor must not pass it.
    pub fn barrier_secs(&self) -> Option<u64> {
        self.held.iter().map(|c| c.event_secs).min()
    }

    /// Hold a commit. Returns `Ok(true)` when it is new, `Ok(false)` when this
    /// exact commit is already held or was already settled as refused. A full
    /// queue is an error: dropping a candidate could change the winner.
    pub fn hold(
        &mut self,
        parent_epoch: u64,
        bytes: Vec<u8>,
        event_secs: u64,
        now_ms: u64,
    ) -> Result<bool, String> {
        let hash = commit_hash(&bytes);
        // Bounded memory: forgetting old refusals only means a re-sent refused
        // commit is tested (and refused) again.
        if self.refused.len() > 4096 {
            self.refused.clear();
        }
        if self.held.iter().any(|c| c.hash == hash) || self.refused.contains(&hash) {
            return Ok(false);
        }
        if self.held.len() >= MAX_HELD {
            return Err(format!("more than {MAX_HELD} commits held"));
        }
        self.held.push(Candidate {
            hash,
            parent_epoch,
            first_seen_ms: now_ms,
            event_secs,
            bytes,
        });
        Ok(true)
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
        for c in &mine {
            match judge.judge(c) {
                Verdict::Valid => {
                    return match judge.merge(c) {
                        Ok(()) => {
                            // The winner and every candidate tried before it
                            // are settled; the rest were made from a parent
                            // epoch that no longer exists.
                            self.held.retain(|h| h.parent_epoch != epoch);
                            self.refused.extend(refused.iter().copied());
                            Outcome::Merged {
                                winner: c.hash,
                                refused,
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
                Verdict::Unprocessable(reason) => {
                    // Candidates refused before it stay dropped.
                    self.drop_refused(&refused);
                    let ask_status = self.failed.insert(c.hash);
                    return Outcome::Failed {
                        hash: c.hash,
                        reason,
                        ask_status,
                        refused,
                    };
                }
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
        assert_eq!(q.hold(0, lo.clone(), 5, 1_000), Ok(true));
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
        q.hold(0, lo, 5, 1_000).unwrap();
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
                q.hold(4, (*c).clone(), 5, 1_000 + i as u64 * 100).unwrap();
            }
            let mut j = Script::default();
            let out = q.settle(4, 3000, 5_000, &mut j);
            assert_eq!(
                out,
                Outcome::Merged {
                    winner: commit_hash(&lo),
                    refused: vec![]
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
        q.hold(0, mid, 5, 1_000).unwrap();
        q.hold(0, lo, 5, 3_500).unwrap();
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
            q.hold(0, c.clone(), 5, 0).unwrap();
        }
        let mut j = Script::default();
        j.verdicts.insert(lo.clone(), Verdict::Refused("x".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Merged {
                winner: commit_hash(&mid),
                refused: vec![commit_hash(&lo)]
            }
        );
        assert_eq!(j.tested, vec![lo.clone(), mid.clone()]);
        assert_eq!(j.merged, vec![mid]);
        // The refused commit coming round again is not a new candidate.
        assert_eq!(q.hold(0, lo, 5, 9), Ok(false));
    }

    #[test]
    fn all_refused_leaves_the_epoch_where_it_was() {
        let (lo, mid, hi) = by_hash();
        let mut q = SettleQueue::new();
        let mut j = Script::default();
        for c in [&lo, &mid, &hi] {
            q.hold(0, c.clone(), 5, 0).unwrap();
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

    #[test]
    fn an_unprocessable_candidate_is_recorded_once_and_stops_the_walk() {
        let (lo, mid, _) = by_hash();
        let mut q = SettleQueue::new();
        q.hold(0, lo.clone(), 7, 0).unwrap();
        q.hold(0, mid.clone(), 9, 0).unwrap();
        let mut j = Script::default();
        j.verdicts
            .insert(lo.clone(), Verdict::Unprocessable("replay".into()));
        let out = q.settle(0, 0, 0, &mut j);
        assert_eq!(
            out,
            Outcome::Failed {
                hash: commit_hash(&lo),
                reason: "replay".into(),
                ask_status: true,
                refused: vec![]
            }
        );
        assert!(j.merged.is_empty(), "a higher hash is not tried past it");
        assert_eq!(j.tested, vec![lo.clone()]);
        // Still held, so the cursor stays before it; asked for status once.
        assert_eq!(q.barrier_secs(), Some(7));
        assert!(q.failed().contains(&commit_hash(&lo)));
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
        q.hold(0, lo.clone(), 5, 0).unwrap();
        q.hold(0, mid.clone(), 5, 0).unwrap();
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
            q.hold(0, c.clone(), 5, 0).unwrap();
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
        q.hold(0, lo.clone(), 5, 0).unwrap();
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
        q.hold(5, lo, 5, 0).unwrap(); // from the future
        q.hold(3, mid, 5, 0).unwrap(); // from the past
        let mut j = Script::default();
        assert_eq!(q.settle(4, 0, 0, &mut j), Outcome::Idle);
        assert!(j.tested.is_empty());
        q.prune_below(4);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn duplicates_are_not_held_twice_and_the_queue_is_bounded() {
        let mut q = SettleQueue::new();
        assert_eq!(q.hold(0, vec![1], 1, 0), Ok(true));
        assert_eq!(q.hold(0, vec![1], 1, 5), Ok(false));
        for i in 0..(MAX_HELD - 1) {
            q.hold(0, vec![2, (i % 250) as u8, (i / 250) as u8], 1, 0)
                .unwrap();
        }
        assert!(q.hold(0, vec![9, 9, 9, 9], 1, 0).is_err());
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
