//! The room policy (GroupContext extension `0xF001`) and what a commit check
//! needs. Pinned to Geb's path B answers, rounds 1 to 4, at release 0.5.15 (commit
//! `fdf804d`); the summary of what each round settled is in this crate's
//! `CLAUDE.md`.
//!
//! # Policy
//!
//! New rooms are founded with `{v:2, committer:"any-staged",
//! settleWindowMs:3000, root:<founder DID>, admins:[]}`; direct rooms add
//! `direct:[lo, hi]`. [`parse_policy`] reads a malformed or missing policy as
//! the v1 default `{v:1, committer:"any-staged", settleWindowMs:3000}`. Nothing
//! reads `committer` beyond the parse, so `"owner"` is not enforced by Geb at
//! this release. Only `root` can change the policy, by a GroupContextExtensions
//! Commit that leaves `committer` and `settleWindowMs` alone.
//!
//! # Commit check
//!
//! Geb tests candidates before one can win rather than picking a winner and then
//! testing it: it walks the candidate Commits for one parent epoch (its own
//! pending Commit included) in ascending SHA-256 order.
//!
//! - a candidate rejected by `validCommit`, or one that seats a forged-binding
//!   leaf, is dropped (`drop_staged`), reported `refused`, and the next hash
//!   is tried;
//! - the first Commit that passes is merged, on every device that reaches the
//!   same verdict;
//! - if all are refused, nothing settles and the epoch stays;
//! - a candidate MLS cannot even process (a replay, a Commit made on another
//!   branch, a standalone Proposal) is recorded `failed` and SKIPPED like a
//!   refusal (the walk never stops). Only if nothing merged does the cursor
//!   stay before it and one `rs` go out.
//!
//! `validCommit` passes a Remove when ANY of four holds: (A) the leaves removed
//! all belong to the sender's own person (without a persona store, the sender's
//! own DID); (B) each removed leaf has a signed leave on file here and the
//! commit adds nothing and changes no policy; (C) it is a re-seat, the same
//! non-empty DID set both removed and added, with the policy untouched; (D) the
//! sender is root or an admin (EXACT DID
//! compare), or the room's policy is v1. It needs a sender whose leaf is bound
//! before the commit, except `selfHeal`. A policy change comes from `root`, is
//! v2 and keeps `committer` / `settleWindowMs`; a direct room seats only its
//! two persons' devices. Adds otherwise pass.
//!
//! Anything else is refused and Geb goes on; it never halts a room.
//!
//! **Two inputs are local knowledge**: "same person" (persona cards, which
//! the bridge does NOT hold: no persona-card intake is built) and "signed
//! leave" (`{t:"lv"}` room lines and dyad `leave` frames, which the bridge
//! takes: `geb::leave`). The only commits that remain card-dependent are a
//! Remove of another DID by a non-root, non-admin sender in a v2 room with no
//! signed leave and not a re-seat (and a direct-room Add of a non-exact DID).
//! A Geb device holding a card linking the DIDs would merge it and we cannot
//! know, so [`valid_commit`] answers [`CommitVerdict::Undecidable`] and the
//! bridge HALTS (persisted) rather than silently fork. That halt is a
//! deliberate bridge-side choice; Geb itself refuses and continues.

use serde_json::Value;

/// Default settle window, ms.
pub const DEFAULT_SETTLE_WINDOW_MS: u32 = 3000;
/// Largest settle window after clamping, ms.
pub const MAX_SETTLE_WINDOW_MS: u32 = 60_000;

/// Who may commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committer {
    /// Any member may stage a commit.
    AnyStaged,
    /// Only the owner (not enforced by Geb at release 0.5.14).
    Owner,
}

/// Who may edit lines (optional field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditPolicy {
    /// Everyone.
    All,
    /// Admins only.
    Admins,
}

/// A parsed room policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPolicy {
    /// 1 or 2.
    pub v: u8,
    /// Who may commit.
    pub committer: Committer,
    /// Settle window, 0-60000 ms.
    pub settle_window_ms: u32,
    /// v2: the root DID.
    pub root: Option<String>,
    /// v2: admin DIDs.
    pub admins: Vec<String>,
    /// Optional edit rule.
    pub edit: Option<EditPolicy>,
    /// Optional direct-room pair (two distinct DIDs, sorted).
    pub direct: Option<[String; 2]>,
}

impl Default for RoomPolicy {
    /// What a malformed policy reads as.
    fn default() -> Self {
        Self {
            v: 1,
            committer: Committer::AnyStaged,
            settle_window_ms: DEFAULT_SETTLE_WINDOW_MS,
            root: None,
            admins: Vec::new(),
            edit: None,
            direct: None,
        }
    }
}

// UNVERIFIED: Geb's answer states the rules but not these details of
// `parsePolicy`: the exact "DID string" predicate (here: starts with `did:`),
// how a non-integer settleWindowMs is rounded (here: floored), whether an
// invalid optional `edit` / `direct` drops only that field or the whole policy
// (here: only that field), and whether `direct` must arrive sorted or is
// sorted on read (here: it must be two distinct DIDs and is returned sorted).
fn is_did(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| s.starts_with("did:"))
}

/// Parse a policy JSON string the way Geb's `parsePolicy` does (answer 7).
/// Pure; never fails: anything malformed is [`RoomPolicy::default`].
pub fn parse_policy(json: &str) -> RoomPolicy {
    parse_inner(json).unwrap_or_default()
}

fn parse_inner(json: &str) -> Option<RoomPolicy> {
    let v: Value = serde_json::from_str(json).ok()?;
    let o = v.as_object()?;
    let ver = o.get("v")?.as_u64()?;
    if ver != 1 && ver != 2 {
        return None;
    }
    let committer = match o.get("committer")?.as_str()? {
        "any-staged" => Committer::AnyStaged,
        "owner" => Committer::Owner,
        _ => return None,
    };
    let w = o.get("settleWindowMs")?.as_f64()?;
    if !w.is_finite() {
        return None;
    }
    let settle_window_ms = w.clamp(0.0, f64::from(MAX_SETTLE_WINDOW_MS)).floor() as u32;
    let (mut root, mut admins) = (None, Vec::new());
    if ver == 2 {
        root = Some(is_did(o.get("root")?)?.to_string());
        for a in o.get("admins")?.as_array()? {
            admins.push(is_did(a)?.to_string());
        }
    }
    let edit = match o.get("edit").and_then(Value::as_str) {
        Some("all") => Some(EditPolicy::All),
        Some("admins") => Some(EditPolicy::Admins),
        _ => None,
    };
    let direct = o.get("direct").and_then(Value::as_array).and_then(|d| {
        let [a, b] = d.as_slice() else { return None };
        let (a, b) = (is_did(a)?, is_did(b)?);
        if a == b {
            return None;
        }
        let mut p = [a.to_string(), b.to_string()];
        p.sort();
        Some(p)
    });
    Some(RoomPolicy {
        v: ver as u8,
        committer,
        settle_window_ms,
        root,
        admins,
        edit,
        direct,
    })
}

/// The two inputs of Geb's `validCommit` that are **local knowledge**: "same
/// person" (from the persona cards a device holds, persona code) and "signed
/// leave" (from the signed leaves `{t:"lv", at, ls}` it has taken,
/// `leave code:33-60`).
///
/// The bridge takes signed leaves (`geb::leave`) but holds **no persona
/// store** (persona-card intake is not built), so `same_person` is exact
/// equality only and `can_evaluate()` is false in production. While that is
/// false [`valid_commit`] answers [`CommitVerdict::Undecidable`] only for the
/// commits a persona card could still rescue (see there), and the caller
/// halts rather than merge or skip them.
pub trait CommitCheckInputs: Send + Sync {
    /// Whether the two answers below are real. False means they are guesses
    /// and `validCommit` cannot be evaluated like Geb.
    fn can_evaluate(&self) -> bool;
    /// Whether devices (or persons) `a` and `b` are the same person.
    fn same_person(&self, a: &str, b: &str) -> bool;
    /// Whether this device holds a signed leave covering `device_did` (exactly
    /// that DID without a persona store).
    fn has_signed_leave(&self, device_did: &str) -> bool;
}

/// Inputs with no persona store and no signed leaves: nothing is known, and
/// [`CommitCheckInputs::can_evaluate`] is false. (Production wraps this with
/// the signed leaves the client holds.)
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalKnowledge;

impl CommitCheckInputs for NoLocalKnowledge {
    fn can_evaluate(&self) -> bool {
        false
    }
    fn same_person(&self, _a: &str, _b: &str) -> bool {
        false
    }
    fn has_signed_leave(&self, _device_did: &str) -> bool {
        false
    }
}

/// What a Commit does, reduced to what `validCommit` reads. Built by the MLS
/// layer from the staged commit; every DID is a BasicCredential identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitFacts {
    /// The committer's device DID.
    pub sender: String,
    /// Devices the commit adds.
    pub adds: Vec<String>,
    /// Devices the commit removes.
    pub removes: Vec<String>,
    /// The new policy when the commit changes the `0xF001` GroupContext
    /// extension (`None`: no policy change).
    pub policy_change: Option<RoomPolicy>,
    /// The commit carries a proposal kind Geb's check is not described for
    /// (Update, PreSharedKey, ReInit, ExternalInit, SelfRemove, custom, a
    /// group-context change beyond the policy, a non-UTF-8 identity). Such a
    /// commit is refused and the walk goes on (UNVERIFIED against Geb).
    pub unclassified: bool,
    /// The sender's current leaf (in the tree the commit is made from) is
    /// **bound** (0.5.15, answers round 2 section 7). Default `false`: fail
    /// closed.
    pub sender_bound: bool,
    /// Device DIDs seated now, before the commit.
    pub seated: Vec<String>,
    /// Added leaves that carry NO binding (`unbound`), by DID. A forged binding
    /// never reaches here: the judge refuses it first.
    pub unbound_adds: Vec<String>,
}

/// The answer of [`valid_commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitVerdict {
    /// Geb's `validCommit` passes.
    Valid,
    /// Geb's `validCommit` fails; the reason names the rule.
    Invalid(String),
    /// The answer needs local knowledge (or a rule) this device lacks.
    Undecidable(String),
}

/// Root and admin are an **exact** DID compare, never widened by persona cards
/// (answers round 4, Q4): a root's sibling device holds no such rights.
fn is_root_or_admin(policy: &RoomPolicy, who: &str) -> bool {
    policy.root.as_deref() == Some(who) || policy.admins.iter().any(|a| a == who)
}

/// `selfHeal` (answers round 4, Q2): the one way an UNBOUND sender may commit a
/// Remove, which is to replace itself. It needs no policy change, only leaves of
/// the sender's own DID removed, at least one leaf added, and every added leaf
/// carrying that DID and a binding signed by the sender's own key (a present binding that does not verify never reaches here: the
/// judge refuses a forged one first, and an unbound one is in `unbound_adds`).
/// A plain heal (path only, no Remove) never reaches this rule at all.
fn self_heal(facts: &CommitFacts) -> bool {
    facts.policy_change.is_none()
        && !facts.removes.is_empty()
        && facts.removes.iter().all(|d| d == &facts.sender)
        && !facts.adds.is_empty()
        && facts.adds.iter().all(|d| d == &facts.sender)
        && facts.unbound_adds.is_empty()
}

/// Geb's `validCommit` (answer 9), pure over the facts, the
/// policy read from the **group context** and the local-knowledge inputs.
///
/// Without a persona store ([`CommitCheckInputs::can_evaluate`] false) every
/// commit Geb decides without persona cards is decided here: adds, removes by
/// the exact-DID root or an admin or in a v1 room, a Remove of the sender's own
/// DID, a Remove covered by a held signed leave, re-seats, root policy
/// changes, an exact member of a direct pair added, and every 0.5.15
/// bound-leaf refusal. Geb itself REFUSES anything else and goes on; it never
/// halts. The ONE residue this bridge cannot decide, and where it halts instead
/// (a deliberate bridge-side choice, the honest alternative to silently
/// forking): a Remove of another DID by a non-root, non-admin sender in a v2
/// room with no signed leave we hold and not a re-seat, which a Geb device
/// holding a persona card linking the two DIDs would merge. Also a direct-room
/// Add of a DID that is not exactly one of the pair. A card-free refusal
/// elsewhere in the same commit still wins.
///
/// UNVERIFIED: the answers state the rules, not these details. A re-seat
/// compares removed and added DIDs as sets; `p.v !== 2` is read on the room's
/// CURRENT policy (before the commit); an admin may change nothing but
/// removes.
pub fn valid_commit(
    policy: &RoomPolicy,
    facts: &CommitFacts,
    inputs: &dyn CommitCheckInputs,
) -> CommitVerdict {
    use CommitVerdict::{Invalid, Undecidable, Valid};
    if facts.unclassified {
        // Refused, and the walk goes on: a member must not be able to halt the
        // link by commit content alone (round 4 Q1, Q6: Geb refuses a commit
        // that fails its check and carries on; it never halts). UNVERIFIED:
        // the answers do not say what Geb does with an Update, PreSharedKey,
        // ReInit, SelfRemove, custom proposal or a group-context change beyond
        // the policy (OpenMLS may refuse it before `validCommit`, which is
        // also "skip"); if Geb merged such a commit we would diverge, and the
        // fork-repair path (`rs`) is what would mend it.
        return Invalid("commit carries a proposal type the check is not described for".into());
    }
    // 0.5.15 (answers round 2 sections 1 and 7), neither rule needs persona
    // cards, so both hold whether or not `can_evaluate`.
    //
    // unboundClaim: an unbound leaf that names the root, an admin or a DID
    // already seated is never seated. (A re-seat's added leaf names a DID that
    // is still seated when the commit is made, so an unbound re-seat leaf is
    // refused too: confirmed, answers round 4 Q5, `seated` is the list before
    // the commit and nothing exempts a DID the same commit removes.)
    for d in &facts.unbound_adds {
        if policy.root.as_deref() == Some(d.as_str())
            || policy.admins.contains(d)
            || facts.seated.contains(d)
        {
            return Invalid(format!(
                "unboundClaim: an unbound leaf names {d}, the root, an admin or a seated DID"
            ));
        }
    }
    // Removing, re-seating (which removes a leaf) and changing policy all need
    // the sender's leaf to have been bound BEFORE the commit; the one exception is
    // `selfHeal` (answers round 4, Q2), a Remove and never a policy change.
    if (!facts.removes.is_empty() || facts.policy_change.is_some())
        && !facts.sender_bound
        && !self_heal(facts)
    {
        return Invalid(
            "a remove, re-seat or policy change needs a sender whose leaf is bound \
             (selfHeal excepted)"
                .into(),
        );
    }
    // From here, a rule that fails is `Invalid` when the inputs are real. When
    // they are not (`!can_evaluate`) a rule fails only if no persona card or
    // signed leave could rescue the commit; one that a card could rescue is
    // recorded in `undecided` and the answer is `Undecidable` unless another,
    // card-free rule refuses it first (a refusal is decisive).
    let cards = inputs.can_evaluate();
    let mut undecided: Option<String> = None;
    let mut needs_cards = |why: &str| -> Option<CommitVerdict> {
        if cards {
            Some(Invalid(why.into()))
        } else {
            undecided.get_or_insert_with(|| format!("{why}; needs persona cards or signed leaves"));
            None
        }
    };
    // Direct rooms: only devices of the two persons (an exact DID needs no
    // card, a sibling device does), and `direct` is fixed.
    if let Some(pair) = &policy.direct {
        for add in &facts.adds {
            let ok = pair.iter().any(|p| add == p || inputs.same_person(add, p));
            if !ok && let Some(v) = needs_cards("a direct room seats only its two persons' devices")
            {
                return v;
            }
        }
        if let Some(new) = &facts.policy_change
            && new.direct.as_ref() != Some(pair)
        {
            return Invalid("a policy change alters direct".into());
        }
    }
    if !facts.removes.is_empty() {
        // Geb's exact `validCommit` for removes (answers
        // round 4, Q6). A Remove passes when ANY of:
        //  1. own person: all removed DIDs are the sender's person (`a === b`,
        //     or the same person by persona card). Without a persona store only
        //     `a === b` can be decided;
        //  2. signed leave: a signed leave we hold covers each removed leaf, and
        //     the commit adds nothing and changes no policy;
        //  3. re-seat: the removed and added DIDs are one non-empty set, policy
        //     untouched;
        //  4. the sender is root or an admin (exact), or the room's policy is v1.
        // Geb REFUSES everything else and goes on; a room is never halted.
        let leave = facts
            .removes
            .iter()
            .all(|r| r == &facts.sender || inputs.same_person(&facts.sender, r));
        let signed_out = facts.adds.is_empty()
            && facts.policy_change.is_none()
            && facts.removes.iter().all(|r| inputs.has_signed_leave(r));
        let reseat = {
            let (mut a, mut r) = (facts.adds.clone(), facts.removes.clone());
            a.sort();
            a.dedup();
            r.sort();
            r.dedup();
            !r.is_empty() && a == r && facts.policy_change.is_none()
        };
        let may_remove = policy.v != 2 || is_root_or_admin(policy, &facts.sender);
        if !(leave || signed_out || reseat || may_remove)
            && let Some(v) = needs_cards(
                "a Remove of a different DID from someone who is neither root, admin, leaving, \
                 signed out nor re-seating",
            )
        {
            return v;
        }
    }
    if let Some(new) = &facts.policy_change {
        // Exact DID compare, confirmed (answers round 4, Q4: `roleOf`,
        // `mayChangePolicy`); persona cards never widen it.
        if policy.root.as_deref() != Some(facts.sender.as_str()) {
            return Invalid("only root may change the policy".into());
        }
        if new.v != 2 {
            return Invalid("a policy change must be v2".into());
        }
        if new.committer != policy.committer || new.settle_window_ms != policy.settle_window_ms {
            return Invalid("a policy change must keep committer and settleWindowMs".into());
        }
    }
    match undecided {
        Some(why) => Undecidable(why),
        None => Valid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "did:peer:2.A";

    #[test]
    fn founding_policy_parses() {
        let p = parse_policy(&format!(
            r#"{{"v":2,"committer":"any-staged","settleWindowMs":3000,"root":"{D}","admins":[]}}"#
        ));
        assert_eq!(p.v, 2);
        assert_eq!(p.root.as_deref(), Some(D));
        assert_eq!(p.settle_window_ms, 3000);
        assert_eq!(p.committer, Committer::AnyStaged);
        assert!(p.admins.is_empty() && p.edit.is_none() && p.direct.is_none());
    }

    #[test]
    fn malformed_reads_as_v1_defaults() {
        let d = RoomPolicy::default();
        assert_eq!((d.v, d.settle_window_ms), (1, 3000));
        for bad in [
            "",
            "not json",
            "[]",
            "null",
            r#"{"v":3,"committer":"any-staged","settleWindowMs":1}"#,
            r#"{"v":1,"committer":"nobody","settleWindowMs":1}"#,
            r#"{"v":1,"committer":"owner"}"#,
            r#"{"v":1,"committer":"owner","settleWindowMs":"5"}"#,
            // v2 needs root and admins
            r#"{"v":2,"committer":"owner","settleWindowMs":1}"#,
            r#"{"v":2,"committer":"owner","settleWindowMs":1,"root":"did:x"}"#,
            r#"{"v":2,"committer":"owner","settleWindowMs":1,"root":5,"admins":[]}"#,
            r#"{"v":2,"committer":"owner","settleWindowMs":1,"root":"did:x","admins":["no"]}"#,
        ] {
            assert_eq!(parse_policy(bad), d, "{bad}");
        }
    }

    #[test]
    fn settle_window_is_clamped() {
        let w = |n: &str| {
            parse_policy(&format!(
                r#"{{"v":1,"committer":"owner","settleWindowMs":{n}}}"#
            ))
            .settle_window_ms
        };
        assert_eq!(w("-5"), 0);
        assert_eq!(w("0"), 0);
        assert_eq!(w("60000"), 60_000);
        assert_eq!(w("1e9"), 60_000);
        assert_eq!(w("250"), 250);
    }

    #[test]
    fn optional_edit_and_direct() {
        let p = parse_policy(
            r#"{"v":2,"committer":"owner","settleWindowMs":1,"root":"did:r","admins":["did:a"],
                "edit":"admins","direct":["did:z","did:b"]}"#,
        );
        assert_eq!(p.committer, Committer::Owner);
        assert_eq!(p.edit, Some(EditPolicy::Admins));
        assert_eq!(p.direct, Some(["did:b".into(), "did:z".into()]));
        assert_eq!(p.admins, vec!["did:a".to_string()]);
        let q = parse_policy(
            r#"{"v":1,"committer":"owner","settleWindowMs":1,"edit":"x","direct":["did:a","did:a"]}"#,
        );
        assert!(q.edit.is_none() && q.direct.is_none());
        assert_eq!(q.committer, Committer::Owner);
    }

    // ---- valid_commit ---------------------------------------------------

    use std::collections::{HashMap, HashSet};

    /// Test fake for the two local-knowledge inputs (NOT Geb's persona cards).
    #[derive(Default)]
    struct Fake {
        person: HashMap<String, String>,
        left: HashSet<String>,
    }
    impl Fake {
        fn dev(mut self, device: &str, person: &str) -> Self {
            self.person.insert(device.into(), person.into());
            self
        }
        fn p(&self, d: &str) -> String {
            self.person.get(d).cloned().unwrap_or_else(|| d.to_string())
        }
    }
    impl CommitCheckInputs for Fake {
        fn can_evaluate(&self) -> bool {
            true
        }
        fn same_person(&self, a: &str, b: &str) -> bool {
            self.p(a) == self.p(b)
        }
        fn has_signed_leave(&self, d: &str) -> bool {
            self.left.contains(&self.p(d))
        }
    }

    fn pol(extra: &str) -> RoomPolicy {
        parse_policy(&format!(
            r#"{{"v":2,"committer":"any-staged","settleWindowMs":3000,"root":"did:root","admins":["did:adm"]{extra}}}"#
        ))
    }
    fn facts(sender: &str) -> CommitFacts {
        CommitFacts {
            sender: sender.into(),
            sender_bound: true,
            ..CommitFacts::default()
        }
    }
    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn adds_always_pass() {
        let mut f = facts("did:m");
        f.adds = s(&["did:new"]);
        assert_eq!(
            valid_commit(&pol(""), &f, &Fake::default()),
            CommitVerdict::Valid
        );
        assert_eq!(
            valid_commit(&pol(""), &f, &NoLocalKnowledge),
            CommitVerdict::Valid
        );
        // An empty commit (a self-update) too.
        let e = facts("did:m");
        assert_eq!(
            valid_commit(&pol(""), &e, &NoLocalKnowledge),
            CommitVerdict::Valid
        );
    }

    #[test]
    fn a_remove_needs_root_admin_or_an_exception() {
        let mut f = facts("did:m");
        f.removes = s(&["did:x"]);
        let inv = |p: &RoomPolicy, f: &CommitFacts, i: &Fake| {
            matches!(valid_commit(p, f, i), CommitVerdict::Invalid(_))
        };
        assert!(inv(&pol(""), &f, &Fake::default()));
        // root and admin
        for who in ["did:root", "did:adm"] {
            f.sender = who.into();
            assert_eq!(
                valid_commit(&pol(""), &f, &Fake::default()),
                CommitVerdict::Valid
            );
        }
        // Root and admin are an EXACT DID compare (round 4 Q4): a root's
        // sibling device, known to the persona store, has no root rights.
        f.sender = "did:root2".into();
        let fake = Fake::default().dev("did:root2", "did:root");
        assert!(inv(&pol(""), &f, &fake));
        // own person: a Remove of the sender's own person's leaves
        let mut l = facts("did:m1");
        l.removes = s(&["did:m1", "did:m2"]);
        let fake = Fake::default().dev("did:m1", "P").dev("did:m2", "P");
        assert_eq!(valid_commit(&pol(""), &l, &fake), CommitVerdict::Valid);
        l.removes = s(&["did:m1", "did:other"]);
        assert!(inv(&pol(""), &l, &fake));
        // signed-out: removed person holds a signed leave, no adds, no policy change
        let mut so = facts("did:m");
        so.removes = s(&["did:gone"]);
        let mut fake = Fake::default().dev("did:gone", "G");
        assert!(inv(&pol(""), &so, &fake));
        fake.left.insert("G".into());
        assert_eq!(valid_commit(&pol(""), &so, &fake), CommitVerdict::Valid);
        so.adds = s(&["did:new"]);
        assert!(
            inv(&pol(""), &so, &fake),
            "with an add it is not a signed-out remove"
        );
        // re-seat: removes = adds, non-empty, same set
        let mut rs = facts("did:m");
        rs.removes = s(&["did:a", "did:b"]);
        rs.adds = s(&["did:b", "did:a"]);
        assert_eq!(
            valid_commit(&pol(""), &rs, &Fake::default()),
            CommitVerdict::Valid
        );
        rs.adds = s(&["did:a"]);
        assert!(inv(&pol(""), &rs, &Fake::default()));
    }

    #[test]
    fn policy_changes_are_root_only_v2_and_keep_committer_and_window() {
        let mut f = facts("did:root");
        let mut new = pol("");
        new.admins = s(&["did:adm", "did:more"]);
        f.policy_change = Some(new.clone());
        let none = Fake::default();
        assert_eq!(valid_commit(&pol(""), &f, &none), CommitVerdict::Valid);
        let inv =
            |f: &CommitFacts| matches!(valid_commit(&pol(""), f, &none), CommitVerdict::Invalid(_));
        f.sender = "did:adm".into();
        assert!(inv(&f), "an admin is not root");
        f.sender = "did:root".into();
        let mut bad = new.clone();
        bad.settle_window_ms = 10;
        f.policy_change = Some(bad);
        assert!(inv(&f));
        let mut bad = new.clone();
        bad.committer = Committer::Owner;
        f.policy_change = Some(bad);
        assert!(inv(&f));
        let mut bad = new;
        bad.v = 1;
        f.policy_change = Some(bad);
        assert!(inv(&f));
        // v1 has no root: nobody may change it.
        let v1 = RoomPolicy::default();
        f.policy_change = Some(pol(""));
        assert!(matches!(
            valid_commit(&v1, &f, &none),
            CommitVerdict::Invalid(_)
        ));
    }

    #[test]
    fn direct_rooms_seat_only_the_two_persons_devices_and_keep_direct() {
        let d = pol(r#","direct":["did:lo","did:hi"]"#);
        let fake = Fake::default().dev("did:lo2", "did:lo");
        let mut f = facts("did:lo");
        f.adds = s(&["did:lo2"]);
        assert_eq!(valid_commit(&d, &f, &fake), CommitVerdict::Valid);
        f.adds = s(&["did:stranger"]);
        assert!(matches!(
            valid_commit(&d, &f, &fake),
            CommitVerdict::Invalid(_)
        ));
        let mut g = facts("did:root");
        g.policy_change = Some(pol(""));
        assert!(matches!(
            valid_commit(&d, &g, &fake),
            CommitVerdict::Invalid(_)
        ));
        g.policy_change = Some(pol(r#","direct":["did:lo","did:hi"]"#));
        assert_eq!(valid_commit(&d, &g, &fake), CommitVerdict::Valid);
    }

    #[test]
    fn removes_re_seats_and_policy_changes_need_a_bound_sender() {
        let none = NoLocalKnowledge;
        let fake = Fake::default();
        let inv = |f: &CommitFacts| {
            matches!(valid_commit(&pol(""), f, &fake), CommitVerdict::Invalid(_))
                && matches!(valid_commit(&pol(""), f, &none), CommitVerdict::Invalid(_))
        };
        // root, unbound: its remove, a re-seat and a policy change are refused.
        let mut r = facts("did:root");
        r.sender_bound = false;
        r.removes = s(&["did:x"]);
        assert!(inv(&r));
        let mut rs = facts("did:m");
        rs.sender_bound = false;
        rs.removes = s(&["did:a"]);
        rs.adds = s(&["did:a"]);
        assert!(inv(&rs), "re-seating someone else, unbound");
        let mut c = facts("did:root");
        c.sender_bound = false;
        c.policy_change = Some(pol(""));
        assert!(inv(&c));
        // The exception: re-seating its own DID onto a BOUND leaf.
        let mut own = facts("did:m");
        own.sender_bound = false;
        own.removes = s(&["did:m"]);
        own.adds = s(&["did:m"]);
        assert_eq!(valid_commit(&pol(""), &own, &fake), CommitVerdict::Valid);
        // ...but not onto an unbound one, and not with a policy change.
        let mut unb = own.clone();
        unb.unbound_adds = s(&["did:m"]);
        assert!(inv(&unb));
        let mut pc = own.clone();
        pc.policy_change = Some(pol(""));
        assert!(inv(&pc));
        // An unbound sender may still add and self-update ("adds always pass").
        let mut a = facts("did:m");
        a.sender_bound = false;
        a.adds = s(&["did:new"]);
        assert_eq!(valid_commit(&pol(""), &a, &none), CommitVerdict::Valid);
        assert_eq!(
            valid_commit(&pol(""), &facts("did:m"), &none),
            CommitVerdict::Valid
        );
    }

    #[test]
    fn an_unbound_leaf_naming_root_an_admin_or_a_seated_did_is_refused() {
        let none = NoLocalKnowledge;
        for claimed in ["did:root", "did:adm", "did:seat"] {
            let mut f = facts("did:m");
            f.seated = s(&["did:m", "did:seat"]);
            f.adds = s(&[claimed]);
            f.unbound_adds = s(&[claimed]);
            assert!(
                matches!(
                    valid_commit(&pol(""), &f, &none),
                    CommitVerdict::Invalid(w) if w.starts_with("unboundClaim")
                ),
                "{claimed}"
            );
        }
        // A fresh DID, or a bound claimant, is fine.
        let mut f = facts("did:m");
        f.seated = s(&["did:m"]);
        f.adds = s(&["did:fresh", "did:root"]);
        f.unbound_adds = s(&["did:fresh"]);
        assert_eq!(valid_commit(&pol(""), &f, &none), CommitVerdict::Valid);
    }

    #[test]
    fn without_local_knowledge_only_card_dependent_commits_are_undecidable() {
        let none = NoLocalKnowledge;
        assert!(!none.can_evaluate());
        let und = |p: &RoomPolicy, f: &CommitFacts| {
            matches!(valid_commit(p, f, &none), CommitVerdict::Undecidable(_))
        };
        let ok =
            |p: &RoomPolicy, f: &CommitFacts| valid_commit(p, f, &none) == CommitVerdict::Valid;
        let inv = |p: &RoomPolicy, f: &CommitFacts| {
            matches!(valid_commit(p, f, &none), CommitVerdict::Invalid(_))
        };
        // Decided WITHOUT cards: an exact-DID root or admin remove.
        for who in ["did:root", "did:adm"] {
            let mut r = facts(who);
            r.removes = s(&["did:x"]);
            assert!(ok(&pol(""), &r), "{who}");
        }
        // A bound self-remove (a leave of the sender's own DID).
        let mut l = facts("did:m");
        l.removes = s(&["did:m"]);
        assert!(ok(&pol(""), &l));
        // A re-seat, an ordinary add, a root policy change.
        let mut rs = facts("did:m");
        rs.removes = s(&["did:a", "did:b"]);
        rs.adds = s(&["did:b", "did:a"]);
        assert!(ok(&pol(""), &rs));
        let mut a = facts("did:m");
        a.adds = s(&["did:n"]);
        assert!(ok(&pol(""), &a));
        let mut c = facts("did:root");
        c.policy_change = Some(pol(""));
        assert!(ok(&pol(""), &c));
        // A non-root policy change and a bad root one are refused, not halted.
        c.sender = "did:adm".into();
        assert!(inv(&pol(""), &c));
        c.sender = "did:root".into();
        let mut bad = pol("");
        bad.settle_window_ms = 1;
        c.policy_change = Some(bad);
        assert!(inv(&pol(""), &c));
        // Still undecidable: a Remove of a DIFFERENT DID by a sender who is
        // neither root nor admin (a sibling device or a signed leave could
        // rescue it), a mixed own/other remove, and a direct-room add of a
        // DID that is not exactly one of the pair.
        let mut r = facts("did:m");
        r.removes = s(&["did:x"]);
        assert!(und(&pol(""), &r));
        r.removes = s(&["did:m", "did:x"]);
        assert!(und(&pol(""), &r));
        let direct = pol(r#","direct":["did:a","did:b"]"#);
        let mut d = facts("did:m");
        d.adds = s(&["did:n"]);
        assert!(und(&direct, &d));
        d.adds = s(&["did:a"]);
        assert!(ok(&direct, &d), "an exact member of the pair needs no card");
        // A card-free refusal beats an undecidable rule.
        let mut both = facts("did:m");
        both.removes = s(&["did:x"]);
        both.policy_change = Some(pol(""));
        assert!(
            inv(&pol(""), &both),
            "non-root policy change: refused first"
        );
        let mut u = facts("did:m");
        u.unclassified = true;
        assert!(inv(&pol(""), &u), "refused and skipped, never a halt");
        assert!(matches!(
            valid_commit(&pol(""), &u, &Fake::default()),
            CommitVerdict::Invalid(_)
        ));
        // With real inputs the same commits are Invalid, not Undecidable.
        let mut r = facts("did:m");
        r.removes = s(&["did:x"]);
        assert!(matches!(
            valid_commit(&pol(""), &r, &Fake::default()),
            CommitVerdict::Invalid(_)
        ));
        // And the own-DID re-seat exception holds without cards.
        let mut own = facts("did:m");
        own.sender_bound = false;
        own.removes = s(&["did:m"]);
        own.adds = s(&["did:m"]);
        assert!(ok(&pol(""), &own));
    }

    // ---- round 4: Q2 selfHeal, Q6 the four pass conditions, the residual halt

    fn verdict(p: &RoomPolicy, f: &CommitFacts, i: &dyn CommitCheckInputs) -> CommitVerdict {
        valid_commit(p, f, i)
    }

    /// Cards (or leaves) the bridge holds: exact only, but with signed leaves.
    struct Leaves(HashSet<String>);
    impl CommitCheckInputs for Leaves {
        fn can_evaluate(&self) -> bool {
            false
        }
        fn same_person(&self, _: &str, _: &str) -> bool {
            false
        }
        fn has_signed_leave(&self, d: &str) -> bool {
            self.0.contains(d)
        }
    }

    #[test]
    fn self_heal_needs_every_clause() {
        let none = NoLocalKnowledge;
        let base = || {
            let mut f = facts("did:m");
            f.sender_bound = false;
            f.removes = s(&["did:m"]);
            f.adds = s(&["did:m"]);
            f
        };
        assert_eq!(verdict(&pol(""), &base(), &none), CommitVerdict::Valid);
        let refused =
            |f: &CommitFacts| matches!(verdict(&pol(""), f, &none), CommitVerdict::Invalid(_));
        // no policy change
        let mut f = base();
        f.policy_change = Some(pol(""));
        assert!(refused(&f), "a policy change");
        // every removed leaf names the sender
        let mut f = base();
        f.removes = s(&["did:m", "did:x"]);
        assert!(refused(&f), "a removed leaf of another DID");
        let mut f = base();
        f.removes = s(&["did:x"]);
        assert!(refused(&f), "only another DID removed");
        // at least one leaf is added
        let mut f = base();
        f.adds = vec![];
        assert!(refused(&f), "nothing added");
        // every added leaf names the sender
        let mut f = base();
        f.adds = s(&["did:m", "did:new"]);
        assert!(refused(&f), "an added leaf of another DID");
        // ...and is bound by the sender's own signature
        let mut f = base();
        f.unbound_adds = s(&["did:m"]);
        assert!(refused(&f), "the added leaf is unbound");
        // A plain heal (path only, no remove) is not a Remove: it never
        // reaches this rule.
        let mut f = facts("did:m");
        f.sender_bound = false;
        assert_eq!(verdict(&pol(""), &f, &none), CommitVerdict::Valid);
    }

    #[test]
    fn each_of_the_four_remove_passes_alone_without_a_persona_store() {
        let none = NoLocalKnowledge;
        // (1) every removed DID is the sender's own (no card needed).
        let mut f = facts("did:m");
        f.removes = s(&["did:m"]);
        assert_eq!(verdict(&pol(""), &f, &none), CommitVerdict::Valid);
        // (2) signed leave: covered, no adds, no policy change.
        let mut f = facts("did:m");
        f.removes = s(&["did:gone", "did:gone2"]);
        let held = Leaves(["did:gone", "did:gone2"].map(String::from).into());
        assert_eq!(verdict(&pol(""), &f, &held), CommitVerdict::Valid);
        let partly = Leaves(["did:gone"].map(String::from).into());
        assert!(matches!(
            verdict(&pol(""), &f, &partly),
            CommitVerdict::Undecidable(_)
        ));
        f.adds = s(&["did:new"]);
        assert!(
            matches!(verdict(&pol(""), &f, &held), CommitVerdict::Undecidable(_)),
            "with an add it is not a signed-out remove"
        );
        // (3) re-seat by any bound member.
        let mut f = facts("did:m");
        f.removes = s(&["did:a"]);
        f.adds = s(&["did:a"]);
        assert_eq!(verdict(&pol(""), &f, &none), CommitVerdict::Valid);
        // ...but not by an unbound one (the bound-sender rule comes first).
        f.sender_bound = false;
        assert!(matches!(
            verdict(&pol(""), &f, &none),
            CommitVerdict::Invalid(_)
        ));
        // (4) root or admin, exact.
        for who in ["did:root", "did:adm"] {
            let mut f = facts(who);
            f.removes = s(&["did:x"]);
            assert_eq!(verdict(&pol(""), &f, &none), CommitVerdict::Valid);
        }
        // (4) a v1 policy: any bound member may remove anyone.
        let v1 = RoomPolicy::default();
        let mut f = facts("did:m");
        f.removes = s(&["did:x"]);
        assert_eq!(verdict(&v1, &f, &none), CommitVerdict::Valid);
        f.sender_bound = false;
        assert!(
            matches!(verdict(&v1, &f, &none), CommitVerdict::Invalid(_)),
            "a v1 room still needs a bound sender"
        );
    }

    #[test]
    fn the_residual_halt_is_only_a_card_dependent_remove() {
        let none = NoLocalKnowledge;
        // Another DID, non-root non-admin, v2, no signed leave, not a re-seat.
        let mut f = facts("did:m");
        f.removes = s(&["did:x"]);
        let CommitVerdict::Undecidable(why) = verdict(&pol(""), &f, &none) else {
            panic!("must halt")
        };
        assert!(why.contains("persona cards or signed leaves"), "{why}");
        // With a real persona store the same commit is refused, as in Geb.
        assert!(matches!(
            verdict(&pol(""), &f, &Fake::default()),
            CommitVerdict::Invalid(_)
        ));
        // A different re-seat set is still a card-dependent remove.
        f.adds = s(&["did:y"]);
        assert!(matches!(
            verdict(&pol(""), &f, &none),
            CommitVerdict::Undecidable(_)
        ));
    }
}
