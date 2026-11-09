//! The room policy (GroupContext extension `0xF001`) and what a commit check
//! needs. Geb path B answers 7 and 9 (code at commit release 0.5.14) and round 2 section 7
//! (release 0.5.15, `fdf804d`).
//!
//! # Policy (answer 7)
//!
//! New rooms are founded with `{v:2, committer:"any-staged",
//! settleWindowMs:3000, root:<founder DID>, admins:[]}`; direct rooms add
//! `direct:[lo, hi]`. [`parse_policy`] mirrors Geb's `parsePolicy`: …
//! …
//! … nothing reads `committer` beyond the parse, so `"owner"` is
//! not enforced by Geb. …
//! … `settleWindowMs`.
//!
//! # Commit check (answer 9)
//!
//! Geb does not … candidate
//! Commits …
//! … before it can win
//! :
//!
//! - … dropped
//!   (`drop_staged`), reported `refused`, the next hash is tried;
//! - the first Commit that passes is merged, on every device that reaches the
//!   same verdict;
//! - all refused: nothing settles and the epoch stays;
//! - …
//!   … `failed`, the read cursor stays before it, the device sends its
//!   room status `{k:"g", op:"rs"}` which starts fork repair.
//!
//! `validCommit`  fails a Commit when
//!
//! - …
//!   …
//! - …
//!   …
//!   …
//!   …
//!   … change);
//! - …
//!   …
//!
//! …
//!
//! **Two inputs are local knowledge**: …
//! … holds (persona code), and "signed leave" from the signed
//! leaves it has taken (`leave code:33-60`, `{t:"lv", at, ls}` in the
//! room). A bridge lacking them refuses …
//! … **forks the epoch**. So it never merges (nor skips) such
//! a commit; with the default group `GebRoom::poll` still stops on any `mc`
//! envelope; [`valid_commit`] is the check, and [`CommitCheckInputs::can_evaluate`]
//! is the gate. Production has only [`NoLocalKnowledge`]; since round 2 only a
//! Remove of a different DID by a non-root, non-admin sender and a direct-room
//! Add of a non-exact DID need them, and those stop the bridge and alert; see
//! `geb::mls` for what is merged.

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
/// We do not have Geb's persona code or leave code, so the only production
/// implementation is [`NoLocalKnowledge`], which reports
/// `can_evaluate() == false`. While that is false [`valid_commit`] answers
/// [`CommitVerdict::Undecidable`] for every commit that removes a member or
/// changes the policy (and for adds to a direct room), and the caller must
/// stop rather than merge or skip it.
pub trait CommitCheckInputs: Send + Sync {
    /// Whether the two answers below are real. False means they are guesses
    /// and `validCommit` cannot be evaluated like Geb.
    fn can_evaluate(&self) -> bool;
    /// Whether devices (or persons) `a` and `b` are the same person.
    fn same_person(&self, a: &str, b: &str) -> bool;
    /// Whether this device holds a signed leave for the person `device_did`
    /// belongs to.
    fn has_signed_leave(&self, device_did: &str) -> bool;
}

/// The production inputs until persona cards and signed leaves exist:
/// nothing is known, and [`CommitCheckInputs::can_evaluate`] is false.
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
    /// (Update, PreSharedKey, ReInit, ExternalInit, custom). Such a commit is
    /// neither merged nor skipped.
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

/// `selfHeal` (used at; answers round 4, Q2):
/// the one way an UNBOUND sender may commit a Remove. All of: …
/// …
/// …
/// signature (a present binding that does not verify never reaches here: the
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

fn is_root_or_admin(policy: &RoomPolicy, who: &str, inputs: &dyn CommitCheckInputs) -> bool {
    let is = |d: &String| d == who || inputs.same_person(who, d);
    policy.root.iter().any(is) || policy.admins.iter().any(is)
}

/// Geb's `validCommit` (answer 9), pure over the facts, the
/// policy read from the **group context** and the local-knowledge inputs.
///
/// Without local knowledge ([`CommitCheckInputs::can_evaluate`] false) every
/// commit Geb decides without persona cards or signed leaves is decided here
/// (round 2 section 7): ordinary adds, exact-DID root or admin removes, a
/// sender removing or re-seating its own DID, other re-seats, root policy
/// changes, an exact member of a direct pair added, and every 0.5.15 bound-leaf
/// refusal. Only a Remove of a different DID by a sender who is neither root
/// nor admin, and a direct-room Add of a DID that is not exactly one of the
/// pair, are [`CommitVerdict::Undecidable`] (a card or signed leave could
/// rescue them, and a wrong answer forks the epoch); a card-free refusal
/// elsewhere in the same commit still wins.
///
/// UNVERIFIED: the answers state the rules, not these details. Sender and
/// removed leaves are compared as device DIDs (exactly, else `same_person`);
/// "not v2" is read on the NEW policy; a re-seat compares removed and added
/// DIDs as sets; a v1 policy has no root, so nobody passes the root test; an
/// admin may change nothing but removes.
pub fn valid_commit(
    policy: &RoomPolicy,
    facts: &CommitFacts,
    inputs: &dyn CommitCheckInputs,
) -> CommitVerdict {
    use CommitVerdict::{Invalid, Undecidable, Valid};
    if facts.unclassified {
        return Undecidable("commit carries a proposal type the check is not described for".into());
    }
    // 0.5.15 (answers round 2 sections 1 and 7), neither rule needs persona
    // cards, so both hold whether or not `can_evaluate`.
    //
    // unboundClaim: an unbound leaf that names the root, an admin or a DID
    // already seated is never seated. (A re-seat's added leaf names a DID that
    // is still seated when the commit is made, so an unbound re-seat leaf is
    // refused too. UNVERIFIED: whether Geb counts the DID being removed in the
    // same commit as seated.)
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
    // …
    // … leaf, as it stands BEFORE the commit, is bound
    // ; the one exception is `selfHeal` (answers round 4,
    // Q2), which is a Remove, never a policy change.
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
    if !facts.removes.is_empty() && !is_root_or_admin(policy, &facts.sender, inputs) {
        // Not (exactly) root or an admin: valid only as …
        // … person: with no cards, the sender's own
        // DID), a signed-out remove, or a re-seat.
        let leave = facts
            .removes
            .iter()
            .all(|r| r == &facts.sender || inputs.same_person(r, &facts.sender));
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
        if !(leave || signed_out || reseat)
            && let Some(v) = needs_cards(
                "a Remove of a different DID from someone who is neither root, admin, leaving, signed out nor re-seating",
            )
        {
            return v;
        }
    }
    if let Some(new) = &facts.policy_change {
        // UNVERIFIED: without cards the root test is an exact DID compare
        // (round 2 section 7: "removes by root or an admin ... …
        // … cards"). If Geb's test also
        // accepts a root's sibling device through `same`, a commit from one
        // is refused here and merged by Geb: a fork (open question 2).
        let root = policy
            .root
            .as_ref()
            .is_some_and(|r| r == &facts.sender || inputs.same_person(&facts.sender, r));
        if !root {
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
        // root, admin, and root's other device
        for who in ["did:root", "did:adm"] {
            f.sender = who.into();
            assert_eq!(
                valid_commit(&pol(""), &f, &Fake::default()),
                CommitVerdict::Valid
            );
        }
        f.sender = "did:root2".into();
        let fake = Fake::default().dev("did:root2", "did:root");
        assert_eq!(valid_commit(&pol(""), &f, &fake), CommitVerdict::Valid);
        // leave: …
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
        assert!(und(&pol(""), &u));
        assert!(matches!(
            valid_commit(&pol(""), &u, &Fake::default()),
            CommitVerdict::Undecidable(_)
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

    // ---- round 4 Q2: selfHeal

    fn verdict(p: &RoomPolicy, f: &CommitFacts, i: &dyn CommitCheckInputs) -> CommitVerdict {
        valid_commit(p, f, i)
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
}
