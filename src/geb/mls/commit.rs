//! Testing a candidate commit: MLS processing, the forged-binding check,
//! `validCommit` over [`CommitFacts`], and merging the winner.
//!
//! # Merging with partial local knowledge (read this before changing it)
//!
//! Geb's `validCommit` needs two things the bridge does not have: persona
//! cards ("same person") and signed leaves (`{t:"lv"}`). With the production
//! inputs ([`NoLocalKnowledge`](crate::geb::policy::NoLocalKnowledge),
//! `can_evaluate() == false`) this module merges a commit **only if all of**:
//!
//! 1. it processes under OpenMLS at our epoch (signature, membership tag,
//!    confirmation tag, required capabilities: the same checks every member
//!    makes);
//! 2. no proposal is a kind Geb's check is not described for (Update,
//!    PreSharedKey, ReInit, ExternalInit, SelfRemove, custom);
//! 3. it is decidable without persona cards: since P0-d that is every commit
//!    except a Remove of a different DID by a sender who is neither root nor
//!    admin and a direct-room Add of a DID that is not exactly a pair member
//!    (`geb::policy::valid_commit` has the table);
//! 4. no added leaf carries a **forged** binding (a binding that is present
//!    and does not verify). A missing binding passes: "seated, unverified".
//!
//! Since 0.5.15 (answers round 2, sections 2 and 7) the judge also REFUSES,
//! each a *refusal* (the walk goes on to the next hash, see below), a commit:
//! carrying any proposal by reference (we never store a proposal, so it shows
//! as `MissingProposal`), a standalone Proposal in an `mc` (never stored),
//! whose update-path leaf names another DID than its sender (`leafAuth`) or
//! carries a forged binding, that adds an unbound leaf naming the root, an
//! admin or a seated DID (`unboundClaim`), or whose sender's leaf is unbound
//! and who removes, re-seats or changes the policy (`validCommit`, with the
//! one exception of re-seating its own DID onto a bound leaf). A bound
//! update-path leaf from an unbound sender is the `heal` shape and is valid.
//! At join, `tree_refusal` refuses a Welcome whose tree holds a forged leaf …
//! … unbound.
//!
//! Refused versus failed (the settle walk): `Verdict::Refused` = dropped, next
//! hash tried, cursor moves; `Verdict::Unprocessable` = cannot be processed at
//! all (replay, other branch, unparsable bytes): recorded failed, the walk
//! STOPS, `rs` is sent once. Everything above is a refusal.
//!
//! Why that is safe: answer 9 and round 2 section 7 state `validCommit` as a
//! list of conditions, and name the three places where persona cards matter
//! (a leave by Remove, a signed leave, a direct room). Everything outside
//! them is decided from the policy, the tree and the leaf bindings alone, so
//! every Geb device reaches the same verdict and so do we: no fork. A commit
//! in those three places is neither merged nor skipped (skipping a commit
//! another device merges also forks): the walk stops and the bridge alerts.
//!
//! What this does NOT rule out, UNVERIFIED because Geb's source is not
//! available: a rule in `validCommit` or the settle path beyond the answers'
//! list (the answers say the list is what fails a commit); a difference in how
//! Geb decodes a DID for the binding check (we refuse a present binding whose
//! DID we cannot decode); and the framing of commit bytes, which decides the hash that
//! orders candidates (settled by round 2 section 6, but never run against a
//! live Geb). If any of these is
//! wrong, the failure mode is a fork that Geb's fork repair (`rs`) is meant to
//! mend. Keeping ALL merging off is `SettleMode::Off`-equivalent: build the
//! group with inputs whose `can_evaluate` is false AND do not call `settle`,
//! or leave the `geb-mls` feature off (the default).

use crate::geb::crypto::{did_peer, leaf};
use crate::geb::policy::{
    CommitCheckInputs, CommitFacts, CommitVerdict, RoomPolicy, parse_policy, valid_commit,
};
use crate::geb::settle::{Candidate, CommitHash, Judge, Verdict};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use std::collections::HashMap;
use tls_codec::Deserialize as _;

/// The device DID in a credential, if it is a UTF-8 identity.
pub fn credential_did(c: &Credential) -> Option<String> {
    String::from_utf8(c.serialized_content().to_vec()).ok()
}

/// The group's policy, read from the **group context** (never the Welcome
/// header). Absent or malformed reads as the v1 default.
pub fn group_policy(group: &MlsGroup) -> RoomPolicy {
    policy_of(group.extensions())
}

pub(crate) fn policy_of(exts: &Extensions<GroupContext>) -> RoomPolicy {
    exts.unknown(leaf::EXT_POLICY)
        .and_then(|u| std::str::from_utf8(&u.0).ok())
        .map(parse_policy)
        .unwrap_or_default()
}

/// How a leaf's binding stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingStatus {
    /// No `0xF002` extension: seated, shown "unverified".
    Missing,
    /// Present and verifies against the DID's key.
    Verified,
    /// Present and does not verify (or cannot be checked): forged.
    Forged,
}

/// Check a leaf's binding (answer 6): the extension value is the UTF-8 binding
/// string, verified with the credential DID's key over the leaf's 32-byte
/// signature public key.
pub fn binding_status(leaf_node: &LeafNode) -> BindingStatus {
    let Some(ext) = leaf_node.extensions().unknown(leaf::EXT_LEAF_BINDING) else {
        return BindingStatus::Missing;
    };
    let ok = (|| {
        let did = credential_did(leaf_node.credential())?;
        let binding = std::str::from_utf8(&ext.0).ok()?;
        let key = <[u8; 32]>::try_from(leaf_node.signature_key().as_slice()).ok()?;
        let vk = did_peer::decode(&did).ok()?.verifying_key().ok()?;
        leaf::verify(&vk, &did, &key, binding).ok()
    })();
    if ok.is_some() {
        BindingStatus::Verified
    } else {
        BindingStatus::Forged
    }
}

/// Reduce a staged commit to what `validCommit` reads. `sender_index` is the
/// committer's leaf in the tree the commit is made from.
pub fn facts_of(
    group: &MlsGroup,
    sender: &Credential,
    sender_index: LeafNodeIndex,
    staged: &StagedCommit,
) -> CommitFacts {
    let mut facts = CommitFacts {
        sender: credential_did(sender).unwrap_or_default(),
        // UNVERIFIED: the sender's leaf BEFORE the commit decides; a commit
        // whose own update path brings a bound leaf does not count as bound
        // for the remove / re-seat / policy rule (only a heal commit, which
        // has no proposals, uses the new leaf).
        sender_bound: group
            .public_group()
            .leaf(sender_index)
            .is_some_and(|l| binding_status(l) == BindingStatus::Verified),
        seated: group
            .members()
            .filter_map(|m| credential_did(&m.credential))
            .collect(),
        ..CommitFacts::default()
    };
    if credential_did(sender).is_none() {
        facts.unclassified = true;
    }
    for q in staged.queued_proposals() {
        match q.proposal() {
            Proposal::Add(a) => match credential_did(a.key_package().leaf_node().credential()) {
                Some(d) => {
                    if binding_status(a.key_package().leaf_node()) == BindingStatus::Missing {
                        facts.unbound_adds.push(d.clone());
                    }
                    facts.adds.push(d);
                }
                None => facts.unclassified = true,
            },
            Proposal::Remove(r) => {
                match group
                    .member_at(r.removed())
                    .and_then(|m| credential_did(&m.credential))
                {
                    Some(d) => facts.removes.push(d),
                    None => facts.unclassified = true,
                }
            }
            Proposal::GroupContextExtensions(g) => {
                let new = g.extensions();
                let old = group.extensions();
                let rest = |e: &Extensions<GroupContext>| {
                    e.iter()
                        .filter(|x| x.extension_type() != ExtensionType::Unknown(leaf::EXT_POLICY))
                        .cloned()
                        .collect::<Vec<_>>()
                };
                if rest(new) != rest(old) {
                    // Something other than the policy changes: not described.
                    facts.unclassified = true;
                }
                let before = old.unknown(leaf::EXT_POLICY).map(|u| &u.0);
                let after = new.unknown(leaf::EXT_POLICY).map(|u| &u.0);
                if before != after {
                    facts.policy_change = Some(policy_of(new));
                }
            }
            _ => facts.unclassified = true,
        }
    }
    facts
}

/// Tests candidates against one group and merges the winner.
pub struct GroupJudge<'a> {
    /// The group, at the epoch the candidates were made from.
    pub group: &'a mut MlsGroup,
    /// The crypto/storage provider.
    pub provider: &'a OpenMlsRustCrypto,
    /// The two local-knowledge inputs.
    pub inputs: &'a dyn CommitCheckInputs,
    /// Verdicts already reached, by commit hash. A PrivateMessage can be
    /// decrypted ONCE (its sender-ratchet secret is deleted on use), so a
    /// candidate that is looked at again on a later poll must not be
    /// processed again: its first verdict stands.
    cache: &'a mut HashMap<CommitHash, Verdict>,
    staged: Option<(crate::geb::settle::CommitHash, Box<StagedCommit>)>,
}

impl<'a> GroupJudge<'a> {
    /// A judge over `group`.
    pub fn new(
        group: &'a mut MlsGroup,
        provider: &'a OpenMlsRustCrypto,
        inputs: &'a dyn CommitCheckInputs,
        cache: &'a mut HashMap<CommitHash, Verdict>,
    ) -> Self {
        Self {
            group,
            provider,
            inputs,
            cache,
            staged: None,
        }
    }
}

impl Judge for GroupJudge<'_> {
    fn judge(&mut self, c: &Candidate) -> Verdict {
        // A previous candidate's staged commit is discarded here.
        self.staged = None;
        if let Some(v) = self.cache.get(&c.hash) {
            return v.clone();
        }
        let v = self.judge_fresh(c);
        // A Valid verdict is never cached: it is merged at once, and the
        // staged commit it left behind cannot be rebuilt.
        if v != Verdict::Valid {
            self.cache.insert(c.hash, v.clone());
        }
        v
    }

    fn merge(&mut self, c: &Candidate) -> Result<(), String> {
        let r = self.merge_staged(c);
        if let Err(why) = &r {
            self.cache
                .insert(c.hash, Verdict::Unprocessable(why.clone()));
        }
        r
    }
}

impl GroupJudge<'_> {
    fn judge_fresh(&mut self, c: &Candidate) -> Verdict {
        let unprocessable = |why: String| Verdict::Unprocessable(why);
        let msg = match parse_message(&c.bytes) {
            Ok(m) => m,
            Err(e) => return unprocessable(e),
        };
        let processed = match self.group.process_message(self.provider, msg) {
            Ok(p) => p,
            // We never store a proposal, so a commit that names one by
            // reference cannot be staged: that is the by-reference refusal
            // (0.5.15) seen from the receiving side, and a refusal, not a
            // failure, so the walk goes on to the next hash.
            Err(ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)) => {
                return Verdict::Refused("a commit carries a proposal by reference".into());
            }
            Err(e) => return unprocessable(format!("process: {e:?}")),
        };
        let sender = processed.credential().clone();
        let Sender::Member(sender_index) = *processed.sender() else {
            return unprocessable("a commit from a sender who is not a member".into());
        };
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            // 0.5.15: a standalone Proposal is refused and NEVER stored (we
            // never call `store_pending_proposal`; `process_message` itself
            // does not store it). A refusal, so the walk goes on to the next
            // hash. UNVERIFIED: that Geb's walk treats this report the same
            // as a `validCommit` failure (gap-analysis question 3); the
            // alternative reading is `failed`, which would stop the walk.
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                return Verdict::Refused("a standalone Proposal is refused, never stored".into());
            }
            _ => return unprocessable("an mc envelope that is not a commit".into()),
        };
        // A proposal by reference is refused (0.5.15): Geb never sends one and
        // a member that merged it would fork from the ones that refuse.
        if staged
            .queued_proposals()
            .any(|q| q.proposal_or_ref_type() == ProposalOrRefType::Reference)
        {
            return Verdict::Refused("a commit carries a proposal by reference".into());
        }
        // Forged binding on any added leaf: refused whatever else is true.
        for a in staged.add_proposals() {
            if binding_status(a.add_proposal().key_package().leaf_node()) == BindingStatus::Forged {
                return Verdict::Refused("an added leaf carries a forged binding".into());
            }
        }
        // leafAuth (0.5.15): the update-path leaf must name the sender's own
        // DID, and its binding, if present, must verify. A bound new leaf is
        // the `heal` shape (a path-only self-update that binds the sender's
        // own leaf) and is valid; an unbound one is an ordinary self-update.
        // UNVERIFIED: Geb's description of a heal says "same signature key";
        // we do not require it, because a binding that verifies is bound to
        // whatever key the new leaf has, and the rest of the commit is
        // processed by OpenMLS either way.
        if let Some(path_leaf) = staged.update_path_leaf_node() {
            let (a, b) = (
                credential_did(&sender),
                credential_did(path_leaf.credential()),
            );
            if a.is_none() || a != b {
                return Verdict::Refused(
                    "leafAuth: the update-path leaf names another DID than the sender".into(),
                );
            }
            if binding_status(path_leaf) == BindingStatus::Forged {
                return Verdict::Refused("the update-path leaf carries a forged binding".into());
            }
        }
        let policy = group_policy(self.group);
        let facts = facts_of(self.group, &sender, sender_index, &staged);
        match valid_commit(&policy, &facts, self.inputs) {
            CommitVerdict::Valid => {
                self.staged = Some((c.hash, staged));
                Verdict::Valid
            }
            CommitVerdict::Invalid(why) => Verdict::Refused(why),
            CommitVerdict::Undecidable(why) => Verdict::Undecidable(why),
        }
    }

    fn merge_staged(&mut self, c: &Candidate) -> Result<(), String> {
        let Some((hash, staged)) = self.staged.take() else {
            return Err("no staged commit for the winner".into());
        };
        if hash != c.hash {
            return Err("the staged commit is not the winner's".into());
        }
        self.group
            .merge_staged_commit(self.provider, *staged)
            .map_err(|e| format!("merge: {e:?}"))
    }
}

/// treeRefusal (0.5.15, answers round 2 section 7): a Welcome is refused when
/// …
/// unbound. Checked on the group a Welcome made, before it is kept.
pub fn tree_refusal(group: &MlsGroup) -> Result<(), String> {
    let mut seen: HashMap<String, (usize, bool)> = HashMap::new();
    for m in group.members() {
        let Some(node) = group.public_group().leaf(m.index) else {
            return Err("a member has no leaf".into());
        };
        let status = binding_status(node);
        let did = credential_did(&m.credential)
            .ok_or_else(|| "a leaf whose identity is not UTF-8".to_string())?;
        if status == BindingStatus::Forged {
            return Err(format!("the leaf of {did} carries a forged binding"));
        }
        let e = seen.entry(did).or_default();
        e.0 += 1;
        e.1 |= status == BindingStatus::Missing;
    }
    if let Some((did, _)) = seen.iter().find(|(_, (n, unbound))| *n > 1 && *unbound) {
        return Err(format!("two leaves for {did}, one of them unbound"));
    }
    Ok(())
}

/// Parse the bytes of an `mc` or `ml` envelope: a full RFC 9420 `MLSMessage`
/// whose body is a **PrivateMessage**, and nothing else (answer 2: "Geb …
/// … one"; the bytes
/// are what `tls_serialize_detached` made of OpenMLS's `MlsMessageOut`).
///
/// Refused, each with its own reason: a bare PrivateMessage or PublicMessage
/// (not an `MLSMessage`), trailing bytes, an `MLSMessage` whose body is a
/// PublicMessage, a Welcome, a GroupInfo or a KeyPackage.
pub fn parse_message(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    let m = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| "not an MLSMessage (bare and trailing-byte forms are refused)".to_string())?;
    match m.extract() {
        MlsMessageBodyIn::PrivateMessage(p) => Ok(ProtocolMessage::from(p)),
        MlsMessageBodyIn::PublicMessage(_) => Err("a PublicMessage is refused".into()),
        _ => Err("an MLSMessage that is not a PrivateMessage".into()),
    }
}

/// Parse a Welcome frame's `w`: an `MLSMessage` whose body is a Welcome
/// (answer 2; Geb answers anything else "not a Welcome", `mls.rs:490-493`).
pub fn parse_welcome(bytes: &[u8]) -> Result<Welcome, String> {
    match MlsMessageIn::tls_deserialize_exact(bytes).map(MlsMessageIn::extract) {
        Ok(MlsMessageBodyIn::Welcome(w)) => Ok(w),
        _ => Err("not a Welcome".into()),
    }
}

/// Parse a KeyPackage string as Geb reads it (answer 1): the alphabet is
/// checked first (`^[A-Za-z0-9+/=]+$`: a base64url string is dropped), the
/// text is standard PADDED base64, and the bytes are the bare TLS
/// `KeyPackage` read with `KeyPackageIn::tls_deserialize_exact` (an
/// `MLSMessage`-wrapped KeyPackage or trailing bytes fail). The result is not
/// yet validated (signature, lifetime): that needs a crypto provider.
pub fn parse_key_package(b64: &str) -> Result<KeyPackageIn, String> {
    if !crate::geb::wire::is_std_b64(b64) {
        return Err("a KeyPackage is standard base64 (^[A-Za-z0-9+/=]+$)".into());
    }
    let bytes = crate::geb::crypto::b64_decode(b64).map_err(|e| e.to_string())?;
    KeyPackageIn::tls_deserialize_exact(&bytes)
        .map_err(|_| "not a bare KeyPackage (an MLSMessage wrapper or trailing bytes)".to_string())
}
