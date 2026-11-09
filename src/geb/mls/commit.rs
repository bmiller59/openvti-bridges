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
//! 2. every proposal in it is an `Add`: no Remove, no GroupContextExtensions,
//!    and no Update / PreSharedKey / ReInit / ExternalInit / SelfRemove /
//!    custom proposal, which Geb's check is not described for;
//! 3. the room is not direct (an Add to a direct room needs "same person");
//! 4. no added leaf carries a **forged** binding (a binding that is present
//!    and does not verify). A missing binding passes: "seated, unverified".
//!
//! Why that is safe: answer 9 states `validCommit` as a list of failure
//! conditions, and "Adds always pass". For a commit meeting 1-4 none of the
//! listed conditions can apply (they concern Removes, policy changes and
//! direct rooms), and the one other refusal Geb makes, a forged binding, is
//! checked here from the DID alone. So every Geb device reaches the verdict
//! "valid" and merges it, and so do we: no fork. Any commit that is not in
//! that class is neither merged nor skipped (skipping a commit another device
//! merges also forks): the walk stops and the bridge alerts.
//!
//! What this does NOT rule out, UNVERIFIED because Geb's source is not
//! available: a rule in `validCommit` or the settle path beyond the answers'
//! list (the answers say the list is what fails a commit); a difference in how
//! Geb decodes a DID for the binding check (we refuse a present binding whose
//! DID we cannot decode); a Geb-side check on an `Update` path leaf's binding
//! (we do not check it); and the framing of commit bytes, which decides the
//! hash that orders candidates (see `geb::mls` docs). If any of these is
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

/// Reduce a staged commit to what `validCommit` reads.
pub fn facts_of(group: &MlsGroup, sender: &Credential, staged: &StagedCommit) -> CommitFacts {
    let mut facts = CommitFacts {
        sender: credential_did(sender).unwrap_or_default(),
        ..CommitFacts::default()
    };
    if credential_did(sender).is_none() {
        facts.unclassified = true;
    }
    for q in staged.queued_proposals() {
        match q.proposal() {
            Proposal::Add(a) => match credential_did(a.key_package().leaf_node().credential()) {
                Some(d) => facts.adds.push(d),
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
            Err(e) => return unprocessable(format!("process: {e:?}")),
        };
        let sender = processed.credential().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return unprocessable("an mc envelope that is not a commit".into());
        };
        // Forged binding on any added leaf: refused whatever else is true.
        for a in staged.add_proposals() {
            if binding_status(a.add_proposal().key_package().leaf_node()) == BindingStatus::Forged {
                return Verdict::Refused("an added leaf carries a forged binding".into());
            }
        }
        let policy = group_policy(self.group);
        let facts = facts_of(self.group, &sender, &staged);
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

/// Parse MLS message bytes into a protocol message. Accepts an MLSMessage
/// wrapper, else a bare PrivateMessage or PublicMessage.
///
/// UNVERIFIED: whether Geb wraps `m` in an MLSMessage (version, wire format)
/// or sends the bare PrivateMessage the guide names. We send the wrapper and
/// read either.
pub fn parse_message(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    if let Ok(m) = MlsMessageIn::tls_deserialize_exact(bytes)
        && let Ok(p) = m.try_into_protocol_message()
    {
        return Ok(p);
    }
    if let Ok(p) = PrivateMessageIn::tls_deserialize_exact(bytes) {
        return Ok(ProtocolMessage::from(p));
    }
    if let Ok(p) = PublicMessageIn::tls_deserialize_exact(bytes) {
        return Ok(ProtocolMessage::from(p));
    }
    Err("not an MLS protocol message".into())
}
