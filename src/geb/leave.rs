//! Signed leaves (Geb path B answers round 2 section 8, round 4 Q7;
//! leave code).
//!
//! A leaver signs … at}`
//! (JCS, `sign_json`) with its device DID's Ed25519 key, and sends it two ways:
//!
//! - a room line `{t:"lv", at, ls:<the leave signature>}`; the line also
//!   carries `sg` like every room plaintext, and `by` is the MLS sender;
//! - … sig}`.
//!
//! A receiver …
//! … ([`LeaveBook`]). A held leave feeds `validCommit` rule 2 (a
//! Remove of a leaver, no adds, no policy change): without one, a Geb device
//! refuses the elected healer's Remove of the leaver and we would fork from
//! every device that took it.
//!
//! The bridge only RECEIVES leaves: it never sends one, elects a healer or
//! commits a Remove (it stays a follower).
//!
//! UNVERIFIED: the `sg` of an `lv` line is read as the same wrapper every
//! room plaintext uses, `{v:1, room, author, body}` with `body` the plaintext
//! without `sg` ( for lines; round 2 says only "like every
//! room plaintext"). The client keeps a leave only for a signer
//! seated in the group and drops it once a merged commit removes the signer
//! (the answers say "newest per signer" and nothing about membership or
//! expiry: both are bridge-side choices, UNVERIFIED against Geb).

use super::crypto::{did_peer, sign};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Most signers kept per room: a backstop only. The client keeps a leave only
/// for a signer seated in the group and prunes it when the signer is removed,
/// so the book is bounded by the room's size; a new signer past this bound is
/// dropped (an update of a held one is not).
pub const MAX_LEAVES: usize = 1024;

/// `leavePayload(room, by, at)` (`leave code:33-35`).
pub fn leave_payload(room: &str, by: &str, at: u64) -> Value {
    json!({"t": "leave", "v": 1, "room": room, "by": by, "at": at})
}

/// Verify a leave signature: `sig` is `sign_json` over [`leave_payload`] by the
/// key in the DID `by`.
pub fn verify_leave(room: &str, by: &str, at: u64, sig: &str) -> Result<()> {
    let key = did_peer::decode(by)?.verifying_key()?;
    sign::verify_json(&key, &leave_payload(room, by, at), sig)
}

/// Verify the `sg` of a room plaintext (`plaintext` is the whole JSON object,
/// `sg` included) for its `author`, the MLS sender.
pub fn verify_room_sg(room: &str, author: &str, plaintext: &Value) -> Result<()> {
    let mut body = plaintext.clone();
    let sg = body
        .as_object_mut()
        .and_then(|o| o.remove("sg"))
        .and_then(|s| s.as_str().map(str::to_string))
        .ok_or_else(|| Error::Wire("room plaintext has no sg".into()))?;
    let key = did_peer::decode(author)?.verifying_key()?;
    let doc = json!({"v": 1, "room": room, "author": author, "body": body});
    sign::verify_json(&key, &doc, &sg)
}

/// A room line `{t:"lv", at, ls, sg}` read from a plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveLine {
    /// The leave's time, ms.
    pub at: u64,
    /// The leave signature (`ls`).
    pub ls: String,
}

/// Read `plaintext` as an `lv` line; `None` when it is not one (any other kind,
/// not JSON, or a malformed `lv`).
pub fn parse_leave_line(plaintext: &Value) -> Option<LeaveLine> {
    let o = plaintext.as_object()?;
    if o.get("t")?.as_str()? != "lv" {
        return None;
    }
    Some(LeaveLine {
        at: o.get("at")?.as_u64()?,
        ls: o.get("ls")?.as_str()?.to_string(),
    })
}

/// One held signed leave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLeave {
    /// The leave's time, ms.
    pub at: u64,
    /// The signature over [`leave_payload`].
    pub sig: String,
}

/// The newest verified signed leave per signer, for one room. Persisted with
/// the client's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveBook {
    leaves: BTreeMap<String, SignedLeave>,
}

impl LeaveBook {
    /// Verify and keep a leave for `room` by `by` (the leaver's device DID).
    /// Returns whether the book changed. A leave whose signature does not
    /// verify is dropped; an older or equal one than the one held changes
    /// nothing.
    pub fn take(&mut self, room: &str, by: &str, at: u64, sig: &str) -> bool {
        if verify_leave(room, by, at, sig).is_err() {
            tracing::debug!("dropping a signed leave that does not verify");
            return false;
        }
        let new = SignedLeave {
            at,
            sig: sig.to_string(),
        };
        if let Some(held) = self.leaves.get(by) {
            if held.at >= at {
                return false;
            }
        } else if self.leaves.len() >= MAX_LEAVES {
            tracing::warn!("too many signed leaves held; dropping a new signer's");
            return false;
        }
        self.leaves.insert(by.to_string(), new);
        true
    }

    /// Forget the leaves of signers who are not in `seated` (a signer removed
    /// by a merged commit: the leave has done its job).
    pub fn retain_seated(&mut self, seated: &[String]) {
        self.leaves.retain(|by, _| seated.iter().any(|d| d == by));
    }

    /// Whether a verified signed leave by exactly `did` is held (without a
    /// persona store the leaver's other devices are not covered).
    pub fn covers(&self, did: &str) -> bool {
        self.leaves.contains_key(did)
    }

    /// The held leave of `did`.
    pub fn get(&self, did: &str) -> Option<&SignedLeave> {
        self.leaves.get(did)
    }

    /// The signers held.
    pub fn signers(&self) -> impl Iterator<Item = &str> {
        self.leaves.keys().map(String::as_str)
    }

    /// Number of signers held.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    pub(crate) fn device(seed: u8) -> (String, SigningKey) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        let did = did_peer::encode(&k.verifying_key().to_bytes(), &[seed; 32], None).unwrap();
        (did, k)
    }

    pub(crate) fn sign_leave(k: &SigningKey, room: &str, by: &str, at: u64) -> String {
        sign::sign_json(k, &leave_payload(room, by, at)).unwrap()
    }

    #[test]
    fn the_payload_is_the_stated_jcs_form() {
        let bytes = serde_json_canonicalizer::to_vec(&leave_payload("r", "did:x", 5)).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"at":5,"by":"did:x","room":"r","t":"leave","v":1}"#
        );
    }

    #[test]
    fn a_valid_leave_is_kept_and_a_forged_or_misdirected_one_is_dropped() {
        let (a, ka) = device(1);
        let (b, kb) = device(2);
        let mut book = LeaveBook::default();
        let good = sign_leave(&ka, "room-0001", &a, 10);
        assert!(book.take("room-0001", &a, 10, &good));
        assert!(book.covers(&a) && !book.covers(&b));
        // Signed by another key, for another room, with another time, or
        // naming another signer: all dropped.
        let forged = sign_leave(&kb, "room-0001", &a, 11);
        assert!(!book.take("room-0001", &a, 11, &forged));
        assert!(!book.take("room-0002", &a, 10, &good));
        assert!(!book.take("room-0001", &a, 12, &good));
        assert!(!book.take("room-0001", &b, 10, &good));
        assert!(!book.take("room-0001", &a, 13, "!!"));
        assert!(!book.take("room-0001", "did:peer:2.bad", 10, &good));
        assert_eq!(book.len(), 1);
        assert_eq!(book.get(&a).unwrap().at, 10);
    }

    #[test]
    fn the_newest_leave_per_signer_wins() {
        let (a, ka) = device(1);
        let mut book = LeaveBook::default();
        let at = |t| sign_leave(&ka, "room-0001", &a, t);
        assert!(book.take("room-0001", &a, 20, &at(20)));
        assert!(!book.take("room-0001", &a, 10, &at(10)), "older");
        assert!(!book.take("room-0001", &a, 20, &at(20)), "equal");
        assert_eq!(book.get(&a).unwrap().at, 20);
        assert!(book.take("room-0001", &a, 30, &at(30)));
        assert_eq!(book.get(&a).unwrap().at, 30);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn the_book_survives_a_serde_round_trip_and_is_bounded() {
        let (a, ka) = device(1);
        let mut book = LeaveBook::default();
        book.take("room-0001", &a, 1, &sign_leave(&ka, "room-0001", &a, 1));
        let back: LeaveBook = serde_json::from_slice(&serde_json::to_vec(&book).unwrap()).unwrap();
        assert_eq!(back, book);
        // A new signer past the bound is dropped, a held one still updates.
        let mut full = LeaveBook::default();
        for i in 0..MAX_LEAVES {
            full.leaves.insert(
                format!("did:peer:2.s{i}"),
                SignedLeave {
                    at: 1,
                    sig: String::new(),
                },
            );
        }
        assert!(!full.take("room-0001", &a, 1, &sign_leave(&ka, "room-0001", &a, 1)));
        assert_eq!(full.len(), MAX_LEAVES);
    }

    #[test]
    fn room_lines_parse_and_their_sg_binds_the_sender() {
        let (a, ka) = device(1);
        let (b, _) = device(2);
        let ls = sign_leave(&ka, "room-0001", &a, 9);
        let mut line = json!({"t": "lv", "at": 9, "ls": ls});
        assert_eq!(
            parse_leave_line(&line),
            Some(LeaveLine {
                at: 9,
                ls: ls.clone()
            })
        );
        let doc = json!({"v": 1, "room": "room-0001", "author": a, "body": line});
        line["sg"] = json!(sign::sign_json(&ka, &doc).unwrap());
        verify_room_sg("room-0001", &a, &line).unwrap();
        // Not the sender's, not this room's, or tampered: refused.
        assert!(verify_room_sg("room-0001", &b, &line).is_err());
        assert!(verify_room_sg("room-0002", &a, &line).is_err());
        let mut tampered = line.clone();
        tampered["at"] = json!(10);
        assert!(verify_room_sg("room-0001", &a, &tampered).is_err());
        // No sg at all.
        assert!(verify_room_sg("room-0001", &a, &json!({"t":"lv","at":9,"ls":ls})).is_err());
        // Other kinds and malformed lv lines are not leave lines.
        for not in [
            json!({"t": "l", "at": 1, "text": "x"}),
            json!({"t": "lv", "at": -1, "ls": "x"}),
            json!({"t": "lv", "at": 1}),
            json!({"t": "lv", "ls": "x"}),
            json!([]),
        ] {
            assert_eq!(parse_leave_line(&not), None, "{not}");
        }
    }
}
