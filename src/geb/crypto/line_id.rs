//! The derived id of a room line (Geb path B answer 10,
//! `src/lib/).
//!
//! It is the first 32 hex characters of SHA-256 over the UTF-8 bytes of
//! `JSON.stringify({g: room, from: author, at, text})`: plain stringify in
//! exactly that key order, **not** JCS. A `re` in a room line names this id.
//! (A copied old dyad line keeps its own 16-hex id; the bridge never copies.)

use crate::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct IdDoc<'a> {
    g: &'a str,
    from: &'a str,
    at: u64,
    text: &'a str,
}

/// The derived id of the line `author` posted in `room` at `at` ms with `text`.
pub fn line_id(room: &str, author: &str, at: u64, text: &str) -> Result<String> {
    // serde_json writes struct fields in declaration order, which is what
    // JSON.stringify does for the object literal.
    let doc = serde_json::to_string(&IdDoc {
        g: room,
        from: author,
        at,
        text,
    })
    .map_err(|e| Error::Wire(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(doc.as_bytes()))[..32].to_string())
}

/// Whether `s` can be a `re` value: `^[0-9a-f]{16,64}$`.
pub fn is_line_ref(s: &str) -> bool {
    (16..=64).contains(&s.len()) && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_derives_from_the_stated_key_order() {
        // Re-derived from the stated string, not a Geb vector.
        let want = hex::encode(Sha256::digest(
            br#"{"g":"room","from":"did:a","at":5,"text":"hi \"x\"\n"}"#,
        ));
        let got = line_id("room", "did:a", 5, "hi \"x\"\n").unwrap();
        assert_eq!(got, want[..32]);
        assert!(is_line_ref(&got));
    }

    #[test]
    fn every_input_changes_the_id() {
        let base = line_id("r", "a", 1, "t").unwrap();
        for other in [
            line_id("r2", "a", 1, "t"),
            line_id("r", "a2", 1, "t"),
            line_id("r", "a", 2, "t"),
            line_id("r", "a", 1, "t2"),
        ] {
            assert_ne!(base, other.unwrap());
        }
    }

    #[test]
    fn line_ref_shape() {
        assert!(is_line_ref(&"a".repeat(16)));
        assert!(is_line_ref(&"0".repeat(64)));
        assert!(!is_line_ref(&"a".repeat(15)));
        assert!(!is_line_ref(&"a".repeat(65)));
        assert!(!is_line_ref(&"A".repeat(16)));
    }
}
