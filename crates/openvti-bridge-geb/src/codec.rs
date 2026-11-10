//! The codec pinned to the guide and Geb's answers (commit release 0.5.14; re-pinned to release 0.5.15, `fdf804d`).

use super::traits::GebCodec;
use super::wire::{Envelope, LineBody, RoomPlaintext};
use crate::{Error, Result};

/// Prefix of the [`Error::Wire`] text for a room plaintext that is valid JSON
/// of a kind we do not read as a line (a reaction, `wp`, `ag`, anything newer).
/// The caller drops it quietly: it is not malformed, only not ours to act on.
pub const NOT_A_LINE: &str = "not a line";

/// Whether `e` is the quiet "not a line" refusal of [`GebCodec::decode_line`].
pub fn is_not_a_line(e: &Error) -> bool {
    matches!(e, Error::Wire(w) if w.starts_with(NOT_A_LINE))
}

/// Guide-of-2026-11-07 shapes.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuideCodec;

impl GebCodec for GuideCodec {
    fn decode_envelope(&self, bytes: &[u8]) -> Result<Envelope> {
        let e: Envelope =
            serde_json::from_slice(bytes).map_err(|e| Error::Wire(format!("envelope: {e}")))?;
        e.validate()?;
        Ok(e)
    }
    fn encode_envelope(&self, envelope: &Envelope) -> Result<Vec<u8>> {
        envelope.validate()?;
        serde_json::to_vec(envelope).map_err(|e| Error::Wire(e.to_string()))
    }
    fn decode_line(&self, bytes: &[u8]) -> Result<LineBody> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| Error::Wire(format!("plaintext: {e}")))?;
        // A room plaintext of a kind this bridge does not read (`wp`, `ag`,
        // `h`, `p`, `n`, `m`, anything newer: round 1 section 11 and round 3
        // "what changes") is dropped without effect. A string `t` other than
        // `l` and `r` is exactly that; a malformed `l` or `r` still errors.
        if let Some(t) = v.get("t").and_then(serde_json::Value::as_str)
            && t != "l"
            && t != "r"
        {
            let t: String = t.chars().filter(|c| !c.is_control()).take(16).collect();
            return Err(Error::Wire(format!("{NOT_A_LINE}: kind {t}")));
        }
        let p: RoomPlaintext =
            serde_json::from_value(v).map_err(|e| Error::Wire(format!("plaintext: {e}")))?;
        match p {
            RoomPlaintext::Line(l) => {
                l.validate_inbound()?;
                Ok(l)
            }
            // A reaction is understood but is not a line; the caller drops it.
            RoomPlaintext::Reaction { .. } => Err(Error::Wire(format!("{NOT_A_LINE}: reaction"))),
        }
    }
    fn encode_line(&self, line: &LineBody) -> Result<Vec<u8>> {
        line.validate()?;
        serde_json::to_vec(&RoomPlaintext::Line(line.clone()))
            .map_err(|e| Error::Wire(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_round_trip_and_hostile_inputs() {
        let c = GuideCodec;
        let l = LineBody::new(3, "hi".into());
        assert_eq!(c.decode_line(&c.encode_line(&l).unwrap()).unwrap(), l);
        for bad in [
            &b"not json"[..],
            br#"{"t":"ag","at":1}"#,
            br#"{"t":"l","at":-1,"text":"x"}"#,
            br#"{"t":"l","at":1,"text":""}"#,
            br#"{"t":"l","at":1,"text":"x","re":"ABC"}"#,
            br#"{"t":"r","at":1,"re":"0123456789abcdef","e":"x","on":true}"#,
            b"[]",
            b"",
        ] {
            assert!(c.decode_line(bad).is_err());
        }
        let over = format!(r#"{{"t":"l","at":1,"text":"{}"}}"#, "x".repeat(20_001));
        assert!(c.decode_line(over.as_bytes()).is_err());
        // Unknown kinds are the quiet refusal; malformed known kinds are not.
        for kind in [
            r#"{"t":"wp","at":1,"k":"x","d":{}}"#,
            r#"{"t":"ag","at":1}"#,
            r#"{"t":"zz-new"}"#,
            r#"{"t":"r","at":1,"re":"0123456789abcdef","e":"x","on":true}"#,
        ] {
            let e = c.decode_line(kind.as_bytes()).unwrap_err();
            assert!(is_not_a_line(&e), "{kind}: {e}");
        }
        assert!(!is_not_a_line(&c.decode_line(b"{not json").unwrap_err()));
        assert!(!is_not_a_line(
            &c.decode_line(br#"{"t":"l","at":1,"text":""}"#).unwrap_err()
        ));
        // Units, not chars: 10,001 emoji are 10,001 chars and 20,002 units.
        let emoji = |n: usize| format!(r#"{{"t":"l","at":1,"text":"{}"}}"#, "\u{1F600}".repeat(n));
        assert!(c.decode_line(emoji(10_000).as_bytes()).is_ok());
        assert!(c.decode_line(emoji(10_001).as_bytes()).is_err());
        assert!(c.decode_envelope(br#"{"t":"nope"}"#).is_err());
    }
}
