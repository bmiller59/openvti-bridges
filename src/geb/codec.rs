//! The codec pinned to the guide and Geb's answers (commit release 0.5.14).

use super::traits::GebCodec;
use super::wire::{Envelope, LineBody, RoomPlaintext};
use crate::{Error, Result};

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
        let p: RoomPlaintext =
            serde_json::from_slice(bytes).map_err(|e| Error::Wire(format!("plaintext: {e}")))?;
        match p {
            RoomPlaintext::Line(l) => {
                l.validate_inbound()?;
                Ok(l)
            }
            // A reaction is understood but is not a line; the caller drops it.
            RoomPlaintext::Reaction { .. } => Err(Error::Wire("not a line".into())),
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
        assert!(c.decode_envelope(br#"{"t":"nope"}"#).is_err());
    }
}
