//! The frame id: …
//! … text (Geb path B answer 5, `src/lib/).
//!
//! ```text
//! …
//! … UTF-16 code unit c: a = imul32(a ^ c, 16777619)
//!                              b = imul32(b ^ c, 0x5bd1e995)
//! id = hex8(a) || hex8(b)        // 16 lowercase hex characters
//! ```
//!
//! The hashed text is exactly what `ChannelRatchet.seal` returned, i.e. the
//! padded base64 the envelope carries. A receiver accepts ack ids matching
//! `^[0-9a-f]{16}$` only ([`is_frame_id`]).

const A0: u32 = 0x811c_9dc5;
const B0: u32 = 0x0100_0193;

/// The id of a frame given as its padded base64 text.
pub fn frame_id(text: &str) -> String {
    let (mut a, mut b) = (A0, B0);
    for c in text.encode_utf16() {
        let c = u32::from(c);
        a = (a ^ c).wrapping_mul(16_777_619);
        b = (b ^ c).wrapping_mul(0x5bd1_e995);
    }
    format!("{a:08x}{b:08x}")
}

/// Whether `s` is a well-formed ack id: exactly 16 lowercase hex characters.
pub fn is_frame_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_text_is_the_two_offsets() {
        // Stated in answer 5.
        assert_eq!(frame_id(""), "811c9dc501000193");
    }

    #[test]
    fn one_character_follows_the_stated_arithmetic() {
        // Derived by hand from the stated passes with 64-bit arithmetic.
        let c = u64::from(b'A');
        let a = ((0x811c_9dc5u64 ^ c) * 16_777_619) & 0xffff_ffff;
        let b = ((0x0100_0193u64 ^ c) * 0x5bd1_e995) & 0xffff_ffff;
        assert_eq!(frame_id("A"), format!("{a:08x}{b:08x}"));
    }

    #[test]
    fn ids_are_well_formed_and_sensitive() {
        let id = frame_id("AAAAAAAA==");
        assert!(is_frame_id(&id));
        assert_ne!(id, frame_id("AAAAAAAB=="));
        assert!(!is_frame_id("ABCDEF0123456789"));
        assert!(!is_frame_id("0123456789abcde"));
        assert!(!is_frame_id("0123456789abcdef0"));
    }
}
