//! HKDF-SHA256 helpers and the secp256k1 counter rule.

use crate::{Error, Result};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::Sha256;

/// HKDF-SHA256 to 32 bytes.
pub fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .map_err(|e| Error::Crypto(format!("hkdf: {e}")))?;
    Ok(out)
}

/// Whether 32 bytes are a valid secp256k1 secret scalar (non-zero, below the
/// group order).
pub fn is_valid_secp256k1_scalar(b: &[u8; 32]) -> bool {
    k256::SecretKey::from_slice(b).is_ok()
}

/// The counter rule from the guide: HKDF-SHA256, no salt, info = `info_base`
/// followed by one counter byte starting at `0x00`; if the result is not a
/// valid scalar, add one to the counter and try again.
///
/// `valid` is a parameter so the retry path can be tested without hunting for
/// an input that lands above the group order (probability about 2^-128).
pub fn derive_with_counter(
    ikm: &[u8],
    info_base: &[u8],
    valid: impl Fn(&[u8; 32]) -> bool,
) -> Result<[u8; 32]> {
    for counter in 0u8..=255 {
        let mut info = info_base.to_vec();
        info.push(counter);
        let candidate = hkdf32(None, ikm, &info)?;
        if valid(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::Crypto(
        "no valid secp256k1 scalar within 256 counters".into(),
    ))
}

/// [`derive_with_counter`] with the real curve check, then BIP-340
/// normalisation: when the secret's public point has an odd Y the secret is
/// replaced by its negation (`n - d`), so the returned secret always has an
/// even-Y point. Geb's vectors return that normalised secret (its
/// `inbox_derivation` secret is the group-order complement of the raw HKDF
/// output, with the same x-only public key); the x-only public key, which is
/// all a Nostr author filter or signature sees, is the same either way.
pub fn derive_secp256k1_secret(ikm: &[u8], info_base: &[u8]) -> Result<[u8; 32]> {
    let raw = derive_with_counter(ikm, info_base, is_valid_secp256k1_scalar)?;
    let sk =
        k256::SecretKey::from_slice(&raw).map_err(|e| Error::Crypto(format!("secp256k1: {e}")))?;
    if sk.public_key().to_sec1_point(true).as_bytes().first() == Some(&0x03) {
        let neg = -*sk.to_nonzero_scalar();
        return Ok(neg.to_bytes().into());
    }
    Ok(raw)
}

/// The x-only (BIP-340 style, 32-byte) public key for a secp256k1 secret.
pub fn xonly_pubkey(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = k256::SecretKey::from_slice(secret)
        .map_err(|e| Error::Crypto(format!("secp256k1: {e}")))?;
    let point = sk.public_key().to_sec1_point(true);
    let bytes = point.as_bytes();
    let x: [u8; 32] = bytes
        .get(1..33)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Crypto("unexpected point encoding".into()))?;
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_rule_retries_with_incremented_counter() {
        let ikm = [7u8; 32];
        let base = b"consensual/inbox/v1/nostr-secret";
        // Reject the counter-0 candidate only.
        let first = hkdf32(None, &ikm, &[base.as_slice(), &[0]].concat()).unwrap();
        let got = derive_with_counter(&ikm, base, |c| *c != first).unwrap();
        let expect = hkdf32(None, &ikm, &[base.as_slice(), &[1]].concat()).unwrap();
        assert_eq!(got, expect);
        assert_ne!(got, first);
        // Accepting everything returns counter 0.
        assert_eq!(derive_with_counter(&ikm, base, |_| true).unwrap(), first);
        // Rejecting everything fails rather than looping or wrapping.
        assert!(derive_with_counter(&ikm, base, |_| false).is_err());
    }

    #[test]
    fn scalar_validity() {
        assert!(!is_valid_secp256k1_scalar(&[0u8; 32]));
        assert!(!is_valid_secp256k1_scalar(&[0xff; 32]));
        assert!(is_valid_secp256k1_scalar(&[1u8; 32]));
    }

    #[test]
    fn xonly_of_scalar_one_is_the_generator_x() {
        // Known: the secp256k1 generator's x coordinate (SEC 2 / BIP-340).
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            hex::encode(xonly_pubkey(&one).unwrap()),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }
}
