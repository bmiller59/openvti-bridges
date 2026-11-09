//! Sealed box for inbox first contact (kind 4178).
//!
//! Blob = `eph_pub(32) || nonce(12) || ChaCha20-Poly1305(ct+tag)`; box key =
//! HKDF-SHA256(salt = eph_pub || recipient_pub, ikm = ECDH, info
//! `consensual/inbox/v1/sealed-box`); content = standard padded base64.

use super::kdf::hkdf32;
use super::{b64_decode, b64_encode, ecdh, x25519_public};
use crate::{Error, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

const INFO: &[u8] = b"consensual/inbox/v1/sealed-box";

fn cipher(
    eph_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
    shared: &[u8; 32],
) -> Result<ChaCha20Poly1305> {
    let salt = [eph_pub.as_slice(), recipient_pub.as_slice()].concat();
    let key = hkdf32(Some(&salt), shared, INFO)?;
    ChaCha20Poly1305::new_from_slice(&key).map_err(|e| Error::Crypto(e.to_string()))
}

/// Seal with a caller-supplied ephemeral secret and nonce (deterministic;
/// exposed for tests and for callers that own their randomness).
/// No AAD is used on the sealed box (Geb path B answer 3,
/// `channel.rs:38-49`).
pub fn seal_with(
    recipient_pub: &[u8; 32],
    eph_secret: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<String> {
    let eph_pub = x25519_public(eph_secret);
    let shared = ecdh(eph_secret, recipient_pub)?;
    let n = Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Crypto("nonce length".into()))?;
    let ct = cipher(&eph_pub, recipient_pub, &shared)?
        .encrypt(&n, plaintext)
        .map_err(|_| Error::Crypto("seal failed".into()))?;
    let mut blob = Vec::with_capacity(32 + 12 + ct.len());
    blob.extend_from_slice(&eph_pub);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    Ok(b64_encode(&blob))
}

/// Seal to `recipient_pub` with fresh randomness.
pub fn seal(recipient_pub: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let mut eph = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::fill(&mut eph);
    rand::fill(&mut nonce);
    seal_with(recipient_pub, &eph, &nonce, plaintext)
}

/// Open a sealed box with the recipient's X25519 secret.
pub fn open(recipient_secret: &[u8; 32], content_b64: &str) -> Result<Vec<u8>> {
    let blob = b64_decode(content_b64)?;
    if blob.len() < 32 + 12 + 16 {
        return Err(Error::Wire("sealed box too short".into()));
    }
    let eph_pub: [u8; 32] = blob[..32]
        .try_into()
        .map_err(|_| Error::Wire("eph".into()))?;
    let nonce = Nonce::try_from(&blob[32..44]).map_err(|_| Error::Wire("nonce".into()))?;
    let recipient_pub = x25519_public(recipient_secret);
    let shared = ecdh(recipient_secret, &eph_pub)?;
    cipher(&eph_pub, &recipient_pub, &shared)?
        .decrypt(&nonce, &blob[44..])
        .map_err(|_| Error::Crypto("sealed box failed to open".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_layout() {
        let rs = [3u8; 32];
        let rp = x25519_public(&rs);
        let b64 = seal(&rp, b"hello inbox").unwrap();
        assert_eq!(open(&rs, &b64).unwrap(), b"hello inbox");
        let blob = b64_decode(&b64).unwrap();
        assert_eq!(blob.len(), 32 + 12 + b"hello inbox".len() + 16);
        assert!(
            b64.ends_with('=') || b64.len().is_multiple_of(4),
            "standard padded base64"
        );
    }

    #[test]
    fn deterministic_with_fixed_inputs_and_recomputable() {
        let rs = [3u8; 32];
        let rp = x25519_public(&rs);
        let a = seal_with(&rp, &[5u8; 32], &[6u8; 12], b"x").unwrap();
        assert_eq!(a, seal_with(&rp, &[5u8; 32], &[6u8; 12], b"x").unwrap());
        // Cross-check: rebuild the key by hand from the guide's description.
        let eph_pub = x25519_public(&[5u8; 32]);
        let shared = ecdh(&rs, &eph_pub).unwrap();
        let salt = [eph_pub.as_slice(), rp.as_slice()].concat();
        let key = hkdf32(Some(&salt), &shared, b"consensual/inbox/v1/sealed-box").unwrap();
        let c = ChaCha20Poly1305::new_from_slice(&key).unwrap();
        let blob = b64_decode(&a).unwrap();
        let n = Nonce::try_from(&blob[32..44]).unwrap();
        assert_eq!(c.decrypt(&n, &blob[44..]).unwrap(), b"x");
    }

    #[test]
    fn tamper_wrong_key_and_short_input_fail() {
        let rs = [3u8; 32];
        let rp = x25519_public(&rs);
        let b64 = seal(&rp, b"secret").unwrap();
        assert!(open(&[4u8; 32], &b64).is_err());
        let mut blob = b64_decode(&b64).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(open(&rs, &b64_encode(&blob)).is_err());
        assert!(open(&rs, &b64_encode(&[0u8; 20])).is_err());
        assert!(open(&rs, "not base64!!").is_err());
    }
}
