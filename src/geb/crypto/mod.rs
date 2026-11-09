//! The pure cryptographic pieces of Geb path B that the guide specifies,
//! implemented from `Geb's implementer's guide (2026-11-07)` and, where they differ, Geb's
//! authoritative answers (`Geb's path B answers, round 1`, code at commit
//! release 0.5.14, and round 2, release 0.5.15 at `fdf804d`). The tests here are round-trips, tamper checks and independent
//! re-derivations written from the stated derivations; none of them is a Geb
//! vector (Geb's own vectors are bound in `tests/vectors.rs`).
//! Each remaining ambiguity is marked `UNVERIFIED:` at the code.

pub mod did_peer;
pub mod frame_id;
pub mod inbox;
pub mod kdf;
pub mod leaf;
pub mod line_id;
pub mod pair;
pub mod ratchet;
pub mod rendezvous;
pub mod sealed;
pub mod sign;

use crate::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Standard padded base64, as Geb uses for event content and frames.
pub fn b64_encode(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Decode standard padded base64.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|e| Error::Wire(format!("base64: {e}")))
}

/// X25519 ECDH, rejecting an all-zero result (a low-order peer key).
pub fn ecdh(secret: &[u8; 32], peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let s = x25519_dalek::StaticSecret::from(*secret);
    let shared = s.diffie_hellman(&x25519_dalek::PublicKey::from(*peer_pub));
    let out = *shared.as_bytes();
    if out.iter().all(|b| *b == 0) {
        return Err(Error::Crypto("ECDH produced an all-zero secret".into()));
    }
    Ok(out)
}

/// The X25519 public key for a secret.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}
