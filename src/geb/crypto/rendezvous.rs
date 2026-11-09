//! Pair and room relay keys: a Nostr secret (which names the mailbox) and an
//! AEAD key (which seals its envelopes).

use super::kdf::{derive_secp256k1_secret, hkdf32, xonly_pubkey};
use super::{ecdh, x25519_public};
use crate::Result;
use zeroize::Zeroizing;

/// HKDF info base for a pair's Nostr secret (counter byte appended).
pub const PAIR_NOSTR_INFO: &[u8] = b"consensual/rendezvous/v1/nostr-secret";
/// HKDF info for a pair's AEAD key (no counter byte).
pub const PAIR_AEAD_INFO: &[u8] = b"consensual/rendezvous/v1/aead-key";

/// A mailbox's keys. Pairs derive them by ECDH; rooms take them from the MLS
/// exporter (labels `geb/room/v2/nostr` and `geb/room/v2/aead`, context = room
/// id bytes) once the MLS layer exists.
pub struct RelayKeys {
    /// secp256k1 secret that signs the mailbox's events.
    pub nostr_secret: Zeroizing<[u8; 32]>,
    /// AES-256-GCM key for envelopes.
    pub aead_key: Zeroizing<[u8; 32]>,
}

impl RelayKeys {
    /// Keys from already-derived parts (the room case).
    pub fn from_parts(nostr_secret: [u8; 32], aead_key: [u8; 32]) -> Self {
        Self {
            nostr_secret: Zeroizing::new(nostr_secret),
            aead_key: Zeroizing::new(aead_key),
        }
    }

    /// The mailbox pubkey, lowercase hex of the x-only key (the `authors`
    /// filter value and part of the AAD).
    pub fn pubkey_hex(&self) -> Result<String> {
        Ok(hex::encode(xonly_pubkey(&self.nostr_secret)?))
    }
}

/// Both sides compute the same keys from X25519 ECDH between their `.E` keys.
pub fn pair_keys(my_e_secret: &[u8; 32], their_e_pub: &[u8; 32]) -> Result<RelayKeys> {
    let shared = ecdh(my_e_secret, their_e_pub)?;
    let nostr = derive_secp256k1_secret(&shared, PAIR_NOSTR_INFO)?;
    let aead = hkdf32(None, &shared, PAIR_AEAD_INFO)?;
    Ok(RelayKeys::from_parts(nostr, aead))
}

/// Convenience: the public half of an `.E` secret.
pub fn e_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_public(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let ka = pair_keys(&a, &e_public(&b)).unwrap();
        let kb = pair_keys(&b, &e_public(&a)).unwrap();
        assert_eq!(*ka.aead_key, *kb.aead_key);
        assert_eq!(ka.pubkey_hex().unwrap(), kb.pubkey_hex().unwrap());
        assert_eq!(ka.pubkey_hex().unwrap().len(), 64);
        assert_ne!(*ka.aead_key, *ka.nostr_secret);
        let kc = pair_keys(&[3u8; 32], &e_public(&b)).unwrap();
        assert_ne!(*ka.aead_key, *kc.aead_key);
    }

    #[test]
    fn matches_independent_derivation_from_the_guide_text() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let shared = ecdh(&a, &e_public(&b)).unwrap();
        let ns = hkdf32(None, &shared, b"consensual/rendezvous/v1/nostr-secret\x00").unwrap();
        let ak = hkdf32(None, &shared, b"consensual/rendezvous/v1/aead-key").unwrap();
        let k = pair_keys(&a, &e_public(&b)).unwrap();
        assert_eq!(*k.nostr_secret, ns);
        assert_eq!(*k.aead_key, ak);
    }
}
