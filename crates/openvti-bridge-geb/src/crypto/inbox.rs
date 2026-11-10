//! Inbox address of a recipient (kind 4178): anyone can derive it from the
//! recipient's public `.E` key.

use super::kdf::{derive_secp256k1_secret, xonly_pubkey};
use crate::Result;

/// HKDF info base for the inbox Nostr secret (guide, "Connecting" step 1).
pub const INBOX_NOSTR_SECRET_INFO: &[u8] = b"consensual/inbox/v1/nostr-secret";

/// The inbox's Nostr secret, derived from the recipient's public X25519 key.
/// The IKM … `ec 01`
/// multicodec prefix and not the multibase text (Geb path B answer 2:
/// `inbox_keys(x25519_pub: &[u8; 32])`, `rendezvous.rs:94-97`). The HKDF info
/// is the label followed by a counter byte that starts at 0 and is
/// …
pub fn inbox_secret(recipient_e_pub: &[u8; 32]) -> Result<[u8; 32]> {
    derive_secp256k1_secret(recipient_e_pub, INBOX_NOSTR_SECRET_INFO)
}

/// The inbox's x-only public key (the Nostr `authors` filter value).
pub fn inbox_pubkey(recipient_e_pub: &[u8; 32]) -> Result<[u8; 32]> {
    xonly_pubkey(&inbox_secret(recipient_e_pub)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::hkdf32;

    #[test]
    fn matches_an_independent_derivation_from_the_guide_text() {
        let e = [9u8; 32];
        let want = hkdf32(None, &e, b"consensual/inbox/v1/nostr-secret\x00").unwrap();
        assert_eq!(inbox_secret(&e).unwrap(), want);
        assert_eq!(inbox_pubkey(&e).unwrap(), xonly_pubkey(&want).unwrap());
        assert_ne!(
            inbox_pubkey(&[10u8; 32]).unwrap(),
            inbox_pubkey(&e).unwrap()
        );
    }
}
