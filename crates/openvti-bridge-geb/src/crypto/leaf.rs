//! The MLS leaf binding (Geb path B answer 6).
//!
//! A device proves that an MLS leaf signature key belongs to its DID by
//! signing, with the DID's key (`.V`, else `.A`), the JCS form of
//! `{"did":"<device DID>","k":"<64 hex>","t":"leaf","v":1}` where `k` is the leaf's own
//! 32-byte Ed25519 MLS signature key written as lowercase hex. The
//! binding is that signature as base64url without padding (86 characters),
//! and the value of the LeafNode extension [`EXT_LEAF_BINDING`] is its UTF-8
//! bytes. A missing binding is seated but "unverified"; a forged one makes
//! the adding Commit invalid on every device.

use super::sign;
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

/// GroupContext extension carrying the room policy (declared, never carried,
/// by a KeyPackage).
pub const EXT_POLICY: u16 = 0xF001;
/// LeafNode extension carrying the binding.
pub const EXT_LEAF_BINDING: u16 = 0xF002;
/// The extension types a KeyPackage's capabilities must list.
pub const CAPABILITY_EXTENSIONS: [u16; 2] = [EXT_POLICY, EXT_LEAF_BINDING];

/// Length of a binding string: 64 signature bytes in unpadded base64url.
pub const BINDING_LEN: usize = 86;

/// The document that is signed (its JCS form is what the signature covers).
pub fn binding_doc(did: &str, leaf_key: &[u8; 32]) -> Value {
    json!({"did": did, "k": hex::encode(leaf_key), "t": "leaf", "v": 1})
}

/// The exact UTF-8 bytes signed: the JCS form of [`binding_doc`].
pub fn signed_bytes(did: &str, leaf_key: &[u8; 32]) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(&binding_doc(did, leaf_key))
        .map_err(|e| Error::Wire(format!("jcs: {e}")))
}

/// Make the binding string for a leaf.
pub fn binding(device_key: &SigningKey, did: &str, leaf_key: &[u8; 32]) -> Result<String> {
    sign::sign_json(device_key, &binding_doc(did, leaf_key))
}

/// The value of the `0xF002` LeafNode extension for a binding.
pub fn extension_value(binding: &str) -> Vec<u8> {
    binding.as_bytes().to_vec()
}

/// Check a binding against the DID's verifying key.
pub fn verify(
    device_key: &VerifyingKey,
    did: &str,
    leaf_key: &[u8; 32],
    binding: &str,
) -> Result<()> {
    if binding.len() != BINDING_LEN {
        return Err(Error::Wire("leaf binding is not 86 characters".into()));
    }
    sign::verify_json(device_key, &binding_doc(did, leaf_key), binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_bytes_are_the_stated_jcs_string() {
        let leaf = [5u8; 32];
        let got = String::from_utf8(signed_bytes("did:peer:2.x", &leaf).unwrap()).unwrap();
        assert_eq!(
            got,
            format!(
                r#"{{"did":"did:peer:2.x","k":"{}","t":"leaf","v":1}}"#,
                "05".repeat(32)
            )
        );
    }

    #[test]
    fn binding_is_86_characters_verifies_and_is_bound_to_everything() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();
        let leaf = [5u8; 32];
        let b = binding(&sk, "did:a", &leaf).unwrap();
        assert_eq!(b.len(), BINDING_LEN);
        assert!(!b.contains('=') && !b.contains('+') && !b.contains('/'));
        assert!(verify(&pk, "did:a", &leaf, &b).is_ok());
        assert!(verify(&pk, "did:b", &leaf, &b).is_err());
        assert!(verify(&pk, "did:a", &[6u8; 32], &b).is_err());
        assert!(verify(&pk, "did:a", &leaf, &b[..85]).is_err());
        let other = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(verify(&other, "did:a", &leaf, &b).is_err());
        assert_eq!(extension_value(&b), b.as_bytes());
    }

    #[test]
    fn extension_ids() {
        assert_eq!(CAPABILITY_EXTENSIONS, [0xF001, 0xF002]);
    }
}
