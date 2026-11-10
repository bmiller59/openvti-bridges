//! `sign_json`: Ed25519 over the RFC 8785 (JCS) form, base64url without
//! padding.

use crate::geb::traits::GebSigner;
use crate::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

fn jcs(v: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| Error::Wire(format!("jcs: {e}")))
}

/// Sign a JSON value.
pub fn sign_json(key: &SigningKey, v: &Value) -> Result<String> {
    let sig = key.sign(&jcs(v)?);
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Verify a `sign_json` signature.
pub fn verify_json(key: &VerifyingKey, v: &Value, sig_b64url: &str) -> Result<()> {
    let raw = URL_SAFE_NO_PAD
        .decode(sig_b64url)
        .map_err(|e| Error::Wire(format!("signature base64url: {e}")))?;
    let sig = Signature::from_slice(&raw).map_err(|e| Error::Wire(format!("signature: {e}")))?;
    key.verify(&jcs(v)?, &sig)
        .map_err(|_| Error::Crypto("signature did not verify".into()))
}

/// A [`GebSigner`] holding the device key in memory (the bridge keeps the
/// exported key in its secret store; this is the in-process holder).
pub struct LocalSigner {
    did: String,
    key: SigningKey,
}

impl LocalSigner {
    /// Wrap a key and its DID.
    pub fn new(did: String, key: SigningKey) -> Self {
        Self { did, key }
    }
}

impl GebSigner for LocalSigner {
    fn did(&self) -> &str {
        &self.did
    }
    fn sign_json(&self, v: &Value) -> Result<String> {
        sign_json(&self.key, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signs_the_canonical_form_independent_of_key_order() {
        let k = SigningKey::from_bytes(&[4u8; 32]);
        let a = json!({"b": 1, "a": [true, null], "c": "é"});
        let b: Value = serde_json::from_str(r#"{"c":"é","a":[true,null],"b":1}"#).unwrap();
        let sa = sign_json(&k, &a).unwrap();
        assert_eq!(sa, sign_json(&k, &b).unwrap());
        verify_json(&k.verifying_key(), &b, &sa).unwrap();
        assert!(!sa.contains('=') && !sa.contains('+') && !sa.contains('/'));
        // Ed25519 is deterministic: 64 bytes -> 86 base64url chars.
        assert_eq!(sa.len(), 86);
    }

    #[test]
    fn canonical_bytes_match_rfc8785_example_shape() {
        let v = json!({"b": 2, "a": 1});
        assert_eq!(jcs(&v).unwrap(), br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn rejects_tampering_wrong_key_and_garbage() {
        let k = SigningKey::from_bytes(&[4u8; 32]);
        let v = json!({"x": 1});
        let s = sign_json(&k, &v).unwrap();
        assert!(verify_json(&k.verifying_key(), &json!({"x": 2}), &s).is_err());
        let other = SigningKey::from_bytes(&[5u8; 32]);
        assert!(verify_json(&other.verifying_key(), &v, &s).is_err());
        assert!(verify_json(&k.verifying_key(), &v, "!!").is_err());
        assert!(verify_json(&k.verifying_key(), &v, "AAAA").is_err());
    }
}
