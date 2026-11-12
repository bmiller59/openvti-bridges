//! `did:peer:2.A<ed>.V<ed>.E<x>[.S<b64url json>]` encode and decode.
//!
//! Each key is a multibase `z` string: base58btc over a multicodec prefix and
//! 32 key bytes (`ed 01` for Ed25519, `ec 01` for X25519). Purpose codes we do
//! not know are skipped, and older V-only DIDs still read. Verifiers use `.V`, or `.A`
//! when there is no `.V`.
//!
//! The element order `A`, `V`, `E` is confirmed by Geb's vectors (byte-exact
//! encode, and `#key-1/2/3` in that order in its DID document). UNVERIFIED:
//! only where `.S` goes relative to them (no vector carries one); the encoder
//! puts it last and the decoder accepts any order.

use crate::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use multibase::Base;
use serde_json::Value;

const ED_PREFIX: [u8; 2] = [0xed, 0x01];
const X_PREFIX: [u8; 2] = [0xec, 0x01];
const PREFIX: &str = "did:peer:2";

/// A decoded `did:peer:2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidPeer {
    /// `.A` assertion key (Ed25519).
    pub assertion: Option<[u8; 32]>,
    /// `.V` authentication key (Ed25519).
    pub authentication: Option<[u8; 32]>,
    /// `.E` key agreement key (X25519).
    pub key_agreement: Option<[u8; 32]>,
    /// `.S` service JSON, if present.
    pub service: Option<Value>,
}

fn enc_key(prefix: [u8; 2], key: &[u8; 32]) -> String {
    let mut b = prefix.to_vec();
    b.extend_from_slice(key);
    multibase::encode(Base::Base58Btc, b)
}

fn dec_key(prefix: [u8; 2], s: &str) -> Result<[u8; 32]> {
    let (base, bytes) = multibase::decode(s).map_err(|e| Error::Wire(format!("multibase: {e}")))?;
    if base != Base::Base58Btc {
        return Err(Error::Wire("did:peer key must be base58btc ('z')".into()));
    }
    if bytes.len() != 34 || bytes[..2] != prefix {
        return Err(Error::Wire(
            "did:peer key has the wrong multicodec prefix or length".into(),
        ));
    }
    bytes[2..]
        .try_into()
        .map_err(|_| Error::Wire("key length".into()))
}

/// Encode the new-identity shape: the same Ed25519 key under `.A` and `.V`,
/// an X25519 key under `.E`, and an optional `.S`.
pub fn encode(ed_pub: &[u8; 32], x_pub: &[u8; 32], service: Option<&Value>) -> Result<String> {
    let ed = enc_key(ED_PREFIX, ed_pub);
    let mut did = format!("{PREFIX}.A{ed}.V{ed}.E{}", enc_key(X_PREFIX, x_pub));
    if let Some(s) = service {
        let json = serde_json::to_vec(s).map_err(|e| Error::Wire(e.to_string()))?;
        did.push_str(&format!(".S{}", URL_SAFE_NO_PAD.encode(json)));
    }
    Ok(did)
}

/// Decode. Unknown purpose codes are ignored; a repeated known code is
/// refused; at least one signing key is required.
pub fn decode(did: &str) -> Result<DidPeer> {
    let rest = did
        .strip_prefix(PREFIX)
        .and_then(|r| r.strip_prefix('.'))
        .ok_or_else(|| Error::Wire("not a did:peer:2".into()))?;
    let mut out = DidPeer {
        assertion: None,
        authentication: None,
        key_agreement: None,
        service: None,
    };
    for el in rest.split('.') {
        let mut chars = el.chars();
        let Some(code) = chars.next() else {
            return Err(Error::Wire("empty did:peer element".into()));
        };
        let value = chars.as_str();
        let dup = || Error::Wire(format!("repeated purpose code {code}"));
        match code {
            'A' if out.assertion.replace(dec_key(ED_PREFIX, value)?).is_some() => {
                return Err(dup());
            }
            'V' if out
                .authentication
                .replace(dec_key(ED_PREFIX, value)?)
                .is_some() =>
            {
                return Err(dup());
            }
            'E' if out
                .key_agreement
                .replace(dec_key(X_PREFIX, value)?)
                .is_some() =>
            {
                return Err(dup());
            }
            'S' => {
                let raw = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|e| Error::Wire(format!("service base64url: {e}")))?;
                let v: Value = serde_json::from_slice(&raw)
                    .map_err(|e| Error::Wire(format!("service json: {e}")))?;
                if out.service.replace(v).is_some() {
                    return Err(dup());
                }
            }
            _ => {} // unknown purpose code: ignored, as Geb's readers do
        }
    }
    if out.assertion.is_none() && out.authentication.is_none() {
        return Err(Error::Wire("did:peer has no signing key".into()));
    }
    Ok(out)
}

/// The DID document Geb's resolver builds (checked against its vector): one
/// verification method per key element, numbered `#key-1`, `#key-2`, ... in
/// the order the elements appear in the DID; `A` goes to `assertionMethod`,
/// `V` to `authentication`, `E` to `keyAgreement`. One Ed25519 key listed under
/// both `.A` and `.V` yields two methods. `.S` and unknown codes add no method.
pub fn document(did: &str) -> Result<Value> {
    decode(did)?; // validate first
    let rest = did
        .strip_prefix(PREFIX)
        .and_then(|r| r.strip_prefix('.'))
        .ok_or_else(|| Error::Wire("not a did:peer:2".into()))?;
    let (mut vms, mut assertion, mut authn, mut agree) = (vec![], vec![], vec![], vec![]);
    for el in rest.split('.') {
        let (code, value) = el.split_at(1);
        let (ty, rel) = match code {
            "A" => ("Ed25519VerificationKey2020", &mut assertion),
            "V" => ("Ed25519VerificationKey2020", &mut authn),
            "E" => ("X25519KeyAgreementKey2020", &mut agree),
            _ => continue,
        };
        let id = format!("{did}#key-{}", vms.len() + 1);
        vms.push(serde_json::json!({
            "id": id,
            "type": ty,
            "controller": did,
            "publicKeyMultibase": value,
        }));
        rel.push(Value::String(id));
    }
    Ok(serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": vms,
        "assertionMethod": assertion,
        "authentication": authn,
        "keyAgreement": agree,
    }))
}

impl DidPeer {
    /// The key that verifies `sign_json`: `.V`, or `.A` when there is no `.V`.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let raw = self
            .authentication
            .or(self.assertion)
            .ok_or_else(|| Error::Wire("no verification key".into()))?;
        VerifyingKey::from_bytes(&raw).map_err(|e| Error::Crypto(format!("ed25519 key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trip_new_shape() {
        let ed = [1u8; 32];
        let x = [2u8; 32];
        let did = encode(&ed, &x, None).unwrap();
        assert!(did.starts_with("did:peer:2.Az"));
        let d = decode(&did).unwrap();
        assert_eq!(
            (d.assertion, d.authentication, d.key_agreement),
            (Some(ed), Some(ed), Some(x))
        );
        assert_eq!(d.service, None);
    }

    #[test]
    fn same_key_under_a_and_v_means_identical_text() {
        let did = encode(&[1u8; 32], &[2u8; 32], None).unwrap();
        let parts: Vec<_> = did.split('.').collect();
        assert_eq!(&parts[1][1..], &parts[2][1..]);
        assert!(parts[3].starts_with("Ez"));
    }

    #[test]
    fn service_element_round_trips() {
        let s = json!({"t": "dm", "s": "wss://nostr.myceli.al"});
        let d = decode(&encode(&[1u8; 32], &[2u8; 32], Some(&s)).unwrap()).unwrap();
        assert_eq!(d.service, Some(s));
    }

    #[test]
    fn reads_v_only_and_ignores_unknown_codes() {
        let ed = enc_key(ED_PREFIX, &[1u8; 32]);
        let x = enc_key(X_PREFIX, &[2u8; 32]);
        let d = decode(&format!("did:peer:2.V{ed}.E{x}.Qwhatever")).unwrap();
        assert_eq!(d.assertion, None);
        assert_eq!(d.authentication, Some([1u8; 32]));
        assert!(d.verifying_key().is_ok());
        // Without .V, .A verifies.
        let a_only = decode(&format!("did:peer:2.A{ed}.E{x}")).unwrap();
        assert_eq!(a_only.verifying_key().unwrap().to_bytes(), [1u8; 32]);
    }

    #[test]
    fn hostile_dids_are_refused() {
        let ed = enc_key(ED_PREFIX, &[1u8; 32]);
        let x = enc_key(X_PREFIX, &[2u8; 32]);
        for bad in [
            "did:key:z6Mk".to_string(),
            "did:peer:2".to_string(),
            "did:peer:2.".to_string(),
            format!("did:peer:2.E{x}"),        // no signing key
            format!("did:peer:2.V{x}"),        // X25519 prefix under V
            format!("did:peer:2.V{ed}.V{ed}"), // repeated
            "did:peer:2.Vnot-multibase".to_string(),
            format!("did:peer:2.V{ed}.S!!!"),
            format!(
                "did:peer:2.V{}",
                multibase::encode(Base::Base58Btc, [0xed, 0x01, 1])
            ),
            format!(
                "did:peer:2.V{}",
                multibase::encode(Base::Base64, [0xed, 0x01, 1])
            ),
        ] {
            assert!(decode(&bad).is_err(), "should refuse {bad}");
        }
    }

    #[test]
    fn multicodec_prefixes_are_visible_in_the_encoding() {
        let (_, bytes) = multibase::decode(enc_key(ED_PREFIX, &[0u8; 32])).unwrap();
        assert_eq!(&bytes[..2], &[0xed, 0x01]);
        let (_, bytes) = multibase::decode(enc_key(X_PREFIX, &[0u8; 32])).unwrap();
        assert_eq!(&bytes[..2], &[0xec, 0x01]);
    }
}
