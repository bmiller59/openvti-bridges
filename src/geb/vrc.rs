//! The verifiable relationship credential (VRC) that connect-when-apart
//! exchanges: W3C VC 2.0 + DTG (`RelationshipCredential`), `issuerScope`
//! `directed`, an `eddsa-jcs-2022` DataIntegrityProof whose
//! `verificationMethod` is `<issuer>#key-1`, and
//! `credentialSubject.issuerPublicKey` equal to the issuer's assertion key
//! (guide, "Connecting" step 8; `vrc.rs:11-14,59-149,210` in Geb).
//!
//! UNVERIFIED: Geb's own `vrc.rs` was not available to this crate, only the
//! guide's summary of it. What the guide states is enforced exactly. What it
//! does not state is taken from the DTG credential model (the
//! `dtg-credentials` crate): the context pair, the type list
//! `["VerifiableCredential","DTGCredential","RelationshipCredential"]`, a
//! top-level `issuerScope`, and `validFrom`. The encoding of
//! `issuerPublicKey` is assumed to be the multibase text of the `.A` element of
//! the DID (the same string the DID carries). A VRC issued here is verified by
//! this code; whether Geb accepts it, and whether this code accepts Geb's, is
//! exactly what a live exchange with Geb would settle.

use super::crypto::did_peer;
use crate::{Error, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const VC_CTX: &str = "https://www.w3.org/ns/credentials/v2";
const DTG_CTX: &str = "https://registry.trustoverip.org/dtg/context/v1";

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the epoch.
pub fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn jcs(v: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(v).map_err(|e| Error::Wire(format!("jcs: {e}")))
}

fn hash_data(proof_config: &Value, unsecured: &Value) -> Result<Vec<u8>> {
    let mut h = Sha256::digest(jcs(proof_config)?).to_vec();
    h.extend_from_slice(&Sha256::digest(jcs(unsecured)?));
    Ok(h)
}

/// The assertion key of a DID, as raw bytes and as its DID-document text.
fn assertion_key(did: &str) -> Result<([u8; 32], String)> {
    let d = did_peer::decode(did)?;
    let raw = d
        .assertion
        .or(d.authentication)
        .ok_or_else(|| Error::Wire("DID has no assertion key".into()))?;
    let mut b = vec![0xed, 0x01];
    b.extend_from_slice(&raw);
    Ok((raw, multibase::encode(multibase::Base::Base58Btc, b)))
}

/// Issue a VRC from `issuer_did` about `subject_did`.
pub fn issue(
    issuer_did: &str,
    issuer_key: &SigningKey,
    subject_did: &str,
    now_secs: u64,
) -> Result<Value> {
    let (raw, text) = assertion_key(issuer_did)?;
    if issuer_key.verifying_key().to_bytes() != raw {
        return Err(Error::Crypto(
            "signing key is not the issuer DID's assertion key".into(),
        ));
    }
    let when = iso8601(now_secs);
    let unsecured = json!({
        "@context": [VC_CTX, DTG_CTX],
        "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
        "issuer": issuer_did,
        "issuerScope": "directed",
        "validFrom": when,
        "credentialSubject": {"id": subject_did, "issuerPublicKey": text},
    });
    let mut proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": format!("{issuer_did}#key-1"),
        "created": when,
        "proofPurpose": "assertionMethod",
        "@context": unsecured["@context"].clone(),
    });
    let sig = issuer_key.sign(&hash_data(&proof, &unsecured)?);
    if let Some(o) = proof.as_object_mut() {
        o.remove("@context");
        o.insert(
            "proofValue".into(),
            Value::String(multibase::encode(
                multibase::Base::Base58Btc,
                sig.to_bytes(),
            )),
        );
    }
    let mut vrc = unsecured;
    if let Some(o) = vrc.as_object_mut() {
        o.insert("proof".into(), proof);
    }
    Ok(vrc)
}

/// Verify a VRC: the issuer is `expect_issuer`, the subject is
/// `expect_subject`, scope is `directed`, the subject carries the issuer's
/// assertion key, and the proof verifies against that key.
pub fn verify(vrc: &Value, expect_issuer: &str, expect_subject: &str) -> Result<()> {
    let bad = |m: &str| Error::Crypto(format!("VRC refused: {m}"));
    let obj = vrc.as_object().ok_or_else(|| bad("not an object"))?;
    let types = obj.get("type").and_then(Value::as_array);
    let has = |t: &str| types.is_some_and(|a| a.iter().any(|x| x.as_str() == Some(t)));
    if !has("VerifiableCredential") || !has("RelationshipCredential") {
        return Err(bad("not a relationship credential"));
    }
    if obj.get("issuer").and_then(Value::as_str) != Some(expect_issuer) {
        return Err(bad("issuer is not the expected party"));
    }
    if obj.get("issuerScope").and_then(Value::as_str) != Some("directed") {
        return Err(bad("issuerScope is not directed"));
    }
    let subject = obj
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("no credentialSubject"))?;
    if subject.get("id").and_then(Value::as_str) != Some(expect_subject) {
        return Err(bad("subject is not the expected party"));
    }
    let (raw, text) = assertion_key(expect_issuer)?;
    if subject.get("issuerPublicKey").and_then(Value::as_str) != Some(text.as_str()) {
        return Err(bad("issuerPublicKey is not the issuer's assertion key"));
    }
    let proof = obj
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("no proof"))?;
    let field = |k: &str| proof.get(k).and_then(Value::as_str);
    if field("type") != Some("DataIntegrityProof")
        || field("cryptosuite") != Some("eddsa-jcs-2022")
        || field("proofPurpose") != Some("assertionMethod")
    {
        return Err(bad("proof is not an eddsa-jcs-2022 DataIntegrityProof"));
    }
    if field("verificationMethod") != Some(format!("{expect_issuer}#key-1").as_str()) {
        return Err(bad("verificationMethod is not <issuer>#key-1"));
    }
    let (base, sig) = multibase::decode(field("proofValue").ok_or_else(|| bad("no proofValue"))?)
        .map_err(|_| bad("proofValue"))?;
    if base != multibase::Base::Base58Btc {
        return Err(bad("proofValue must be base58btc"));
    }
    let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| bad("proofValue length"))?;
    let mut unsecured = vrc.clone();
    let mut config = Value::Object(proof.clone());
    if let Some(o) = unsecured.as_object_mut() {
        o.remove("proof");
    }
    if let Some(o) = config.as_object_mut() {
        o.remove("proofValue");
        if let Some(c) = obj.get("@context") {
            o.insert("@context".into(), c.clone());
        }
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| bad("issuer key"))?;
    key.verify(&hash_data(&config, &unsecured)?, &sig)
        .map_err(|_| bad("signature did not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn party(seed: u8) -> (String, SigningKey) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        (
            did_peer::encode(&k.verifying_key().to_bytes(), &[seed; 32], None).unwrap(),
            k,
        )
    }

    #[test]
    fn iso_dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_709_164_800 + 3661), "2024-02-29T01:01:01Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn issue_and_verify_and_every_check_bites() {
        let (a, ak) = party(1);
        let (b, _) = party(2);
        let (c, _) = party(3);
        let v = issue(&a, &ak, &b, 1_700_000_000).unwrap();
        verify(&v, &a, &b).unwrap();
        assert_eq!(v["proof"]["verificationMethod"], format!("{a}#key-1"));
        assert_eq!(v["issuerScope"], "directed");
        assert!(verify(&v, &b, &b).is_err(), "wrong issuer");
        assert!(verify(&v, &a, &c).is_err(), "wrong subject");
        let mut t = v.clone();
        t["credentialSubject"]["id"] = c.clone().into();
        assert!(verify(&t, &a, &c).is_err(), "edited after signing");
        let mut t = v.clone();
        t["credentialSubject"]["issuerPublicKey"] = "zNope".into();
        assert!(verify(&t, &a, &b).is_err());
        let mut t = v.clone();
        t["issuerScope"] = "public".into();
        assert!(verify(&t, &a, &b).is_err());
        let mut t = v.clone();
        t["proof"]["verificationMethod"] = format!("{a}#key-2").into();
        assert!(verify(&t, &a, &b).is_err());
        let mut t = v.clone();
        t.as_object_mut().unwrap().remove("proof");
        assert!(verify(&t, &a, &b).is_err());
        // A VRC signed by someone else but claiming to be from a.
        let (_, mk) = party(9);
        assert!(issue(&a, &mk, &b, 1).is_err());
    }
}
