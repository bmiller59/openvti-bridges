//! Nostr event primitives: the NIP-01 event id and BIP-340 signatures.
//!
//! Resolved here (previously `UNVERIFIED`): the id is the lowercase hex sha256
//! of the UTF-8 serialisation `[0,<pubkey>,<created_at>,<kind>,<tags>,<content>]`
//! with no whitespace and only the NIP-01 escapes in strings (`\n \" \\ \r \t
//! \b \f`); the signature is BIP-340 Schnorr over the 32 id bytes. The
//! signature path is bound to the published BIP-340 vectors (indexes 0, 1 and
//! 2 of `bip-0340/test-vectors.csv`) in this module's tests. The id path has
//! no published byte vector in NIP-01, so its test re-derives the hash from the
//! serialisation written out by hand and says so.

use super::traits::RelayEvent;
use crate::{Error, Result};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Mailbox kind for pair and room envelopes.
pub const KIND_MAILBOX: u32 = 4177;
/// Inbox kind for sealed first contact.
pub const KIND_INBOX: u32 = 4178;

fn push_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            // NIP-01 names no other escape. Other control characters are
            // written as \u00XX, as JSON requires; no event this crate builds
            // contains one (content is base64), and a relay event that does
            // must hash the same way to verify or it is dropped.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The NIP-01 serialisation that the id hashes.
pub fn serialize_for_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let mut s = String::with_capacity(content.len() + 128);
    s.push_str("[0,");
    push_escaped(&mut s, pubkey);
    s.push_str(&format!(",{created_at},{kind},["));
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        for (j, item) in tag.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            push_escaped(&mut s, item);
        }
        s.push(']');
    }
    s.push_str("],");
    push_escaped(&mut s, content);
    s.push(']');
    s
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn signing_key(secret: &[u8; 32]) -> Result<SigningKey> {
    SigningKey::from_bytes(&(*secret).into()).map_err(|_| Error::Crypto("nostr secret key".into()))
}

/// BIP-340 sign `msg` (any length; Nostr passes the 32 id bytes) with explicit
/// auxiliary randomness. Exposed so the published vectors can be bound.
pub fn schnorr_sign_with(secret: &[u8; 32], msg: &[u8], aux: &[u8; 32]) -> Result<[u8; 64]> {
    let sig = signing_key(secret)?
        .sign_raw(msg, aux)
        .map_err(|_| Error::Crypto("schnorr sign".into()))?;
    Ok(sig.to_bytes())
}

/// BIP-340 verify.
pub fn schnorr_verify(xonly_pub: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(&(*xonly_pub).into())
        .map_err(|_| Error::Crypto("nostr pubkey is not a valid x-only key".into()))?;
    let sig = Signature::try_from(sig).map_err(|_| Error::Wire("signature length".into()))?;
    vk.verify_raw(msg, &sig)
        .map_err(|_| Error::Crypto("schnorr signature did not verify".into()))
}

impl RelayEvent {
    /// The id this event's fields hash to.
    pub fn compute_id(&self) -> String {
        hex::encode(Sha256::digest(
            serialize_for_id(
                &self.pubkey,
                self.created_at,
                self.kind,
                &self.tags,
                &self.content,
            )
            .as_bytes(),
        ))
    }

    /// Build and sign an event with a secp256k1 secret (fresh BIP-340 aux
    /// randomness).
    pub fn sign(
        secret: &[u8; 32],
        kind: u32,
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<RelayEvent> {
        let pubkey = hex::encode(super::crypto::kdf::xonly_pubkey(secret)?);
        let mut ev = RelayEvent {
            id: String::new(),
            pubkey,
            kind,
            created_at,
            content,
            tags,
            sig: String::new(),
        };
        let id = ev.compute_id();
        let mut aux = [0u8; 32];
        rand::fill(&mut aux);
        let id_bytes = hex::decode(&id).map_err(|e| Error::Crypto(e.to_string()))?;
        ev.sig = hex::encode(schnorr_sign_with(secret, &id_bytes, &aux)?);
        ev.id = id;
        Ok(ev)
    }

    /// Check the shape, that the id is the hash of the fields, and the
    /// signature. A relay's word is never enough: every event a client
    /// receives is checked here before it is used.
    pub fn verify(&self) -> Result<()> {
        if !is_hex(&self.id, 64) || !is_hex(&self.pubkey, 64) || !is_hex(&self.sig, 128) {
            return Err(Error::Wire(
                "event id, pubkey and sig must be lowercase hex".into(),
            ));
        }
        if self.compute_id() != self.id {
            return Err(Error::Crypto("event id does not match its fields".into()));
        }
        let pk: [u8; 32] = hex::decode(&self.pubkey)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Error::Wire("pubkey".into()))?;
        let id = hex::decode(&self.id).map_err(|e| Error::Wire(e.to_string()))?;
        let sig = hex::decode(&self.sig).map_err(|e| Error::Wire(e.to_string()))?;
        schnorr_verify(&pk, &id, &sig)
    }

    /// The NIP-40 `expiration` tag, if it has one that parses.
    pub fn expiration(&self) -> Option<u64> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("expiration"))
            .and_then(|t| t.get(1))
            .and_then(|v| v.parse().ok())
    }

    /// Whether NIP-40 says the event has expired at `now_secs`.
    pub fn is_expired(&self, now_secs: u64) -> bool {
        self.expiration().is_some_and(|e| e <= now_secs)
    }

    /// Size of the NIP-01 JSON, the quantity the posting limit bounds: 120,000
    /// bytes (`wire::MAX_EVENT_BYTES`; the relay carries up to 131,072, which
    /// is what we accept when reading, `wire::MAX_RECV_EVENT_BYTES`).
    pub fn json_len(&self) -> usize {
        self.to_json().to_string().len()
    }

    /// The event as the NIP-01 wire object.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id, "pubkey": self.pubkey, "created_at": self.created_at,
            "kind": self.kind, "tags": self.tags, "content": self.content, "sig": self.sig,
        })
    }

    /// Parse the NIP-01 wire object (shape only; call [`RelayEvent::verify`]).
    pub fn from_json(v: &serde_json::Value) -> Result<RelayEvent> {
        let s = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .map(str::to_string)
                .ok_or_else(|| Error::Wire(format!("event field {k}")))
        };
        let n = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_u64())
                .ok_or_else(|| Error::Wire(format!("event field {k}")))
        };
        let tags: Vec<Vec<String>> = serde_json::from_value(
            v.get("tags")
                .cloned()
                .ok_or_else(|| Error::Wire("event field tags".into()))?,
        )
        .map_err(|e| Error::Wire(format!("event tags: {e}")))?;
        Ok(RelayEvent {
            id: s("id")?,
            pubkey: s("pubkey")?,
            kind: u32::try_from(n("kind")?).map_err(|_| Error::Wire("kind".into()))?,
            created_at: n("created_at")?,
            content: s("content")?,
            tags,
            sig: s("sig")?,
        })
    }
}

/// The standard tags for kinds 4177 and 4178: `["v","1"]` and a NIP-40
/// `expiration` seven days out.
pub fn standard_tags(created_at: u64) -> Vec<Vec<String>> {
    vec![
        vec!["v".into(), "1".into()],
        vec![
            "expiration".into(),
            (created_at + super::room::EXPIRY_SECS).to_string(),
        ],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // Published BIP-340 vectors (bips/bip-0340/test-vectors.csv), indexes 0-2.
    #[test]
    fn bip340_published_vectors() {
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000003",
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
                 25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            ),
            (
                "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341\
                 8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            ),
        ];
        for (sk, pk, aux, msg, sig) in cases {
            let (sk, pk, aux, msg) = (h32(sk), h32(pk), h32(aux), h32(msg));
            let want = hex::decode(sig).unwrap();
            assert_eq!(
                super::super::crypto::kdf::xonly_pubkey(&sk).unwrap(),
                pk,
                "pubkey"
            );
            assert_eq!(schnorr_sign_with(&sk, &msg, &aux).unwrap().to_vec(), want);
            schnorr_verify(&pk, &msg, &want).unwrap();
            let mut bad = want.clone();
            bad[10] ^= 1;
            assert!(schnorr_verify(&pk, &msg, &bad).is_err());
        }
    }

    #[test]
    fn id_is_the_hash_of_the_nip01_serialisation_written_out_by_hand() {
        // Re-derivation, not a published vector: NIP-01 gives the shape, not bytes.
        let tags = vec![vec!["v".to_string(), "1".to_string()]];
        let s = serialize_for_id(
            &"ab".repeat(32),
            1700000000,
            4177,
            &tags,
            "a\"b\\c\nd\u{1}é",
        );
        let want = format!(
            "[0,\"{}\",1700000000,4177,[[\"v\",\"1\"]],\"a\\\"b\\\\c\\nd\\u0001é\"]",
            "ab".repeat(32)
        );
        assert_eq!(s, want);
    }

    #[test]
    fn sign_verify_and_every_tamper_fails() {
        let sk = [7u8; 32];
        let ev = RelayEvent::sign(&sk, 4177, 1000, standard_tags(1000), "AAAA".into()).unwrap();
        ev.verify().unwrap();
        assert_eq!(ev.expiration(), Some(1000 + 7 * 86400));
        assert!(ev.is_expired(1000 + 7 * 86400));
        assert!(!ev.is_expired(1001));
        let mut t = ev.clone();
        t.content = "AAAB".into();
        assert!(t.verify().is_err(), "content changed, id stale");
        let mut t = ev.clone();
        t.id = t.compute_id();
        t.created_at += 1;
        t.id = t.compute_id();
        assert!(t.verify().is_err(), "id recomputed but signature stale");
        let mut t = ev.clone();
        t.sig = "00".repeat(64);
        assert!(t.verify().is_err());
        let mut t = ev.clone();
        t.sig = t.sig.to_uppercase();
        assert!(t.verify().is_err());
        let rt = RelayEvent::from_json(&ev.to_json()).unwrap();
        assert_eq!(rt, ev);
        assert!(RelayEvent::from_json(&serde_json::json!({"id":1})).is_err());
    }
}
