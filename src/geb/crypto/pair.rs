//! Envelope sealing on a mailbox (kind 4177): AES-256-GCM, random 12-byte
//! nonce, AAD = UTF-8 `consensual/rendezvous/v1|<mailbox pubkey hex>|<kind>`,
//! content = standard padded base64 of `nonce || ct`.

use super::rendezvous::RelayKeys;
use super::{b64_decode, b64_encode};
use crate::{Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

/// The AAD for a mailbox event of `kind`.
pub fn aad(pubkey_hex: &str, kind: u32) -> Vec<u8> {
    format!("consensual/rendezvous/v1|{pubkey_hex}|{kind}").into_bytes()
}

fn cipher(keys: &RelayKeys) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(&keys.aead_key[..]).map_err(|e| Error::Crypto(e.to_string()))
}

/// Seal with a caller-supplied nonce (tests, deterministic re-posts).
pub fn seal_with(
    keys: &RelayKeys,
    kind: u32,
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<String> {
    let aad = aad(&keys.pubkey_hex()?, kind);
    let n = Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Crypto("nonce length".into()))?;
    let ct = cipher(keys)?
        .encrypt(
            &n,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("seal failed".into()))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(b64_encode(&out))
}

/// Seal with a fresh random nonce.
pub fn seal(keys: &RelayKeys, kind: u32, plaintext: &[u8]) -> Result<String> {
    let mut nonce = [0u8; 12];
    rand::fill(&mut nonce);
    seal_with(keys, kind, &nonce, plaintext)
}

/// Open an event's content.
pub fn open(keys: &RelayKeys, kind: u32, content_b64: &str) -> Result<Vec<u8>> {
    let raw = b64_decode(content_b64)?;
    if raw.len() < 12 + 16 {
        return Err(Error::Wire("envelope too short".into()));
    }
    let nonce = Nonce::try_from(&raw[..12]).map_err(|_| Error::Wire("nonce".into()))?;
    let aad = aad(&keys.pubkey_hex()?, kind);
    cipher(keys)?
        .decrypt(
            &nonce,
            Payload {
                msg: &raw[12..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("envelope failed to open".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> RelayKeys {
        RelayKeys::from_parts([1u8; 32], [2u8; 32])
    }

    #[test]
    fn round_trip() {
        let k = keys();
        let c = seal(&k, 4177, b"{\"t\":\"ack\",\"a\":[]}").unwrap();
        assert_eq!(open(&k, 4177, &c).unwrap(), b"{\"t\":\"ack\",\"a\":[]}");
    }

    #[test]
    fn aad_binds_kind_and_mailbox() {
        let k = keys();
        let c = seal(&k, 4177, b"x").unwrap();
        assert!(open(&k, 4178, &c).is_err());
        let other = RelayKeys::from_parts([9u8; 32], [2u8; 32]);
        assert!(open(&other, 4177, &c).is_err());
    }

    #[test]
    fn matches_manual_construction_with_the_stated_aad() {
        let k = keys();
        let c = seal_with(&k, 4177, &[7u8; 12], b"payload").unwrap();
        let raw = b64_decode(&c).unwrap();
        assert_eq!(&raw[..12], &[7u8; 12]);
        let want_aad = format!("consensual/rendezvous/v1|{}|4177", k.pubkey_hex().unwrap());
        assert_eq!(aad(&k.pubkey_hex().unwrap(), 4177), want_aad.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&[2u8; 32]).unwrap();
        let n = Nonce::try_from(&raw[..12]).unwrap();
        let pt = cipher
            .decrypt(
                &n,
                Payload {
                    msg: &raw[12..],
                    aad: want_aad.as_bytes(),
                },
            )
            .unwrap();
        assert_eq!(pt, b"payload");
    }

    #[test]
    fn tamper_and_garbage_fail() {
        let k = keys();
        let mut raw = b64_decode(&seal(&k, 4177, b"x").unwrap()).unwrap();
        raw[13] ^= 1;
        assert!(open(&k, 4177, &b64_encode(&raw)).is_err());
        assert!(open(&k, 4177, &b64_encode(&[0u8; 5])).is_err());
    }
}
