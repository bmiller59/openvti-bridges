//! The Geb device identity `G_b` and its keys (key custody for this adapter).
//!
//! `G_b` = `did:peer:2.A<ed>.V<ed>.E<x>`. The VTA mints two key records in the
//! bridge's context (one Ed25519, one separately derived X25519) through the
//! core's [`KeyMinter`]; this module builds the DID itself with the already
//! bound encoder (no `.S`), and the core keeps the two secrets, as an opaque
//! payload under kind `geb`, in the bridge's secret store.
//!
//! Why export: the VTA signing oracle frames its signatures and offers no
//! X25519 ECDH oracle, so it cannot produce Geb's raw JCS signature or run the
//! dyad's key agreement.
//!
//! This crate names no VTA type: minting goes through [`KeyMinter`], which the
//! VTI side implements.
//!
//! UNVERIFIED: `public_key_multibase` of an exported X25519 key is compared to
//! the public key derived from the exported secret and a mismatch refuses; the
//! real VTA's encoding of that field (raw or multicodec-prefixed) is accepted
//! both ways but not observed.

use crate::crypto::{did_peer, x25519_public};
use crate::dyad::GebIdentity;
use crate::traits::GebSigner;
use crate::{Error, Result};
use ed25519_dalek::SigningKey;
use openvti_bridge_core::secrets::{KeyMinter, LinkSecrets, MintKeyType, MintedKey, SecretHex};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The kind under which this adapter's payload is stored.
pub const KIND: &str = "geb";

/// What Geb needs for one link: the device DID and the two exported keys.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GebLinkSecrets {
    /// The Geb device DID, `did:peer:2.A.V.E`.
    pub device_did: String,
    /// The VTA key record behind `.A` / `.V`.
    pub ed_key_id: String,
    /// The VTA key record behind `.E`.
    pub x_key_id: String,
    ed_secret: SecretHex,
    x_secret: SecretHex,
}

impl std::fmt::Debug for GebLinkSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GebLinkSecrets")
            .field("device_did", &self.device_did)
            .field("ed_key_id", &self.ed_key_id)
            .field("x_key_id", &self.x_key_id)
            .finish_non_exhaustive()
    }
}

impl GebLinkSecrets {
    /// Build from the two exported secrets. The DID is derived here, never
    /// taken from the caller.
    pub fn new(
        ed_key_id: &str,
        x_key_id: &str,
        ed_secret: &[u8; 32],
        x_secret: &[u8; 32],
    ) -> Result<Self> {
        let ed_pub = SigningKey::from_bytes(ed_secret).verifying_key().to_bytes();
        let device_did = did_peer::encode(&ed_pub, &x25519_public(x_secret), None)?;
        Ok(Self {
            device_did,
            ed_key_id: ed_key_id.into(),
            x_key_id: x_key_id.into(),
            ed_secret: SecretHex::from_bytes(ed_secret),
            x_secret: SecretHex::from_bytes(x_secret),
        })
    }

    /// The device identity for the dyad and the MLS leaf binding.
    pub fn identity(&self) -> Result<GebIdentity> {
        let ed = self.ed_secret.to_32()?;
        let x = self.x_secret.to_32()?;
        let id = GebIdentity::new(SigningKey::from_bytes(&ed), *x)?;
        if id.did() != self.device_did {
            return Err(Error::Crypto(
                "the stored keys do not produce the stored device DID".into(),
            ));
        }
        Ok(id)
    }

    /// The core's secrets for a link: `persona` and a fresh link secret, with
    /// this identity as the `geb` payload. The device DID and both key records
    /// are what the core refuses to see on two links.
    pub fn into_link_secrets(&self, persona: &str) -> Result<LinkSecrets> {
        let payload = Zeroizing::new(
            serde_json::to_vec(self).map_err(|_| Error::Store("encode geb secrets".into()))?,
        );
        Ok(LinkSecrets::new(persona).with_adapter(
            KIND,
            &payload,
            vec![
                self.device_did.clone(),
                self.ed_key_id.clone(),
                self.x_key_id.clone(),
            ],
        ))
    }

    /// Read the `geb` payload of a link's secrets. Refuses a link that holds
    /// another adapter's identity.
    pub fn from_link_secrets(l: &LinkSecrets) -> Result<Self> {
        let raw = l.adapter_payload(KIND)?;
        serde_json::from_slice(&raw)
            .map_err(|_| Error::Store("unreadable geb secrets in the secret store".into()))
    }
}

/// Mint and export the two device keys for `link_id` in `context`, and build
/// the link's Geb secrets.
///
/// Each call mints two fresh key records; it never reuses a key. The minter's
/// calls are single attempts: the caller reruns setup, which mints new records.
pub async fn mint_device_identity(
    minter: &dyn KeyMinter,
    context: &str,
    link_id: &str,
) -> Result<GebLinkSecrets> {
    let ed = mint(minter, context, link_id, "ed", MintKeyType::Ed25519).await?;
    let x = mint(minter, context, link_id, "x", MintKeyType::X25519).await?;
    if ed.key_id == x.key_id {
        return Err(Error::Crypto("the VTA returned one key id twice".into()));
    }
    // The two secrets must be independent: a shared secret would tie the
    // signing key to the agreement key.
    if ed.secret[..] == x.secret[..] {
        return Err(Error::Crypto(
            "the VTA returned the same secret for the Ed25519 and X25519 keys".into(),
        ));
    }
    GebLinkSecrets::new(&ed.key_id, &x.key_id, &ed.secret, &x.secret)
}

async fn mint(
    minter: &dyn KeyMinter,
    context: &str,
    link_id: &str,
    which: &str,
    key_type: MintKeyType,
) -> Result<MintedKey> {
    let label = format!("openvti-bridges/{KIND}/{link_id}/device-{which}");
    let key = minter.mint_and_export(context, &label, key_type).await?;
    check_public(key_type, &key.secret, &key.public_multibase)?;
    Ok(key)
}

/// The exported secret must produce the public key the VTA names.
fn check_public(key_type: MintKeyType, secret: &[u8; 32], public_mb: &str) -> Result<()> {
    let derived: [u8; 32] = match key_type {
        MintKeyType::Ed25519 => SigningKey::from_bytes(secret).verifying_key().to_bytes(),
        MintKeyType::X25519 => x25519_public(secret),
        _ => return Err(Error::Unsupported("a key type this adapter does not use")),
    };
    let (_, raw) = multibase::decode(public_mb)
        .map_err(|_| Error::Crypto("exported public key is not multibase".into()))?;
    let key = if raw.len() == 34 { &raw[2..] } else { &raw[..] };
    if key != derived {
        return Err(Error::Crypto(
            "the exported secret does not match the VTA's public key".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openvti_bridge_core::secrets::BridgeSecrets;
    use std::sync::Mutex;

    /// A minter with no VTA behind it: this crate's own reading of what a
    /// `KeyMinter` returns.
    #[derive(Default)]
    struct FakeMinter {
        n: Mutex<u8>,
        asked: Mutex<Vec<(String, String, MintKeyType)>>,
        lie: bool,
    }

    #[async_trait]
    impl KeyMinter for FakeMinter {
        async fn mint_and_export(
            &self,
            context: &str,
            label: &str,
            key_type: MintKeyType,
        ) -> Result<MintedKey> {
            let mut n = self.n.lock().unwrap();
            *n += 1;
            let secret = [*n; 32];
            self.asked
                .lock()
                .unwrap()
                .push((context.into(), label.into(), key_type));
            let public = match key_type {
                MintKeyType::Ed25519 => SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
                _ => x25519_public(&secret),
            };
            let shown = if self.lie { [9u8; 32] } else { public };
            Ok(MintedKey {
                key_id: format!("key-{n}"),
                secret: Zeroizing::new(secret),
                public_multibase: multibase::encode(multibase::Base::Base58Btc, shown),
            })
        }
    }

    #[tokio::test]
    async fn mints_two_keys_in_the_context_with_geb_labels_and_builds_the_did_locally() {
        let m = FakeMinter::default();
        let s = mint_device_identity(&m, "openvti-bridges", "l1")
            .await
            .unwrap();
        let asked = m.asked.lock().unwrap().clone();
        assert_eq!(asked.len(), 2);
        assert_eq!(
            asked[0],
            (
                "openvti-bridges".into(),
                "openvti-bridges/geb/l1/device-ed".into(),
                MintKeyType::Ed25519
            )
        );
        assert_eq!(asked[1].1, "openvti-bridges/geb/l1/device-x");
        assert_eq!(asked[1].2, MintKeyType::X25519);
        let d = did_peer::decode(&s.device_did).unwrap();
        assert_eq!(d.assertion, d.authentication);
        assert!(s.device_did.starts_with("did:peer:2.A"));
        assert_eq!(s.identity().unwrap().did(), s.device_did);
    }

    #[tokio::test]
    async fn a_public_key_that_does_not_match_the_secret_is_refused() {
        let m = FakeMinter {
            lie: true,
            ..Default::default()
        };
        let e = mint_device_identity(&m, "c", "l1").await.err().unwrap();
        assert!(e.to_string().contains("does not match"), "{e}");
    }

    #[tokio::test]
    async fn the_payload_round_trips_the_core_blob_and_is_never_printed() {
        let m = FakeMinter::default();
        let g = mint_device_identity(&m, "c", "l1").await.unwrap();
        let ls = g.into_link_secrets("did:key:p1").unwrap();
        let mut blob = BridgeSecrets::new();
        blob.insert("l1", ls).unwrap();
        let raw = serde_json::to_vec(&blob).unwrap();
        let back: BridgeSecrets = serde_json::from_slice(&raw).unwrap();
        let again = GebLinkSecrets::from_link_secrets(back.link("l1").unwrap()).unwrap();
        assert_eq!(again.device_did, g.device_did);
        assert_eq!(again.identity().unwrap().did(), g.device_did);
        // A second link may not reuse the device identity or the persona.
        let dup = g.into_link_secrets("did:key:p2").unwrap();
        assert!(blob.insert("l2", dup).is_err());
        let g2 = mint_device_identity(&m, "c", "l2").await.unwrap();
        let e = blob
            .insert("l2", g2.into_link_secrets("did:key:p1").unwrap())
            .unwrap_err();
        assert!(e.to_string().contains("persona"), "{e}");
        // No Debug form carries a secret.
        let ed_hex = serde_json::to_value(&g).unwrap()["ed_secret"]
            .as_str()
            .unwrap()
            .to_string();
        let dbg = format!("{blob:?} {g:?} {:?}", blob.link("l1").unwrap());
        assert!(!dbg.contains(&ed_hex));
    }

    #[tokio::test]
    async fn another_kinds_identity_is_refused() {
        let ls = LinkSecrets::new("did:key:p").with_adapter("other", b"{}", vec![]);
        let e = GebLinkSecrets::from_link_secrets(&ls).unwrap_err();
        assert!(e.to_string().contains("other"), "{e}");
        let none = LinkSecrets::new("did:key:p");
        assert!(GebLinkSecrets::from_link_secrets(&none).is_err());
    }
}
