//! Identity and key custody (plan section 4), behind feature `vtc`.
//!
//! Two identities per link, never linked:
//!
//! - **The room persona `P_b`** is held by the user's VTA and never leaves it.
//!   This module only records its DID. There is deliberately no export call
//!   for it anywhere in this crate.
//! - **The Geb device DID `G_b`** = `did:peer:2.A<ed>.V<ed>.E<x>`. The VTA mints
//!   two key records in the `geb-bridge` context (one Ed25519, one separately
//!   derived X25519); the bridge exports each once with `keys/export-secret/0.1`,
//!   builds the DID itself with the already-bound encoder (no `.S`), and keeps
//!   the two secrets only in its own secret store ([`SecretStore`], over
//!   `vti-secrets`, so the backend is the operator's choice: keyring, a cloud
//!   secret manager, an encrypted file).
//!
//! Why export: the VTA signing oracle frames its signatures and offers no
//! X25519 ECDH oracle, so it cannot produce Geb's raw JCS signature or run the
//! dyad's key agreement (plan section 4).
//!
//! The secret store holds one blob, [`BridgeSecrets`]: a 32-byte *store key*
//! (from which [`crate::atrest`] derives the at-rest keys for ratchet, MLS and
//! signature-key state) and one [`LinkSecrets`] per link. Nothing here ever
//! prints a secret: `Debug` is hand-written and names only DIDs and key ids.
//!
//! Orphans (R2.1): the mint is two creates and two exports before the secrets
//! are saved. A crash between leaves key records at the VTA that nothing
//! references; they cost nothing and are listed under the `geb-bridge` context
//! for the operator to revoke. The config is written only after the secrets.
//!
//! UNVERIFIED: a derived key is exportable by default
//! (`vta_sdk::client::VtaClient::create_key` says so) but whether a context
//! policy can flip that default was not checked against a real VTA; an export
//! refusal is surfaced as the VTA's error, never worked around.
//! UNVERIFIED: `public_key_multibase` of an exported X25519 key is compared to
//! the public key derived from the exported secret and a mismatch refuses; the
//! real VTA's encoding of that field (raw or multicodec-prefixed) is accepted
//! both ways but not observed.

use crate::geb::crypto::{did_peer, x25519_public};
use crate::geb::dyad::GebIdentity;
use crate::{Error, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vta_sdk::client::{CreateKeyRequest, VtaClient};
use vta_sdk::keys::KeyType;
use vti_common::seed_store::SeedStore;
use zeroize::{Zeroize, Zeroizing};

/// Bumped when the stored shape changes.
const VERSION: u32 = 1;

/// A secret as lowercase hex. Wiped on drop; `Debug` prints nothing of it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretHex(String);

impl SecretHex {
    fn from_bytes(b: &[u8]) -> Self {
        Self(hex::encode(b))
    }
    fn to_32(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut raw = hex::decode(&self.0).map_err(|_| Error::Crypto("stored secret".into()))?;
        let out = <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| Error::Crypto("stored secret is not 32 bytes".into()));
        raw.zeroize();
        out.map(Zeroizing::new)
    }
}

impl Drop for SecretHex {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Everything held for one link.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSecrets {
    /// The Geb device DID, `did:peer:2.A.V.E`.
    pub device_did: String,
    /// The VTA key record behind `.A` / `.V`.
    pub ed_key_id: String,
    /// The VTA key record behind `.E`.
    pub x_key_id: String,
    /// The room persona DID (held by the VTA, never exported).
    pub persona: String,
    ed_secret: SecretHex,
    x_secret: SecretHex,
    /// Keys the deterministic record keys of this link.
    link_secret: SecretHex,
}

impl std::fmt::Debug for LinkSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkSecrets")
            .field("device_did", &self.device_did)
            .field("ed_key_id", &self.ed_key_id)
            .field("x_key_id", &self.x_key_id)
            .field("persona", &self.persona)
            .finish_non_exhaustive()
    }
}

impl LinkSecrets {
    /// Build from the two exported secrets. The DID is derived here, never
    /// taken from the caller.
    pub fn new(
        ed_key_id: &str,
        x_key_id: &str,
        persona: &str,
        ed_secret: &[u8; 32],
        x_secret: &[u8; 32],
    ) -> Result<Self> {
        let ed_pub = SigningKey::from_bytes(ed_secret).verifying_key().to_bytes();
        let device_did = did_peer::encode(&ed_pub, &x25519_public(x_secret), None)?;
        let mut link_secret = Zeroizing::new([0u8; 32]);
        rand::fill(&mut link_secret[..]);
        Ok(Self {
            device_did,
            ed_key_id: ed_key_id.into(),
            x_key_id: x_key_id.into(),
            persona: persona.into(),
            ed_secret: SecretHex::from_bytes(ed_secret),
            x_secret: SecretHex::from_bytes(x_secret),
            link_secret: SecretHex::from_bytes(&link_secret[..]),
        })
    }

    /// The device identity for the dyad and the MLS leaf binding.
    pub fn identity(&self) -> Result<GebIdentity> {
        let ed = self.ed_secret.to_32()?;
        let x = self.x_secret.to_32()?;
        let id = GebIdentity::new(SigningKey::from_bytes(&ed), *x)?;
        use crate::geb::traits::GebSigner;
        if id.did() != self.device_did {
            return Err(Error::Crypto(
                "the stored keys do not produce the stored device DID".into(),
            ));
        }
        Ok(id)
    }

    /// The secret that keys this link's deterministic record keys.
    pub fn link_secret(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.link_secret.to_32()
    }
}

/// The blob in the secret store.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeSecrets {
    version: u32,
    store_key: SecretHex,
    links: BTreeMap<String, LinkSecrets>,
    /// The long-term VTA client `did:key` and its private key (multibase):
    /// what `run` authenticates to the VTA with. Narrowed at the VTA to the
    /// room capabilities; never an admin credential.
    client: Option<ClientCredential>,
}

/// The bridge's long-term VTA client credential.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCredential {
    /// The client `did:key`.
    pub did: String,
    private_key_multibase: SecretHex,
}

impl std::fmt::Debug for ClientCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredential")
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

impl ClientCredential {
    /// Wrap a client key.
    pub fn new(did: &str, private_key_multibase: &str) -> Self {
        Self {
            did: did.into(),
            private_key_multibase: SecretHex::from_bytes(private_key_multibase.as_bytes()),
        }
    }
    /// The private key, multibase.
    pub fn private_key_multibase(&self) -> Result<Zeroizing<String>> {
        let raw = hex::decode(&self.private_key_multibase.0)
            .map_err(|_| Error::Crypto("stored client key".into()))?;
        String::from_utf8(raw)
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto("stored client key".into()))
    }
}

impl std::fmt::Debug for BridgeSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeSecrets")
            .field("links", &self.links.keys().collect::<Vec<_>>())
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl BridgeSecrets {
    /// An empty blob with a fresh store key.
    pub fn new() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        rand::fill(&mut k[..]);
        Self {
            version: VERSION,
            store_key: SecretHex::from_bytes(&k[..]),
            links: BTreeMap::new(),
            client: None,
        }
    }

    /// The store key the at-rest keys are derived from.
    pub fn store_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.store_key.to_32()
    }

    /// The links held, by id.
    pub fn link_ids(&self) -> impl Iterator<Item = &str> {
        self.links.keys().map(String::as_str)
    }

    /// One link's secrets.
    pub fn link(&self, id: &str) -> Option<&LinkSecrets> {
        self.links.get(id)
    }

    /// The long-term client credential, if setup stored one.
    pub fn client(&self) -> Option<&ClientCredential> {
        self.client.as_ref()
    }

    /// Store the client credential.
    pub fn set_client(&mut self, c: ClientCredential) {
        self.client = Some(c);
    }

    /// Add a link. Refuses any reuse: the link id, the device DID, either VTA
    /// key record or the persona may belong to one link only (a shared
    /// identity correlates every room it sits in, plan section 4).
    pub fn insert(&mut self, link_id: &str, secrets: LinkSecrets) -> Result<()> {
        if self.links.contains_key(link_id) {
            return Err(Error::Config(format!("link {link_id} already has keys")));
        }
        for (other, o) in &self.links {
            let clash = if o.device_did == secrets.device_did {
                Some("device DID")
            } else if o.persona == secrets.persona {
                Some("persona")
            } else if o.ed_key_id == secrets.ed_key_id || o.x_key_id == secrets.x_key_id {
                Some("key record")
            } else {
                None
            };
            if let Some(what) = clash {
                return Err(Error::Config(format!(
                    "link {link_id}: the {what} is already used by link {other}; \
                     one Geb device DID and one room persona per link"
                )));
            }
        }
        self.links.insert(link_id.into(), secrets);
        Ok(())
    }

    /// Remove a link's secrets (the VTA key records are not revoked here).
    pub fn remove(&mut self, link_id: &str) -> bool {
        self.links.remove(link_id).is_some()
    }
}

impl Default for BridgeSecrets {
    fn default() -> Self {
        Self::new()
    }
}

/// The bridge's own secret store: one blob in a `vti-secrets` backend.
pub struct SecretStore {
    inner: Box<dyn SeedStore>,
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(format!("secret store: {e}"))
}

impl SecretStore {
    /// Wrap a backend (tests use this directly).
    pub fn new(inner: Box<dyn SeedStore>) -> Self {
        Self { inner }
    }

    /// Open the backend `[secrets]` selects. Refuses `config_seed` (it keeps
    /// the key in `config.toml`).
    pub fn open(
        secrets: &crate::config::SecretsConfig,
        data_dir: &std::path::Path,
    ) -> Result<Self> {
        let cfg: vti_secrets::SecretsConfig = toml::Value::Table(secrets.0.clone())
            .try_into()
            .map_err(|e| Error::Config(format!("[secrets]: {e}")))?;
        if matches!(cfg.backend, Some(vti_secrets::SecretBackend::ConfigSeed)) || cfg.seed.is_some()
        {
            return Err(Error::Config(
                "secrets.backend = config_seed would keep the bridge keys in config.toml".into(),
            ));
        }
        let inner = vti_secrets::create_seed_store(&cfg, data_dir).map_err(store_err)?;
        Ok(Self { inner })
    }

    /// Whether a successful save survives a restart.
    pub fn persists(&self) -> bool {
        self.inner.set_persists_across_restart()
    }

    /// Read the blob. `None` when nothing is stored yet.
    pub async fn load(&self) -> Result<Option<BridgeSecrets>> {
        let Some(raw) = self.inner.get().await.map_err(store_err)? else {
            return Ok(None);
        };
        let raw = Zeroizing::new(raw);
        let s: BridgeSecrets = serde_json::from_slice(&raw)
            .map_err(|_| Error::Store("secret store: unreadable bridge secrets".into()))?;
        if s.version != VERSION {
            return Err(Error::Store(format!(
                "secret store: bridge secrets version {} is not {VERSION}",
                s.version
            )));
        }
        Ok(Some(s))
    }

    /// Replace the blob.
    pub async fn save(&self, s: &BridgeSecrets) -> Result<()> {
        let raw = Zeroizing::new(
            serde_json::to_vec(s).map_err(|_| Error::Store("encode bridge secrets".into()))?,
        );
        self.inner.set(&raw).await.map_err(store_err)
    }
}

fn vta_err(what: &str, e: vta_sdk::error::VtaError) -> Error {
    Error::Foreign(format!("VTA {what}: {e}"))
}

/// Mint and export the two device keys for `link_id` in `context`, and build
/// the link's secrets. `persona` is only recorded.
///
/// Each call mints two fresh key records; it never reuses a key. The VTA calls
/// are single attempts (`create_key` and `get_key_secret` are not looped: the
/// caller reruns setup, which mints new records).
pub async fn mint_device_identity(
    client: &VtaClient,
    context: &str,
    link_id: &str,
    persona: &str,
) -> Result<LinkSecrets> {
    let ed = mint_and_export(client, context, link_id, "ed", KeyType::Ed25519).await?;
    let x = mint_and_export(client, context, link_id, "x", KeyType::X25519).await?;
    if ed.0 == x.0 {
        return Err(Error::Crypto("the VTA returned one key id twice".into()));
    }
    // The two secrets must be independent: a shared secret would tie the
    // signing key to the agreement key.
    if ed.1[..] == x.1[..] {
        return Err(Error::Crypto(
            "the VTA returned the same secret for the Ed25519 and X25519 keys".into(),
        ));
    }
    LinkSecrets::new(&ed.0, &x.0, persona, &ed.1, &x.1)
}

async fn mint_and_export(
    client: &VtaClient,
    context: &str,
    link_id: &str,
    which: &str,
    key_type: KeyType,
) -> Result<(String, Zeroizing<[u8; 32]>)> {
    let created = client
        .create_key(CreateKeyRequest {
            key_type: key_type.clone(),
            derivation_path: None,
            key_id: None,
            mnemonic: None,
            label: Some(format!("geb-bridge/{link_id}/device-{which}")),
            context_id: Some(context.to_string()),
            // Derived, not internal: an internal key can never be exported.
            internal: None,
        })
        .await
        .map_err(|e| vta_err("create key", e))?;
    if created.key_type != key_type {
        return Err(Error::Crypto("the VTA minted a key of another type".into()));
    }
    let exported = client
        .get_key_secret(&created.key_id)
        .await
        .map_err(|e| vta_err("export key", e))?;
    if exported.key_id != created.key_id || exported.key_type != key_type {
        return Err(Error::Crypto(
            "the VTA exported a different key than asked for".into(),
        ));
    }
    let secret = Zeroizing::new(
        vta_sdk::did_key::decode_private_key_multibase(&exported.private_key_multibase)
            .map_err(|e| Error::Crypto(format!("exported key: {e}")))?,
    );
    check_public(&key_type, &secret, &exported.public_key_multibase)?;
    Ok((created.key_id, secret))
}

/// The exported secret must produce the public key the VTA names.
fn check_public(key_type: &KeyType, secret: &[u8; 32], public_mb: &str) -> Result<()> {
    let derived: [u8; 32] = match key_type {
        KeyType::Ed25519 => SigningKey::from_bytes(secret).verifying_key().to_bytes(),
        _ => x25519_public(secret),
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
