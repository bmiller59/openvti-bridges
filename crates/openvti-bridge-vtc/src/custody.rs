//! The bridge's secret store and its VTA key minter (the VTI side of key
//! custody; the blob's shape and the adapters' payloads are in
//! [`openvti_bridge_core::secrets`]).
//!
//! The secret store holds one blob, [`BridgeSecrets`], in a `vti-secrets`
//! backend of the operator's choice: keyring, a cloud secret manager, an
//! encrypted file. [`VtaKeyMinter`] is the [`KeyMinter`] over the user's VTA: a
//! derived key is created in the bridge's context and its secret exported once
//! with `keys/export-secret/0.1`. The persona key is never exported and nothing
//! here can ask for it.
//!
//! Orphans (R2.1): a mint is a create and an export per key before the secrets
//! are saved. A crash between leaves key records at the VTA that nothing
//! references; they cost nothing and are listed under the `openvti-bridges`
//! context for the operator to revoke. The config is written only after the
//! secrets.
//!
//! UNVERIFIED: a derived key is exportable by default
//! (`vta_sdk::client::VtaClient::create_key` says so) but whether a context
//! policy can flip that default was not checked against a real VTA; an export
//! refusal is surfaced as the VTA's error, never worked around.

use crate::{Error, Result};
use async_trait::async_trait;
use openvti_bridge_core::secrets::{BridgeSecrets, KeyMinter, MintKeyType, MintedKey, VERSION};
use vta_sdk::client::{CreateKeyRequest, VtaClient};
use vta_sdk::keys::KeyType;
use vti_common::seed_store::SeedStore;
use zeroize::Zeroizing;

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
        secrets: &openvti_bridge_core::config::SecretsConfig,
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
        if s.version() != VERSION {
            return Err(Error::Store(format!(
                "secret store: bridge secrets version {} is not {VERSION}; there is no reader \
                 for an older layout, so discard the stored secrets and run `setup` and `link \
                 add` again",
                s.version()
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

/// A [`KeyMinter`] over the user's VTA.
pub struct VtaKeyMinter<'a>(pub &'a VtaClient);

fn vta_key_type(t: MintKeyType) -> Result<KeyType> {
    match t {
        MintKeyType::Ed25519 => Ok(KeyType::Ed25519),
        MintKeyType::X25519 => Ok(KeyType::X25519),
        _ => Err(Error::Unsupported("a key type this VTA minter cannot mint")),
    }
}

#[async_trait]
impl KeyMinter for VtaKeyMinter<'_> {
    async fn mint_and_export(
        &self,
        context: &str,
        label: &str,
        key_type: MintKeyType,
    ) -> Result<MintedKey> {
        let want = vta_key_type(key_type)?;
        let created = self
            .0
            .create_key(CreateKeyRequest {
                key_type: want.clone(),
                derivation_path: None,
                key_id: None,
                mnemonic: None,
                label: Some(label.to_string()),
                context_id: Some(context.to_string()),
                // Derived, not internal: an internal key can never be exported.
                internal: None,
            })
            .await
            .map_err(|e| vta_err("create key", e))?;
        if created.key_type != want {
            return Err(Error::Crypto("the VTA minted a key of another type".into()));
        }
        let exported = self
            .0
            .get_key_secret(&created.key_id)
            .await
            .map_err(|e| vta_err("export key", e))?;
        if exported.key_id != created.key_id || exported.key_type != want {
            return Err(Error::Crypto(
                "the VTA exported a different key than asked for".into(),
            ));
        }
        let secret = Zeroizing::new(
            vta_sdk::did_key::decode_private_key_multibase(&exported.private_key_multibase)
                .map_err(|e| Error::Crypto(format!("exported key: {e}")))?,
        );
        Ok(MintedKey {
            key_id: created.key_id,
            secret,
            public_multibase: exported.public_key_multibase,
        })
    }
}
