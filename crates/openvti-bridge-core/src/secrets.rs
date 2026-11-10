//! The bridge's secret blob, adapter-neutral: what is stored, never how it is
//! stored (the secret-store backends are the VTI side's, in
//! `openvti-bridge-vtc`) and never what an adapter keeps inside it.
//!
//! Two identities per link, never linked:
//!
//! - **The room persona** is held by the user's VTA and never leaves it. This
//!   module only records its DID. There is deliberately no export call for it
//!   anywhere in this workspace.
//! - **The adapter's own identity** (for Geb, a `did:peer` device DID over two
//!   exported keys) is minted through a [`KeyMinter`] and kept here as an
//!   opaque payload under the adapter's kind. The core stores it, redacted in
//!   every `Debug`, and never interprets it.
//!
//! The blob is [`BridgeSecrets`]: a 32-byte *store key* (from which
//! [`crate::atrest`] derives the at-rest keys for adapter state) and one
//! [`LinkSecrets`] per link. Nothing here ever prints a secret: `Debug` is
//! hand-written and names only DIDs and ids.
//!
//! Version 2 is the first layout with adapter payloads. There is no reader for
//! version 1 (the pre-restructure blob held Geb's device keys in fixed
//! fields): nothing was deployed, so an old secret store is discarded and
//! re-created by `setup` and `link add`.

use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// Bumped when the stored shape changes.
pub const VERSION: u32 = 2;

/// A secret as lowercase hex. Wiped on drop; `Debug` prints nothing of it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretHex(String);

impl SecretHex {
    /// Wrap bytes.
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(hex::encode(b))
    }
    /// The bytes back, wiped on drop.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        hex::decode(&self.0)
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto("stored secret".into()))
    }
    /// The 32 bytes back; refuses any other length.
    pub fn to_32(&self) -> Result<Zeroizing<[u8; 32]>> {
        let raw = self.to_bytes()?;
        <[u8; 32]>::try_from(raw.as_slice())
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto("stored secret is not 32 bytes".into()))
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

/// What an adapter keeps for one link, opaque to the core.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterSecret {
    /// Public identifiers the adapter says must belong to one link only (a
    /// device DID, VTA key record ids): compared across links by
    /// [`BridgeSecrets::insert`].
    ids: Vec<String>,
    payload: SecretHex,
}

/// Everything held for one link.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSecrets {
    /// The room persona DID (held by the VTA, never exported).
    pub persona: String,
    /// Keys the deterministic record keys of this link.
    link_secret: SecretHex,
    /// The adapter's secret payload, by adapter kind.
    adapter: BTreeMap<String, AdapterSecret>,
}

impl std::fmt::Debug for LinkSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkSecrets")
            .field("persona", &self.persona)
            .field("adapter_kinds", &self.adapter.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl LinkSecrets {
    /// A link's secrets with a fresh link secret and no adapter payload yet.
    pub fn new(persona: &str) -> Self {
        let mut link_secret = Zeroizing::new([0u8; 32]);
        rand::fill(&mut link_secret[..]);
        Self {
            persona: persona.into(),
            link_secret: SecretHex::from_bytes(&link_secret[..]),
            adapter: BTreeMap::new(),
        }
    }

    /// Keep an adapter's `payload` under its `kind`. `ids` are the public
    /// identifiers that may belong to one link only.
    pub fn with_adapter(mut self, kind: &str, payload: &[u8], ids: Vec<String>) -> Self {
        self.adapter.insert(
            kind.into(),
            AdapterSecret {
                ids,
                payload: SecretHex::from_bytes(payload),
            },
        );
        self
    }

    /// The payload the adapter `kind` stored. Refuses a link that holds a
    /// payload for any other kind, or none for this one: a link is never
    /// started with another adapter's identity.
    pub fn adapter_payload(&self, kind: &str) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(other) = self.adapter.keys().find(|k| k.as_str() != kind) {
            return Err(Error::Config(format!(
                "this link's stored identity is for adapter `{other}`, not `{kind}`"
            )));
        }
        self.adapter
            .get(kind)
            .ok_or_else(|| Error::Config(format!("this link holds no `{kind}` adapter identity")))?
            .payload
            .to_bytes()
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
        let raw = self.private_key_multibase.to_bytes()?;
        String::from_utf8(raw.to_vec())
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

    /// The version this blob was stored at; a store refuses any but
    /// [`VERSION`].
    pub fn version(&self) -> u32 {
        self.version
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

    /// Add a link. Refuses any reuse: the link id, the persona or any
    /// adapter-declared identifier (a device DID, a VTA key record) may belong
    /// to one link only (a shared identity correlates every room it sits in).
    pub fn insert(&mut self, link_id: &str, secrets: LinkSecrets) -> Result<()> {
        if self.links.contains_key(link_id) {
            return Err(Error::Config(format!("link {link_id} already has keys")));
        }
        for (other, o) in &self.links {
            let clash = if o.persona == secrets.persona {
                Some("persona")
            } else if o.adapter.values().any(|a| {
                secrets
                    .adapter
                    .values()
                    .any(|b| a.ids.iter().any(|id| b.ids.contains(id)))
            }) {
                Some("adapter identity or key record")
            } else {
                None
            };
            if let Some(what) = clash {
                return Err(Error::Config(format!(
                    "link {link_id}: the {what} is already used by link {other}; \
                     one persona and one adapter identity per link"
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

/// The curve of a key to mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MintKeyType {
    /// Ed25519 (signing).
    Ed25519,
    /// X25519 (key agreement).
    X25519,
}

/// A key the VTA minted and exported once.
pub struct MintedKey {
    /// The VTA's key record id.
    pub key_id: String,
    /// The 32-byte secret.
    pub secret: Zeroizing<[u8; 32]>,
    /// The public key as the VTA names it (multibase, raw or multicodec
    /// prefixed): the adapter checks it against the secret.
    pub public_multibase: String,
}

/// Mints and exports a key through the user's VTA. An adapter that needs key
/// material of its own declares what it needs and asks for it here; it never
/// names a derivation path or a key id of its own choosing (key custody:
/// choosing a path is holding a key), and the persona key is never available
/// through this trait. Implemented by the VTI side (`openvti-bridge-vtc`), so
/// an adapter crate does not depend on the VTA SDK.
#[async_trait]
pub trait KeyMinter: Send + Sync {
    /// Mint a fresh derived key of `key_type` in `context` with `label`, and
    /// export its secret once. Each call mints a new key record; it never
    /// reuses one. A single attempt: nothing here loops, the caller reruns the
    /// operation, which mints new records.
    async fn mint_and_export(
        &self,
        context: &str,
        label: &str,
        key_type: MintKeyType,
    ) -> Result<MintedKey>;
}
