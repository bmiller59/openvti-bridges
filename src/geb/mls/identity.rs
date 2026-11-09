//! The bridge's MLS identity and its KeyPackages.
//!
//! The MLS signature key is a random OpenMLS key, **not** the Geb device key.
//! The device DID's key proves the link between the two by signing the leaf
//! binding (`geb::crypto::leaf`) through the [`GebSigner`] seam, so this module
//! never holds the device key. The binding goes in LeafNode extension `0xF002`.
//! The KeyPackage declares extensions `[0xF001, 0xF002]` and …
//! … (answer 7).

use crate::geb::crypto::leaf;
use crate::geb::traits::GebSigner;
use crate::{Error, Result};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use std::sync::Mutex;

/// The one ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
/// (`0x0001`), `mls.rs:26`.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Where the MLS signature key lives between runs.
///
/// Encrypted-at-rest hook point: the key is a long-lived secret (it signs
/// every commit and message this leaf makes). The default [`MemoryVault`]
/// keeps it in process memory only, so a restart loses the leaf; a durable
/// implementation must encrypt `private` before it touches disk. NOTE: the
/// OpenMLS group state itself (epoch secrets, tree) is also in memory only
/// for now; persisting it is a separate piece of work and the reason a
/// restart currently means being re-seated.
pub trait SignatureKeyVault: Send + Sync {
    /// The stored `(private, public)` pair, if any.
    fn load(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>>;
    /// Store the pair.
    fn save(&self, private: &[u8], public: &[u8]) -> Result<()>;
}

/// In-memory vault: plain, not durable. See [`SignatureKeyVault`].
#[derive(Default)]
pub struct MemoryVault(Mutex<Option<(Vec<u8>, Vec<u8>)>>);

impl SignatureKeyVault for MemoryVault {
    fn load(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::Crypto("vault poisoned".into()))?
            .clone())
    }
    fn save(&self, private: &[u8], public: &[u8]) -> Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| Error::Crypto("vault poisoned".into()))? =
            Some((private.to_vec(), public.to_vec()));
        Ok(())
    }
}

fn mls<E: std::fmt::Debug>(what: &str, e: E) -> Error {
    Error::Crypto(format!("mls {what}: {e:?}"))
}

/// The extension types a Geb KeyPackage declares.
pub fn declared_extensions() -> [ExtensionType; 2] {
    [
        ExtensionType::Unknown(leaf::EXT_POLICY),
        ExtensionType::Unknown(leaf::EXT_LEAF_BINDING),
    ]
}

/// Leaf capabilities: `Capabilities::new(None, None, Some(&[0xF001, 0xF002]),
/// None, None)`, as Geb builds them (answer 7).
pub fn leaf_capabilities() -> Capabilities {
    Capabilities::new(None, None, Some(&declared_extensions()), None, None)
}

/// How far back a KeyPackage's `not_before` is set, seconds (round 3 section
/// 5: at least an hour, so a receiver whose clock is behind ours does not
/// refuse a package minted a moment ago).
pub const LIFETIME_BACKDATE_SECS: u64 = 60 * 60;
/// How long a KeyPackage is valid after minting, seconds: 84 days, the
/// OpenMLS 0.8.2 default Geb's packages carry (Geb sets none).
pub const LIFETIME_SECS: u64 = 84 * 24 * 60 * 60;

/// The lifetime every outgoing KeyPackage carries: `not_before = now - 1 h`,
/// `not_after = now + 84 days`. Set explicitly, so it does not move with an
/// OpenMLS default; a package with no lifetime is refused by Geb's adder
/// (`MissingLifetime`).
pub fn key_package_lifetime(now_secs: u64) -> Lifetime {
    Lifetime::init(
        now_secs.saturating_sub(LIFETIME_BACKDATE_SECS),
        now_secs.saturating_add(LIFETIME_SECS),
    )
}

/// A device's MLS identity: signature key and BasicCredential (the device DID
/// as UTF-8).
pub struct MlsIdentity {
    /// The OpenMLS signature key pair.
    pub signer: SignatureKeyPair,
    /// The credential and the key it is bound to.
    pub credential: CredentialWithKey,
    did: String,
}

impl MlsIdentity {
    /// Load the key from the vault or make a random one, and register it with
    /// the provider's storage.
    pub fn new(
        did: &str,
        provider: &OpenMlsRustCrypto,
        vault: &dyn SignatureKeyVault,
    ) -> Result<Self> {
        let signer = match vault.load()? {
            Some((private, public)) => {
                SignatureKeyPair::from_raw(SUITE.signature_algorithm(), private, public)
            }
            None => {
                // OpenMLS exposes the private half only under its `test-utils`
                // feature, so make the Ed25519 key here (the provider stores
                // the 32-byte seed as the private key) and hand it over.
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                rand::fill(&mut seed[..]);
                let public = ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes();
                vault.save(&seed[..], &public)?;
                SignatureKeyPair::from_raw(
                    SUITE.signature_algorithm(),
                    seed.to_vec(),
                    public.to_vec(),
                )
            }
        };
        signer
            .store(provider.storage())
            .map_err(|e| mls("store signature key", e))?;
        let credential = CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, did.as_bytes().to_vec()),
            signature_key: signer.public().into(),
        };
        Ok(Self {
            signer,
            credential,
            did: did.to_string(),
        })
    }

    /// The device DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The 32-byte Ed25519 MLS signature public key.
    pub fn leaf_key(&self) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(self.signer.public())
            .map_err(|_| Error::Crypto("MLS signature key is not 32 bytes".into()))
    }

    /// The leaf binding string, signed by the Geb device key through `signer`.
    pub fn binding(&self, signer: &dyn GebSigner) -> Result<String> {
        signer.sign_json(&leaf::binding_doc(&self.did, &self.leaf_key()?))
    }

    /// A fresh single-use KeyPackage carrying the `0xF002` binding and an
    /// explicit lifetime valid at `now_secs` ([`key_package_lifetime`]). This is
    /// the ONLY way this crate mints a KeyPackage to hand out: there is no
    /// unbound variant (round 3 section 3: an unbound package can never be
    /// re-seated). The private halves are written to the provider's storage,
    /// where the Welcome that consumes it will find them.
    pub fn key_package(
        &self,
        provider: &OpenMlsRustCrypto,
        device: &dyn GebSigner,
        now_secs: u64,
    ) -> Result<KeyPackage> {
        let binding = self.binding(device)?;
        let ext = Extension::Unknown(
            leaf::EXT_LEAF_BINDING,
            UnknownExtension(leaf::extension_value(&binding)),
        );
        let leaf_exts =
            Extensions::<LeafNode>::single(ext).map_err(|e| mls("leaf extension", e))?;
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(leaf_capabilities())
            .leaf_node_extensions(leaf_exts)
            .key_package_lifetime(key_package_lifetime(now_secs))
            .build(SUITE, provider, &self.signer, self.credential.clone())
            .map_err(|e| mls("key package", e))?;
        Ok(bundle.key_package().clone())
    }
}
