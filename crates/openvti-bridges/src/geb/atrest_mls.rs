//! The at-rest [`SealedFile`] as the MLS client's storage: the group-state
//! snapshot and the signature key vault. Lives here, in the Geb adapter, because
//! the traits are Geb's; the core's `atrest` knows nothing of them.

use super::mls::{GroupStateStore, SignatureKeyVault};
use crate::atrest::SealedFile;
use crate::{Error, Result};

impl GroupStateStore for SealedFile {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.read()?.map(|z| z.to_vec()))
    }
    fn save(&self, snapshot: &[u8]) -> Result<()> {
        self.write(snapshot)
    }
}

/// The MLS signature key, encrypted at rest.
impl SignatureKeyVault for SealedFile {
    fn load(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let Some(raw) = self.read()? else {
            return Ok(None);
        };
        let (private, public): (String, String) = serde_json::from_slice(&raw)
            .map_err(|_| Error::Crypto("signature key record is unreadable".into()))?;
        let dec =
            |s: &str| hex::decode(s).map_err(|_| Error::Crypto("signature key record".into()));
        Ok(Some((dec(&private)?, dec(&public)?)))
    }
    fn save(&self, private: &[u8], public: &[u8]) -> Result<()> {
        let raw = zeroize::Zeroizing::new(
            serde_json::to_vec(&(hex::encode(private), hex::encode(public)))
                .map_err(|_| Error::Crypto("encode signature key".into()))?,
        );
        self.write(&raw)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_signature_key_vault_and_state_file_refuse_the_wrong_key_and_tampering() {
        use super::*;
        use crate::atrest::AtRestKey;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sig.enc");
        let vault = SealedFile::new(
            path.clone(),
            AtRestKey::derive(&[1; 32], "mls").unwrap(),
            "mls/l1/sigkey",
        );
        assert!(SignatureKeyVault::load(&vault).unwrap().is_none());
        SignatureKeyVault::save(&vault, &[7u8; 32], &[8u8; 32]).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(8).any(|w| w == [7u8; 8]), "no plaintext key");
        assert_eq!(
            SignatureKeyVault::load(&vault).unwrap(),
            Some((vec![7u8; 32], vec![8u8; 32]))
        );
        let wrong = SealedFile::new(
            path.clone(),
            AtRestKey::derive(&[2; 32], "mls").unwrap(),
            "mls/l1/sigkey",
        );
        assert!(SignatureKeyVault::load(&wrong).is_err());
        let state = SealedFile::new(
            dir.path().join("st.enc"),
            AtRestKey::derive(&[1; 32], "mls").unwrap(),
            "mls/l1/state",
        );
        GroupStateStore::save(&state, b"snapshot").unwrap();
        assert_eq!(
            GroupStateStore::load(&state).unwrap(),
            Some(b"snapshot".to_vec())
        );
        let mut blob = std::fs::read(dir.path().join("st.enc")).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        std::fs::write(dir.path().join("st.enc"), blob).unwrap();
        assert!(GroupStateStore::load(&state).is_err());
    }
}
