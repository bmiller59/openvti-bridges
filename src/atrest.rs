//! Encryption at rest for the state that holds live secrets: the dyad's
//! ratchet chain keys, the MLS signature key and the persisted MLS group state.
//!
//! One 32-byte *store key* lives in the bridge's secret store
//! ([`crate::custody::BridgeSecrets`]). [`AtRestKey::derive`] turns it into an
//! independent key per purpose with HKDF-SHA256, so a leak of one purpose's
//! key (or a chosen-ciphertext trick across purposes) does not open another.
//! Every record is XChaCha20-Poly1305 with a fresh random 24-byte nonce and
//! the record's own name as associated data, so a blob moved to another
//! record, link or purpose fails to open: the wrong key and the wrong place are
//! the same error.
//!
//! Blob layout: `0x01 || nonce(24) || ciphertext+tag`.
//!
//! Bridged text is sealed too: [`EncryptedState`] seals the `text`, `title` and
//! `author` of every journal and outbox event (purpose `state`, AAD
//! `journal|outbox/<link>/<key>`), so a bridged message does not sit on disk in
//! clear. What stays in clear, exactly: the events' `origin`, `origin_id`,
//! `link`, `at`, `kind`, `reply_to`, `record_key` and `provenance` (ids, a
//! timestamp, the foreign room and device identifiers, the message hash; no
//! message text); the outbox's receipt rank and retired flag; the xref (the
//! `vtc:` / `vtkey:` / `foreign:` / `failed:` keys, which hold ids, foreign
//! line ids and a failure reason that may quote an error); the cursors; the
//! retention index; and the fjall files' metadata. Rows written by an earlier
//! version are plaintext and are read as they are (they leave when pruned). A
//! sealed row is confidential, not authenticated against deletion or
//! replacement of a whole row: nothing here is a rollback defence. `status`
//! counts pending entries without opening any body, so it needs no key. A
//! process that holds the store key in memory can read everything; this
//! protects the disk at rest, not a live compromise.

use crate::foreign::Receipt;
use crate::model::BridgeEvent;
use crate::store::{BridgeStore, PruneStats, StateSpace};
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use std::path::PathBuf;
use std::sync::Arc;
use zeroize::Zeroizing;

const FORMAT: u8 = 1;
const NONCE_LEN: usize = 24;
/// HKDF-SHA256 to 32 bytes. Local to this module so the core never reaches
/// into an adapter's crypto helpers.
fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(salt, ikm)
        .expand(info, &mut out)
        .map_err(|e| Error::Crypto(format!("hkdf: {e}")))?;
    Ok(out)
}

const SALT: &[u8] = b"vti-geb-bridge/at-rest/v1";

/// A purpose-bound at-rest key.
#[derive(Clone)]
pub struct AtRestKey {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for AtRestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AtRestKey(<redacted>)")
    }
}

impl AtRestKey {
    /// Derive the key for `purpose` (for example `"state"` or `"mls"`).
    pub fn derive(store_key: &[u8; 32], purpose: &str) -> Result<Self> {
        let k = hkdf32(Some(SALT), store_key, purpose.as_bytes())?;
        Ok(Self {
            key: Arc::new(Zeroizing::new(k)),
        })
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(&self.key[..])
            .map_err(|_| Error::Crypto("at-rest key".into()))
    }

    /// Encrypt `plaintext` for the record named `aad`.
    pub fn seal(&self, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce[..]);
        let n = XNonce::try_from(nonce.as_slice()).map_err(|_| Error::Crypto("nonce".into()))?;
        let ct = self
            .cipher()?
            .encrypt(
                &n,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| Error::Crypto("at-rest seal failed".into()))?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(FORMAT);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a blob made for the record named `aad`. Any failure (wrong key,
    /// wrong record, tampering, truncation) is the same error.
    pub fn open(&self, aad: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let fail = || {
            Error::Crypto(format!(
                "record {aad} does not open (wrong key or tampered)"
            ))
        };
        if blob.len() < 1 + NONCE_LEN + 16 || blob[0] != FORMAT {
            return Err(fail());
        }
        let n = XNonce::try_from(&blob[1..1 + NONCE_LEN]).map_err(|_| fail())?;
        self.cipher()?
            .decrypt(
                &n,
                Payload {
                    msg: &blob[1 + NONCE_LEN..],
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| fail())
    }
}

fn space_name(s: StateSpace) -> &'static str {
    match s {
        StateSpace::Links => "links",
        StateSpace::Ratchets => "ratchets",
    }
}

/// A [`BridgeStore`] that encrypts the adapter-owned state records
/// ([`StateSpace::Links`], [`StateSpace::Ratchets`]) and passes everything
/// else straight through. `scope` (the link id) is part of each record's AAD.
pub struct EncryptedState {
    inner: Arc<dyn BridgeStore>,
    key: AtRestKey,
    scope: String,
}

impl EncryptedState {
    /// Wrap `inner`.
    pub fn new(inner: Arc<dyn BridgeStore>, key: AtRestKey, scope: &str) -> Self {
        Self {
            inner,
            key,
            scope: scope.into(),
        }
    }

    fn aad(&self, space: StateSpace, key: &str) -> String {
        format!("state/{}/{}/{key}", self.scope, space_name(space))
    }

    fn event_aad(&self, kind: &str, key: &str) -> String {
        format!("{kind}/{}/{key}", self.scope)
    }

    /// The event with its text, title and author sealed into `text`.
    fn seal_event(&self, kind: &str, key: &str, ev: &BridgeEvent) -> Result<BridgeEvent> {
        let body = serde_json::to_vec(&SealedBody {
            author: ev.author.clone(),
            title: ev.title.clone(),
            text: ev.text.clone(),
        })
        .map_err(|e| Error::Store(format!("event does not encode: {e}")))?;
        let blob = self.key.seal(&self.event_aad(kind, key), &body)?;
        let mut sealed = ev.clone();
        sealed.author = SEALED_AUTHOR.into();
        sealed.title = None;
        sealed.text = B64.encode(blob);
        Ok(sealed)
    }

    /// The inverse of [`Self::seal_event`]; a plaintext row (an earlier
    /// version's) passes through unchanged.
    fn open_event(&self, kind: &str, key: &str, ev: BridgeEvent) -> Result<BridgeEvent> {
        if ev.author != SEALED_AUTHOR {
            return Ok(ev);
        }
        let aad = self.event_aad(kind, key);
        let blob = B64
            .decode(ev.text.as_bytes())
            .map_err(|_| Error::Crypto(format!("record {aad} does not open (not sealed text)")))?;
        let body = self.key.open(&aad, &blob)?;
        let b: SealedBody = serde_json::from_slice(&body)
            .map_err(|_| Error::Crypto(format!("record {aad} does not open (bad body)")))?;
        let mut out = ev;
        out.author = b.author;
        out.title = b.title;
        out.text = b.text;
        Ok(out)
    }
}

/// Marks an event whose body is sealed (a character no real author has).
const SEALED_AUTHOR: &str = "\u{1}at-rest/v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedBody {
    author: String,
    title: Option<String>,
    text: String,
}

#[async_trait]
impl BridgeStore for EncryptedState {
    async fn cursor(&self, name: &str) -> Result<Option<Vec<u8>>> {
        self.inner.cursor(name).await
    }
    async fn set_cursor(&self, name: &str, value: &[u8]) -> Result<()> {
        self.inner.set_cursor(name, value).await
    }
    async fn journal_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        let sealed = self.seal_event("journal", key, event)?;
        self.inner.journal_insert(key, &sealed).await
    }
    async fn outbox_insert(&self, key: &str, event: &BridgeEvent) -> Result<bool> {
        let sealed = self.seal_event("outbox", key, event)?;
        self.inner.outbox_insert(key, &sealed).await
    }
    async fn outbox_mark(&self, key: &str, receipt: Receipt) -> Result<()> {
        self.inner.outbox_mark(key, receipt).await
    }
    async fn outbox_receipt(&self, key: &str) -> Result<Option<Receipt>> {
        self.inner.outbox_receipt(key).await
    }
    async fn outbox_unposted(&self) -> Result<Vec<(String, BridgeEvent)>> {
        let mut out = Vec::new();
        for (k, ev) in self.inner.outbox_unposted().await? {
            let ev = self.open_event("outbox", &k, ev)?;
            out.push((k, ev));
        }
        Ok(out)
    }
    async fn outbox_pending_keys(&self) -> Result<Vec<String>> {
        self.inner.outbox_pending_keys().await
    }
    async fn outbox_retire(&self, key: &str) -> Result<()> {
        self.inner.outbox_retire(key).await
    }
    async fn xref_set_expiring(&self, a: &str, b: &str) -> Result<()> {
        self.inner.xref_set_expiring(a, b).await
    }
    async fn prune(&self, now_secs: u64, retention_secs: u64) -> Result<PruneStats> {
        self.inner.prune(now_secs, retention_secs).await
    }
    async fn state_get(&self, space: StateSpace, key: &str) -> Result<Option<Vec<u8>>> {
        match self.inner.state_get(space, key).await? {
            None => Ok(None),
            Some(blob) => Ok(Some(self.key.open(&self.aad(space, key), &blob)?.to_vec())),
        }
    }
    async fn state_put(&self, space: StateSpace, key: &str, value: &[u8]) -> Result<()> {
        let blob = self.key.seal(&self.aad(space, key), value)?;
        self.inner.state_put(space, key, &blob).await
    }
    async fn xref_set(&self, a: &str, b: &str) -> Result<()> {
        self.inner.xref_set(a, b).await
    }
    async fn xref_has(&self, a: &str) -> Result<bool> {
        self.inner.xref_has(a).await
    }
    async fn xref_get(&self, a: &str) -> Result<Option<String>> {
        self.inner.xref_get(a).await
    }
}

/// One encrypted file, replaced atomically (write a sibling, fsync, rename,
/// fsync the directory) and created mode `0600`. Synchronous on purpose: the
/// MLS client persists inside short critical sections, never across an await.
#[derive(Clone)]
pub struct SealedFile {
    path: PathBuf,
    key: AtRestKey,
    aad: String,
}

impl SealedFile {
    /// A file at `path`, bound to the record name `aad`.
    pub fn new(path: PathBuf, key: AtRestKey, aad: &str) -> Self {
        Self {
            path,
            key,
            aad: aad.into(),
        }
    }

    /// Whether the file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Decrypt the file. `None` when it does not exist; an error when it does
    /// not open.
    pub fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match std::fs::read(&self.path) {
            Ok(blob) => self.key.open(&self.aad, &blob).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Store(format!("read {}: {e}", self.path.display()))),
        }
    }

    /// Replace the file's contents.
    pub fn write(&self, plaintext: &[u8]) -> Result<()> {
        use std::io::Write;
        let io = |what: &str, e: std::io::Error| {
            Error::Store(format!("{what} {}: {e}", self.path.display()))
        };
        let blob = self.key.seal(&self.aad, plaintext)?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&dir).map_err(|e| io("create dir for", e))?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| io("open", e))?;
        f.write_all(&blob).map_err(|e| io("write", e))?;
        f.sync_all().map_err(|e| io("sync", e))?;
        drop(f);
        std::fs::rename(&tmp, &self.path).map_err(|e| io("rename onto", e))?;
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn key(b: u8, purpose: &str) -> AtRestKey {
        AtRestKey::derive(&[b; 32], purpose).unwrap()
    }

    #[test]
    fn round_trip_and_every_failure_is_the_same_error() {
        let k = key(1, "state");
        let blob = k.seal("rec/a", b"secret chain").unwrap();
        assert_eq!(&**k.open("rec/a", &blob).unwrap(), b"secret chain");
        // Fresh nonce each time.
        assert_ne!(blob, k.seal("rec/a", b"secret chain").unwrap());
        // Wrong record name, wrong key, wrong purpose, flipped bit, truncation.
        assert!(k.open("rec/b", &blob).is_err());
        assert!(key(2, "state").open("rec/a", &blob).is_err());
        assert!(key(1, "mls").open("rec/a", &blob).is_err());
        for i in [0, 1, 30, blob.len() - 1] {
            let mut t = blob.clone();
            t[i] ^= 1;
            assert!(k.open("rec/a", &t).is_err(), "byte {i}");
        }
        assert!(k.open("rec/a", &blob[..blob.len() - 1]).is_err());
        assert!(k.open("rec/a", &[]).is_err());
        assert!(!format!("{k:?}").contains('['));
    }

    #[tokio::test]
    async fn encrypted_state_stores_no_plaintext_and_binds_the_place() {
        let inner = Arc::new(MemoryStore::new());
        let s = EncryptedState::new(inner.clone(), key(1, "state"), "l1");
        s.state_put(StateSpace::Ratchets, "peer", b"chain-key-bytes")
            .await
            .unwrap();
        let raw = inner
            .state_get(StateSpace::Ratchets, "peer")
            .await
            .unwrap()
            .unwrap();
        assert!(!raw.windows(5).any(|w| w == b"chain"));
        assert_eq!(
            s.state_get(StateSpace::Ratchets, "peer").await.unwrap(),
            Some(b"chain-key-bytes".to_vec())
        );
        // The same blob under another key, space or link does not open.
        inner
            .state_put(StateSpace::Ratchets, "other", &raw)
            .await
            .unwrap();
        assert!(s.state_get(StateSpace::Ratchets, "other").await.is_err());
        inner
            .state_put(StateSpace::Links, "peer", &raw)
            .await
            .unwrap();
        assert!(s.state_get(StateSpace::Links, "peer").await.is_err());
        let other_link = EncryptedState::new(inner.clone(), key(1, "state"), "l2");
        assert!(
            other_link
                .state_get(StateSpace::Ratchets, "peer")
                .await
                .is_err()
        );
        // Wrong store key refuses; a missing record is simply absent.
        let wrong = EncryptedState::new(inner.clone(), key(9, "state"), "l1");
        assert!(wrong.state_get(StateSpace::Ratchets, "peer").await.is_err());
        assert_eq!(
            s.state_get(StateSpace::Ratchets, "none").await.unwrap(),
            None
        );
        // Cursors pass through unencrypted.
        s.set_cursor("halt", b"why").await.unwrap();
        assert_eq!(inner.cursor("halt").await.unwrap(), Some(b"why".to_vec()));
    }

    #[test]
    fn sealed_file_is_private_atomic_and_tamper_evident() {
        let dir = tempfile::tempdir().unwrap();
        let f = SealedFile::new(dir.path().join("d/x.enc"), key(1, "mls"), "mls/l1/state");
        assert_eq!(f.read().unwrap().map(|z| z.to_vec()), None);
        f.write(b"one").unwrap();
        f.write(b"two").unwrap();
        assert_eq!(&**f.read().unwrap().unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.path().join("d/x.enc")).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        assert!(
            !std::fs::read(dir.path().join("d/x.enc"))
                .unwrap()
                .windows(3)
                .any(|w| w == b"two")
        );
        let mut blob = std::fs::read(dir.path().join("d/x.enc")).unwrap();
        blob[30] ^= 1;
        std::fs::write(dir.path().join("d/x.enc"), blob).unwrap();
        assert!(f.read().is_err());
        // Another record name over the same bytes fails too.
        let g = SealedFile::new(dir.path().join("d/x.enc"), key(1, "mls"), "mls/l2/state");
        assert!(g.read().is_err());
    }
}
