//! The dyad channel key and the symmetric ratchet.
//!
//! Channel key = HKDF-SHA256(ikm = X25519 shared secret, no salt, info
//! `consensual/dyad-channel/v1`). Two chains start from the channel key under
//! `lo2hi` and `hi2lo`; …
//! `lo2hi`. Each step derives a message key (`msg`) and the next chain key
//! (`chain`). A frame is `counter u32 BE || nonce(12) || ChaCha20-Poly1305`.
//! A receiver keeps 512 skipped keys and heals jumps up to 65,536.
//!
//! Settled by Geb's answers 3 and 4 (read from their code, `ratchet.rs:57-75`):
//! the labels `lo2hi` / `hi2lo`, `msg` and `chain` are HKDF **info** strings
//! with the key as IKM and no salt; there is no AAD on a frame (the same
//! `seal` / `open` as the sealed box); the lo/hi side …
//! … || nonce(12) ||
//! ct+tag(16)`.

use super::kdf::hkdf32;
use super::{b64_decode, b64_encode};
use crate::{Error, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Skipped message keys a receiver retains.
pub const MAX_SKIPPED: usize = 512;
/// Largest counter jump a receiver heals.
pub const MAX_JUMP: u32 = 65_536;

type Key = Zeroizing<[u8; 32]>;

/// Which side of a dyad a DID is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Side {
    /// The DID string sorts lower.
    #[serde(rename = "lo")]
    Lo,
    /// The DID string sorts higher.
    #[serde(rename = "hi")]
    Hi,
}

impl Side {
    /// The other side.
    pub fn other(self) -> Side {
        match self {
            Side::Lo => Side::Hi,
            Side::Hi => Side::Lo,
        }
    }
    fn label(self) -> &'static [u8] {
        match self {
            Side::Lo => b"lo2hi",
            Side::Hi => b"hi2lo",
        }
    }
}

/// My side, by comparing DID strings. Equal DIDs are not a dyad.
pub fn my_side(my_did: &str, their_did: &str) -> Result<Side> {
    match my_did.cmp(their_did) {
        std::cmp::Ordering::Less => Ok(Side::Lo),
        std::cmp::Ordering::Greater => Ok(Side::Hi),
        std::cmp::Ordering::Equal => Err(Error::Crypto("a dyad needs two different DIDs".into())),
    }
}

/// The channel key from the X25519 shared secret.
pub fn channel_key(shared: &[u8; 32]) -> Result<Key> {
    Ok(Zeroizing::new(hkdf32(
        None,
        shared,
        b"consensual/dyad-channel/v1",
    )?))
}

fn step(chain: &Key) -> Result<(Key, Key)> {
    let mk = Zeroizing::new(hkdf32(None, &chain[..], b"msg")?);
    let next = Zeroizing::new(hkdf32(None, &chain[..], b"chain")?);
    Ok((mk, next))
}

fn aead(mk: &Key) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(&mk[..]).map_err(|e| Error::Crypto(e.to_string()))
}

fn encrypt_frame(mk: &Key, counter: u32, nonce: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>> {
    let n = Nonce::try_from(nonce.as_slice()).map_err(|_| Error::Crypto("nonce".into()))?;
    let ct = aead(mk)?
        .encrypt(&n, pt)
        .map_err(|_| Error::Crypto("seal failed".into()))?;
    let mut out = counter.to_be_bytes().to_vec();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_frame(mk: &Key, frame: &[u8]) -> Result<Vec<u8>> {
    let n = Nonce::try_from(&frame[4..16]).map_err(|_| Error::Wire("nonce".into()))?;
    aead(mk)?
        .decrypt(&n, &frame[16..])
        .map_err(|_| Error::Crypto("frame failed to open".into()))
}

/// A sending chain's persisted form. The chain key is secret: whoever stores
/// this protects it like a key.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SendState {
    /// Chain key, hex.
    pub chain: String,
    /// Next counter.
    pub counter: u32,
}

/// A receiving chain's persisted form (secret, see [`SendState`]).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RecvState {
    /// Chain key, hex.
    pub chain: String,
    /// Next expected counter.
    pub next: u32,
    /// Skipped message keys by counter, hex.
    pub skipped: Vec<(u32, String)>,
}

fn key_from_hex(s: &str) -> Result<Key> {
    let v = hex::decode(s).map_err(|e| Error::Store(format!("ratchet state: {e}")))?;
    let a: [u8; 32] = v
        .try_into()
        .map_err(|_| Error::Store("ratchet state key length".into()))?;
    Ok(Zeroizing::new(a))
}

/// The sending chain.
pub struct SendChain {
    chain: Key,
    counter: u32,
}

impl SendChain {
    /// Start the chain I send on (`sender_side` = my side).
    pub fn new(channel_key: &Key, sender_side: Side) -> Result<Self> {
        Ok(Self {
            chain: Zeroizing::new(hkdf32(None, &channel_key[..], sender_side.label())?),
            counter: 0,
        })
    }

    /// The persisted form.
    pub fn snapshot(&self) -> SendState {
        SendState {
            chain: hex::encode(&self.chain[..]),
            counter: self.counter,
        }
    }

    /// Rebuild from the persisted form.
    pub fn restore(s: &SendState) -> Result<Self> {
        Ok(Self {
            chain: key_from_hex(&s.chain)?,
            counter: s.counter,
        })
    }

    /// Seal with a caller-supplied nonce (tests).
    pub fn seal_with(&mut self, nonce: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>> {
        let (mk, next) = step(&self.chain)?;
        let frame = encrypt_frame(&mk, self.counter, nonce, pt)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("ratchet exhausted".into()))?;
        self.chain = next;
        Ok(frame)
    }

    /// Seal with a fresh nonce; returns the frame bytes.
    pub fn seal(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        rand::fill(&mut nonce);
        self.seal_with(&nonce, pt)
    }

    /// Seal and encode as the padded base64 the mailbox envelope carries.
    pub fn seal_b64(&mut self, pt: &[u8]) -> Result<String> {
        Ok(b64_encode(&self.seal(pt)?))
    }
}

/// The receiving chain, with skipped-key handling.
pub struct RecvChain {
    chain: Key,
    next: u32,
    skipped: BTreeMap<u32, Key>,
}

impl RecvChain {
    /// Start the chain the peer sends on (`sender_side` = the peer's side).
    pub fn new(channel_key: &Key, sender_side: Side) -> Result<Self> {
        Ok(Self {
            chain: Zeroizing::new(hkdf32(None, &channel_key[..], sender_side.label())?),
            next: 0,
            skipped: BTreeMap::new(),
        })
    }

    /// The persisted form.
    pub fn snapshot(&self) -> RecvState {
        RecvState {
            chain: hex::encode(&self.chain[..]),
            next: self.next,
            skipped: self
                .skipped
                .iter()
                .map(|(n, k)| (*n, hex::encode(&k[..])))
                .collect(),
        }
    }

    /// Rebuild from the persisted form.
    pub fn restore(s: &RecvState) -> Result<Self> {
        let mut skipped = BTreeMap::new();
        for (n, k) in &s.skipped {
            skipped.insert(*n, key_from_hex(k)?);
        }
        Ok(Self {
            chain: key_from_hex(&s.chain)?,
            next: s.next,
            skipped,
        })
    }

    /// Skipped keys currently held.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Open a frame. State changes only when the frame authenticates, so a
    /// forged frame cannot advance or drain the chain.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 4 + 12 + 16 {
            return Err(Error::Wire("frame too short".into()));
        }
        let counter = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if counter < self.next {
            let mk = self.skipped.get(&counter).ok_or_else(|| {
                Error::Crypto("frame replayed or older than the skipped window".into())
            })?;
            let pt = decrypt_frame(mk, frame)?;
            self.skipped.remove(&counter);
            return Ok(pt);
        }
        if counter - self.next > MAX_JUMP {
            return Err(Error::Crypto(
                "counter jump beyond the healing limit".into(),
            ));
        }
        let mut chain = self.chain.clone();
        let mut newly_skipped = Vec::new();
        for n in self.next..counter {
            let (mk, next) = step(&chain)?;
            newly_skipped.push((n, mk));
            chain = next;
        }
        let (mk, next) = step(&chain)?;
        let pt = decrypt_frame(&mk, frame)?;
        // Authenticated: commit.
        self.chain = next;
        self.next = counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("ratchet exhausted".into()))?;
        for (n, k) in newly_skipped {
            self.skipped.insert(n, k);
        }
        while self.skipped.len() > MAX_SKIPPED {
            self.skipped.pop_first();
        }
        Ok(pt)
    }

    /// Open a frame carried as padded base64.
    pub fn open_b64(&mut self, s: &str) -> Result<Vec<u8>> {
        self.open(&b64_decode(s)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SendChain, RecvChain) {
        let ck = channel_key(&[8u8; 32]).unwrap();
        (
            SendChain::new(&ck, Side::Lo).unwrap(),
            RecvChain::new(&ck, Side::Lo).unwrap(),
        )
    }

    #[test]
    fn snapshots_resume_the_chains_exactly() {
        let (mut s, mut r) = pair();
        let f: Vec<_> = (0..4).map(|i| s.seal(&[i]).unwrap()).collect();
        assert_eq!(r.open(&f[2]).unwrap(), [2]);
        let mut s2 = SendChain::restore(&s.snapshot()).unwrap();
        let mut r2 = RecvChain::restore(&r.snapshot()).unwrap();
        assert_eq!(r2.skipped_len(), 2);
        assert_eq!(r2.open(&f[0]).unwrap(), [0]);
        assert_eq!(r2.open(&f[3]).unwrap(), [3]);
        assert_eq!(r2.open(&s2.seal(b"x").unwrap()).unwrap(), b"x");
        assert!(
            SendChain::restore(&SendState {
                chain: "zz".into(),
                counter: 0
            })
            .is_err()
        );
    }

    #[test]
    fn sides_by_string_order() {
        assert_eq!(my_side("did:a", "did:b").unwrap(), Side::Lo);
        assert_eq!(my_side("did:b", "did:a").unwrap(), Side::Hi);
        assert!(my_side("did:a", "did:a").is_err());
    }

    #[test]
    fn in_order_round_trip_and_counter_layout() {
        let (mut s, mut r) = pair();
        let f0 = s.seal(b"zero").unwrap();
        let f1 = s.seal(b"one").unwrap();
        assert_eq!(&f0[..4], &0u32.to_be_bytes());
        assert_eq!(&f1[..4], &1u32.to_be_bytes());
        assert_eq!(f0.len(), 4 + 12 + 4 + 16);
        assert_eq!(r.open(&f0).unwrap(), b"zero");
        assert_eq!(r.open(&f1).unwrap(), b"one");
    }

    #[test]
    fn directions_are_independent() {
        let ck = channel_key(&[8u8; 32]).unwrap();
        let mut lo = SendChain::new(&ck, Side::Lo).unwrap();
        let mut hi_rx_wrong = RecvChain::new(&ck, Side::Hi).unwrap();
        assert!(hi_rx_wrong.open(&lo.seal(b"x").unwrap()).is_err());
    }

    #[test]
    fn out_of_order_uses_skipped_keys_once() {
        let (mut s, mut r) = pair();
        let frames: Vec<_> = (0..5)
            .map(|i| s.seal(format!("m{i}").as_bytes()).unwrap())
            .collect();
        assert_eq!(r.open(&frames[3]).unwrap(), b"m3");
        assert_eq!(r.skipped_len(), 3);
        assert_eq!(r.open(&frames[1]).unwrap(), b"m1");
        assert_eq!(r.open(&frames[0]).unwrap(), b"m0");
        assert!(r.open(&frames[1]).is_err(), "a skipped key opens once");
        assert_eq!(r.open(&frames[4]).unwrap(), b"m4");
        assert!(r.open(&frames[3]).is_err(), "replay of a consumed counter");
    }

    #[test]
    fn jump_limit_and_skipped_cap() {
        let (mut s, mut r) = pair();
        let mut frames = Vec::new();
        for i in 0..=(MAX_JUMP + 1) {
            if i == 0 || i == MAX_JUMP || i == MAX_JUMP + 1 {
                frames.push(s.seal(b"x").unwrap());
            } else {
                s.seal(b"x").unwrap();
            }
        }
        // Counter MAX_JUMP + 1 from next = 0 is beyond the limit.
        assert!(r.open(&frames[2]).is_err());
        // Exactly MAX_JUMP is healed, and only the newest 512 keys are kept.
        assert_eq!(r.open(&frames[1]).unwrap(), b"x");
        assert_eq!(r.skipped_len(), MAX_SKIPPED);
        // Counter 0 was evicted: the oldest skipped key is gone.
        assert!(r.open(&frames[0]).is_err());
    }

    #[test]
    fn forged_frame_does_not_advance_state() {
        let (mut s, mut r) = pair();
        let good = s.seal(b"real").unwrap();
        let mut forged = good.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(r.open(&forged).is_err());
        assert_eq!(r.skipped_len(), 0);
        assert_eq!(r.open(&good).unwrap(), b"real");
        // Far-future forged counter must not drain or advance either.
        let mut far = good.clone();
        far[..4].copy_from_slice(&5000u32.to_be_bytes());
        assert!(r.open(&far).is_err());
        assert_eq!(r.skipped_len(), 0);
    }

    #[test]
    fn matches_manual_derivation_from_the_guide_text() {
        let ck = channel_key(&[8u8; 32]).unwrap();
        assert_eq!(
            *ck,
            hkdf32(None, &[8u8; 32], b"consensual/dyad-channel/v1").unwrap()
        );
        let mut s = SendChain::new(&ck, Side::Hi).unwrap();
        let frame = s.seal_with(&[1u8; 12], b"p").unwrap();
        let chain0 = hkdf32(None, &ck[..], b"hi2lo").unwrap();
        let mk = hkdf32(None, &chain0, b"msg").unwrap();
        let c = ChaCha20Poly1305::new_from_slice(&mk).unwrap();
        let n = Nonce::try_from(&frame[4..16]).unwrap();
        assert_eq!(c.decrypt(&n, &frame[16..]).unwrap(), b"p");
    }

    #[test]
    fn base64_transport_and_short_frames() {
        let (mut s, mut r) = pair();
        let b = s.seal_b64(b"hello").unwrap();
        assert_eq!(r.open_b64(&b).unwrap(), b"hello");
        assert!(r.open(&[0u8; 10]).is_err());
    }
}
