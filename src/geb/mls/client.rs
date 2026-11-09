//! `MlsGroupClient`: the `GebGroup` over OpenMLS.
//!
//! No std lock is held across an await: state changes happen in short
//! synchronous sections, and dyad I/O happens between them.

use super::commit::{GroupJudge, credential_did, group_policy, parse_message, parse_welcome};
use super::identity::{MlsIdentity, SUITE, SignatureKeyVault};
use crate::foreign::JoinState;
use crate::geb::crypto::b64_decode;
use crate::geb::crypto::leaf;
use crate::geb::crypto::rendezvous::RelayKeys;
use crate::geb::policy::CommitCheckInputs;
use crate::geb::settle::{CommitHash, Outcome, SettleQueue, Verdict};
use crate::geb::traits::{GebDyad, GebGroup, GebSigner, OpenedMessage, SettleReport};
use crate::geb::wire::{Frame, GroupOp, RoomInfo, RoomRef};
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tls_codec::Serialize as _;

/// Exporter label for the room's Nostr secret.
pub const LABEL_NOSTR: &str = "geb/room/v2/nostr";
/// Exporter label for the room's AEAD key.
pub const LABEL_AEAD: &str = "geb/room/v2/aead";
/// Most KeyPackages in one `kp-stock`.
pub const MAX_STOCK: usize = 16;
/// Default size of a stock.
pub const DEFAULT_STOCK: usize = 8;

/// What the client needs to know about its room.
#[derive(Debug, Clone)]
pub struct MlsConfig {
    /// The room id (also the MLS group id, as UTF-8).
    pub room_id: String,
    /// Members we hold a dyad with and seat through (device DIDs).
    pub peers: Vec<String>,
    /// KeyPackages per stock, 1-16.
    pub stock_size: usize,
}

impl MlsConfig {
    /// A config for `room_id` seated through `peers`.
    pub fn new(room_id: &str, peers: Vec<String>) -> Self {
        Self {
            room_id: room_id.to_string(),
            peers,
            stock_size: DEFAULT_STOCK,
        }
    }
}

/// Where the MLS group state is kept between runs.
///
/// A snapshot holds OpenMLS's whole key store for this client (epoch secrets,
/// the ratchet tree, the leaf's private keys, unused KeyPackage private keys),
/// so an implementation MUST encrypt it before it touches disk
/// (`atrest::SealedFile` does). `save` is synchronous and is called inside the
/// client's short critical sections, never across an await.
pub trait GroupStateStore: Send + Sync {
    /// The last saved snapshot, if any.
    fn load(&self) -> Result<Option<Vec<u8>>>;
    /// Durably replace the snapshot.
    fn save(&self, snapshot: &[u8]) -> Result<()>;
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    v: u32,
    stocked: bool,
    stock_gen: u64,
    /// Set once a merged commit removed us; the link is over.
    removed: Option<String>,
    /// OpenMLS storage entries, base64.
    values: Vec<(String, String)>,
}

const SNAPSHOT_V: u32 = 1;

enum State {
    Unseated,
    Seated(Box<MlsGroup>),
    Removed(String),
}

struct Inner {
    provider: OpenMlsRustCrypto,
    ident: MlsIdentity,
    state: State,
    queue: SettleQueue,
    judged: HashMap<CommitHash, Verdict>,
    stock_gen: u64,
    stocked: bool,
}

/// The Geb-side MLS client.
pub struct MlsGroupClient {
    cfg: MlsConfig,
    device: Arc<dyn GebSigner>,
    dyad: Arc<dyn GebDyad>,
    inputs: Arc<dyn CommitCheckInputs>,
    inner: Mutex<Inner>,
    persist: Option<Arc<dyn GroupStateStore>>,
}

fn mls<E: std::fmt::Debug>(what: &str, e: E) -> Error {
    Error::Crypto(format!("mls {what}: {e:?}"))
}

impl MlsGroupClient {
    /// Build a client. `inputs` supplies the two local-knowledge facts; use
    /// [`crate::geb::policy::NoLocalKnowledge`] in production.
    pub fn new(
        cfg: MlsConfig,
        device: Arc<dyn GebSigner>,
        dyad: Arc<dyn GebDyad>,
        inputs: Arc<dyn CommitCheckInputs>,
        vault: &dyn SignatureKeyVault,
    ) -> Result<Self> {
        if cfg.stock_size == 0 || cfg.stock_size > MAX_STOCK {
            return Err(Error::Config("stock_size must be 1-16".into()));
        }
        if !crate::geb::wire::is_room_id(&cfg.room_id) {
            return Err(Error::Config(
                "room id must match [A-Za-z0-9_-]{8,64}".into(),
            ));
        }
        let provider = OpenMlsRustCrypto::default();
        let ident = MlsIdentity::new(device.did(), &provider, vault)?;
        Ok(Self {
            cfg,
            device,
            dyad,
            inputs,
            inner: Mutex::new(Inner {
                provider,
                ident,
                state: State::Unseated,
                queue: SettleQueue::new(),
                judged: HashMap::new(),
                stock_gen: 0,
                stocked: false,
            }),
            persist: None,
        })
    }

    /// Keep the group state in `store` and resume from it: when a snapshot
    /// exists the client comes back seated (or removed), at the epoch and
    /// ratchet position of the last save, with no re-seating.
    ///
    /// Saved after every step a restart must not lose or repeat: stocking or
    /// answering with a KeyPackage (before it is sent), joining, sealing a line
    /// (before it is returned to be posted, so a sender-ratchet generation is
    /// never reused), and a merged commit. NOT saved after `open`: a message
    /// opened and lost to a crash before the pump journalled it must open again
    /// on the restart, and the relay still has it. The settle queue (commits
    /// held but not merged) is memory-only; the pump's cursor barrier keeps the
    /// relay position behind them so they are read and held again.
    pub fn with_state_store(mut self, store: Arc<dyn GroupStateStore>) -> Result<Self> {
        if let Some(raw) = store.load()? {
            let raw = zeroize::Zeroizing::new(raw);
            let snap: Snapshot = serde_json::from_slice(&raw)
                .map_err(|_| Error::Crypto("MLS state snapshot is unreadable".into()))?;
            if snap.v != SNAPSHOT_V {
                return Err(Error::Crypto("MLS state snapshot version".into()));
            }
            let room = self.cfg.room_id.clone();
            let g = self
                .inner
                .get_mut()
                .map_err(|_| Error::Foreign("mls state poisoned".into()))?;
            {
                let mut values = g
                    .provider
                    .storage()
                    .values
                    .write()
                    .map_err(|_| Error::Foreign("mls storage poisoned".into()))?;
                for (k, v) in &snap.values {
                    let dec = |x: &String| {
                        STANDARD
                            .decode(x)
                            .map_err(|_| Error::Crypto("MLS state snapshot entry".into()))
                    };
                    values.insert(dec(k)?, dec(v)?);
                }
            }
            g.stocked = snap.stocked;
            g.stock_gen = snap.stock_gen;
            g.state = match snap.removed {
                Some(why) => State::Removed(why),
                None => match MlsGroup::load(
                    g.provider.storage(),
                    &GroupId::from_slice(room.as_bytes()),
                )
                .map_err(|e| mls("load group", e))?
                {
                    Some(group) => State::Seated(Box::new(group)),
                    None => State::Unseated,
                },
            };
        }
        self.persist = Some(store);
        Ok(self)
    }

    /// Write the snapshot (no-op without a store). Fails closed: a caller that
    /// cannot persist must not go on to post.
    fn persist_state(&self, g: &Inner) -> Result<()> {
        let Some(store) = &self.persist else {
            return Ok(());
        };
        let removed = match &g.state {
            State::Removed(w) => Some(w.clone()),
            _ => None,
        };
        let values = g
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Foreign("mls storage poisoned".into()))?
            .iter()
            .map(|(k, v)| (STANDARD.encode(k), STANDARD.encode(v)))
            .collect();
        let snap = Snapshot {
            v: SNAPSHOT_V,
            stocked: g.stocked,
            stock_gen: g.stock_gen,
            removed,
            values,
        };
        let raw = zeroize::Zeroizing::new(
            serde_json::to_vec(&snap).map_err(|_| Error::Crypto("encode MLS state".into()))?,
        );
        store.save(&raw)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Foreign("mls state poisoned".into()))
    }

    /// The current epoch, when seated.
    pub fn epoch(&self) -> Option<u64> {
        let g = self.lock().ok()?;
        match &g.state {
            State::Seated(grp) => Some(grp.epoch().as_u64()),
            _ => None,
        }
    }

    /// Device DIDs of the current members, when seated.
    pub fn members(&self) -> Vec<String> {
        let Ok(g) = self.lock() else {
            return Vec::new();
        };
        match &g.state {
            State::Seated(grp) => grp
                .members()
                .filter_map(|m| credential_did(&m.credential))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// How each current member's leaf binding stands (`Missing` is shown
    /// "unverified" by Geb).
    pub fn member_bindings(&self) -> Vec<(String, super::commit::BindingStatus)> {
        let Ok(g) = self.lock() else {
            return Vec::new();
        };
        match &g.state {
            State::Seated(grp) => grp
                .members()
                .filter_map(|m| {
                    let node = grp.public_group().leaf(m.index)?;
                    Some((
                        credential_did(&m.credential)?,
                        super::commit::binding_status(node),
                    ))
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The hashes of commits recorded failed (cannot be processed).
    pub fn failed_commits(&self) -> Vec<[u8; 32]> {
        self.lock()
            .map(|g| g.queue.failed().iter().copied().collect())
            .unwrap_or_default()
    }

    /// Number of commits held for the settle window.
    pub fn held_commits(&self) -> usize {
        self.lock().map(|g| g.queue.len()).unwrap_or(0)
    }

    fn make_kp(&self, g: &Inner) -> Result<Vec<u8>> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let kp = g
            .ident
            .key_package(&g.provider, self.device.as_ref(), now_secs)?;
        kp.tls_serialize_detached()
            .map_err(|e| mls("serialise key package", e))
    }

    /// Validate a Welcome frame the way answer 8 says and join from it.
    fn join_from_welcome(&self, g: &mut Inner, room: &RoomInfo, w: &str) -> Result<()> {
        room.validate()?;
        if room.id != self.cfg.room_id {
            return Err(Error::Wire("welcome is for another room".into()));
        }
        // The header's policy is informational: re-clean it, and read the real
        // one from the group context below.
        let header_policy = room.policy();
        let bytes = b64_decode(w)?;
        let welcome =
            parse_welcome(&bytes).map_err(|why| Error::Wire(format!("welcome: {why}")))?;
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 1000))
            .build();
        let staged = StagedWelcome::new_from_welcome(&g.provider, &cfg, welcome, None)
            .map_err(|e| Error::Wire(format!("welcome: {e:?}")))?;
        let ctx = staged.group_context();
        if ctx.group_id().as_slice() != self.cfg.room_id.as_bytes() {
            return Err(Error::Wire("welcome group id is not the room id".into()));
        }
        if ctx.ciphersuite() != SUITE {
            return Err(Error::Wire("welcome ciphersuite is not 0x0001".into()));
        }
        if ctx.extensions().unknown(leaf::EXT_POLICY).is_none() {
            return Err(Error::Wire("welcome group has no 0xF001 policy".into()));
        }
        let ctx_policy = super::commit::policy_of(ctx.extensions());
        if ctx_policy != header_policy {
            tracing::warn!(
                "welcome header policy differs from the group context; using the context"
            );
        }
        let mut group = staged
            .into_group(&g.provider)
            .map_err(|e| Error::Wire(format!("join: {e:?}")))?;
        // treeRefusal (0.5.15). OpenMLS exposes the tree only once the group
        // exists, so a refusal deletes what `into_group` just stored: nothing
        // of a refused Welcome is kept or persisted.
        if let Err(why) = super::commit::tree_refusal(&group) {
            if let Err(e) = group.delete(g.provider.storage()) {
                tracing::error!(error = ?e, "could not delete the group of a refused welcome");
            }
            return Err(Error::Wire(format!("treeRefusal: {why}")));
        }
        g.state = State::Seated(Box::new(group));
        Ok(())
    }

    fn keys_of(g: &Inner, room: &str) -> Result<RelayKeys> {
        let State::Seated(grp) = &g.state else {
            return match &g.state {
                State::Removed(w) => Err(Error::Refused(w.clone())),
                _ => Err(Error::Foreign("not seated in the room yet".into())),
            };
        };
        let x = |label: &str| -> Result<[u8; 32]> {
            let v = grp
                .export_secret(g.provider.crypto(), label, room.as_bytes(), 32)
                .map_err(|e| mls("export secret", e))?;
            <[u8; 32]>::try_from(v.as_slice())
                .map_err(|_| Error::Crypto("exporter returned the wrong length".into()))
        };
        Ok(RelayKeys::from_parts(x(LABEL_NOSTR)?, x(LABEL_AEAD)?))
    }

    async fn send_rs(&self) {
        let frame = Frame::Group(GroupOp::Rs {
            room: Some(RoomRef {
                id: self.cfg.room_id.clone(),
                name: None,
            }),
        });
        for peer in &self.cfg.peers {
            if let Err(e) = self.dyad.send(peer, &frame).await {
                tracing::warn!(error = %e, "could not send the room status request");
            }
        }
    }
}

#[async_trait]
impl GebGroup for MlsGroupClient {
    async fn ensure_seated(&self) -> Result<JoinState> {
        // 1. Stock KeyPackages once (a stock counts as consent to be added).
        let stock = {
            let mut g = self.lock()?;
            match &g.state {
                State::Removed(w) => return Err(Error::Refused(w.clone())),
                State::Seated(_) => return Ok(JoinState::Seated),
                State::Unseated => {}
            }
            if g.stocked {
                None
            } else {
                let mut kps = Vec::new();
                for _ in 0..self.cfg.stock_size {
                    kps.push(STANDARD.encode(self.make_kp(&g)?));
                }
                g.stock_gen += 1;
                // The private halves exist now; keep them before the public
                // halves leave, or a Welcome after a restart cannot be used.
                self.persist_state(&g)?;
                Some(Frame::Group(GroupOp::KpStock {
                    generation: g.stock_gen,
                    kps,
                }))
            }
        };
        if let Some(frame) = stock {
            let mut sent = false;
            for peer in &self.cfg.peers {
                match self.dyad.send(peer, &frame).await {
                    Ok(()) => sent = true,
                    Err(e) => tracing::warn!(error = %e, "could not send kp-stock"),
                }
            }
            if sent {
                let mut g = self.lock()?;
                g.stocked = true;
                self.persist_state(&g)?;
            }
        }
        // 2. Answer kp-req, accept a welcome.
        for peer in &self.cfg.peers {
            let frames = match self.dyad.recv(peer).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, "dyad read failed while seating");
                    continue;
                }
            };
            for frame in frames {
                match frame {
                    Frame::Group(GroupOp::KpReq { room }) if room.id == self.cfg.room_id => {
                        let kp = {
                            let g = self.lock()?;
                            let kp = STANDARD.encode(self.make_kp(&g)?);
                            self.persist_state(&g)?;
                            kp
                        };
                        let reply = Frame::Group(GroupOp::Kp {
                            room: RoomRef {
                                id: self.cfg.room_id.clone(),
                                name: None,
                            },
                            kp,
                        });
                        if let Err(e) = self.dyad.send(peer, &reply).await {
                            tracing::warn!(error = %e, "could not answer kp-req");
                        }
                    }
                    Frame::Group(GroupOp::Welcome { room, w, .. }) => {
                        let mut g = self.lock()?;
                        match self.join_from_welcome(&mut g, &room, &w) {
                            Ok(()) => {
                                self.persist_state(&g)?;
                                return Ok(JoinState::Seated);
                            }
                            Err(e) => tracing::warn!(error = %e, "ignoring a welcome"),
                        }
                    }
                    other => {
                        tracing::debug!(?other, "ignoring a dyad frame while seating");
                    }
                }
            }
        }
        Ok(JoinState::Pending)
    }

    async fn leave(&self) -> Result<()> {
        // Geb's leave is a signed leave `{t:"lv", at, ls}` (leave code),
        // which we do not have; silently dropping out would leave a ghost leaf.
        Err(Error::Unsupported(
            "leaving a Geb room needs a signed leave (leave code), which is not available",
        ))
    }

    fn relay_keys(&self) -> Result<RelayKeys> {
        let g = self.lock()?;
        Self::keys_of(&g, &self.cfg.room_id)
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut g = self.lock()?;
        let Inner {
            provider,
            ident,
            state,
            ..
        } = &mut *g;
        let bytes = match state {
            State::Seated(grp) => {
                let out = grp
                    .create_message(provider, &ident.signer, plaintext)
                    .map_err(|e| mls("create message", e))?;
                out.tls_serialize_detached()
                    .map_err(|e| mls("serialise message", e))?
            }
            State::Removed(w) => return Err(Error::Refused(w.clone())),
            State::Unseated => return Err(Error::Foreign("not seated in the room yet".into())),
        };
        // The sender-ratchet generation just used is saved before the caller
        // can post: a restart never seals a second line at the same generation.
        self.persist_state(&g)?;
        Ok(bytes)
    }

    fn open(&self, message: &[u8]) -> Result<OpenedMessage> {
        let mut g = self.lock()?;
        let Inner {
            provider, state, ..
        } = &mut *g;
        let State::Seated(grp) = state else {
            return Err(Error::Foreign("not seated in the room yet".into()));
        };
        let msg = parse_message(message).map_err(Error::Wire)?;
        let processed = grp
            .process_message(provider, msg)
            .map_err(|e| Error::Wire(format!("open: {e:?}")))?;
        let sender_did = credential_did(processed.credential())
            .ok_or_else(|| Error::Wire("sender identity is not UTF-8".into()))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => Ok(OpenedMessage {
                sender_did,
                plaintext: m.into_bytes(),
            }),
            // A commit, proposal or anything else in an `ml` envelope is not a
            // line; dropped (a staged commit is discarded, never merged).
            _ => Err(Error::Wire(
                "an ml envelope that is not an application message".into(),
            )),
        }
    }

    async fn hold_commit(
        &self,
        parent_epoch: u64,
        commit: &[u8],
        event_secs: u64,
        now_ms: u64,
    ) -> Result<()> {
        let mut g = self.lock()?;
        let epoch = match &g.state {
            State::Seated(grp) => grp.epoch().as_u64(),
            State::Removed(w) => return Err(Error::Refused(w.clone())),
            State::Unseated => return Err(Error::Foreign("not seated in the room yet".into())),
        };
        // Receivers ignore a commit made from an epoch below theirs
        // .
        if parent_epoch < epoch {
            return Ok(());
        }
        g.queue
            .hold(parent_epoch, commit.to_vec(), event_secs, now_ms)
            .map_err(|why| {
                tracing::error!(security_alert = true, %why, "too many commits held; stopping");
                Error::Unsupported("too many Geb commits held for the settle window; stopping")
            })?;
        Ok(())
    }

    async fn settle(&self, now_ms: u64) -> Result<SettleReport> {
        let mut ask_status = false;
        let report = {
            let mut g = self.lock()?;
            let Inner {
                provider,
                state,
                queue,
                judged,
                ..
            } = &mut *g;
            let State::Seated(grp) = state else {
                return match state {
                    State::Removed(w) => Err(Error::Refused(w.clone())),
                    _ => Ok(SettleReport::default()),
                };
            };
            let epoch = grp.epoch().as_u64();
            queue.prune_below(epoch);
            let window = group_policy(grp).settle_window_ms;
            let outcome = {
                let mut judge = GroupJudge::new(grp, provider, self.inputs.as_ref(), judged);
                queue.settle(epoch, window, now_ms, &mut judge)
            };
            let mut epoch_changed = false;
            match outcome {
                Outcome::Idle | Outcome::Holding { .. } | Outcome::AllRefused { .. } => {}
                Outcome::Merged { refused, .. } => {
                    epoch_changed = true;
                    // Candidates of the old epoch can never be tested again.
                    judged.clear();
                    if !refused.is_empty() {
                        tracing::warn!(
                            refused = refused.len(),
                            "dropped commits that failed validCommit"
                        );
                    }
                }
                Outcome::Failed {
                    reason,
                    ask_status: ask,
                    ..
                } => {
                    tracing::warn!(%reason, "a commit could not be processed; recorded failed");
                    ask_status = ask;
                }
                Outcome::MergeFailed { reason, .. } => {
                    tracing::warn!(%reason, "a valid commit could not be merged; recorded failed");
                    ask_status = true;
                }
                Outcome::Blocked { reason, hash } => {
                    // Merging could fork the epoch, and so could skipping.
                    // Not logged here: the pump persists the halt and raises
                    // the one alert (logging per tick is what this avoids).
                    return Err(Error::UndecidableCommit(format!(
                        "epoch {epoch}, commit {}: {reason}; needs persona cards or signed \
                         leaves to evaluate, stopping instead of forking the epoch",
                        hex::encode(hash)
                    )));
                }
            }
            if epoch_changed && !grp.is_active() {
                let why = "removed from the room by a merged commit".to_string();
                *state = State::Removed(why.clone());
                self.persist_state(&g)?;
                return Err(Error::Refused(why));
            }
            let cursor_barrier_secs = queue.barrier_secs();
            if epoch_changed {
                self.persist_state(&g)?;
            }
            SettleReport {
                epoch_changed,
                cursor_barrier_secs,
            }
        };
        if ask_status {
            self.send_rs().await;
        }
        Ok(report)
    }
}
