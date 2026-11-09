//! `MlsGroupClient`: the `GebGroup` over OpenMLS.
//!
//! No std lock is held across an await: state changes happen in short
//! synchronous sections, and dyad I/O happens between them.

mod heal;
pub use heal::Split;

use super::commit::{GroupJudge, credential_did, group_policy, parse_message, parse_welcome};
use super::identity::{MlsIdentity, SUITE, SignatureKeyVault};
use crate::foreign::JoinState;
use crate::geb::crypto::b64_decode;
use crate::geb::crypto::leaf;
use crate::geb::crypto::rendezvous::RelayKeys;
use crate::geb::leave::LeaveBook;
use crate::geb::policy::CommitCheckInputs;
use crate::geb::settle::{CommitHash, Held, Outcome, SettleQueue, Verdict};
use crate::geb::traits::{GebDyad, GebGroup, GebSigner, OpenedMessage, SettleReport};
use crate::geb::wire::{Frame, GroupOp, RoomInfo, RoomRef};
use crate::store::BridgeStore;
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use tls_codec::Serialize as _;

/// Exporter label for the room's Nostr secret.
pub const LABEL_NOSTR: &str = "geb/room/v2/nostr";
/// Exporter label for the room's AEAD key.
pub const LABEL_AEAD: &str = "geb/room/v2/aead";
/// Most KeyPackages in one `kp-stock` (receivers keep at most 16).
pub const MAX_STOCK: usize = 16;
/// Default size of a stock: Geb sends six per stock (round 3 section 5,
/// `STOCK_N`).
pub const DEFAULT_STOCK: usize = 6;
/// A contact is re-stocked when our last stock to them is older than this
/// (Geb's `STOCK_STALE_MS`, 7 days).
pub const STOCK_STALE_MS: u64 = 7 * 24 * 3600 * 1000;
/// Single packages (a `kp` answer, a seat-ask package) keep their private
/// keys this long.
pub const SINGLE_KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
/// A stock minted this recently is always kept, whatever its generation.
pub const RECENT_KEEP_MS: u64 = 3600 * 1000;
/// Stock generations kept per contact (the newest two): a holder may still
/// spend the previous one.
pub const STOCK_GENS_KEPT: usize = 2;
/// A `kp-low` is answered at most this often per contact. OUR CHOICE (not
/// Geb's): a stock is six key pairs and a persisted snapshot, so a peer that
/// repeats `kp-low` cannot make us mint and persist without bound.
pub const KP_LOW_MIN_INTERVAL_MS: u64 = 60_000;
/// While seated the dyads are read for `kp-low` / `seat-check` at most this
/// often (each read is a relay fetch per peer).
pub const SERVICE_EVERY_MS: u64 = 5_000;

/// Clock in milliseconds.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What the client needs to know about its room.
#[derive(Debug, Clone)]
pub struct MlsConfig {
    /// The room id (also the MLS group id, as UTF-8).
    pub room_id: String,
    /// Members we hold a dyad with and seat through (device DIDs).
    pub peers: Vec<String>,
    /// KeyPackages per stock, 1-16.
    pub stock_size: usize,
    /// Tests only: join a direct room anyway, to exercise the commit rules
    /// that apply inside one. Never set in production code.
    #[cfg(test)]
    pub(crate) allow_direct_for_test: bool,
}

impl MlsConfig {
    /// A config for `room_id` seated through `peers`.
    pub fn new(room_id: &str, peers: Vec<String>) -> Self {
        Self {
            room_id: room_id.to_string(),
            peers,
            stock_size: DEFAULT_STOCK,
            #[cfg(test)]
            allow_direct_for_test: false,
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

/// KeyPackages minted together for one contact. `refs` are the KeyPackage hash
/// references under which OpenMLS keeps the private halves, so pruning can
/// delete them.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Batch {
    /// The stock generation, `0` for a single package.
    generation: u64,
    at_ms: u64,
    refs: Vec<Vec<u8>>,
}

/// What we know of the packages we gave one contact (a device DID).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Contact {
    /// The last stock generation of ours SENT to them (`gen` counts the stocks
    /// we have sent to this one contact, never packages, never global).
    last_gen: u64,
    last_sent_ms: u64,
    /// When we last answered a `kp-low` from them.
    last_low_ms: u64,
    stocks: Vec<Batch>,
    singles: Vec<Batch>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    v: u32,
    /// Legacy (one global stock flag); read only to migrate.
    #[serde(default)]
    stocked: bool,
    #[serde(default)]
    stock_gen: u64,
    #[serde(default)]
    contacts: std::collections::BTreeMap<String, Contact>,
    /// The newest verified signed leave per signer (round 4 Q7).
    #[serde(default)]
    leaves: LeaveBook,
    /// Settled-commit chain, own lines, split record (rs and re-seat).
    #[serde(default)]
    heal: heal::Persist,
    /// Set once a merged commit removed us; the link is over.
    removed: Option<String>,
    /// OpenMLS storage entries, base64.
    values: Vec<(String, String)>,
}

const SNAPSHOT_V: u32 = 1;

enum State {
    Unseated,
    Seated(Box<MlsGroup>),
    /// A merged commit removed our leaf AND added our DID back (a re-seat): the
    /// old, inactive group is kept only until the Welcome replaces it.
    Reseating(Box<MlsGroup>),
    Removed(String),
}

struct Inner {
    provider: OpenMlsRustCrypto,
    ident: MlsIdentity,
    state: State,
    queue: SettleQueue,
    judged: HashMap<CommitHash, Verdict>,
    contacts: std::collections::BTreeMap<String, Contact>,
    /// Signed leaves held; they feed `validCommit` rule 2.
    leaves: LeaveBook,
    last_service_ms: u64,
    heal: heal::HealState,
}

/// The configured inputs plus the signed leaves this client holds: a leave
/// covers its signer's exact DID (there is no persona store to widen it).
struct WithLeaves<'a> {
    base: &'a dyn CommitCheckInputs,
    leaves: &'a LeaveBook,
}

impl CommitCheckInputs for WithLeaves<'_> {
    fn can_evaluate(&self) -> bool {
        self.base.can_evaluate()
    }
    fn same_person(&self, a: &str, b: &str) -> bool {
        self.base.same_person(a, b)
    }
    fn has_signed_leave(&self, device_did: &str) -> bool {
        self.leaves.covers(device_did) || self.base.has_signed_leave(device_did)
    }
}

/// The Geb-side MLS client.
pub struct MlsGroupClient {
    cfg: MlsConfig,
    device: Arc<dyn GebSigner>,
    dyad: Arc<dyn GebDyad>,
    inputs: Arc<dyn CommitCheckInputs>,
    inner: Mutex<Inner>,
    persist: Option<Arc<dyn GroupStateStore>>,
    /// Where the non-secret fork marker goes (`geb::forkmark`), and the link
    /// it names. `None`: no marker is kept (tests, an embedding without
    /// `status`).
    fork_sink: Option<(Arc<dyn BridgeStore>, String)>,
    clock: Clock,
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
                contacts: Default::default(),
                leaves: LeaveBook::default(),
                last_service_ms: 0,
                heal: heal::HealState::default(),
            }),
            persist: None,
            fork_sink: None,
            clock: Arc::new(system_now_ms),
        })
    }

    /// Keep the non-secret fork marker (`geb::forkmark`) in `store` for
    /// `link_id`, written when a split is recorded and updated when a re-seat
    /// Welcome is accepted, so `status` can show it without the MLS keys.
    pub fn with_fork_marker(mut self, store: Arc<dyn BridgeStore>, link_id: &str) -> Self {
        self.fork_sink = Some((store, link_id.to_string()));
        self
    }

    /// Use `clock` (milliseconds) for KeyPackage lifetimes, stock ages and
    /// pruning. Tests only; the default is the system clock.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
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
            g.contacts = snap.contacts;
            g.leaves = snap.leaves;
            g.heal.p = snap.heal;
            if g.contacts.is_empty() && snap.stocked && snap.stock_gen > 0 {
                // A snapshot from before stock state was per contact: one
                // stock of this generation went to every peer. Their keys are
                // not tracked, so they are never pruned.
                let now = (self.clock)();
                for peer in &self.cfg.peers {
                    g.contacts.insert(
                        peer.clone(),
                        Contact {
                            last_gen: snap.stock_gen,
                            last_sent_ms: now,
                            ..Contact::default()
                        },
                    );
                }
            }
            g.state = match snap.removed {
                Some(why) => State::Removed(why),
                None => match MlsGroup::load(
                    g.provider.storage(),
                    &GroupId::from_slice(room.as_bytes()),
                )
                .map_err(|e| mls("load group", e))?
                {
                    Some(group) if !group.is_active() && g.heal.p.reseating => {
                        State::Reseating(Box::new(group))
                    }
                    Some(group) => State::Seated(Box::new(group)),
                    // A snapshot that once held the group and no longer does:
                    // our local copy is missing (answers round 2 section 8).
                    None => {
                        g.heal.lost_copy = g.heal.p.was_seated;
                        State::Unseated
                    }
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
            stocked: false,
            stock_gen: 0,
            contacts: g.contacts.clone(),
            leaves: g.leaves.clone(),
            heal: g.heal.p.clone(),
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

    /// Whether OpenMLS still holds the private halves of the KeyPackage `b64`.
    #[cfg(test)]
    pub(crate) fn holds_key_package(&self, b64: &str) -> bool {
        let g = self.lock().unwrap();
        let raw = STANDARD.decode(b64).unwrap();
        let r =
            openmls::ciphersuite::hash_ref::make_key_package_ref(&raw, SUITE, g.provider.crypto())
                .unwrap();
        StorageProvider::<CURRENT_VERSION>::key_package::<KeyPackageRef, KeyPackageBundle>(
            g.provider.storage(),
            &r,
        )
        .unwrap()
        .is_some()
    }

    /// Mint one outgoing KeyPackage (always bound, always with a lifetime valid
    /// now): its standard base64 and the hash reference its private halves are
    /// stored under.
    fn make_kp(&self, g: &Inner, now_ms: u64) -> Result<(String, Vec<u8>)> {
        let kp = g
            .ident
            .key_package(&g.provider, self.device.as_ref(), now_ms / 1000)?;
        let hash_ref = kp
            .hash_ref(g.provider.crypto())
            .map_err(|e| mls("key package reference", e))?;
        let raw = kp
            .tls_serialize_detached()
            .map_err(|e| mls("serialise key package", e))?;
        let b64 = STANDARD.encode(raw);
        if b64.len() > crate::geb::wire::MAX_STOCK_KP_CHARS {
            return Err(Error::Crypto("a KeyPackage over 65,536 characters".into()));
        }
        // TLS-encoded, so pruning can rebuild the reference.
        let hash_ref = hash_ref
            .tls_serialize_detached()
            .map_err(|e| mls("serialise key package reference", e))?;
        Ok((b64, hash_ref))
    }

    /// Mint a stock of `gen` for `peer` and remember its keys. The send is the
    /// caller's; `last_gen` moves only when it succeeds.
    fn mint_stock(&self, g: &mut Inner, peer: &str, generation: u64, now_ms: u64) -> Result<Frame> {
        let mut kps = Vec::new();
        let mut refs = Vec::new();
        for _ in 0..self.cfg.stock_size {
            let (b64, r) = self.make_kp(g, now_ms)?;
            kps.push(b64);
            refs.push(r);
        }
        g.contacts
            .entry(peer.to_string())
            .or_default()
            .stocks
            .push(Batch {
                generation,
                at_ms: now_ms,
                refs,
            });
        Ok(Frame::Group(GroupOp::KpStock { generation, kps }))
    }

    /// Delete the private halves of everything past its keep rule: per
    /// contact the newest TWO stock generations (the newest batch of each) plus
    /// any batch … for 7 days.
    /// Returns whether anything was removed.
    fn prune(&self, g: &mut Inner, now_ms: u64) -> bool {
        let Inner {
            provider, contacts, ..
        } = g;
        let mut changed = false;
        for c in contacts.values_mut() {
            let mut gens: Vec<u64> = c.stocks.iter().map(|b| b.generation).collect();
            gens.sort_unstable_by(|a, b| b.cmp(a));
            gens.dedup();
            gens.truncate(STOCK_GENS_KEPT);
            let newest_at: std::collections::HashMap<u64, u64> =
                gens.iter().fold(Default::default(), |mut m, g_| {
                    let at = c
                        .stocks
                        .iter()
                        .filter(|b| b.generation == *g_)
                        .map(|b| b.at_ms)
                        .max()
                        .unwrap_or(0);
                    m.insert(*g_, at);
                    m
                });
            let recent = |b: &Batch| b.at_ms.saturating_add(RECENT_KEEP_MS) > now_ms;
            let keep_stock = |b: &Batch| {
                recent(b)
                    || newest_at
                        .get(&b.generation)
                        .is_some_and(|at| *at == b.at_ms)
            };
            let keep_single = |b: &Batch| b.at_ms.saturating_add(SINGLE_KEEP_MS) > now_ms;
            for (list, keep) in [
                (&mut c.stocks, &keep_stock as &dyn Fn(&Batch) -> bool),
                (&mut c.singles, &keep_single as &dyn Fn(&Batch) -> bool),
            ] {
                list.retain(|b| {
                    if keep(b) {
                        return true;
                    }
                    for r in &b.refs {
                        let Ok(r) =
                            <KeyPackageRef as tls_codec::Deserialize>::tls_deserialize_exact(r)
                        else {
                            tracing::warn!("a stored KeyPackage reference is unreadable; skipped");
                            continue;
                        };
                        if let Err(e) = StorageProvider::<CURRENT_VERSION>::delete_key_package(
                            provider.storage(),
                            &r,
                        ) {
                            tracing::warn!(error = ?e, "could not delete a pruned KeyPackage");
                        }
                    }
                    changed = true;
                    false
                });
            }
        }
        changed
    }

    /// Stock `peer` again at `generation`: mint (persisted before the frame
    /// leaves, so a Welcome after a restart can be opened), send, and only then
    /// record the generation as sent.
    async fn send_stock(&self, peer: &str, generation: u64) -> bool {
        let now = (self.clock)();
        let frame = {
            let Ok(mut g) = self.lock() else { return false };
            let frame = match self.mint_stock(&mut g, peer, generation, now) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, "could not mint a stock");
                    return false;
                }
            };
            if let Err(e) = self.persist_state(&g) {
                tracing::warn!(error = %e, "could not persist a new stock; not sending it");
                return false;
            }
            frame
        };
        match self.dyad.send(peer, &frame).await {
            Ok(()) => {
                if let Ok(mut g) = self.lock() {
                    let c = g.contacts.entry(peer.to_string()).or_default();
                    c.last_gen = c.last_gen.max(generation);
                    c.last_sent_ms = now;
                    self.prune(&mut g, now);
                    if let Err(e) = self.persist_state(&g) {
                        tracing::warn!(error = %e, "could not persist the sent stock");
                    }
                }
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not send kp-stock");
                false
            }
        }
    }

    /// Answer `kp-low {gen, n}` with a new stock at
    /// `max(our last gen sent to them, their gen) + 1`.
    async fn answer_kp_low(&self, peer: &str, their_gen: u64) {
        let now = (self.clock)();
        let generation = {
            let Ok(mut g) = self.lock() else { return };
            let c = g.contacts.entry(peer.to_string()).or_default();
            if c.last_low_ms != 0 && now < c.last_low_ms.saturating_add(KP_LOW_MIN_INTERVAL_MS) {
                tracing::debug!("kp-low repeated too soon; not re-stocking again");
                return;
            }
            c.last_low_ms = now;
            c.last_gen.max(their_gen) + 1
        };
        self.send_stock(peer, generation).await;
    }

    /// Answer `kp-req` with one KeyPackage, whose keys are kept for 7 days.
    async fn answer_kp_req(&self, peer: &str) {
        let now = (self.clock)();
        let kp = {
            let Ok(mut g) = self.lock() else { return };
            let (kp, r) = match self.make_kp(&g, now) {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!(error = %e, "could not mint a KeyPackage");
                    return;
                }
            };
            g.contacts
                .entry(peer.to_string())
                .or_default()
                .singles
                .push(Batch {
                    generation: 0,
                    at_ms: now,
                    refs: vec![r],
                });
            self.prune(&mut g, now);
            if let Err(e) = self.persist_state(&g) {
                tracing::warn!(error = %e, "could not persist a KeyPackage; not sending it");
                return;
            }
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

    /// Answer `seat-check {room, e}` (round 3 section 3, round 4 Q8): with a
    /// body-bearing `rs` when we hold the room. When we do not, Geb expects a
    /// `seat-ask` with a fresh bound package: we send that (backed off).
    async fn answer_seat_check(&self, peer: &str, room: &RoomRef) {
        if room.id != self.cfg.room_id {
            return;
        }
        let seated = self
            .lock()
            .map(|g| matches!(g.state, State::Seated(_)))
            .unwrap_or(false);
        if seated {
            self.send_rs_to(peer, true).await;
        } else {
            self.seat_ask_with_kp(peer).await;
        }
    }

    /// While seated: read each peer's dyad for `kp-low` and `seat-check`
    /// (at most every [`SERVICE_EVERY_MS`]); everything else is dropped.
    async fn service_dyads(&self, now_ms: u64) {
        {
            let Ok(mut g) = self.lock() else { return };
            if g.last_service_ms != 0 && now_ms < g.last_service_ms.saturating_add(SERVICE_EVERY_MS)
            {
                return;
            }
            g.last_service_ms = now_ms;
        }
        for peer in &self.cfg.peers {
            let frames = match self.dyad.recv(peer).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::debug!(error = %e, "dyad read failed while seated");
                    // The dyad is down: it announces itself again when it is up.
                    if let Ok(mut g) = self.lock() {
                        g.heal.announced.remove(peer);
                    }
                    continue;
                }
            };
            // The dyad answered: a link that comes up is told our status.
            let first = self
                .lock()
                .map(|mut g| g.heal.announced.insert(peer.clone()))
                .unwrap_or(false);
            if first {
                self.send_rs_to(peer, false).await;
            }
            for frame in frames {
                match frame {
                    Frame::Group(GroupOp::KpLow { generation, .. }) => {
                        self.answer_kp_low(peer, generation).await;
                    }
                    Frame::Group(GroupOp::SeatCheck { room, .. }) => {
                        self.answer_seat_check(peer, &room).await;
                    }
                    Frame::Group(GroupOp::Leave { room, by, at, sig }) => {
                        self.take_leave_frame(&room, &by, at, &sig);
                    }
                    Frame::Group(GroupOp::Rs { room, s, .. }) => {
                        self.on_rs(peer, room, s).await;
                    }
                    Frame::Group(GroupOp::Rc { room, e, c }) => {
                        self.on_rc(peer, &room, e, &c);
                    }
                    // A re-seat Welcome while we hold the room (round 2 section
                    // 8), replacing the group; or a stray one, ignored.
                    Frame::Group(GroupOp::Welcome { room, w, .. }) => {
                        self.on_reseat_welcome(peer, &room, &w).await;
                    }
                    // Nothing for us to do: we are never the healer.
                    Frame::Group(GroupOp::SeatAsk { .. }) => {
                        tracing::debug!("seat-ask from a peer: acked, no action (never healer)");
                    }
                    other => tracing::debug!(?other, "ignoring a dyad frame while seated"),
                }
            }
        }
        let now = (self.clock)();
        if let Ok(mut g) = self.lock()
            && self.prune(&mut g, now)
            && let Err(e) = self.persist_state(&g)
        {
            tracing::warn!(error = %e, "could not persist after pruning");
        }
    }

    /// Validate a Welcome frame the way answer 8 says and join from it.
    ///
    /// `replace` is `Some(welcomer)` for a Welcome that arrives while we hold the
    /// room (a re-seat, answers round 2 section 8): the old group is deleted
    /// from storage first, after every refusal check, and only when the new
    /// group is consistent with a re-seat of OUR DID; any failure restores the
    /// old state untouched. `None` is the ordinary first join.
    fn join_from_welcome(
        &self,
        g: &mut Inner,
        room: &RoomInfo,
        w: &str,
        replace: Option<&str>,
    ) -> Result<()> {
        let Some(welcomer) = replace else {
            return self.join_inner(g, room, w, None);
        };
        let known = match &g.state {
            State::Seated(old) | State::Reseating(old) => old
                .members()
                .filter_map(|m| credential_did(&m.credential))
                .any(|d| d == welcomer),
            _ => false,
        };
        if !known {
            return Err(Error::Wire(
                "re-seat welcome from a device that is not a member of our group".into(),
            ));
        }
        // OpenMLS refuses a Welcome for a group id it already holds
        // (`GroupAlreadyExists`), so the old group is deleted from storage
        // FIRST (answers round 2 section 8: `mls.rs:498-506`). A copy of the
        // whole store is taken before, and put back if anything after it
        // refuses: a refused or inconsistent Welcome leaves the old state as it
        // was.
        let backup = g
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Foreign("mls storage poisoned".into()))?
            .clone();
        if let State::Seated(old) | State::Reseating(old) = &mut g.state
            && let Err(e) = old.delete(g.provider.storage())
        {
            tracing::error!(error = ?e, "could not delete the old group before a re-seat");
        }
        let r = self.join_inner(g, room, w, replace);
        if r.is_err()
            && let Ok(mut v) = g.provider.storage().values.write()
        {
            *v = backup;
        }
        r
    }

    fn join_inner(
        &self,
        g: &mut Inner,
        room: &RoomInfo,
        w: &str,
        replace: Option<&str>,
    ) -> Result<()> {
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
        let staged =
            StagedWelcome::new_from_welcome(&g.provider, &cfg, welcome, None).map_err(|e| {
                if matches!(e, WelcomeError::NoMatchingKeyPackage) {
                    Error::Wire(format!("{}: {e:?}", heal::NO_KP))
                } else {
                    Error::Wire(format!("welcome: {e:?}"))
                }
            })?;
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
        // Round 3 section 9: a direct room (policy `direct:[lo, hi]`) seats only
        // devices of its two persons, judged from persona cards we do not
        // hold; a third-party bridge is not one of them. Refuse before the
        // group is stored: nothing of this Welcome is kept. `Refused` stops
        // the link (persisted halt); the leaf the adder made for us stays in
        // that room, since leaving is not built.
        #[cfg(test)]
        let allow_direct = self.cfg.allow_direct_for_test;
        #[cfg(not(test))]
        let allow_direct = false;
        if !allow_direct && super::commit::declares_direct(ctx.extensions()) {
            return Err(Error::Refused(
                "this is a direct room (policy `direct`); a bridge cannot sit in a direct room \
                 (Geb round 3 section 9). Remove this link: `link remove`"
                    .into(),
            ));
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
        if replace.is_some()
            && let Err(why) = self.reseat_consistent(g, &group)
        {
            return Err(Error::Wire(format!("not a re-seat of us: {why}")));
        }
        let now = (self.clock)();
        let old_epoch = match &g.state {
            State::Seated(o) | State::Reseating(o) => Some(o.epoch().as_u64()),
            _ => None,
        };
        g.state = State::Seated(Box::new(group));
        self.after_join(g, old_epoch, now);
        Ok(())
    }

    fn keys_of(g: &Inner, room: &str) -> Result<RelayKeys> {
        let State::Seated(grp) = &g.state else {
            return match &g.state {
                State::Removed(w) => Err(Error::Refused(w.clone())),
                State::Reseating(_) => Err(Error::Foreign(
                    "re-seat in progress: waiting for the Welcome".into(),
                )),
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

    /// A dyad `leave` frame: verified like a room line's `ls`, and kept when it
    /// is the signer's newest. A frame for another room is dropped.
    fn take_leave_frame(&self, room: &RoomRef, by: &str, at: u64, sig: &str) {
        if room.id != self.cfg.room_id {
            return;
        }
        if let Err(e) = self.take_signed_leave(by, at, sig) {
            tracing::warn!(error = %e, "could not keep a signed leave");
        }
    }

    /// Verify and keep a signed leave by the device DID `by` for this room
    /// (the same payload whether it came as a room line or a dyad frame).
    /// Returns whether it was new. Persisted before return, so a restart keeps
    /// it.
    pub fn take_signed_leave(&self, by: &str, at: u64, sig: &str) -> Result<bool> {
        let mut g = self.lock()?;
        if !g.leaves.take(&self.cfg.room_id, by, at, sig) {
            return Ok(false);
        }
        self.persist_state(&g)?;
        Ok(true)
    }

    /// The device DIDs a held signed leave covers.
    pub fn signed_leaves(&self) -> Vec<String> {
        self.lock()
            .map(|g| g.leaves.signers().map(str::to_string).collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl GebGroup for MlsGroupClient {
    async fn ensure_seated(&self) -> Result<JoinState> {
        // 1. Stock KeyPackages (a stock counts as consent to be added): a
        // first stock for every contact never stocked, and a new generation
        // for one whose last stock is older than 7 days (this idle wait for a
        // Welcome is the natural place; a seated member is not re-stocked,
        // see CLAUDE.md "Open items").
        {
            match &self.lock()?.state {
                State::Removed(w) => return Err(Error::Refused(w.clone())),
                State::Seated(_) => return Ok(JoinState::Seated),
                State::Unseated | State::Reseating(_) => {}
            }
            let now = (self.clock)();
            let due: Vec<(String, u64)> = {
                let g = self.lock()?;
                self.cfg
                    .peers
                    .iter()
                    .filter_map(|p| {
                        let c = g.contacts.get(p);
                        let last = c.map_or(0, |c| c.last_gen);
                        let at = c.map_or(0, |c| c.last_sent_ms);
                        (last == 0 || now >= at.saturating_add(STOCK_STALE_MS))
                            .then(|| (p.clone(), last + 1))
                    })
                    .collect()
            };
            for (peer, generation) in due {
                self.send_stock(&peer, generation).await;
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
                        self.answer_kp_req(peer).await;
                    }
                    Frame::Group(GroupOp::KpLow { generation, .. }) => {
                        self.answer_kp_low(peer, generation).await;
                    }
                    Frame::Group(GroupOp::SeatCheck { room, .. }) => {
                        self.answer_seat_check(peer, &room).await;
                    }
                    Frame::Group(GroupOp::Leave { room, by, at, sig }) => {
                        self.take_leave_frame(&room, &by, at, &sig);
                    }
                    Frame::Group(GroupOp::Welcome { room, w, .. }) => {
                        let outcome = {
                            let mut g = self.lock()?;
                            let replace = matches!(g.state, State::Reseating(_)).then_some(&**peer);
                            let r = self.join_from_welcome(&mut g, &room, &w, replace);
                            if r.is_ok() {
                                self.persist_state(&g)?;
                            }
                            r
                        };
                        match outcome {
                            Ok(()) => {
                                self.sync_fork_marker().await;
                                self.send_rs_all(true, &[]).await;
                                return Ok(JoinState::Seated);
                            }
                            // A refusal of the room itself stops the link.
                            Err(e @ Error::Refused(_)) => return Err(e),
                            // Added from a package whose private keys we no
                            // longer hold: ask for a re-seat from a fresh,
                            // BOUND one (round 3 section 5, round 2 section 8).
                            Err(Error::Wire(w)) if w.starts_with(heal::NO_KP) => {
                                tracing::warn!("a welcome for a KeyPackage we no longer hold");
                                self.seat_ask_with_kp(peer).await;
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
        self.heal_unseated_tick().await;
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

    fn note_signed_leave(&self, by: &str, at: u64, sig: &str) -> Result<bool> {
        self.take_signed_leave(by, at, sig)
    }

    fn awaiting_reseat(&self) -> bool {
        self.lock()
            .map(|g| matches!(g.state, State::Reseating(_)))
            .unwrap_or(false)
    }

    fn pending_reposts(&self) -> Vec<crate::geb::wire::LineBody> {
        self.lock()
            .map(|g| g.heal.p.pending_reposts.clone())
            .unwrap_or_default()
    }

    fn reposts_done(&self, n: usize) -> Result<()> {
        let mut g = self.lock()?;
        let n = n.min(g.heal.p.pending_reposts.len());
        g.heal.p.pending_reposts.drain(..n);
        self.persist_state(&g)
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
            State::Unseated | State::Reseating(_) => {
                return Err(Error::Foreign("not seated in the room yet".into()));
            }
        };
        let epoch = match &g.state {
            State::Seated(grp) => grp.epoch().as_u64(),
            _ => 0,
        };
        heal::record_own_line(&mut g.heal.p, epoch, plaintext);
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
            State::Unseated | State::Reseating(_) => {
                return Err(Error::Foreign("not seated in the room yet".into()));
            }
        };
        // Receivers ignore a commit made from an epoch below theirs
        // .
        if parent_epoch < epoch {
            return Ok(());
        }
        // The `e` and the bytes are unauthenticated until judged, so a limit
        // on what is held drops the commit (logged) and never fails the poll.
        match g
            .queue
            .hold(epoch, parent_epoch, commit.to_vec(), event_secs, now_ms)
        {
            Held::New | Held::Duplicate => {}
            Held::Dropped(why) => {
                tracing::warn!(
                    security_alert = true,
                    parent_epoch,
                    epoch,
                    why,
                    "dropped an mc envelope instead of holding it"
                );
            }
        }
        Ok(())
    }

    async fn settle(&self, now_ms: u64) -> Result<SettleReport> {
        let live = self
            .lock()
            .map(|g| matches!(g.state, State::Seated(_) | State::Reseating(_)))
            .unwrap_or(false);
        if live {
            self.service_dyads(now_ms).await;
            self.heal_tick(now_ms).await;
        }
        let mut ask_status = false;
        let mut sent_to_all = false;
        let mut added: Vec<String> = Vec::new();
        let report = {
            let mut g = self.lock()?;
            let Inner {
                provider,
                state,
                queue,
                judged,
                leaves,
                heal,
                ..
            } = &mut *g;
            if matches!(state, State::Reseating(_)) {
                return Ok(SettleReport {
                    reread: std::mem::take(&mut heal.reread),
                    ..SettleReport::default()
                });
            }
            let State::Seated(grp) = state else {
                return match state {
                    State::Removed(w) => Err(Error::Refused(w.clone())),
                    _ => Ok(SettleReport::default()),
                };
            };
            let epoch = grp.epoch().as_u64();
            queue.prune_below(epoch);
            let window = group_policy(grp).settle_window_ms;
            let members_before: Vec<String> = grp
                .members()
                .filter_map(|m| credential_did(&m.credential))
                .collect();
            let (outcome, merged_bytes, reseats_us) = {
                let inputs = WithLeaves {
                    base: self.inputs.as_ref(),
                    leaves,
                };
                let mut judge = GroupJudge::new(grp, provider, &inputs, judged);
                let o = queue.settle(epoch, window, now_ms, &mut judge);
                (o, judge.merged_bytes.take(), judge.reseats_us)
            };
            let mut epoch_changed = false;
            let mut winner: Option<[u8; 32]> = None;
            match outcome {
                Outcome::Idle | Outcome::Holding { .. } | Outcome::AllRefused { .. } => {}
                Outcome::Merged {
                    refused,
                    failed,
                    winner: w,
                    ..
                } => {
                    epoch_changed = true;
                    winner = Some(w);
                    // Candidates of the old epoch can never be tested again.
                    judged.clear();
                    if !refused.is_empty() || !failed.is_empty() {
                        // A failed candidate changes nothing once one merged:
                        // no `rs`, no cursor barrier.
                        tracing::warn!(
                            refused = refused.len(),
                            failed = failed.len(),
                            "skipped commits below the merged one"
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
                        "epoch {epoch}, commit {}: {reason}. This bridge holds no persona \
                         store (persona cards are not built) and no signed leave covers the \
                         removed leaves. Geb itself would refuse such a commit and carry on, \
                         but a Geb device holding a persona card that links the two DIDs would \
                         merge it and we cannot know; stopping is a deliberate bridge-side \
                         choice, the honest alternative to silently forking the epoch",
                        hex::encode(hash)
                    )));
                }
            }
            if epoch_changed && !grp.is_active() {
                if reseats_us {
                    // One Commit removed our leaf and added us back: the
                    // Welcome that follows replaces this group.
                    let State::Seated(old) = std::mem::replace(state, State::Unseated) else {
                        unreachable!("the state was Seated a moment ago")
                    };
                    *state = State::Reseating(old);
                    heal.p.reseating = true;
                    heal.reseating_since_ms = now_ms;
                    tracing::warn!(
                        "a merged commit re-seats us; waiting for its Welcome over the dyad"
                    );
                    self.persist_state(&g)?;
                    return Ok(SettleReport::default());
                }
                let why = "removed from the room by a merged commit".to_string();
                *state = State::Removed(why.clone());
                self.persist_state(&g)?;
                return Err(Error::Refused(why));
            }
            if epoch_changed {
                // The settled Commit joins the chain our `rs` reports, and its
                // bytes are kept to answer a lagging peer with `rc`.
                let made = grp.epoch().as_u64();
                let auth = heal::auth_hex(grp);
                heal.note_settled(epoch, made, winner, &auth, merged_bytes);
                added = grp
                    .members()
                    .filter_map(|m| credential_did(&m.credential))
                    .filter(|d| !members_before.contains(d))
                    .collect();
                sent_to_all = true;
            }
            let cursor_barrier_secs = queue.barrier_secs(grp.epoch().as_u64());
            let reread = std::mem::take(&mut heal.reread);
            if epoch_changed {
                self.persist_state(&g)?;
            }
            SettleReport {
                epoch_changed,
                cursor_barrier_secs,
                reread,
            }
        };
        if sent_to_all {
            // After each settle that applied a Commit: to every member we hold
            // a dyad with except one newly added (round 2 section 5).
            self.send_rs_all(false, &added).await;
        }
        if ask_status {
            self.send_rs_all(true, &[]).await;
        }
        Ok(report)
    }
}
