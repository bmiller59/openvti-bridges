//! Tests of the Geb-side MLS client against an in-process second OpenMLS
//! client playing a Geb member (`sim.rs`). Self-consistency only: this is not
//! evidence of byte-compatibility with real Geb.

use super::client::KP_LOW_MIN_INTERVAL_MS;
use super::sim::{Bus, MemDyad, Sim, mc, ml, post, welcome_frame};
use super::*;
use crate::Error;
use crate::foreign::{ForeignRoom, JoinState, Polled};
use crate::geb::codec::GuideCodec;
use crate::geb::crypto::{did_peer, leaf, pair};
use crate::geb::fake::FakeRelay;
use crate::geb::policy::{CommitCheckInputs, NoLocalKnowledge};
use crate::geb::room::{GebRoom, KIND_MAILBOX};
use crate::geb::settle::commit_hash;
use crate::geb::traits::{GebCodec, GebGroup, GebRelay, GebSigner};
use crate::geb::wire::{Envelope, Frame, GroupOp, signing_doc};
use crate::model::{AuthorCheck, BridgeEvent, EventKind, Origin};
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const ROOM: &str = "geb-room-0001";

fn policy(root: &str, extra: &str) -> String {
    format!(
        r#"{{"v":2,"committer":"any-staged","settleWindowMs":3000,"root":"{root}","admins":[]{extra}}}"#
    )
}

/// Test fake: everything is known, nobody is the same person as anybody else,
/// nobody has left. (NOT Geb's persona cards.)
struct AllKnown;
impl CommitCheckInputs for AllKnown {
    fn can_evaluate(&self) -> bool {
        true
    }
    fn same_person(&self, a: &str, b: &str) -> bool {
        a == b
    }
    fn has_signed_leave(&self, _: &str) -> bool {
        false
    }
}

struct World {
    relay: Arc<FakeRelay>,
    relay_dyn: Arc<dyn GebRelay>,
    bus: Arc<Bus>,
    clock: Arc<AtomicU64>,
    a: Sim,
    b: Sim,
    policy: String,
    dyad: Arc<MemDyad>,
    client: Arc<MlsGroupClient>,
    room: GebRoom,
    our_did: String,
    our_dev: SigningKey,
}

impl World {
    /// A (root, founder) and B in a room; our client built but not yet seated.
    fn build(inputs: Arc<dyn CommitCheckInputs>, extra_policy: &str) -> World {
        Self::build_with(inputs, extra_policy, false)
    }

    fn build_with(
        inputs: Arc<dyn CommitCheckInputs>,
        extra_policy: &str,
        allow_direct: bool,
    ) -> World {
        let relay = Arc::new(FakeRelay::new());
        let relay_dyn: Arc<dyn GebRelay> = relay.clone();
        let bus = Bus::new();
        let clock = Arc::new(AtomicU64::new(10_000));
        let mut a = Sim::new(1);
        let mut b = Sim::new(2);
        let pol = policy(&a.did, extra_policy);
        a.create_room(ROOM, &pol);
        let (c, w) = a.stage_add(b.key_package());
        let _ = c;
        a.merge_pending();
        b.join(&w);

        let our_dev = SigningKey::from_bytes(&[50u8; 32]);
        let our_did =
            did_peer::encode(&our_dev.verifying_key().to_bytes(), &[50u8; 32], None).unwrap();
        let device: Arc<dyn GebSigner> = Arc::new(crate::geb::crypto::sign::LocalSigner::new(
            our_did.clone(),
            our_dev.clone(),
        ));
        let dyad = MemDyad::new(&our_did, &bus);
        let mut mc = MlsConfig::new(ROOM, vec![a.did.clone()]);
        mc.allow_direct_for_test = allow_direct;
        let client = Arc::new(
            MlsGroupClient::new(
                mc,
                device.clone(),
                dyad.clone(),
                inputs,
                &MemoryVault::default(),
            )
            .unwrap(),
        );
        let c2 = clock.clone();
        let room = GebRoom::new(
            ROOM.into(),
            relay.clone(),
            client.clone(),
            device,
            Arc::new(GuideCodec),
            Arc::new(move || c2.load(Ordering::SeqCst)),
        );
        World {
            relay,
            relay_dyn,
            bus,
            clock,
            a,
            b,
            policy: pol,
            dyad,
            client,
            room,
            our_did,
            our_dev,
        }
    }

    /// A adds us from our stock; B follows; the welcome goes over the dyad.
    async fn seat(&mut self) {
        assert_eq!(self.room.join().await.unwrap(), JoinState::Pending);
        let stock = self.bus.take(&self.our_did, &self.a.did);
        let Some(Frame::Group(GroupOp::KpStock { kps, .. })) = stock.first().cloned() else {
            panic!("no kp-stock")
        };
        let kp = parse_kp(&kps[0]);
        let (commit, welcome) = self.a.stage_add(kp);
        self.a.merge_pending();
        self.b.apply(&commit).unwrap();
        self.bus.put(
            &self.a.did,
            &self.our_did,
            welcome_frame(ROOM, &self.a.did, &self.policy, &welcome),
        );
        assert_eq!(self.room.join().await.unwrap(), JoinState::Seated);
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }
    fn at(&self, ms: u64) {
        self.clock.store(ms, Ordering::SeqCst);
    }
    fn secs(&self) -> u64 {
        self.now() / 1000
    }

    async fn post_ml(&self, who: &Sim, bytes: &[u8]) {
        post(&self.relay_dyn, &who.keys(ROOM), &ml(bytes), self.secs()).await;
    }

    /// Post a commit under the keys of `who`'s current (parent) epoch.
    async fn post_mc(&self, who: &Sim, bytes: &[u8]) {
        post(
            &self.relay_dyn,
            &who.keys(ROOM),
            &mc(who.epoch(), bytes),
            self.secs(),
        )
        .await;
    }

    async fn poll(&self) -> crate::Result<Vec<Polled>> {
        self.room.poll(None).await
    }

    fn our_keys_match(&self, s: &Sim) -> bool {
        let k = self.client.relay_keys().unwrap();
        let o = s.keys(ROOM);
        *k.nostr_secret == *o.nostr_secret && *k.aead_key == *o.aead_key
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What every KeyPackage we hand out must be (round 3 section 5 and 3): a
/// lifetime valid now (`not_before` at least an hour back, `not_after` 84 days
/// ahead), and the `0xF002` leaf binding, which verifies against OUR device
/// key for OUR DID and the leaf's own signature key.
fn assert_outgoing_kp(kp: &KeyPackage, dev: &SigningKey, did: &str) {
    let now = now_secs();
    let life = kp.life_time();
    assert!(
        life.not_before() <= now.saturating_sub(3600) + 2 && life.not_before() + 3600 + 5 >= now,
        "not_before is now minus one hour"
    );
    assert!(
        life.not_after().abs_diff(now + 84 * 24 * 3600) <= 5,
        "not_after is now plus 84 days"
    );
    life.validate().expect("the lifetime is valid now");
    assert_eq!(binding_status(kp.leaf_node()), BindingStatus::Verified);
    let ext = kp.leaf_node().extensions().unknown(0xF002).unwrap();
    let key = <[u8; 32]>::try_from(kp.leaf_node().signature_key().as_slice()).unwrap();
    leaf::verify(
        &dev.verifying_key(),
        did,
        &key,
        std::str::from_utf8(&ext.0).unwrap(),
    )
    .unwrap();
}

#[test]
fn there_is_exactly_one_way_to_mint_a_keypackage_and_it_is_bound() {
    // `MlsIdentity::key_package` is the only builder call outside the test
    // simulator: an unbound outgoing package cannot be made by accident.
    let mut n = 0;
    for (name, src) in [
        ("client.rs", include_str!("client.rs")),
        ("commit.rs", include_str!("commit.rs")),
        ("identity.rs", include_str!("identity.rs")),
        ("mod.rs", include_str!("mod.rs")),
    ] {
        let live = src.split("#[cfg(test)]").next().unwrap();
        let c = live.matches("KeyPackage::builder()").count();
        if name == "identity.rs" {
            assert_eq!(c, 1);
        } else {
            assert_eq!(c, 0, "{name} mints a KeyPackage on its own");
        }
        n += c;
    }
    assert_eq!(n, 1);
    // The one builder sets the binding and the lifetime.
    let id = include_str!("identity.rs");
    assert!(id.contains(".leaf_node_extensions(leaf_exts)"));
    assert!(id.contains(".key_package_lifetime(key_package_lifetime(now_secs))"));
}

fn parse_kp(b64: &str) -> KeyPackage {
    super::parse_key_package(b64)
        .unwrap()
        .validate(
            openmls_traits::OpenMlsProvider::crypto(
                &openmls_rust_crypto::OpenMlsRustCrypto::default(),
            ),
            ProtocolVersion::Mls10,
        )
        .unwrap()
}

fn text_event(text: &str, at: u64) -> BridgeEvent {
    BridgeEvent {
        origin: Origin::Vtc,
        origin_id: "k|1".into(),
        link: "l1".into(),
        author: "did:alice".into(),
        at,
        title: None,
        text: text.into(),
        kind: EventKind::Post,
        reply_to: None,
        record_key: None,
        provenance: None,
    }
}

/// Stage commits on `a` and `b` (both from the same epoch) until the hash
/// order is as wanted; returns (a_commit, b_commit). `mk` stages one.
fn staged_pair(
    a: &mut Sim,
    b: &mut Sim,
    a_lower: bool,
    mk_a: &dyn Fn(&mut Sim) -> Vec<u8>,
    mk_b: &dyn Fn(&mut Sim) -> Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    for _ in 0..200 {
        let ca = mk_a(a);
        let cb = mk_b(b);
        if (commit_hash(&ca) < commit_hash(&cb)) == a_lower {
            return (ca, cb);
        }
        a.drop_pending();
        b.drop_pending();
    }
    panic!("could not get the wanted hash order");
}

// ---- parsing strictness (P0-a, answers round 2 sections 1 and 2) ---------------

/// The body of an MLSMessage (version 2 bytes + wire format 2 bytes dropped).
fn bare(m: &[u8]) -> Vec<u8> {
    m[4..].to_vec()
}

#[test]
fn only_a_private_message_mlsmessage_is_read_from_mc_and_ml() {
    use super::commit::parse_message;
    let mut a = Sim::new(1);
    let mut b = Sim::new(2);
    a.create_room(ROOM, &policy(&a.did, ""));
    let (commit, welcome) = a.stage_add(b.key_package());
    // Good: the MLSMessage(PrivateMessage) OpenMLS made.
    assert!(parse_message(&commit).is_ok());
    // Bare PrivateMessage (the MLSMessage header stripped): refused.
    let why = parse_message(&bare(&commit)).err().unwrap();
    assert!(why.contains("not an MLSMessage"), "{why}");
    // Trailing bytes: refused.
    let mut padded = commit.clone();
    padded.push(0);
    assert!(parse_message(&padded).is_err());
    // An MLSMessage that is a Welcome, a KeyPackage: refused.
    let why = parse_message(&welcome).err().unwrap();
    assert!(why.contains("not a PrivateMessage"), "{why}");
    let kp = MlsMessageOut::from(b.key_package());
    assert!(parse_message(&tls_codec::Serialize::tls_serialize_detached(&kp).unwrap()).is_err());
    assert!(parse_message(&[]).is_err());
    a.merge_pending();
    b.join(&welcome);
    // A PublicMessage commit (a group on the mixed policy): refused by name,
    // both wrapped and bare.
    let mut p = Sim::new(3);
    p.plaintext_handshake = true;
    p.create_room("geb-room-plain", &policy(&p.did, ""));
    let public = p.stage_self_update();
    let why = parse_message(&public).err().unwrap();
    assert!(why.contains("PublicMessage"), "{why}");
    assert!(parse_message(&bare(&public)).is_err());
}

#[tokio::test]
async fn a_public_or_bare_commit_is_recorded_failed_and_a_bare_line_is_not_opened() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    // A bare line is not opened.
    let line = w.a.seal_line(ROOM, 5, "hi", true);
    assert!(w.client.open(&bare(&line)).is_err());
    assert!(w.client.open(&line).is_ok());
    // A bare commit is held, then recorded failed (it cannot be processed).
    let c = w.a.stage_self_update();
    w.a.drop_pending();
    w.post_mc(&w.a, &bare(&c)).await;
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert_eq!(w.client.failed_commits().len(), 1);
    assert_eq!(w.client.epoch(), Some(w.a.epoch()), "nothing merged");
}

#[test]
fn a_welcome_must_be_an_mlsmessage_whose_body_is_a_welcome() {
    use super::commit::parse_welcome;
    let mut a = Sim::new(1);
    let b = Sim::new(2);
    a.create_room(ROOM, &policy(&a.did, ""));
    let (commit, welcome) = a.stage_add(b.key_package());
    assert!(parse_welcome(&welcome).is_ok());
    for bad in [bare(&welcome), commit.clone(), vec![], b"garbage".to_vec()] {
        assert_eq!(parse_welcome(&bad).err().as_deref(), Some("not a Welcome"));
    }
    let mut padded = welcome.clone();
    padded.push(1);
    assert_eq!(
        parse_welcome(&padded).err().as_deref(),
        Some("not a Welcome")
    );
}

#[tokio::test]
async fn a_bare_welcome_does_not_seat_us() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) =
        w.bus.take(&w.our_did, &w.a.did).first().cloned()
    else {
        panic!()
    };
    let (_c, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &bare(&welcome)),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Seated);
}

#[test]
fn a_keypackage_is_a_bare_tls_keypackage_in_standard_base64() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use tls_codec::Serialize as _;
    let s = Sim::new(4);
    let kp = s.key_package();
    let raw = kp.tls_serialize_detached().unwrap();
    let ok = STANDARD.encode(&raw);
    assert!(super::parse_key_package(&ok).is_ok());
    // MLSMessage-wrapped: refused.
    let wrapped = MlsMessageOut::from(kp.clone())
        .tls_serialize_detached()
        .unwrap();
    assert!(super::parse_key_package(&STANDARD.encode(wrapped)).is_err());
    // Trailing bytes: refused.
    let mut t = raw.clone();
    t.push(0);
    assert!(super::parse_key_package(&STANDARD.encode(t)).is_err());
    // base64url alphabet: dropped. Force a url-only character in.
    let url = format!("{ok}-_");
    assert!(
        super::parse_key_package(&url)
            .err()
            .unwrap()
            .contains("standard base64")
    );
    let url_form = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
    if url_form.contains(['-', '_']) {
        assert!(super::parse_key_package(&url_form).is_err());
    }
    assert!(super::parse_key_package("").is_err());
    // Our own stock and `kp` frames pass the same gate.
    let f = Frame::Group(GroupOp::Kp {
        room: crate::geb::wire::RoomRef {
            id: ROOM.into(),
            name: None,
        },
        kp: ok.clone(),
    });
    assert!(f.validate().is_ok());
}

// ---- identity and KeyPackages ---------------------------------------------

#[test]
fn the_mls_key_is_random_and_not_the_device_key() {
    let dev = SigningKey::from_bytes(&[3u8; 32]);
    let did = did_peer::encode(&dev.verifying_key().to_bytes(), &[3u8; 32], None).unwrap();
    let signer = crate::geb::crypto::sign::LocalSigner::new(did.clone(), dev.clone());
    let p = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let vault = MemoryVault::default();
    let id = MlsIdentity::new(&did, &p, &vault).unwrap();
    assert_ne!(id.leaf_key().unwrap(), dev.verifying_key().to_bytes());
    // A vault that already holds the key gives the same identity back.
    let p2 = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let again = MlsIdentity::new(&did, &p2, &vault).unwrap();
    assert_eq!(id.leaf_key().unwrap(), again.leaf_key().unwrap());
    let other = MlsIdentity::new(&did, &p2, &MemoryVault::default()).unwrap();
    assert_ne!(id.leaf_key().unwrap(), other.leaf_key().unwrap());
    // The binding is the device DID's signature over the MLS key, 86 chars.
    let b = id.binding(&signer).unwrap();
    assert_eq!(b.len(), leaf::BINDING_LEN);
    leaf::verify(&dev.verifying_key(), &did, &id.leaf_key().unwrap(), &b).unwrap();
    // The KeyPackage carries it and declares exactly the two extensions.
    let kp = id.key_package(&p, &signer, now_secs()).unwrap();
    assert_eq!(kp.ciphersuite(), SUITE);
    assert_outgoing_kp(&kp, &dev, &did);
    assert_eq!(binding_status(kp.leaf_node()), BindingStatus::Verified);
    let exts = kp.leaf_node().capabilities().extensions();
    assert!(exts.contains(&ExtensionType::Unknown(0xF001)));
    assert!(exts.contains(&ExtensionType::Unknown(0xF002)));
    assert_eq!(
        kp.leaf_node().credential().serialized_content(),
        did.as_bytes()
    );
}

#[test]
fn config_is_checked() {
    let dev = SigningKey::from_bytes(&[3u8; 32]);
    let did = did_peer::encode(&dev.verifying_key().to_bytes(), &[3u8; 32], None).unwrap();
    let bus = Bus::new();
    let mk = |cfg: MlsConfig| {
        MlsGroupClient::new(
            cfg,
            Arc::new(crate::geb::crypto::sign::LocalSigner::new(
                did.clone(),
                dev.clone(),
            )),
            MemDyad::new(&did, &bus),
            Arc::new(NoLocalKnowledge),
            &MemoryVault::default(),
        )
    };
    let mut c = MlsConfig::new(ROOM, vec![]);
    c.stock_size = 17;
    assert!(mk(c).is_err());
    assert!(mk(MlsConfig::new("short", vec![])).is_err());
    assert!(mk(MlsConfig::new(ROOM, vec![])).is_ok());
}

// ---- seating ----------------------------------------------------------------

#[tokio::test]
async fn we_are_seated_over_the_dyad_from_a_stock() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    // Only a kp-stock went out, once; never a cap.
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let sent = w.dyad.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "one stock, not re-sent while pending");
    let Frame::Group(GroupOp::KpStock { generation, kps }) = &sent[0].1 else {
        panic!("expected kp-stock")
    };
    assert_eq!((*generation, kps.len()), (1, DEFAULT_STOCK));
    assert!(kps.len() <= MAX_STOCK);
    let mut seen = std::collections::HashSet::new();
    for k in kps {
        let kp = parse_kp(k);
        assert_eq!(kp.ciphersuite(), SUITE);
        let caps = kp.leaf_node().capabilities().extensions();
        assert!(caps.contains(&ExtensionType::Unknown(0xF001)));
        assert!(caps.contains(&ExtensionType::Unknown(0xF002)));
        assert_eq!(binding_status(kp.leaf_node()), BindingStatus::Verified);
        assert_outgoing_kp(&kp, &w.our_dev, &w.our_did);
        // The binding verifies against OUR device DID's key.
        let ext = kp.leaf_node().extensions().unknown(0xF002).unwrap();
        let key = <[u8; 32]>::try_from(kp.leaf_node().signature_key().as_slice()).unwrap();
        let init = kp.hpke_init_key().as_slice().to_vec();
        leaf::verify(
            &w.our_dev.verifying_key(),
            &w.our_did,
            &key,
            std::str::from_utf8(&ext.0).unwrap(),
        )
        .unwrap();
        assert!(seen.insert(init), "every KeyPackage has its own init key");
        assert_eq!(
            kp.leaf_node().credential().serialized_content(),
            w.our_did.as_bytes()
        );
    }
    // A takes the first KeyPackage and welcomes us.
    w.seat_after_stock_already_sent().await;
}

impl World {
    async fn seat_after_stock_already_sent(&mut self) {
        let Some(Frame::Group(GroupOp::KpStock { kps, .. })) =
            self.bus.take(&self.our_did, &self.a.did).first().cloned()
        else {
            panic!("no stock on the bus")
        };
        let (commit, welcome) = self.a.stage_add(parse_kp(&kps[0]));
        self.a.merge_pending();
        self.b.apply(&commit).unwrap();
        self.bus.put(
            &self.a.did,
            &self.our_did,
            welcome_frame(ROOM, &self.a.did, &self.policy, &welcome),
        );
        assert_eq!(self.room.join().await.unwrap(), JoinState::Seated);
        assert_eq!(
            self.room.join().await.unwrap(),
            JoinState::Seated,
            "idempotent"
        );
        let mut members = self.client.members();
        members.sort();
        let mut want = vec![self.a.did.clone(), self.b.did.clone(), self.our_did.clone()];
        want.sort();
        assert_eq!(members, want);
        assert_eq!(self.client.epoch(), Some(self.a.epoch()));
        assert!(self.our_keys_match(&self.a));
        // Policy is read from the group context, not the header.
        let bindings = self.client.member_bindings();
        assert!(bindings.iter().all(|(_, s)| *s == BindingStatus::Verified));
    }
}

#[tokio::test]
async fn a_kp_req_is_answered_with_a_kp_and_other_rooms_are_ignored() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let rr = |id: &str| crate::geb::wire::RoomRef {
        id: id.into(),
        name: Some("Test room".into()),
    };
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::KpReq {
            room: rr("other-room-9"),
        }),
    );
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::KpReq { room: rr(ROOM) }),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let out = w.bus.take(&w.our_did, &w.a.did);
    let kps: Vec<_> = out
        .iter()
        .filter_map(|f| match f {
            Frame::Group(GroupOp::Kp { room, kp }) => Some((room.id.clone(), kp.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(kps.len(), 1, "one kp, for our room only");
    assert_eq!(kps[0].0, ROOM);
    assert_outgoing_kp(&parse_kp(&kps[0].1), &w.our_dev, &w.our_did);
    // A adds us with that KeyPackage and the welcome seats us.
    let (commit, welcome) = w.a.stage_add(parse_kp(&kps[0].1));
    w.a.merge_pending();
    w.b.apply(&commit).unwrap();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Seated);
}

#[tokio::test]
async fn bad_welcomes_are_ignored_and_we_stay_pending() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) =
        w.bus.take(&w.our_did, &w.a.did).first().cloned()
    else {
        panic!()
    };
    let (_c, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    let good = welcome_frame(ROOM, &w.a.did, &w.policy, &welcome);
    let Frame::Group(GroupOp::Welcome {
        room,
        w: bytes,
        ent,
    }) = good.clone()
    else {
        panic!()
    };
    let with = |f: &dyn Fn(&mut crate::geb::wire::RoomInfo)| {
        let mut r = room.clone();
        f(&mut r);
        Frame::Group(GroupOp::Welcome {
            room: r,
            w: bytes.clone(),
            ent,
        })
    };
    let cases = [
        with(&|r| r.name = "x".repeat(81)),
        with(&|r| r.name = String::new()),
        with(&|r| r.founder = "did:key:z6Mk".into()),
        with(&|r| r.id = "other-room-9".into()),
        with(&|r| r.v = 1),
    ];
    for bad in cases {
        // The dyad refuses to send an invalid frame, so put it on the bus as a
        // hostile peer's would arrive.
        w.bus.put(&w.a.did, &w.our_did, bad);
        assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    }
    // Garbage welcome bytes.
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::Welcome {
            room: room.clone(),
            w: "AAAA".into(),
            ent: None,
        }),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    // A welcome whose group id is not the room id.
    let mut other = Sim::new(9);
    other.create_room("different-room-1", &policy(&other.did, ""));
    // (a Welcome for us needs our KeyPackage; use the next one in the stock)
    let (_c, w2) = other.stage_add(parse_kp(&kps[1]));
    other.merge_pending();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &other.did, &policy(&other.did, ""), &w2),
    );
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    // The genuine one still seats us.
    w.bus.put(&w.a.did, &w.our_did, good);
    assert_eq!(w.room.join().await.unwrap(), JoinState::Seated);
}

#[tokio::test]
async fn a_keypackage_without_0xf001_cannot_be_added() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let mut plain = Sim::new(7);
    plain.plain_capabilities = true;
    let kp = plain.key_package();
    let (p, s) = (&w.a.provider, &w.a.signer);
    let r = w.a.group.as_mut().unwrap().add_members(p, s, &[kp]);
    assert!(r.is_err(), "RequiredCapabilities{{0xF001}} refuses the add");
    // Ours is accepted (seating works).
    w.seat().await;
}

#[tokio::test]
async fn nothing_works_before_seating_and_leaving_fails_closed() {
    let w = World::build(Arc::new(NoLocalKnowledge), "");
    assert!(w.client.relay_keys().is_err());
    assert!(w.client.seal(b"x").is_err());
    assert!(w.room.post(&text_event("x", 1)).await.is_err());
    assert!(matches!(w.room.leave().await, Err(Error::Unsupported(_))));
}

// ---- lines --------------------------------------------------------------------

#[tokio::test]
async fn lines_flow_both_ways_signed_and_unsigned_are_marked() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    // Us -> A and B.
    let posted = w
        .room
        .post(&text_event("hello from the bridge", 1_700_000_000_000))
        .await
        .unwrap();
    assert!(posted.foreign_ref.is_some());
    let ev = w
        .relay
        .all()
        .into_iter()
        .find(|e| e.pubkey == w.a.keys(ROOM).pubkey_hex().unwrap())
        .expect("posted under the room's mailbox");
    let env = GuideCodec
        .decode_envelope(&pair::open(&w.a.keys(ROOM), KIND_MAILBOX, &ev.content).unwrap())
        .unwrap();
    let Envelope::Ml { m } = env else { panic!() };
    let bytes = crate::geb::crypto::b64_decode(&m).unwrap();
    for sim in [&mut w.a, &mut w.b] {
        let (sender, line) = sim.open_line(&bytes).expect("a member opens our line");
        assert_eq!(sender, w.our_did);
        assert_eq!(line.text, "hello from the bridge");
        let sg = line.sg.clone().expect("signed");
        let doc = signing_doc(ROOM, &w.our_did, &line).unwrap();
        crate::geb::crypto::sign::verify_json(&w.our_dev.verifying_key(), &doc, &sg).unwrap();
    }
    // A, B -> us: one signed, one unsigned.
    w.at(11_000);
    let signed = w.a.seal_line(ROOM, 5, "hi bridge", true);
    let unsigned = w.b.seal_line(ROOM, 6, "trust me", false);
    w.post_ml(&w.a, &signed).await;
    w.post_ml(&w.b, &unsigned).await;
    let got = w.poll().await.unwrap();
    let by_text: std::collections::HashMap<_, _> = got
        .iter()
        .map(|p| (p.event.text.clone(), p.event.provenance.clone().unwrap()))
        .collect();
    assert_eq!(by_text["hi bridge"].check, AuthorCheck::Verified);
    assert_eq!(by_text["hi bridge"].author_device, w.a.did);
    assert_eq!(by_text["trust me"].check, AuthorCheck::Unsigned);
    // Our own line is not echoed back.
    assert!(got.iter().all(|p| p.event.author != w.our_did));
}

// ---- epochs, settling ----------------------------------------------------------

#[tokio::test]
async fn competing_commits_resolve_by_lowest_hash_after_the_window_on_all_clients() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let e0 = w.a.epoch();
    // A and B commit at once; make A's the lower so the winner is not "ours first".
    for a_lower in [true, false] {
        let e = w.a.epoch();
        let (ca, cb) = staged_pair(
            &mut w.a,
            &mut w.b,
            a_lower,
            &|s| s.stage_self_update(),
            &|s| s.stage_self_update(),
        );
        w.post_mc(&w.a, &ca).await;
        w.post_mc(&w.b, &cb).await;
        // A line sent in the old epoch during the window is still readable.
        let old_epoch_line = w.a.seal_line(ROOM, 7, "sent during the window", true);
        w.post_ml(&w.a, &old_epoch_line).await;
        let t0 = w.now();
        let got = w.poll().await.unwrap();
        assert_eq!(w.client.epoch(), Some(e), "held, not applied at once");
        assert_eq!(w.client.held_commits(), 2);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event.text, "sent during the window");
        // The cursor does not pass the held commits.
        assert_eq!(got[0].cursor.0, (t0 / 1000).to_be_bytes().to_vec());
        w.at(t0 + 2999);
        w.poll().await.unwrap();
        assert_eq!(w.client.epoch(), Some(e), "one ms short of the window");
        w.at(t0 + 3000);
        w.poll().await.unwrap();
        assert_eq!(w.client.epoch(), Some(e + 1));
        // Everyone applies the same rule and lands on the same winner.
        let winner =
            w.a.settle(Some(&ca), std::slice::from_ref(&cb), &|_| true)
                .unwrap();
        let winner_b =
            w.b.settle(Some(&cb), std::slice::from_ref(&ca), &|_| true)
                .unwrap();
        assert_eq!(winner, winner_b);
        assert_eq!(winner, if a_lower { ca } else { cb });
        assert_eq!(w.a.epoch(), e + 1);
        assert_eq!(w.b.epoch(), e + 1);
        assert!(w.our_keys_match(&w.a) && w.our_keys_match(&w.b));
        assert_eq!(w.client.held_commits(), 0);
        w.at(w.now() + 10_000);
    }
    assert_eq!(w.client.epoch(), Some(e0 + 2));
}

#[tokio::test]
async fn relay_keys_change_with_every_merged_commit_and_both_sides_agree() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let mut seen = vec![w.client.relay_keys().unwrap().pubkey_hex().unwrap()];
    for i in 0..3u64 {
        assert!(w.our_keys_match(&w.a));
        let c = w.a.stage_self_update();
        w.post_mc(&w.a, &c).await; // …
        w.a.merge_pending();
        w.b.apply(&c).unwrap();
        let t = w.now();
        w.poll().await.unwrap();
        w.at(t + 3000);
        // The commit was read under the old keys; after the merge the poll
        // reads again under the new ones and gets a line posted there.
        let line = w.a.seal_line(ROOM, 100 + i, &format!("line {i}"), true);
        w.post_ml(&w.a, &line).await;
        let got = w.poll().await.unwrap();
        assert_eq!(
            got.len(),
            1,
            "the line under the NEW keys arrives in the same poll"
        );
        assert_eq!(got[0].event.text, format!("line {i}"));
        assert!(w.our_keys_match(&w.a) && w.our_keys_match(&w.b));
        let pk = w.client.relay_keys().unwrap().pubkey_hex().unwrap();
        assert!(!seen.contains(&pk), "keys are new each epoch");
        seen.push(pk);
        w.at(w.now() + 10_000);
    }
}

#[tokio::test]
async fn a_commit_failing_valid_commit_is_dropped_and_the_next_wins() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    // B (not root, not an admin) tries to remove A, and has the lower hash.
    // A, root, makes an ordinary commit.
    let a_did = w.a.did.clone();
    let (ca, cb) = staged_pair(
        &mut w.a,
        &mut w.b,
        false,
        &|s| s.stage_self_update(),
        &|s| s.stage_remove(&a_did),
    );
    assert!(commit_hash(&cb) < commit_hash(&ca));
    w.post_mc(&w.a, &ca).await;
    w.post_mc(&w.b, &cb).await;
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    // A's commit won; B's was dropped on our side...
    assert_eq!(w.client.epoch(), Some(w.a.epoch() + 1));
    // ...and on theirs, which apply the same verdict.
    let valid_for_geb = |c: &[u8]| c != cb.as_slice();
    let wa =
        w.a.settle(Some(&ca), std::slice::from_ref(&cb), &valid_for_geb)
            .unwrap();
    let wb =
        w.b.settle(Some(&cb), std::slice::from_ref(&ca), &valid_for_geb)
            .unwrap();
    assert_eq!(
        (wa.as_slice(), wb.as_slice()),
        (ca.as_slice(), ca.as_slice())
    );
    assert!(w.our_keys_match(&w.a) && w.our_keys_match(&w.b));
    assert_eq!(w.client.members().len(), 3, "nobody was removed");
}

#[tokio::test]
async fn root_may_remove_and_change_policy_but_not_others() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    // Root removes B: valid.
    let b_did = w.b.did.clone();
    let c = w.a.stage_remove(&b_did);
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert!(!w.client.members().contains(&b_did));
    assert!(w.our_keys_match(&w.a));
    // Root changes the policy keeping committer and window: valid.
    let new = policy(&w.a.did, r#","edit":"admins""#);
    let c = w.a.stage_policy(&new);
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.at(w.now() + 10_000);
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert!(w.our_keys_match(&w.a));
    let g = w.client.epoch().unwrap();
    assert_eq!(g, w.a.epoch());
}

#[tokio::test]
async fn an_invalid_policy_change_is_dropped_and_the_next_commit_wins() {
    // (a) root moves settleWindowMs; (b) a non-root changes the policy.
    for root_moves_window in [true, false] {
        let mut w = World::build(Arc::new(AllKnown), "");
        w.seat().await;
        let root = w.a.did.clone();
        let moved = policy(&root, "").replace("3000", "10");
        let edit = policy(&root, r#","edit":"admins""#);
        let (bad, good) = if root_moves_window {
            staged_pair(
                &mut w.a,
                &mut w.b,
                true,
                &|s| s.stage_policy(&moved),
                &|s| s.stage_self_update(),
            )
        } else {
            // B's policy change must be the lower hash: swap the roles.
            let (b_commit, a_commit) =
                staged_pair(&mut w.b, &mut w.a, true, &|s| s.stage_policy(&edit), &|s| {
                    s.stage_self_update()
                });
            (b_commit, a_commit)
        };
        let (bad_poster_is_a, e) = (root_moves_window, w.a.epoch());
        if bad_poster_is_a {
            w.post_mc(&w.a, &bad).await;
            w.post_mc(&w.b, &good).await;
        } else {
            w.post_mc(&w.b, &bad).await;
            w.post_mc(&w.a, &good).await;
        }
        let t = w.now();
        w.poll().await.unwrap();
        w.at(t + 3000);
        w.poll().await.unwrap();
        assert_eq!(w.client.epoch(), Some(e + 1));
        let valid = |c: &[u8]| c != bad.as_slice();
        let (own_a, own_b) = if bad_poster_is_a {
            (&bad, &good)
        } else {
            (&good, &bad)
        };
        w.a.settle(Some(own_a), std::slice::from_ref(own_b), &valid)
            .unwrap();
        w.b.settle(Some(own_b), std::slice::from_ref(own_a), &valid)
            .unwrap();
        assert!(w.our_keys_match(&w.a) && w.our_keys_match(&w.b));
        // The room's policy is unchanged (read from the group context).
        let g_policy = {
            let g = w.a.group.as_ref().unwrap();
            super::group_policy(g)
        };
        assert_eq!(g_policy.settle_window_ms, 3000);
        assert!(g_policy.edit.is_none());
    }
}

#[tokio::test]
async fn a_forged_leaf_binding_is_refused_even_without_local_knowledge() {
    // Production inputs: the forged-binding check needs no local knowledge.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let mut evil = Sim::new(8);
    evil.forge_binding = true;
    let forged_kp = evil.key_package();
    assert_eq!(binding_status(forged_kp.leaf_node()), BindingStatus::Forged);
    let (c_forged, c_ok) = {
        let mut out = None;
        for _ in 0..200 {
            let (cf, _) = w.a.stage_add(forged_kp.clone());
            let co = w.b.stage_self_update();
            if commit_hash(&cf) < commit_hash(&co) {
                out = Some((cf, co));
                break;
            }
            w.a.drop_pending();
            w.b.drop_pending();
        }
        out.unwrap()
    };
    w.post_mc(&w.a, &c_forged).await;
    w.post_mc(&w.b, &c_ok).await;
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), Some(w.a.epoch() + 1));
    assert!(
        !w.client.members().iter().any(|m| m == &evil.did),
        "forged leaf never seated"
    );
    let valid = |c: &[u8]| c != c_forged.as_slice();
    let wa =
        w.a.settle(Some(&c_forged), std::slice::from_ref(&c_ok), &valid)
            .unwrap();
    assert_eq!(wa, c_ok);
    w.b.settle(Some(&c_ok), std::slice::from_ref(&c_forged), &valid)
        .unwrap();
    assert!(w.our_keys_match(&w.a) && w.our_keys_match(&w.b));
}

#[tokio::test]
async fn a_missing_binding_is_seated_and_reported_unverified() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    // A KeyPackage with the declared extensions but no binding.
    let ghost = Sim::new(11);
    let kp = {
        let b = KeyPackage::builder().leaf_node_capabilities(super::identity::leaf_capabilities());
        b.build(SUITE, &ghost.provider, &ghost.signer, ghost.cred.clone())
            .unwrap()
            .key_package()
            .clone()
    };
    assert_eq!(binding_status(kp.leaf_node()), BindingStatus::Missing);
    let (c, _welcome) = w.a.stage_add(kp);
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert_eq!(w.client.members().len(), 4);
    let status: std::collections::HashMap<_, _> = w.client.member_bindings().into_iter().collect();
    assert_eq!(status[&ghost.did], BindingStatus::Missing);
    assert!(w.our_keys_match(&w.a));
}

// ---- 0.5.15 commit and tree rules (P0-c) -----------------------------------------

/// Poll to hold what was posted, wait the window, poll to settle it.
async fn settle_posted(w: &World) -> crate::Result<()> {
    let t = w.now();
    w.poll().await?;
    w.at(t + 3000);
    w.poll().await.map(|_| ())
}

/// Seat `who` (a fresh Sim) through A's commit: merged on A, B and us.
async fn add_member(w: &mut World, who: &mut Sim) {
    let (c, welcome) = w.a.stage_add(who.key_package());
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    settle_posted(w).await.unwrap();
    who.join(&welcome);
    assert_eq!(w.client.epoch(), Some(w.a.epoch()));
    w.at(w.now() + 10_000);
}

/// `bad` (made on B, the lower hash) must be REFUSED (not failed), the walk must
/// go on, and A's ordinary commit must win and merge. Returns our client's
/// failed-commit count (always 0 here, asserted).
async fn refused_then_next_wins(w: &mut World, mk_bad_on_b: &dyn Fn(&mut Sim) -> Vec<u8>) {
    let e = w.a.epoch();
    let (good, bad) = staged_pair(
        &mut w.a,
        &mut w.b,
        false,
        &|s| s.stage_self_update(),
        mk_bad_on_b,
    );
    assert!(commit_hash(&bad) < commit_hash(&good));
    w.post_mc(&w.b, &bad).await;
    w.post_mc(&w.a, &good).await;
    settle_posted(w).await.unwrap();
    assert!(
        w.client.failed_commits().is_empty(),
        "a refusal is not a failure"
    );
    assert_eq!(w.client.epoch(), Some(e + 1), "the next hash was merged");
    w.a.merge_pending();
    w.b.drop_pending();
    assert!(w.our_keys_match(&w.a));
}

#[tokio::test]
async fn by_reference_proposals_and_standalone_proposals_are_refused_not_failed() {
    let kp = Sim::new(30).key_package();
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    // A commit that names its proposal by reference.
    refused_then_next_wins(&mut w, &|s| s.stage_by_ref_add(kp.clone()).1).await;
    // A standalone Proposal in an `mc` is refused and never stored.
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    refused_then_next_wins(&mut w, &|s| s.stage_proposal(kp.clone())).await;
    assert!(
        !w.client.members().iter().any(|m| m == &Sim::new(30).did),
        "nobody was added by a proposal"
    );
    // A lone one: refused, nothing held afterwards, nothing failed.
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let e = w.client.epoch();
    let p = w.b.stage_proposal(kp.clone());
    w.post_mc(&w.b, &p).await;
    settle_posted(&w).await.unwrap();
    assert_eq!(w.client.epoch(), e);
    assert!(w.client.failed_commits().is_empty());
    assert_eq!(w.client.held_commits(), 0);
}

#[tokio::test]
async fn leaf_auth_refuses_an_update_path_leaf_that_names_another_did() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let other = Sim::new(31);
    refused_then_next_wins(&mut w, &|s| {
        let params = LeafNodeParameters::builder()
            .with_credential_with_key(CredentialWithKey {
                credential: other.cred.credential.clone(),
                signature_key: s.cred.signature_key.clone(),
            })
            .build();
        s.stage_update_with(params)
    })
    .await;
}

#[tokio::test]
async fn a_forged_binding_on_the_update_path_leaf_is_refused() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    refused_then_next_wins(&mut w, &|s| {
        s.forge_binding = true;
        let ext = s.binding_ext();
        s.forge_binding = false;
        s.stage_update_with(LeafNodeParameters::builder().with_extensions(ext).build())
    })
    .await;
}

#[tokio::test]
async fn an_unbound_leaf_naming_the_root_or_a_seated_did_is_never_seated() {
    for (claimed_seed, who) in [(1u8, "the root"), (2u8, "a seated member")] {
        let mut w = World::build(Arc::new(NoLocalKnowledge), "");
        w.seat().await;
        let mut imp = Sim::new(claimed_seed);
        imp.unbound = true;
        let kp = imp.key_package();
        assert_eq!(binding_status(kp.leaf_node()), BindingStatus::Missing);
        refused_then_next_wins(&mut w, &|s| s.stage_add(kp.clone()).0).await;
        assert_eq!(
            w.client.members().len(),
            3,
            "{who}: the claimant is not seated"
        );
    }
    // An unbound leaf of a DID nobody holds is still seated (answer 1).
    // (a_missing_binding_is_seated_and_reported_unverified)
}

#[tokio::test]
async fn an_unbound_sender_cannot_remove_or_change_policy_and_can_heal_its_own_leaf() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let mut u = Sim::new(40);
    u.unbound = true;
    add_member(&mut w, &mut u).await;
    let b_did = w.b.did.clone();
    let status: std::collections::HashMap<_, _> = w.client.member_bindings().into_iter().collect();
    assert_eq!(status[&u.did], BindingStatus::Missing);
    // An unbound sender's Remove is refused, even though nothing about it
    // needs persona cards; the walk goes on to A's commit.
    let e = w.a.epoch();
    let (good, bad) = staged_pair(&mut w.a, &mut u, false, &|s| s.stage_self_update(), &|s| {
        s.stage_remove(&b_did)
    });
    w.post_mc(&u, &bad).await;
    w.post_mc(&w.a, &good).await;
    settle_posted(&w).await.unwrap();
    assert_eq!(w.client.epoch(), Some(e + 1));
    assert!(w.client.members().contains(&b_did));
    w.a.merge_pending();
    u.drop_pending();
    u.apply(&good).unwrap();
    w.b.apply(&good).unwrap();
    w.at(w.now() + 10_000);
    // Same for a policy change.
    let e = w.a.epoch();
    let edit = policy(&w.a.did, r#","edit":"admins""#);
    let (good, bad) = staged_pair(&mut w.a, &mut u, false, &|s| s.stage_self_update(), &|s| {
        s.stage_policy(&edit)
    });
    w.post_mc(&u, &bad).await;
    w.post_mc(&w.a, &good).await;
    settle_posted(&w).await.unwrap();
    assert_eq!(w.client.epoch(), Some(e + 1));
    w.a.merge_pending();
    u.drop_pending();
    u.apply(&good).unwrap();
    w.b.apply(&good).unwrap();
    w.at(w.now() + 10_000);
    // The heal: a path-only self-update whose new leaf carries U's binding.
    let heal = u.stage_update_with(
        LeafNodeParameters::builder()
            .with_extensions(u.binding_ext())
            .build(),
    );
    w.post_mc(&u, &heal).await;
    u.merge_pending();
    w.a.apply(&heal).unwrap();
    w.b.apply(&heal).unwrap();
    settle_posted(&w).await.unwrap();
    assert_eq!(w.client.epoch(), Some(u.epoch()));
    let status: std::collections::HashMap<_, _> = w.client.member_bindings().into_iter().collect();
    assert_eq!(
        status[&u.did],
        BindingStatus::Verified,
        "the heal bound the leaf"
    );
    assert!(w.our_keys_match(&u));
    // Now U is bound; its Remove is judged by the ordinary rules (not root:
    // refused by AllKnown-style rules is P0-d's concern; here, undecidable
    // without cards, which is the documented halt).
}

/// Steps of `seat()` up to, not including, the final join: A adds `extra`
/// first (so the tree the Welcome carries holds it), then our KeyPackage.
async fn offer_welcome_after(w: &mut World, extra: &mut Sim) -> JoinState {
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let (c, _) = w.a.stage_add(extra.key_package());
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) =
        w.bus.take(&w.our_did, &w.a.did).first().cloned()
    else {
        panic!("no kp-stock")
    };
    let (commit, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    w.b.apply(&commit).unwrap();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    w.room.join().await.unwrap()
}

#[tokio::test]
async fn a_welcome_with_a_forged_leaf_or_a_duplicate_unbound_did_is_refused() {
    // (a) a forged leaf in the tree.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let mut evil = Sim::new(41);
    evil.forge_binding = true;
    assert_eq!(
        offer_welcome_after(&mut w, &mut evil).await,
        JoinState::Pending
    );
    assert_eq!(w.client.epoch(), None, "nothing of it was kept");
    // (b) two leaves for one DID, one of them unbound (B's DID, no binding).
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let mut dup = Sim::new(2);
    dup.unbound = true;
    assert_eq!(
        offer_welcome_after(&mut w, &mut dup).await,
        JoinState::Pending
    );
    assert_eq!(w.client.epoch(), None);
    // (c) two leaves for one DID, BOTH bound, is not a treeRefusal (a re-seat
    // in flight leaves exactly this), and an unbound leaf of a fresh DID is
    // seated.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let mut fresh = Sim::new(42);
    fresh.unbound = true;
    assert_eq!(
        offer_welcome_after(&mut w, &mut fresh).await,
        JoinState::Seated
    );
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let mut twin = Sim::new(2);
    assert_eq!(
        offer_welcome_after(&mut w, &mut twin).await,
        JoinState::Seated
    );
}

// ---- partial local knowledge ---------------------------------------------------

#[tokio::test]
async fn without_local_knowledge_root_removes_and_policy_changes_merge_and_only_card_cases_halt() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    // An Add-only commit is merged.
    let newbie = Sim::new(12);
    let (c, _) = w.a.stage_add(newbie.key_package());
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    settle_posted(&w).await.unwrap();
    assert!(w.client.members().contains(&newbie.did));
    assert!(w.our_keys_match(&w.a));
    w.at(w.now() + 10_000);

    // P0-d: root's Remove of B is decided (exact DID, bound sender) and merged.
    let b_did = w.b.did.clone();
    let c = w.a.stage_remove(&b_did);
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    settle_posted(&w).await.unwrap();
    assert!(!w.client.members().contains(&b_did));
    assert!(w.our_keys_match(&w.a));
    w.at(w.now() + 10_000);

    // ...and so is root's policy change.
    let c = w.a.stage_policy(&policy(&w.a.did, r#","edit":"all""#));
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    settle_posted(&w).await.unwrap();
    assert!(w.our_keys_match(&w.a));
    assert_eq!(w.client.epoch(), Some(w.a.epoch()));

    // A non-root's policy change is refused, not a halt: the epoch stays.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let e = w.client.epoch();
    let c = w.b.stage_policy(&policy(&w.a.did, r#","edit":"all""#));
    w.post_mc(&w.b, &c).await;
    w.b.drop_pending();
    settle_posted(&w).await.unwrap();
    assert_eq!(w.client.epoch(), e);
    assert!(w.client.failed_commits().is_empty());

    // The residual halt: a non-root, non-admin removes a DIFFERENT DID.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let epoch = w.client.epoch().unwrap();
    let keys_before = w.client.relay_keys().unwrap().pubkey_hex().unwrap();
    let a_did = w.a.did.clone();
    let c = w.b.stage_remove(&a_did);
    w.post_mc(&w.b, &c).await;
    w.b.drop_pending();
    let t = w.now();
    w.poll().await.unwrap(); // held
    w.at(t + 3000);
    let e = w.poll().await.unwrap_err();
    assert!(matches!(e, Error::UndecidableCommit(_)), "{e}");
    assert!(
        e.to_string().contains("epoch ") && e.to_string().contains("commit "),
        "{e}"
    );
    assert_eq!(w.client.epoch(), Some(epoch), "epoch stays");
    assert_eq!(
        w.client.relay_keys().unwrap().pubkey_hex().unwrap(),
        keys_before
    );
    // It keeps stopping: the commit is still held, never silently dropped.
    assert!(matches!(w.poll().await, Err(Error::UndecidableCommit(_))));
    assert_eq!(w.client.held_commits(), 1);
}

#[tokio::test]
async fn a_lower_hash_undecidable_commit_blocks_even_when_a_higher_one_is_fine() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let a_did = w.a.did.clone();
    // B (not root, not admin) removes A: undecidable. A's ordinary commit has
    // the higher hash.
    let (cu, cr) = staged_pair(
        &mut w.b,
        &mut w.a,
        true,
        &|s| s.stage_remove(&a_did),
        &|s| s.stage_self_update(),
    );
    w.post_mc(&w.b, &cu).await;
    w.post_mc(&w.a, &cr).await;
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    assert!(w.poll().await.is_err());
    assert_eq!(
        w.client.epoch(),
        Some(w.a.epoch()),
        "the higher, fine commit is not merged past it"
    );
}

#[tokio::test]
async fn adds_to_a_direct_room_are_undecidable_without_persona_cards() {
    // Sim::new is deterministic, so the two persons' DIDs are known up front.
    let (lo, hi) = (Sim::new(1).did, Sim::new(2).did);
    // (A real client refuses a Welcome into a direct room, round 3 section 9;
    // the test switch lets it in so the commit rule itself is still pinned.)
    let mut w = World::build_with(
        Arc::new(NoLocalKnowledge),
        &format!(r#","direct":["{lo}","{hi}"]"#),
        true,
    );
    w.seat().await;
    let newbie = Sim::new(13);
    let (c, _) = w.a.stage_add(newbie.key_package());
    w.post_mc(&w.a, &c).await;
    w.a.drop_pending();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    assert!(matches!(w.poll().await, Err(Error::UndecidableCommit(_))));
    assert!(!w.client.members().contains(&newbie.did));
}

// ---- removal, replay -----------------------------------------------------------

#[tokio::test]
async fn a_merged_commit_removing_us_is_refused() {
    let mut w = World::build(Arc::new(AllKnown), "");
    w.seat().await;
    let us = w.our_did.clone();
    let c = w.a.stage_remove(&us);
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    let e = w.poll().await.unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");
    // The state is sticky: join, seal and keys all say refused.
    assert!(matches!(w.room.join().await, Err(Error::Refused(_))));
    assert!(matches!(w.client.relay_keys(), Err(Error::Refused(_))));
    assert!(matches!(w.client.seal(b"x"), Err(Error::Refused(_))));
}

#[tokio::test]
async fn a_replayed_commit_is_recorded_failed_and_asks_for_the_room_status_once() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let old_epoch = w.a.epoch();
    let c = w.a.stage_self_update();
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), Some(old_epoch + 1));

    // Replay it with `e` set to the epoch we are in now (a lying envelope).
    w.at(w.now() + 10_000);
    post(
        &w.relay_dyn,
        &w.a.keys(ROOM),
        &mc(w.a.epoch(), &c),
        w.secs(),
    )
    .await;
    // A line sent after it, in the same epoch.
    let line = w.a.seal_line(ROOM, 9, "after the replay", true);
    w.post_ml(&w.a, &line).await;
    let t = w.now();
    w.poll().await.unwrap(); // held
    w.at(t + 3000);
    let got = w.poll().await.unwrap();
    assert_eq!(w.client.epoch(), Some(old_epoch + 1), "the epoch stays");
    assert_eq!(w.client.failed_commits().len(), 1);
    // Cursor stays before the failed commit.
    assert!(
        got.iter()
            .all(|p| p.cursor.0 == (t / 1000).to_be_bytes().to_vec())
    );
    // The room status request went to A, once.
    let rs = |d: &MemDyad| {
        d.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, f)| matches!(f, Frame::Group(GroupOp::Rs { .. })))
            .count()
    };
    assert_eq!(rs(&w.dyad), 1);
    w.at(w.now() + 5000);
    w.poll().await.unwrap();
    assert_eq!(rs(&w.dyad), 1, "not asked again for the same commit");

    // A commit made from an epoch below ours is ignored at the door.
    let held = w.client.held_commits();
    post(&w.relay_dyn, &w.a.keys(ROOM), &mc(old_epoch, &c), w.secs()).await;
    w.poll().await.unwrap();
    assert_eq!(w.client.held_commits(), held);
}

// ---- persistence across a restart ------------------------------------------

#[derive(Default)]
struct MemState(std::sync::Mutex<Option<Vec<u8>>>, AtomicU64);
impl GroupStateStore for MemState {
    fn load(&self) -> crate::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, s: &[u8]) -> crate::Result<()> {
        self.1.fetch_add(1, Ordering::SeqCst);
        *self.0.lock().unwrap() = Some(s.to_vec());
        Ok(())
    }
}

/// A new process: a client and room over the same device, dyad and relay,
/// resuming from `store` and `vault`.
fn restarted(
    w: &World,
    store: Arc<dyn GroupStateStore>,
    vault: &dyn SignatureKeyVault,
) -> (Arc<MlsGroupClient>, GebRoom) {
    let device: Arc<dyn GebSigner> = Arc::new(crate::geb::crypto::sign::LocalSigner::new(
        w.our_did.clone(),
        w.our_dev.clone(),
    ));
    let client = Arc::new(
        MlsGroupClient::new(
            MlsConfig::new(ROOM, vec![w.a.did.clone()]),
            device.clone(),
            w.dyad.clone(),
            Arc::new(NoLocalKnowledge),
            vault,
        )
        .unwrap()
        .with_state_store(store)
        .unwrap(),
    );
    let c2 = w.clock.clone();
    let room = GebRoom::new(
        ROOM.into(),
        w.relay.clone(),
        client.clone(),
        device,
        Arc::new(GuideCodec),
        Arc::new(move || c2.load(Ordering::SeqCst)),
    );
    (client, room)
}

#[tokio::test]
async fn a_restart_resumes_seated_without_re_seating() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let store = Arc::new(MemState::default());
    let vault = MemoryVault::default();
    let (c1, room1) = restarted(&w, store.clone(), &vault);
    // Seat the persisted client the way `World::seat` seats the plain one.
    assert_eq!(room1.join().await.unwrap(), JoinState::Pending);
    let stock = w.bus.take(&w.our_did, &w.a.did);
    let Some(Frame::Group(GroupOp::KpStock { kps, .. })) = stock.first().cloned() else {
        panic!("no kp-stock")
    };
    let (commit, welcome) = w.a.stage_add(parse_kp(&kps[0]));
    w.a.merge_pending();
    w.b.apply(&commit).unwrap();
    w.bus.put(
        &w.a.did,
        &w.our_did,
        welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
    );
    assert_eq!(room1.join().await.unwrap(), JoinState::Seated);
    let epoch = c1.epoch().unwrap();
    // A line before the restart.
    room1
        .post(&text_event("before the restart", 1_700_000_000_000))
        .await
        .unwrap();
    let saves = store.1.load(Ordering::SeqCst);
    assert!(saves >= 3, "stock, join and seal each saved ({saves})");
    drop((c1, room1));

    // Restart: a new client from the stored state is seated at once, at the
    // same epoch, under the same relay keys, and sends no second stock.
    let sent_before = w.dyad.sent.lock().unwrap().len();
    let (c2, room2) = restarted(&w, store.clone(), &vault);
    assert_eq!(c2.epoch(), Some(epoch));
    assert!(w.a.keys(ROOM).pubkey_hex().unwrap() == c2.relay_keys().unwrap().pubkey_hex().unwrap());
    assert_eq!(room2.join().await.unwrap(), JoinState::Seated);
    assert_eq!(w.dyad.sent.lock().unwrap().len(), sent_before);
    // A line after the restart opens for a member, in order after the first
    // (a repeated sender-ratchet generation would not).
    room2
        .post(&text_event("after the restart", 1_700_000_001_000))
        .await
        .unwrap();
    let mailbox = w.a.keys(ROOM).pubkey_hex().unwrap();
    let mut evs: Vec<_> = w
        .relay
        .all()
        .into_iter()
        .filter(|e| e.pubkey == mailbox)
        .collect();
    evs.sort_by_key(|e| e.created_at);
    let mut texts = Vec::new();
    for ev in &evs {
        let env = GuideCodec
            .decode_envelope(&pair::open(&w.a.keys(ROOM), KIND_MAILBOX, &ev.content).unwrap())
            .unwrap();
        if let Envelope::Ml { m } = env {
            let bytes = crate::geb::crypto::b64_decode(&m).unwrap();
            let (_, line) = w.a.open_line(&bytes).expect("a member opens it");
            texts.push(line.text);
        }
    }
    assert_eq!(texts.len(), 2);
    assert!(texts.iter().any(|t| t == "before the restart"));
    assert!(texts.iter().any(|t| t == "after the restart"));
    // And a member's line reaches the restarted client.
    w.at(w.now() + 5_000);
    let theirs = w.a.seal_line(ROOM, 9, "hello again", true);
    w.post_ml(&w.a, &theirs).await;
    let got = room2.poll(None).await.unwrap();
    assert!(got.iter().any(|p| p.event.text == "hello again"));
}

#[tokio::test]
async fn a_corrupt_snapshot_refuses_to_start() {
    let w = World::build(Arc::new(NoLocalKnowledge), "");
    let store = Arc::new(MemState::default());
    *store.0.lock().unwrap() = Some(b"not a snapshot".to_vec());
    let device: Arc<dyn GebSigner> = Arc::new(crate::geb::crypto::sign::LocalSigner::new(
        w.our_did.clone(),
        w.our_dev.clone(),
    ));
    let r = MlsGroupClient::new(
        MlsConfig::new(ROOM, vec![w.a.did.clone()]),
        device,
        w.dyad.clone(),
        Arc::new(NoLocalKnowledge),
        &MemoryVault::default(),
    )
    .unwrap()
    .with_state_store(store);
    assert!(r.is_err());
}

// ---- stock handling (round 3 section 5 and 3) ------------------------------

struct StockWorld {
    client: Arc<MlsGroupClient>,
    room: GebRoom,
    bus: Arc<Bus>,
    dyad: Arc<MemDyad>,
    peer: String,
    me: String,
    dev: SigningKey,
    clock: Arc<AtomicU64>,
    store: Arc<MemState>,
    vault: Arc<MemoryVault>,
}

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;

impl StockWorld {
    /// A client on a controllable clock that starts at the real time (its
    /// KeyPackage lifetimes must be valid for the parsing helpers).
    fn new() -> Self {
        let bus = Bus::new();
        let peer = Sim::new(1).did;
        let dev = SigningKey::from_bytes(&[60u8; 32]);
        let me = did_peer::encode(&dev.verifying_key().to_bytes(), &[60u8; 32], None).unwrap();
        let clock = Arc::new(AtomicU64::new(now_secs() * 1000));
        let dyad = MemDyad::new(&me, &bus);
        let store = Arc::new(MemState::default());
        let vault = Arc::new(MemoryVault::default());
        let (client, room) = Self::boot(&dev, &me, &peer, &dyad, &clock, &store, &vault);
        StockWorld {
            client,
            room,
            bus,
            dyad,
            peer,
            me,
            dev,
            clock,
            store,
            vault,
        }
    }

    fn boot(
        dev: &SigningKey,
        me: &str,
        peer: &str,
        dyad: &Arc<MemDyad>,
        clock: &Arc<AtomicU64>,
        store: &Arc<MemState>,
        vault: &Arc<MemoryVault>,
    ) -> (Arc<MlsGroupClient>, GebRoom) {
        let device: Arc<dyn GebSigner> = Arc::new(crate::geb::crypto::sign::LocalSigner::new(
            me.to_string(),
            dev.clone(),
        ));
        let c1 = clock.clone();
        let client = Arc::new(
            MlsGroupClient::new(
                MlsConfig::new(ROOM, vec![peer.to_string()]),
                device.clone(),
                dyad.clone(),
                Arc::new(NoLocalKnowledge),
                vault.as_ref(),
            )
            .unwrap()
            .with_clock(Arc::new(move || c1.load(Ordering::SeqCst)))
            .with_state_store(store.clone())
            .unwrap(),
        );
        let c2 = clock.clone();
        let room = GebRoom::new(
            ROOM.into(),
            Arc::new(FakeRelay::new()),
            client.clone(),
            device,
            Arc::new(GuideCodec),
            Arc::new(move || c2.load(Ordering::SeqCst)),
        );
        (client, room)
    }

    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    /// Frames we sent to the peer since the last call.
    fn sent(&self) -> Vec<Frame> {
        self.bus.take(&self.me, &self.peer)
    }

    fn deliver(&self, f: Frame) {
        self.bus.put(&self.peer, &self.me, f);
    }

    fn stock(&self) -> (u64, Vec<String>) {
        let mut stocks: Vec<_> = self
            .sent()
            .into_iter()
            .filter_map(|f| match f {
                Frame::Group(GroupOp::KpStock { generation, kps }) => Some((generation, kps)),
                _ => None,
            })
            .collect();
        assert_eq!(stocks.len(), 1, "exactly one stock was sent");
        stocks.remove(0)
    }

    fn kp_low(&self, generation: u64) {
        self.deliver(Frame::Group(GroupOp::KpLow { generation, n: 1 }));
    }
}

#[tokio::test]
async fn the_first_stock_is_gen_1_of_six_bound_packages_with_a_lifetime() {
    let w = StockWorld::new();
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    let (generation, kps) = w.stock();
    assert_eq!((generation, kps.len()), (1, 6));
    assert_eq!(DEFAULT_STOCK, 6);
    for k in &kps {
        assert!(
            k.len() <= 65_536
                && k.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        );
        assert_outgoing_kp(&parse_kp(k), &w.dev, &w.me);
    }
    // Not re-sent while pending.
    assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
    assert!(w.sent().is_empty());
}

#[tokio::test]
async fn kp_low_is_answered_with_max_of_our_last_gen_and_theirs_plus_one() {
    let w = StockWorld::new();
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 1);
    // They hold our gen 1: the next is 2.
    w.kp_low(1);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    let (g2, kps) = w.stock();
    assert_eq!((g2, kps.len()), (2, 6));
    // Their gen is ahead of ours (we lost state, or they count differently):
    // theirs + 1.
    w.kp_low(9);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 10);
    // A stale kp-low (their gen below ours) still moves us forward, never back.
    w.kp_low(1);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 11);
    // A kp-low repeated within a minute is not answered again (our choice).
    w.kp_low(11);
    w.room.join().await.unwrap();
    assert!(w.sent().is_empty());
}

#[tokio::test]
async fn the_last_gen_sent_survives_a_restart() {
    let w = StockWorld::new();
    w.room.join().await.unwrap();
    w.stock();
    w.kp_low(1);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 2);
    let (_c, room) = StockWorld::boot(
        &w.dev, &w.me, &w.peer, &w.dyad, &w.clock, &w.store, &w.vault,
    );
    // No second first-stock after a restart.
    room.join().await.unwrap();
    assert!(w.sent().is_empty());
    w.kp_low(2);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    room.join().await.unwrap();
    assert_eq!(w.stock().0, 3, "gen continues from the persisted last gen");
}

#[tokio::test]
async fn a_stock_older_than_seven_days_is_replaced_while_pending() {
    let w = StockWorld::new();
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 1);
    w.advance(7 * DAY_MS - 1000);
    w.room.join().await.unwrap();
    assert!(w.sent().is_empty(), "not yet stale");
    w.advance(2000);
    w.room.join().await.unwrap();
    assert_eq!(w.stock().0, 2);
}

#[tokio::test]
async fn private_keys_are_kept_for_the_newest_two_gens_and_the_last_hour_only() {
    let w = StockWorld::new();
    w.room.join().await.unwrap();
    let g1 = w.stock().1;
    let mut later = Vec::new();
    for generation in [1u64, 2, 3] {
        w.kp_low(generation);
        w.advance(2 * HOUR_MS);
        w.room.join().await.unwrap();
        later.push(w.stock().1);
    }
    let (g2, g3, g4) = (&later[0], &later[1], &later[2]);
    // g4 and g3 are the newest two; g4 was minted just now, g3 two hours ago.
    assert!(w.client.holds_key_package(&g4[0]));
    assert!(w.client.holds_key_package(&g3[0]));
    assert!(
        !w.client.holds_key_package(&g2[0]),
        "third newest, older than an hour"
    );
    assert!(!w.client.holds_key_package(&g1[0]));
    // A gen minted within the last hour is kept even beyond the newest two.
    w.kp_low(4);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    let g5 = w.stock().1;
    w.kp_low(5);
    w.advance(KP_LOW_MIN_INTERVAL_MS);
    w.room.join().await.unwrap();
    let g6 = w.stock().1;
    for k in [&g4, &g5, &g6] {
        assert!(
            w.client.holds_key_package(&k[0]),
            "g4 is the third newest but was minted within the hour"
        );
    }
    assert!(!w.client.holds_key_package(&g3[0]));
}

#[tokio::test]
async fn single_packages_are_kept_seven_days_then_pruned() {
    let w = StockWorld::new();
    w.deliver(Frame::Group(GroupOp::KpReq {
        room: crate::geb::wire::RoomRef {
            id: ROOM.into(),
            name: None,
        },
    }));
    w.room.join().await.unwrap();
    let sent = w.sent();
    let kp = sent
        .iter()
        .find_map(|f| match f {
            Frame::Group(GroupOp::Kp { kp, .. }) => Some(kp.clone()),
            _ => None,
        })
        .expect("a kp answer");
    assert_outgoing_kp(&parse_kp(&kp), &w.dev, &w.me);
    w.advance(7 * DAY_MS - HOUR_MS);
    w.kp_low(1);
    w.room.join().await.unwrap();
    assert!(w.client.holds_key_package(&kp), "still inside 7 days");
    w.advance(2 * HOUR_MS);
    w.kp_low(2);
    w.room.join().await.unwrap();
    // The kp-low just answered pruned it.
    assert!(!w.client.holds_key_package(&kp), "pruned after 7 days");
}

#[tokio::test]
async fn seat_check_is_answered_with_the_minimal_rs_when_seated_and_not_otherwise() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    let check = |e| {
        Frame::Group(GroupOp::SeatCheck {
            room: crate::geb::wire::RoomRef {
                id: ROOM.into(),
                name: None,
            },
            e,
        })
    };
    // Unseated: nothing is sent for it (seat-ask is not built).
    let u = StockWorld::new();
    u.deliver(check(1));
    u.room.join().await.unwrap();
    assert!(
        u.sent()
            .iter()
            .all(|f| !matches!(f, Frame::Group(GroupOp::Rs { .. })))
    );
    w.seat().await;
    w.bus.take(&w.our_did, &w.a.did);
    // Seated: the next settle pass reads the dyad and answers the asker.
    w.bus.put(&w.a.did, &w.our_did, check(2));
    w.poll().await.unwrap();
    let out = w.bus.take(&w.our_did, &w.a.did);
    assert_eq!(
        out,
        vec![Frame::Group(GroupOp::Rs {
            room: Some(crate::geb::wire::RoomRef {
                id: ROOM.into(),
                name: None
            })
        })]
    );
    // Another room's seat-check is not ours.
    w.at(w.now() + 60_000);
    w.bus.put(
        &w.a.did,
        &w.our_did,
        Frame::Group(GroupOp::SeatCheck {
            room: crate::geb::wire::RoomRef {
                id: "other-room-9".into(),
                name: None,
            },
            e: 1,
        }),
    );
    w.poll().await.unwrap();
    assert!(w.bus.take(&w.our_did, &w.a.did).is_empty());
}

// ---- bridges refuse direct rooms (round 3 section 9) -----------------------

#[tokio::test]
async fn a_welcome_into_a_direct_room_is_refused_and_nothing_is_kept() {
    let probe = World::build(Arc::new(NoLocalKnowledge), "");
    let (lo, hi) = {
        let mut p = [probe.a.did.clone(), probe.b.did.clone()];
        p.sort();
        (p[0].clone(), p[1].clone())
    };
    for direct in [
        format!(r#","direct":["{lo}","{hi}"]"#),
        // Read raw: even a pair parse_policy would clean away still counts.
        r#","direct":["not-a-did"]"#.to_string(),
    ] {
        let mut w = World::build(Arc::new(NoLocalKnowledge), &direct);
        assert_eq!(w.room.join().await.unwrap(), JoinState::Pending);
        let stock = w.bus.take(&w.our_did, &w.a.did);
        let Some(Frame::Group(GroupOp::KpStock { kps, .. })) = stock.first().cloned() else {
            panic!("no kp-stock")
        };
        let (_commit, welcome) = w.a.stage_add(parse_kp(&kps[0]));
        w.a.merge_pending();
        w.bus.put(
            &w.a.did,
            &w.our_did,
            welcome_frame(ROOM, &w.a.did, &w.policy, &welcome),
        );
        let e = w.room.join().await.unwrap_err();
        assert!(matches!(e, Error::Refused(_)), "{e:?}");
        assert!(e.to_string().contains("direct room"), "{e}");
        assert_eq!(w.client.epoch(), None, "not seated, no group kept");
        assert!(w.client.members().is_empty());
    }
}
