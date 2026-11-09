//! Tests of the Geb-side MLS client against an in-process second OpenMLS
//! client playing a Geb member (`sim.rs`). Self-consistency only: this is not
//! evidence of byte-compatibility with real Geb.

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
use tls_codec::Deserialize as _;

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
        let client = Arc::new(
            MlsGroupClient::new(
                MlsConfig::new(ROOM, vec![a.did.clone()]),
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

fn parse_kp(b64: &str) -> KeyPackage {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    KeyPackageIn::tls_deserialize_exact(&bytes)
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
    let kp = id.key_package(&p, &signer).unwrap();
    assert_eq!(kp.ciphersuite(), SUITE);
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

// ---- partial local knowledge ---------------------------------------------------

#[tokio::test]
async fn without_local_knowledge_adds_merge_and_removes_and_policy_changes_stop_the_bridge() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    // An Add-only commit is merged.
    let newbie = Sim::new(12);
    let (c, _) = w.a.stage_add(newbie.key_package());
    w.post_mc(&w.a, &c).await;
    w.a.merge_pending();
    w.b.apply(&c).unwrap();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    w.poll().await.unwrap();
    assert!(w.client.members().contains(&newbie.did));
    assert!(w.our_keys_match(&w.a));
    let epoch = w.client.epoch().unwrap();
    let keys_before = w.client.relay_keys().unwrap().pubkey_hex().unwrap();

    // A Remove (even by root) is neither merged nor skipped: the poll errors.
    w.at(w.now() + 10_000);
    let b_did = w.b.did.clone();
    let c = w.a.stage_remove(&b_did);
    w.post_mc(&w.a, &c).await;
    w.a.drop_pending();
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

    // Same for a policy change, in a fresh world.
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let c = w.a.stage_policy(&policy(&w.a.did, r#","edit":"all""#));
    w.post_mc(&w.a, &c).await;
    w.a.drop_pending();
    let t = w.now();
    w.poll().await.unwrap();
    w.at(t + 3000);
    assert!(matches!(w.poll().await, Err(Error::UndecidableCommit(_))));
}

#[tokio::test]
async fn a_lower_hash_undecidable_commit_blocks_even_when_a_higher_one_is_fine() {
    let mut w = World::build(Arc::new(NoLocalKnowledge), "");
    w.seat().await;
    let b_did = w.b.did.clone();
    let (cr, cu) = staged_pair(
        &mut w.a,
        &mut w.b,
        true,
        &|s| s.stage_remove(&b_did),
        &|s| s.stage_self_update(),
    );
    w.post_mc(&w.a, &cr).await;
    w.post_mc(&w.b, &cu).await;
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
    let mut w = World::build(
        Arc::new(NoLocalKnowledge),
        &format!(r#","direct":["{lo}","{hi}"]"#),
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
