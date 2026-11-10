//! Full-stack, in-process, offline end to end.
//!
//! Room side (all real except the VTA): a `room-host` on a TCP port, the room
//! fixture, `VtcRoom` over a `VtaClient` whose VTA is the harness `TestVta`.
//! Bridge (the production assembly, `wiring::assemble`): fjall store, sealed
//! state, `StatefulDyad`, `MlsGroupClient`, `GebRoom`, the pump. Keys come from
//! `geb::custody::mint_device_identity` against the key-serving fake VTA and live in
//! the bridge's own secret store. Geb side: the in-process `TestRelay` over
//! real websockets, and a Geb member played by `geb::mls::sim::Sim` (an
//! independent OpenMLS client, written from the guide) with its own real
//! `StatefulDyad`.
//!
//! WHAT THIS DOES NOT PROVE: byte-compatibility with real Geb. The relay is
//! this crate's test relay, the Geb member is this crate's own reading of the
//! guide and answers, and the MLS framing choices listed at the top of
//! `geb/mls/mod.rs` are unverified against Geb's code. It does not exercise
//! the wss/TLS path, a real VTA (the persona's room operations are the harness
//! fake), a sealed-tier room, a mid-step crash (the `harness.rs` tests
//! kill the pump between every pair of store operations; here a "kill" is a
//! drop-and-reboot between steps), or Geb's persona cards and signed leaves.
//! A VTC-side edit and retraction are carried for real (a tombstone on the
//! host becomes a reply line).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::key_vta::KeyVta;
use common::world::*;
use ed25519_dalek::SigningKey;
use openmls::prelude::*;
use openvti_bridges::config::{Directions, LinkConfig, SecretsConfig, Tier};
use openvti_bridges::custody::{SecretStore, VtaKeyMinter};
use openvti_bridges::fjall_store::FjallStore;
use openvti_bridges::foreign::JoinState;
use openvti_bridges::geb::codec::GuideCodec;
use openvti_bridges::geb::crypto::{b64_decode, pair};
use openvti_bridges::geb::custody::mint_device_identity;
use openvti_bridges::geb::dyad::{GebIdentity, Phase, StatefulDyad};
use openvti_bridges::geb::event::KIND_MAILBOX;
use openvti_bridges::geb::mls::sim::{Sim, mc, ml, post, welcome_frame};
use openvti_bridges::geb::nostr::{NostrConfig, NostrRelay};
use openvti_bridges::geb::policy::CommitCheckInputs;
use openvti_bridges::geb::test_relay::TestRelay;
use openvti_bridges::geb::traits::{GebCodec, GebDyad, GebRelay, GebSigner};
use openvti_bridges::geb::wire::{Envelope, Frame, GroupOp};
use openvti_bridges::geb::{GebConfig, GebLinkConfig};
use openvti_bridges::halt::{self, ClearConfirmation, Cleared, HaltReason};
use openvti_bridges::ops;
use openvti_bridges::pump::TickReport;
use openvti_bridges::room::PROVENANCE_OPEN;
use openvti_bridges::run::{End, Health, LinkTick, Timing, supervise};
use openvti_bridges::secrets::{BridgeSecrets, LinkSecrets};
use openvti_bridges::store::BridgeStore;
use openvti_bridges::wiring::{LinkInputs, LinkParts, assemble};
use openvti_bridges::{Error, Result};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tls_codec::Deserialize as _;
use vta_sdk::client::VtaClient;

const T0: u64 = 1_700_000_000;
const ROOM: &str = "geb-room-0001";

fn relay_cfg(url: &str) -> NostrConfig {
    let mut c = NostrConfig::new(url);
    c.op_timeout = Duration::from_secs(8);
    c.backoff_min = Duration::from_millis(10);
    c.backoff_max = Duration::from_millis(80);
    c
}

/// A Geb member: the independent OpenMLS client and a real dyad under the
/// same device DID (the `Sim`'s DID is replaced by the dyad identity's).
struct Member {
    sim: Sim,
    dyad: StatefulDyad,
    relay: Arc<dyn GebRelay>,
    seen: HashSet<String>,
}

fn member(seed: u8, relay_url: &str, now: &Arc<AtomicU64>) -> Member {
    let id =
        Arc::new(GebIdentity::new(SigningKey::from_bytes(&[seed; 32]), [seed + 100; 32]).unwrap());
    let mut sim = Sim::new(seed);
    sim.did = id.did().to_string();
    sim.cred = CredentialWithKey {
        credential: Credential::new(CredentialType::Basic, sim.did.as_bytes().to_vec()),
        signature_key: sim.signer.public().into(),
    };
    let relay: Arc<dyn GebRelay> = Arc::new(NostrRelay::new(relay_cfg(relay_url)).unwrap());
    let n = now.clone();
    let dyad = StatefulDyad::new(
        id,
        relay.clone(),
        Arc::new(openvti_bridges::store::MemoryStore::new()),
        Arc::new(move || n.load(Ordering::SeqCst) * 1000),
    );
    Member {
        sim,
        dyad,
        relay,
        seen: HashSet::new(),
    }
}

impl Member {
    /// Lines in the room mailbox that this member has not read yet.
    async fn new_lines(&mut self) -> Vec<(String, openvti_bridges::geb::wire::LineBody)> {
        let keys = self.sim.keys(ROOM);
        let mailbox = keys.pubkey_hex().unwrap();
        let mut evs = self
            .relay
            .fetch(KIND_MAILBOX, &mailbox, None)
            .await
            .unwrap();
        evs.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let mut out = Vec::new();
        for ev in evs {
            if !self.seen.insert(ev.id.clone()) {
                continue;
            }
            let Ok(bytes) = pair::open(&keys, KIND_MAILBOX, &ev.content) else {
                continue;
            };
            let Ok(Envelope::Ml { m }) = GuideCodec.decode_envelope(&bytes) else {
                continue;
            };
            // Our own lines and the bridge's: only the bridge's open here.
            if let Some(line) = self.sim.open_line(&b64_decode(&m).unwrap()) {
                out.push(line);
            }
        }
        out
    }

    async fn says(&mut self, now: &AtomicU64, text: &str) {
        let at = now.load(Ordering::SeqCst);
        let bytes = self.sim.seal_line(ROOM, at * 1000, text, true);
        post(&self.relay, &self.sim.keys(ROOM), &ml(&bytes), at).await;
    }
}

/// Test fake: everything is known, nobody is the same person as anybody else,
/// nobody has left. NOT Geb's persona cards; it exists to reach the merge
/// paths that `NoLocalKnowledge` (production) refuses.
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

struct Env {
    world: World,
    relay: TestRelay,
    now: Arc<AtomicU64>,
    dir: tempfile::TempDir,
    secrets: LinkSecrets,
    store_key: [u8; 32],
    link: LinkConfig,
    a: Member,
    policy: String,
    inputs: Option<Arc<dyn CommitCheckInputs>>,
}

struct Proc {
    parts: LinkParts,
    store: Arc<FjallStore>,
}

impl Env {
    async fn new(inputs: Option<Arc<dyn CommitCheckInputs>>) -> Env {
        let host = start_host().await;
        let world = World::new(&host).await;
        let now = Arc::new(AtomicU64::new(T0));
        let relay = TestRelay::start(now.clone()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();

        // Custody: mint through the fake VTA, keep only in the secret store,
        // read it back as the process would.
        let kv = Arc::new(KeyVta::default());
        let kvc = VtaClient::loopback(kv.clone());
        let minted = mint_device_identity(&VtaKeyMinter(&kvc), "openvti-bridges", "l1")
            .await
            .unwrap()
            .into_link_secrets(world.persona())
            .unwrap();
        let mut blob = BridgeSecrets::new();
        let store_key = *blob.store_key().unwrap();
        blob.insert("l1", minted).unwrap();
        let cfg = SecretsConfig(
            toml::from_str("backend = \"plaintext\"\nallow_plaintext = true\ncache_ttl_secs = 0")
                .unwrap(),
        );
        let ss = SecretStore::open(&cfg, dir.path()).unwrap();
        ss.save(&blob).await.unwrap();
        let secrets = ss
            .load()
            .await
            .unwrap()
            .unwrap()
            .link("l1")
            .unwrap()
            .clone();
        assert_eq!(kv.exported.lock().unwrap().len(), 2, "device keys only");

        let mut a = member(1, &relay.url(), &now);
        let policy = format!(
            r#"{{"v":2,"committer":"any-staged","settleWindowMs":3000,"root":"{}","admins":[]}}"#,
            a.sim.did
        );
        a.sim.create_room(ROOM, &policy);
        let link = LinkConfig {
            id: "l1".into(),
            vtc_room: world.fixture.room.room_id.clone(),
            host_did: "did:key:zHost".into(),
            host_url: Some(world.host.url.clone()),
            persona: world.persona().to_string(),
            kind: "geb".into(),
            adapter: std::collections::BTreeMap::from([(
                "geb".to_string(),
                GebLinkConfig {
                    room_id: ROOM.into(),
                    peers: vec![a.sim.did.clone()],
                }
                .to_table(),
            )]),
            deny_authors: Vec::new(),
            directions: Directions::Both,
            tier: Tier::Open,
            tier_optin: true,
            poll_secs: 1,
            enabled: true,
            display_name: None,
            announce: false,
            notices: Default::default(),
            retention_days: openvti_bridges::pump::DEFAULT_RETENTION_DAYS,
        };
        Env {
            world,
            relay,
            now,
            dir,
            secrets,
            store_key,
            link,
            a,
            policy,
            inputs,
        }
    }

    fn secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn tick(&self) {
        self.now.fetch_add(1, Ordering::SeqCst);
    }
    fn link_dir(&self) -> std::path::PathBuf {
        openvti_bridges::wiring::link_dir(self.dir.path(), "l1")
    }

    fn try_boot_with(&self, store_key: [u8; 32]) -> Result<Proc> {
        let dir = self.link_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let store = Arc::new(FjallStore::open(&dir.join("store"))?);
        let n = self.now.clone();
        let parts = assemble(LinkInputs {
            link: self.link.clone(),
            geb: GebConfig::default(),
            secrets: self.secrets.clone(),
            store_key: zeroize::Zeroizing::new(store_key),
            dir,
            store: store.clone(),
            relay: Arc::new(NostrRelay::new(relay_cfg(&self.relay.url()))?),
            vta: Arc::new(VtaClient::loopback(self.world.vta.clone())),
            host: openvti_bridges::vtc::host::HostDelivery::for_loopback_tests(
                &self.world.host.url,
            ),
            clock: Arc::new(move || n.load(Ordering::SeqCst) * 1000),
            commit_inputs: self.inputs.clone(),
            pause: None,
        })?;
        Ok(Proc { parts, store })
    }

    fn boot(&self) -> Proc {
        self.try_boot_with(self.store_key).unwrap()
    }
}

/// A Geb member's KeyPackage out of a `kp-stock` entry.
fn parse_kp(b64: &str) -> KeyPackage {
    use openmls_traits::OpenMlsProvider;
    let bytes = STANDARD.decode(b64).unwrap();
    KeyPackageIn::tls_deserialize_exact(&bytes)
        .unwrap()
        .validate(
            openmls_rust_crypto::OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .unwrap()
}

/// Connect (ours is the inviter), driving A's side concurrently.
async fn connect(env: &mut Env, p: &Proc) {
    let a_did = env.a.sim.did.clone();
    let our_did = p.parts.device_did.clone();
    let now = env.now.clone();
    let driver = async {
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            now.fetch_add(1, Ordering::SeqCst);
            for inv in env.a.dyad.invitations().await.unwrap() {
                env.a.dyad.accept(&inv).await.unwrap();
            }
            let _ = env.a.dyad.sync(&our_did).await;
            if env.a.dyad.phase(&our_did).await.unwrap() == Some(Phase::Connected) {
                return;
            }
        }
        panic!("A never connected");
    };
    let (ours, ()) = tokio::join!(
        ops::connect(
            &p.parts,
            &a_did,
            Some("bridge"),
            Duration::from_secs(20),
            Duration::from_millis(25),
        ),
        driver
    );
    assert_eq!(ours.unwrap(), Phase::Connected);
}

fn bridged_by(records: &[openvti_bridges::room::RoomRecord], persona: &str) -> usize {
    records
        .iter()
        .filter(|r| r.author == persona && r.body.starts_with(PROVENANCE_OPEN))
        .count()
}

/// Dyad connect, KeyPackage stock, seated by Welcome, both directions, an
/// edit and a retraction as reply lines, and a reboot between every step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_whole_stack_connects_seats_relays_and_survives_restarts() {
    let mut env = Env::new(None).await;
    let persona = env.world.persona().to_string();
    let a_did = env.a.sim.did.clone();
    let mut p = env.boot();

    // --- dyad connect (Geb member <-> bridge), over real websockets.
    connect(&mut env, &p).await;
    assert_eq!(
        p.parts.dyad.phase(&a_did).await.unwrap(),
        Some(Phase::Connected)
    );

    // --- KeyPackage stock; the member takes one and welcomes us.
    assert_eq!(ops::stock_kps(&p.parts).await.unwrap(), JoinState::Pending);
    env.tick();
    let frames = env.a.dyad.recv(&p.parts.device_did).await.unwrap();
    let kps = frames
        .iter()
        .find_map(|f| match f {
            Frame::Group(GroupOp::KpStock { kps, .. }) => Some(kps.clone()),
            _ => None,
        })
        .expect("a kp-stock arrived over the dyad");
    assert_eq!(kps.len(), 6, "Geb sends six per stock");
    let (_commit, welcome) = env.a.sim.stage_add(parse_kp(&kps[0]));
    env.a.sim.merge_pending();
    env.a
        .dyad
        .send(
            &p.parts.device_did,
            &welcome_frame(ROOM, &a_did, &env.policy, &welcome),
        )
        .await
        .unwrap();
    env.tick();

    // --- seated via the Welcome (the pump joins).
    assert_eq!(p.parts.pump.start().await.unwrap(), JoinState::Seated);
    assert_eq!(p.parts.group.members().len(), 2);

    // --- restart 1: nothing is re-seated, nothing is sent again.
    drop(p);
    p = env.boot();
    assert_eq!(p.parts.pump.start().await.unwrap(), JoinState::Seated);
    assert!(
        p.parts.group.epoch().is_some(),
        "resumed seated from sealed state"
    );

    // --- a room record appears in the Geb room exactly once.
    env.world.human_writes("k1", "Plan", "hello geb").await;
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!((r.posted, r.written), (1, 0));
    env.tick();
    let lines = env.a.new_lines().await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].1.text.contains("hello geb"));
    assert_eq!(lines[0].0, p.parts.device_did);
    assert!(lines[0].1.sg.is_some(), "the bridge signs as itself");
    let again = p.parts.pump.tick().await.unwrap();
    assert_eq!((again.posted, again.written), (0, 0));
    assert!(env.a.new_lines().await.is_empty());

    // --- restart 2: the record is not posted a second time.
    drop(p);
    p = env.boot();
    p.parts.pump.start().await.unwrap();
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!((r.posted, r.written), (0, 0));
    assert!(env.a.new_lines().await.is_empty());

    // --- a Geb member's signed line becomes exactly one `observed` record.
    env.a.says(&env.now, "hi from geb").await;
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!((r.posted, r.written), (0, 1));
    let recs = env.world.records().await;
    assert_eq!(bridged_by(&recs, &persona), 1, "{recs:?}");
    let rec = recs
        .iter()
        .find(|r| r.body.contains("hi from geb"))
        .expect("the line is a record");
    assert!(rec.body.contains("\"basis\":\"observed\""), "{}", rec.body);
    assert!(rec.body.contains("Quoted, untrusted"));
    assert!(rec.body.contains(&a_did), "carries the signed author");
    // Not echoed back to Geb, and a second tick adds nothing.
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!((r.posted, r.written), (0, 0));
    assert!(env.a.new_lines().await.is_empty());

    // --- the process is down while the member speaks; on boot, one record.
    drop(p);
    env.a.says(&env.now, "said while you were away").await;
    env.tick();
    p = env.boot();
    p.parts.pump.start().await.unwrap();
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!(r.written, 1, "opened under the restored MLS state");
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!(r.written, 0);
    assert_eq!(bridged_by(&env.world.records().await, &persona), 2);

    // --- an edit in the room becomes a reply line (Geb has no edit).
    env.world
        .human_edits("k1", "Plan", "hello geb, revised", 1)
        .await;
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!(r.posted, 1);
    env.tick();
    let lines = env.a.new_lines().await;
    assert_eq!(lines.len(), 1);
    assert!(lines[0].1.text.contains("revised"));
    let original = p
        .parts
        .store
        .xref_get("vtc:k1|1")
        .await
        .unwrap()
        .filter(|s| !s.is_empty())
        .expect("the original line's id was kept");
    // The edit's `re` is the earlier line of the same record KEY (the host's
    // version is room-wide arrival order, so the key decides, not `version`).
    assert_eq!(lines[0].1.re.as_deref(), Some(original.as_str()));
    let edit_origin = p
        .parts
        .store
        .xref_get("vtkey:k1")
        .await
        .unwrap()
        .expect("the key is marked bridged at its newest version");
    assert_ne!(edit_origin, "k1|1");
    let edit_line = p
        .parts
        .store
        .xref_get(&format!("vtc:{edit_origin}"))
        .await
        .unwrap()
        .filter(|s| !s.is_empty())
        .expect("the edit line's id was kept");

    // --- a retraction in the room (a real tombstone on the host) becomes a
    // reply line to the newest bridged line of that key: an ordinary signed
    // line with `re`, never a new kind.
    env.world.human_retracts("k1").await;
    env.tick();
    let r = p.parts.pump.tick().await.unwrap();
    assert_eq!(r.posted, 1);
    env.tick();
    let lines = env.a.new_lines().await;
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].1.re.as_deref(), Some(edit_line.as_str()));
    assert!(lines[0].1.text.contains("[retracted: earlier post"));

    // --- state at rest: the ratchet record and the MLS files are sealed.
    let raw = p
        .store
        .state_get("geb/ratchets", &a_did)
        .await
        .unwrap()
        .expect("a ratchet record exists");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&raw).is_err(),
        "ratchet state is not plaintext JSON"
    );
    for f in ["mls-state.enc", "mls-sigkey.enc"] {
        let bytes = std::fs::read(env.link_dir().join(f)).unwrap();
        assert!(
            !bytes.windows(ROOM.len()).any(|w| w == ROOM.as_bytes()),
            "{f} holds the room id in clear"
        );
    }
    // A wrong store key does not open any of it.
    drop(p);
    assert!(env.try_boot_with([9u8; 32]).is_err());
    // And the right one still does, with the cursors intact.
    let p = env.boot();
    let st = ops::status(&*p.parts.store).await.unwrap();
    assert!(st.browse_version >= 1 && st.halted.is_none());
    assert!(st.last_relayed_secs.is_some());
    assert_eq!(st.outbox_depth, 0);
}

/// A commit that removes us halts the link, raises the alert, and the halt
/// survives a restart (production inputs stop the poll instead; see below).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remove_us_commit_halts_the_link_and_stays_halted() {
    let mut env = Env::new(Some(Arc::new(AllKnown))).await;
    let a_did = env.a.sim.did.clone();
    let p = env.boot();
    connect(&mut env, &p).await;
    ops::stock_kps(&p.parts).await.unwrap();
    env.tick();
    let kps = env
        .a
        .dyad
        .recv(&p.parts.device_did)
        .await
        .unwrap()
        .into_iter()
        .find_map(|f| match f {
            Frame::Group(GroupOp::KpStock { kps, .. }) => Some(kps),
            _ => None,
        })
        .unwrap();
    let (_c, welcome) = env.a.sim.stage_add(parse_kp(&kps[0]));
    env.a.sim.merge_pending();
    env.a
        .dyad
        .send(
            &p.parts.device_did,
            &welcome_frame(ROOM, &a_did, &env.policy, &welcome),
        )
        .await
        .unwrap();
    env.tick();
    assert_eq!(p.parts.pump.start().await.unwrap(), JoinState::Seated);

    // The founder removes us: the commit goes out under the parent epoch's
    // keys, and the settle window (3 s) passes.
    let our_did = p.parts.device_did.clone();
    let commit = env.a.sim.stage_remove(&our_did);
    post(
        &env.a.relay,
        &env.a.sim.keys(ROOM),
        &mc(env.a.sim.epoch(), &commit),
        env.secs(),
    )
    .await;
    env.a.sim.merge_pending();
    env.tick();
    let first = p.parts.pump.tick().await;
    assert!(first.is_ok(), "held for the settle window: {first:?}");
    for _ in 0..5 {
        env.tick();
    }
    // Supervised: the removal is a refusal, so supervision ends Halted.
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let pump: Arc<dyn LinkTick> = p.parts.pump.clone();
    let end = supervise(
        "l1",
        pump,
        Timing {
            poll: Duration::from_millis(10),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(20),
            min_healthy: Duration::from_millis(50),
        },
        rx,
        Arc::new(Health::default()),
    )
    .await;
    let End::Halted(why) = end else {
        panic!("expected the link to halt, got {end:?}")
    };
    assert!(why.contains("removed"), "{why}");
    let st = ops::status(&*p.parts.store).await.unwrap();
    assert!(
        st.halted
            .as_ref()
            .is_some_and(|w| w.detail().contains("removed"))
    );

    // Restart: still halted, without the process touching the Geb room.
    drop(p);
    let p = env.boot();
    let e = p.parts.pump.tick().await.unwrap_err();
    assert!(
        matches!(e, Error::Refused(ref w) if w.contains("link stopped")),
        "{e}"
    );
    assert!(matches!(
        p.parts.pump.start().await.unwrap_err(),
        Error::Refused(_)
    ));
    let end = supervise(
        "l1",
        p.parts.pump.clone(),
        Timing::for_poll_secs(1),
        tokio::sync::watch::channel(false).1,
        Arc::new(Health::default()),
    )
    .await;
    assert!(
        matches!(end, End::Halted(_)),
        "a restarted link stays halted"
    );
}

/// Production inputs (no persona cards, no signed leaves) cannot evaluate a
/// commit that removes a different member from a sender who is neither root
/// nor admin: merging or skipping could fork the epoch, so the link halts, persisted and distinct from a refusal (`geb.undecidable-commit`,
/// epoch and commit hash recorded), alerts once, and stays halted across a
/// restart until an operator clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_production_inputs_an_undecidable_removal_halts_persistently() {
    let mut env = Env::new(None).await;
    let a_did = env.a.sim.did.clone();
    let p = env.boot();
    connect(&mut env, &p).await;
    ops::stock_kps(&p.parts).await.unwrap();
    env.tick();
    let kps = env
        .a
        .dyad
        .recv(&p.parts.device_did)
        .await
        .unwrap()
        .into_iter()
        .find_map(|f| match f {
            Frame::Group(GroupOp::KpStock { kps, .. }) => Some(kps),
            _ => None,
        })
        .unwrap();
    // A second, ordinary member joins first: root's own removes are decided
    // without persona cards, so the halt needs a non-root sender removing a
    // DIFFERENT DID (here B removing the bridge).
    let mut b = Sim::new(2);
    let (_cb, welcome_b) = env.a.sim.stage_add(b.key_package());
    env.a.sim.merge_pending();
    b.join(&welcome_b);
    let (commit_in, welcome) = env.a.sim.stage_add(parse_kp(&kps[0]));
    env.a.sim.merge_pending();
    b.apply(&commit_in).unwrap();
    env.a
        .dyad
        .send(
            &p.parts.device_did,
            &welcome_frame(ROOM, &a_did, &env.policy, &welcome),
        )
        .await
        .unwrap();
    env.tick();
    p.parts.pump.start().await.unwrap();
    let commit = b.stage_remove(&p.parts.device_did);
    post(
        &env.a.relay,
        &b.keys(ROOM),
        &mc(b.epoch(), &commit),
        env.secs(),
    )
    .await;
    env.tick();
    let _ = p.parts.pump.tick().await;
    for _ in 0..5 {
        env.tick();
    }
    let e: Result<TickReport> = p.parts.pump.tick().await;
    assert!(matches!(e, Err(Error::AdapterHalt { .. })), "{e:?}");
    let st = ops::status(&*p.parts.store).await.unwrap();
    let Some(HaltReason::Adapter { code, detail }) = st.halted else {
        panic!(
            "expected a persisted undecidable-commit halt, got {:?}",
            st.halted
        )
    };
    assert_eq!(code, "geb.undecidable-commit");
    assert!(
        detail.contains("epoch ") && detail.contains("commit "),
        "{detail}"
    );

    // Later ticks answer from the record (no re-evaluation, no new alert).
    let e = p.parts.pump.tick().await.unwrap_err();
    assert!(
        matches!(e, Error::AdapterHalt { ref detail, .. } if detail.contains("link stopped")),
        "{e}"
    );

    // Restart: still halted, and the supervisor ends halted instead of
    // retrying with backoff.
    drop(p);
    let p = env.boot();
    let end = supervise(
        "l1",
        p.parts.pump.clone(),
        Timing::for_poll_secs(1),
        tokio::sync::watch::channel(false).1,
        Arc::new(Health::default()),
    )
    .await;
    assert!(
        matches!(end, End::Halted(ref w) if w.contains("undecidable")),
        "{end:?}"
    );

    // The operator clears it (after being told what it was).
    let store = &*p.parts.store;
    assert!(
        halt::clear(store, ClearConfirmation::default())
            .await
            .is_err(),
        "--yes is required"
    );
    assert!(halt::read(store).await.unwrap().is_some());
    let cleared = halt::clear(
        store,
        ClearConfirmation {
            yes: true,
            readmitted: false,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        cleared,
        Cleared::Cleared(HaltReason::Adapter { .. })
    ));
    assert!(ops::status(store).await.unwrap().halted.is_none());
    // Still undecidable once the commit is read again: halts again at once.
    // (The held queue does not survive a restart: the commit is read from the
    // relay again, held for the settle window, then judged again.)
    let _ = p.parts.pump.tick().await;
    for _ in 0..5 {
        env.tick();
    }
    let e = p.parts.pump.tick().await;
    assert!(matches!(e, Err(Error::AdapterHalt { .. })), "{e:?}");
    assert!(ops::status(store).await.unwrap().halted.is_some());
}
