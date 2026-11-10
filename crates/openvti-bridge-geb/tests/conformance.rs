//! The shared conformance suite against the Geb room, in process: two
//! `GebRoom`s over the `FakeRelay` and the `FakeGroup` double (no MLS, no
//! network). This is the repository's own reading of Geb, not byte
//! compatibility with a real node.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use openvti_bridge_conformance::{
    CASES, Fixture, Knobs, Outcome, Peer, Rig, Staged, Unsupported, run_all,
};
use openvti_bridge_core::Result;
use openvti_bridge_core::foreign::{ForeignRoom, JoinState};
use openvti_bridge_core::model::{BridgeEvent, EventKind, Origin};
use openvti_bridge_geb::codec::GuideCodec;
use openvti_bridge_geb::crypto::did_peer;
use openvti_bridge_geb::crypto::sign::LocalSigner;
use openvti_bridge_geb::fake::{FakeGroup, FakeRelay};
use openvti_bridge_geb::room::GebRoom;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// The most unsupported cases this adapter may report. Each is written down in
/// the `Unsupported` reason; raising this needs a reason too.
const MAX_UNSUPPORTED: usize = 1;

const NOW_MS: u64 = 1_700_000_100_000;

fn member(
    relay: &Arc<FakeRelay>,
    seed: u8,
    clock: openvti_bridge_geb::room::Clock,
) -> (Arc<GebRoom>, Arc<FakeGroup>) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let did = did_peer::encode(&key.verifying_key().to_bytes(), &[seed; 32], None).unwrap();
    let group = Arc::new(FakeGroup::new(&did));
    let room = Arc::new(GebRoom::new(
        "room-1".into(),
        relay.clone(),
        group.clone(),
        Arc::new(LocalSigner::new(did, key)),
        Arc::new(GuideCodec),
        clock,
    ));
    (room, group)
}

/// The peer posts at the time it is told to say a line, so lines carry distinct
/// relay timestamps.
struct Peerless(Arc<GebRoom>, Arc<AtomicU64>);

#[async_trait]
impl Peer for Peerless {
    async fn say(&self, text: &str, at_ms: u64) -> Result<()> {
        self.1.store(at_ms, Ordering::SeqCst);
        self.0
            .post(&BridgeEvent {
                origin: Origin::Vtc,
                origin_id: format!("peer|{at_ms}"),
                link: "l1".into(),
                author: "did:key:zPeer".into(),
                at: at_ms,
                title: None,
                text: text.into(),
                kind: EventKind::Post,
                reply_to: None,
                record_key: None,
                provenance: None,
            })
            .await
            .map(|_| ())
    }
}

struct GebKnobs(Arc<FakeGroup>);

impl Knobs for GebKnobs {
    fn set_pending(&self, pending: bool) -> Staged {
        self.0.set_join_state(if pending {
            JoinState::Pending
        } else {
            JoinState::Seated
        });
        Ok(())
    }
    fn refuse(&self, why: &str) -> Staged {
        self.0.refuse(why);
        Ok(())
    }
    fn fail_posts(&self, _permanent: Option<bool>) -> Staged {
        Err(Unsupported(
            "the FakeRelay stages dropped frames, not classified post failures; the classes are held by the room and relay unit tests",
        ))
    }
}

struct GebFixture;

#[async_trait]
impl Fixture for GebFixture {
    async fn fresh(&self) -> Rig {
        let relay = Arc::new(FakeRelay::new());
        let (ours, group) = member(&relay, 1, Arc::new(|| NOW_MS));
        let at = Arc::new(AtomicU64::new(NOW_MS - 10_000));
        let c = at.clone();
        let (theirs, _) = member(&relay, 2, Arc::new(move || c.load(Ordering::SeqCst)));
        Rig {
            room: ours,
            peer: Box::new(Peerless(theirs, at)),
            knobs: Box::new(GebKnobs(group)),
        }
    }
}

#[tokio::test]
async fn geb_passes_every_case_it_can_stage_and_writes_down_the_rest() {
    let out = run_all(&GebFixture).await;
    assert_eq!(out.len(), CASES.len());
    let skipped: Vec<_> = out
        .iter()
        .filter(|(_, o)| matches!(o, Outcome::Unsupported(_)))
        .collect();
    assert!(
        skipped.len() <= MAX_UNSUPPORTED,
        "too many unsupported cases: {skipped:?}"
    );
}
