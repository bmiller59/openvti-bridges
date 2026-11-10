//! The suite against the core's in-memory loopback room: the reference, with
//! nothing unsupported.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use async_trait::async_trait;
use openvti_bridge_conformance::{CASES, Fixture, Knobs, Outcome, Peer, Rig, Staged, run_all};
use openvti_bridge_core::Result;
use openvti_bridge_core::loopback::Loopback;
use std::sync::Arc;

struct Side(Arc<Loopback>);

#[async_trait]
impl Peer for Side {
    async fn say(&self, text: &str, at_ms: u64) -> Result<()> {
        self.0.inject("did:key:zPeer", text, at_ms)
    }
}

impl Knobs for Side {
    fn set_pending(&self, pending: bool) -> Staged {
        self.0.set_pending(pending).ok();
        Ok(())
    }
    fn refuse(&self, why: &str) -> Staged {
        self.0.refuse(why).ok();
        Ok(())
    }
    fn fail_posts(&self, permanent: Option<bool>) -> Staged {
        self.0.fail_posts(permanent).ok();
        Ok(())
    }
}

struct LoopbackFixture;

#[async_trait]
impl Fixture for LoopbackFixture {
    async fn fresh(&self) -> Rig {
        let room = Arc::new(Loopback::new("bridge"));
        Rig {
            room: room.clone(),
            peer: Box::new(Side(room.clone())),
            knobs: Box::new(Side(room)),
        }
    }
}

#[tokio::test]
async fn loopback_passes_every_case_with_none_unsupported() {
    let out = run_all(&LoopbackFixture).await;
    assert_eq!(out.len(), CASES.len());
    for (name, o) in out {
        assert_eq!(o, Outcome::Passed, "{name}");
    }
}
