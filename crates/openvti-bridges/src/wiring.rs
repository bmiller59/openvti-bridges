//! Assembling one running link from its parts (features `vtc` and `geb-mls`):
//! the VTC room side over the user's VTA, the Geb side (relay, stateful dyad,
//! MLS group, `GebRoom`) with its state sealed at rest, and the pump between.
//!
//! The binary and the end-to-end tests build a link through the same
//! [`assemble`], so the test stack is the production stack with a loopback
//! relay and a fake VTA substituted at the edges.
//!
//! Layout under `<data_dir>/links/<link id>/`: `store/` (fjall), `mls-state.enc`
//! (the OpenMLS key store snapshot) and `mls-sigkey.enc` (the MLS signature
//! key). One link per directory keeps each link's cursors, halt record and
//! ratchets apart, and its dyad state under its own device DID.

use crate::atrest::{AtRestKey, EncryptedState, SealedFile};
use crate::config::{GebConfig, LinkConfig};
use crate::custody::LinkSecrets;
use crate::geb::codec::GuideCodec;
use crate::geb::dyad::StatefulDyad;
use crate::geb::mls::{MlsConfig, MlsGroupClient};
use crate::geb::policy::{CommitCheckInputs, NoLocalKnowledge};
use crate::geb::room::{Clock, GebRoom};
use crate::geb::traits::{GebRelay, GebSigner};
use crate::pause::PauseSource;
use crate::pump::{LinkRuntime, Pump};
use crate::store::BridgeStore;
use crate::vtc::host::HostDelivery;
use crate::vtc::{VtcRoom, VtcRoomConfig};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vta_sdk::client::VtaClient;

/// `<data_dir>/links/<id>`.
pub fn link_dir(data_dir: &Path, link_id: &str) -> PathBuf {
    data_dir.join("links").join(link_id)
}

/// The wall clock in milliseconds.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}

/// Everything one link is built from.
pub struct LinkInputs {
    /// The link's configuration.
    pub link: LinkConfig,
    /// The `[geb]` table.
    pub geb: GebConfig,
    /// The link's device keys and secrets.
    pub secrets: LinkSecrets,
    /// The secret-store key at-rest keys derive from.
    pub store_key: zeroize::Zeroizing<[u8; 32]>,
    /// The link's directory ([`link_dir`]).
    pub dir: PathBuf,
    /// The link's durable store, before encryption is layered on.
    pub store: Arc<dyn BridgeStore>,
    /// The Nostr relay (one per device identity).
    pub relay: Arc<dyn GebRelay>,
    /// A client for the user's VTA, in the `openvti-bridges` context.
    pub vta: Arc<VtaClient>,
    /// Delivery to the room host.
    pub host: HostDelivery,
    /// Milliseconds.
    pub clock: Clock,
    /// What the MLS group knows of persona cards. `None` is production:
    /// [`NoLocalKnowledge`] (no persona store; the signed leaves the client
    /// takes are added on top), which decides every commit except the
    /// card-dependent Remove (see `geb::policy::valid_commit`) and halts on
    /// that one. Tests inject a fake to reach the other paths.
    pub commit_inputs: Option<Arc<dyn CommitCheckInputs>>,
    /// The kill switch the pump obeys (`link pause`, see [`crate::pause`]).
    /// `None` is a link that never pauses (tests with no config file).
    pub pause: Option<Arc<dyn PauseSource>>,
}

/// A link, assembled.
pub struct LinkParts {
    /// Both directions.
    pub pump: Arc<Pump>,
    /// The Geb dyad (`geb connect`, handshake progress).
    pub dyad: Arc<StatefulDyad>,
    /// The Geb MLS group (`geb stock-kps`, seating).
    pub group: Arc<MlsGroupClient>,
    /// The Geb room as a `ForeignRoom` (the pump posts through it).
    pub foreign: Arc<GebRoom>,
    /// The store the pump uses (state records encrypted).
    pub store: Arc<dyn BridgeStore>,
    /// The Geb device DID.
    pub device_did: String,
}

/// Build the link.
pub fn assemble(i: LinkInputs) -> Result<LinkParts> {
    if i.link.persona != i.secrets.persona {
        return Err(Error::Config(format!(
            "link {}: the configured persona is not the one its keys were minted for",
            i.link.id
        )));
    }
    let state_key = AtRestKey::derive(&i.store_key, "state")?;
    let mls_key = AtRestKey::derive(&i.store_key, "mls")?;
    let store: Arc<dyn BridgeStore> =
        Arc::new(EncryptedState::new(i.store.clone(), state_key, &i.link.id));
    let identity = Arc::new(i.secrets.identity()?);
    let signer: Arc<dyn GebSigner> = identity.clone();
    let dyad = Arc::new(StatefulDyad::new(
        identity,
        i.relay.clone(),
        store.clone(),
        i.clock.clone(),
    ));
    let sigkey = SealedFile::new(
        i.dir.join("mls-sigkey.enc"),
        mls_key.clone(),
        &format!("mls/{}/sigkey", i.link.id),
    );
    let state = SealedFile::new(
        i.dir.join("mls-state.enc"),
        mls_key,
        &format!("mls/{}/state", i.link.id),
    );
    let group = Arc::new(
        MlsGroupClient::new(
            MlsConfig::new(&i.link.geb_room_id, i.link.geb_peers.clone()),
            signer.clone(),
            dyad.clone(),
            i.commit_inputs
                .unwrap_or_else(|| Arc::new(NoLocalKnowledge)),
            &sigkey,
        )?
        .with_state_store(Arc::new(state))?
        .with_fork_marker(store.clone(), &i.link.id),
    );
    let geb_room = Arc::new(GebRoom::new(
        i.link.geb_room_id.clone(),
        i.relay,
        group.clone(),
        signer,
        Arc::new(GuideCodec),
        i.clock,
    ));
    let room = Arc::new(VtcRoom::new(
        i.vta,
        i.host,
        VtcRoomConfig {
            room_id: i.link.vtc_room.clone(),
            host_did: i.link.host_did.clone(),
            persona: i.link.persona.clone(),
        },
    ));
    let mut rt = LinkRuntime::new(
        &i.link.id,
        &i.link.persona,
        i.secrets.link_secret()?.to_vec(),
        i.link.directions,
    );
    rt.deny_list = i.geb.deny_list.clone();
    rt.display_name = i.link.display_name.clone();
    rt.announce = i.link.announce;
    rt.notices = i.link.notices.clone();
    rt.retention_days = i.link.retention_days;
    let device_did = i.secrets.device_did.clone();
    let mut pump = Pump::new(rt, room, geb_room.clone(), store.clone());
    if let Some(p) = i.pause {
        pump = pump.with_pause(p);
    }
    let pump = Arc::new(pump);
    Ok(LinkParts {
        pump,
        dyad,
        group,
        foreign: geb_room,
        store,
        device_did,
    })
}
