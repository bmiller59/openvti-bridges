//! Assembling one running link from its parts: the VTC room side over the
//! user's VTA, the foreign side a registered kind builds ([`BridgeKind::build`]),
//! the state sealed at rest, and the pump between.
//!
//! The binary and the end-to-end tests build a link through the same
//! [`assemble`], so the test stack is the production stack with a loopback
//! relay and a fake VTA substituted at the edges.
//!
//! Layout under `<data_dir>/links/<link id>/`: `store/` (fjall) and whatever
//! files the kind keeps beside it (Geb: `mls-state.enc`, `mls-sigkey.enc`). One
//! link per directory keeps each link's cursors, halt record and adapter state
//! apart.

use crate::{Error, Result};
use openvti_bridge_core::adapter::{AdapterHandle, BuiltLink, LinkCtx};
use openvti_bridge_core::atrest::{AtRestKey, EncryptedState};
use openvti_bridge_core::config::LinkConfig;
use openvti_bridge_core::pause::PauseSource;
use openvti_bridge_core::pump::{LinkRuntime, Pump};
use openvti_bridge_core::secrets::LinkSecrets;
use openvti_bridge_core::store::BridgeStore;
use openvti_bridge_vtc::host::HostDelivery;
use openvti_bridge_vtc::{VtcRoom, VtcRoomConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use vta_sdk::client::VtaClient;

/// `<data_dir>/links/<id>`.
pub fn link_dir(data_dir: &Path, link_id: &str) -> PathBuf {
    data_dir.join("links").join(link_id)
}

/// The context a kind builds one link from: the persona check, and the state
/// sealed at rest over the link's durable `store`.
pub fn link_ctx(
    link: &LinkConfig,
    global: toml::Table,
    secrets: LinkSecrets,
    store_key: zeroize::Zeroizing<[u8; 32]>,
    dir: PathBuf,
    store: Arc<dyn BridgeStore>,
) -> Result<LinkCtx> {
    if link.persona != secrets.persona {
        return Err(Error::Config(format!(
            "link {}: the configured persona is not the one its keys were minted for",
            link.id
        )));
    }
    let state_key = AtRestKey::derive(&store_key, "state")?;
    let store: Arc<dyn BridgeStore> = Arc::new(EncryptedState::new(store, state_key, &link.id));
    Ok(LinkCtx {
        link: link.clone(),
        global,
        secrets,
        store_key,
        dir,
        store,
    })
}

/// What the VTI side of a link is built from.
pub struct LinkInputs {
    /// A client for the user's VTA, in the `openvti-bridges` context.
    pub vta: Arc<VtaClient>,
    /// Delivery to the room host.
    pub host: HostDelivery,
    /// The kill switch the pump obeys (`link pause`, see [`openvti_bridge_core::pause`]).
    /// `None` is a link that never pauses (tests with no config file).
    pub pause: Option<Arc<dyn PauseSource>>,
}

/// A link, assembled.
pub struct LinkParts {
    /// Both directions.
    pub pump: Arc<Pump>,
    /// The store the pump uses (state records encrypted).
    pub store: Arc<dyn BridgeStore>,
    /// The kind's operator verbs for this link.
    pub handle: Arc<dyn AdapterHandle>,
}

/// Build the link: the VTC room, the pump over it and the kind's foreign side.
pub fn assemble(i: LinkInputs, ctx: &LinkCtx, built: BuiltLink) -> Result<LinkParts> {
    let link = &ctx.link;
    let room = Arc::new(VtcRoom::new(
        i.vta,
        i.host,
        VtcRoomConfig {
            room_id: link.vtc_room.clone(),
            host_did: link.host_did.clone(),
            persona: link.persona.clone(),
        },
    ));
    let mut rt = LinkRuntime::new(
        &link.id,
        &link.persona,
        ctx.secrets.link_secret()?.to_vec(),
        link.directions,
    );
    rt.deny_authors = link.deny_authors.clone();
    rt.display_name = link.display_name.clone();
    rt.announce = link.announce;
    rt.notices = link.notices.clone();
    rt.retention_days = link.retention_days;
    let mut pump = Pump::new(rt, room, built.foreign, ctx.store.clone());
    if let Some(p) = i.pause {
        pump = pump.with_pause(p);
    }
    Ok(LinkParts {
        pump: Arc::new(pump),
        store: ctx.store.clone(),
        handle: built.handle,
    })
}
