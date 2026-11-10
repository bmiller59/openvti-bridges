//! Geb as a bridge kind: the settings the operator gives in `[bridges.geb]`
//! and in a link's `[links.geb]` table, and the rules the core cannot know.

use crate::{Error, Result};
use async_trait::async_trait;
use openvti_bridge_core::adapter::{BridgeKind, VerbSpec};
use openvti_bridge_core::secrets::{KeyMinter, LinkSecrets};
use openvti_bridge_core::store::BridgeStore;
use serde::{Deserialize, Serialize};
#[cfg(feature = "mls")]
use {
    crate::codec::GuideCodec,
    crate::custody::GebLinkSecrets,
    crate::dyad::{Phase, StatefulDyad},
    crate::mls::{MlsConfig, MlsGroupClient},
    crate::policy::{CommitCheckInputs, NoLocalKnowledge},
    crate::room::{Clock, GebRoom},
    crate::traits::{GebGroup, GebRelay, GebSigner},
    openvti_bridge_core::adapter::{AdapterHandle, BuiltLink, LinkCtx, VerbResult},
    openvti_bridge_core::atrest::{AtRestKey, SealedFile},
    openvti_bridge_core::foreign::JoinState,
    std::sync::Arc,
    std::time::Duration,
};

/// The kind name: `kind = "geb"`.
pub const KIND_NAME: &str = "geb";

/// Longest bridge display name Geb accepts, in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 40;

/// The `[bridges.geb]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GebConfig {
    /// Relay URL.
    #[serde(default = "default_relay")]
    pub relay_url: String,
}

impl Default for GebConfig {
    fn default() -> Self {
        Self {
            relay_url: default_relay(),
        }
    }
}

fn default_relay() -> String {
    "wss://nostr.myceli.al".into()
}

impl GebConfig {
    /// Read the `[bridges.geb]` table (absent means the defaults).
    pub fn from_table(t: Option<&toml::Table>) -> Result<Self> {
        let Some(t) = t else {
            return Ok(Self::default());
        };
        let msg = |e: toml::de::Error| {
            let m = e.to_string();
            // `settle_ms` used to be accepted and was never read: the settle
            // window is the room's own (`0xF001` policy, `settleWindowMs`).
            // Name the key and say where the value really comes from.
            if m.contains("settle_ms") {
                Error::Config(format!(
                    "{m}\n[bridges.geb] settle_ms is no longer a setting: the commit settle \
                     window is taken from the room's own 0xF001 policy (settleWindowMs); remove \
                     the key"
                ))
            } else {
                Error::Config(m)
            }
        };
        t.clone().try_into().map_err(msg)
    }
}

/// One link's `[links.geb]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GebLinkConfig {
    /// Geb room id.
    pub room_id: String,
    /// Geb members (device DIDs) the bridge holds a dyad with and is seated
    /// through. Added by `bridge geb connect`.
    #[serde(default)]
    pub peers: Vec<String>,
}

impl GebLinkConfig {
    /// Read a link's `[links.geb]` table.
    pub fn from_table(t: &toml::Table) -> Result<Self> {
        let c: Self = t
            .clone()
            .try_into()
            .map_err(|e: toml::de::Error| Error::Config(e.to_string()))?;
        if c.room_id.is_empty() {
            return Err(Error::Config("room_id must not be empty".into()));
        }
        Ok(c)
    }

    /// The table to store in a link's `adapter` map.
    pub fn to_table(&self) -> toml::Table {
        match toml::Value::try_from(self) {
            Ok(toml::Value::Table(t)) => t,
            _ => toml::Table::new(),
        }
    }
}

/// The Geb kind.
pub struct GebKind;

/// The registered Geb kind.
pub static KIND: GebKind = GebKind;

const GEB_VERBS: &[VerbSpec] = &[
    VerbSpec {
        name: "connect",
        help: "open a dyad with a Geb member's device DID and add it to the link (contacts the relay)",
        args: "<did>",
    },
    VerbSpec {
        name: "stock-kps",
        help: "stock KeyPackages with the link's peers: consent to be added (contacts the relay)",
        args: "",
    },
];

fn be8(b: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(b).ok().map(u64::from_be_bytes)
}

#[async_trait]
impl BridgeKind for GebKind {
    fn kind(&self) -> &'static str {
        KIND_NAME
    }

    fn describe(&self) -> &'static str {
        "Geb rooms over Nostr and MLS (path B)"
    }

    fn validate_global(&self, table: &toml::Table) -> Result<()> {
        GebConfig::from_table(Some(table)).map(|_| ())
    }

    fn validate_link(&self, table: &toml::Table) -> Result<()> {
        GebLinkConfig::from_table(table).map(|_| ())
    }

    fn foreign_room_key(&self, table: &toml::Table) -> Result<String> {
        Ok(GebLinkConfig::from_table(table)?.room_id)
    }

    fn max_display_name(&self) -> Option<usize> {
        Some(MAX_DISPLAY_NAME_CHARS)
    }

    fn pinned_reading(&self) -> String {
        crate::status_line()
    }

    /// The newest relay `created_at` read, in seconds.
    fn describe_cursor(&self, raw: &[u8]) -> String {
        be8(raw).map_or_else(|| hex::encode(raw), |v| v.to_string())
    }

    /// The last recorded fork split and where it stands (a non-secret marker).
    async fn status_lines(&self, store: &dyn BridgeStore) -> Result<Vec<String>> {
        Ok(crate::forkmark::read(store)
            .await?
            .map(|f| vec![f.describe()])
            .unwrap_or_default())
    }

    fn verbs(&self) -> &'static [VerbSpec] {
        GEB_VERBS
    }

    fn halt_codes(&self) -> &'static [(&'static str, &'static str)] {
        crate::HALT_CODES
    }

    async fn mint_link_secrets(
        &self,
        minter: &dyn KeyMinter,
        context: &str,
        link: &openvti_bridge_core::config::LinkConfig,
    ) -> Result<LinkSecrets> {
        crate::custody::mint_device_identity(minter, context, &link.id)
            .await?
            .into_link_secrets(&link.persona)
    }

    fn describe_secrets(&self, secrets: &LinkSecrets) -> Option<String> {
        crate::custody::GebLinkSecrets::from_link_secrets(secrets)
            .ok()
            .map(|g| format!("Geb device DID {}", g.device_did))
    }

    #[cfg(all(feature = "live", feature = "mls"))]
    async fn build(&self, ctx: &LinkCtx) -> Result<BuiltLink> {
        use crate::nostr::{NostrConfig, NostrRelay};
        let cfg = GebConfig::from_table(Some(&ctx.global))?;
        let relay = Arc::new(NostrRelay::new(NostrConfig::new(&cfg.relay_url))?);
        let (room, handle) = build_with(
            ctx,
            GebParts {
                relay,
                clock: system_clock(),
                commit_inputs: None,
            },
        )?;
        Ok(BuiltLink {
            foreign: room,
            handle,
        })
    }
}

/// The wall clock in milliseconds.
#[cfg(feature = "mls")]
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    })
}

/// What a Geb link is built over, which tests replace at the edges.
#[cfg(feature = "mls")]
pub struct GebParts {
    /// The Nostr relay (one per device identity).
    pub relay: Arc<dyn GebRelay>,
    /// Milliseconds.
    pub clock: Clock,
    /// What the MLS group knows of persona cards. `None` is production:
    /// `NoLocalKnowledge` (no persona store; the signed leaves the client
    /// takes are added on top), which decides every commit except the
    /// card-dependent Remove (see `policy::valid_commit`) and halts on that
    /// one. Tests inject a fake to reach the other paths.
    pub commit_inputs: Option<Arc<dyn CommitCheckInputs>>,
}

/// A built Geb link's operator handle: the dyad (`connect`), the MLS group
/// (`stock-kps`, seating) and the device DID.
#[cfg(feature = "mls")]
pub struct GebHandle {
    /// The Geb dyad (handshake progress).
    pub dyad: Arc<StatefulDyad>,
    /// The Geb MLS group (seating).
    pub group: Arc<MlsGroupClient>,
    /// The Geb device DID.
    pub device_did: String,
    /// The link's display name, sent in an invitation.
    pub display_name: Option<String>,
    /// The link id, for the verb output.
    pub link: String,
}

/// Build the Geb side of a link over `parts`. Layout under the link's dir:
/// `mls-state.enc` (the OpenMLS key store snapshot) and `mls-sigkey.enc` (the
/// MLS signature key), sealed at rest.
#[cfg(feature = "mls")]
pub fn build_with(ctx: &LinkCtx, parts: GebParts) -> Result<(Arc<GebRoom>, Arc<GebHandle>)> {
    if ctx.link.kind != KIND_NAME {
        return Err(Error::Config(format!(
            "link {}: kind {:?} is not built by the geb adapter",
            ctx.link.id, ctx.link.kind
        )));
    }
    let geb_link =
        GebLinkConfig::from_table(ctx.link.adapter.get(KIND_NAME).ok_or_else(|| {
            Error::Config(format!("link {}: no [links.geb] table", ctx.link.id))
        })?)?;
    let mls_key = AtRestKey::derive(&ctx.store_key, "mls")?;
    let store = ctx.store.clone();
    let geb_secrets = GebLinkSecrets::from_link_secrets(&ctx.secrets)?;
    let identity = Arc::new(geb_secrets.identity()?);
    let signer: Arc<dyn GebSigner> = identity.clone();
    let dyad = Arc::new(StatefulDyad::new(
        identity,
        parts.relay.clone(),
        store.clone(),
        parts.clock.clone(),
    ));
    let sigkey = SealedFile::new(
        ctx.dir.join("mls-sigkey.enc"),
        mls_key.clone(),
        &format!("mls/{}/sigkey", ctx.link.id),
    );
    let state = SealedFile::new(
        ctx.dir.join("mls-state.enc"),
        mls_key,
        &format!("mls/{}/state", ctx.link.id),
    );
    let group = Arc::new(
        MlsGroupClient::new(
            MlsConfig::new(&geb_link.room_id, geb_link.peers.clone()),
            signer.clone(),
            dyad.clone(),
            parts
                .commit_inputs
                .unwrap_or_else(|| Arc::new(NoLocalKnowledge)),
            &sigkey,
        )?
        .with_state_store(Arc::new(state))?
        .with_fork_marker(store, &ctx.link.id),
    );
    let room = Arc::new(GebRoom::new(
        geb_link.room_id.clone(),
        parts.relay,
        group.clone(),
        signer,
        Arc::new(GuideCodec),
        parts.clock,
    ));
    let handle = Arc::new(GebHandle {
        dyad,
        group,
        device_did: geb_secrets.device_did.clone(),
        display_name: ctx.link.display_name.clone(),
        link: ctx.link.id.clone(),
    });
    Ok((room, handle))
}

#[cfg(feature = "mls")]
impl GebHandle {
    /// Invite `peer_did` and drive the handshake until it connects or
    /// `timeout` passes. Safe to repeat: the invitation is resumable (same
    /// nonce), and a connected peer returns at once. Returns the phase reached.
    pub async fn connect(
        &self,
        peer_did: &str,
        display_name: Option<&str>,
        timeout: Duration,
        step: Duration,
    ) -> Result<Phase> {
        match self.dyad.phase(peer_did).await? {
            // Nothing yet: answer an invitation they sent first, else send ours.
            None => {
                let mut answered = false;
                for inv in self.dyad.invitations().await? {
                    if inv.from == peer_did {
                        self.dyad.accept(&inv).await?;
                        answered = true;
                    }
                }
                if !answered {
                    self.dyad.invite(peer_did, display_name).await?;
                }
            }
            // Ours is outstanding: repost it (same nonce) in case the post failed.
            Some(Phase::Invited) => {
                self.dyad.invite(peer_did, display_name).await?;
            }
            Some(_) => {}
        }
        let started = std::time::Instant::now();
        loop {
            self.dyad.sync(peer_did).await?;
            match self.dyad.phase(peer_did).await? {
                Some(Phase::Connected) => return Ok(Phase::Connected),
                Some(Phase::Expired) => {
                    return Err(Error::Foreign(
                        "the invitation expired unanswered (7 days)".into(),
                    ));
                }
                p if started.elapsed() >= timeout => {
                    return Ok(p.unwrap_or(Phase::Invited));
                }
                _ => tokio::time::sleep(step).await,
            }
        }
    }

    /// Stock KeyPackages with the configured peers (and take a Welcome if one
    /// has already arrived). The stock counts as consent to be added to the
    /// room.
    pub async fn stock_kps(&self) -> Result<JoinState> {
        self.group.ensure_seated().await
    }
}

#[cfg(feature = "mls")]
#[async_trait]
impl AdapterHandle for GebHandle {
    async fn verb(&self, name: &str, args: &[String]) -> Result<VerbResult> {
        match (name, args) {
            ("connect", [peer]) => {
                let phase = self
                    .connect(
                        peer,
                        self.display_name.as_deref(),
                        Duration::from_secs(60),
                        Duration::from_secs(3),
                    )
                    .await?;
                Ok(VerbResult {
                    lines: vec![format!("{peer}: {phase:?}")],
                    remember: vec![("peers".into(), peer.clone())],
                })
            }
            ("connect", _) => Err(Error::Config("usage: connect <did>".into())),
            ("stock-kps", []) => {
                let state = self.stock_kps().await?;
                Ok(VerbResult {
                    lines: vec![format!("{}: {state:?}", self.link)],
                    remember: Vec::new(),
                })
            }
            ("stock-kps", _) => Err(Error::Config("usage: stock-kps".into())),
            (other, _) => Err(Error::Config(format!("no such verb {other:?}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn a_link_table_needs_a_room_and_refuses_unknown_keys() {
        let c = GebLinkConfig::from_table(&t("room_id = \"r\"")).unwrap();
        assert!(c.peers.is_empty());
        assert!(GebLinkConfig::from_table(&t("peers = [\"a\"]")).is_err());
        assert!(GebLinkConfig::from_table(&t("room_id = \"\"")).is_err());
        assert!(GebLinkConfig::from_table(&t("room_id = \"r\"\nextra = 1")).is_err());
        assert_eq!(KIND.foreign_room_key(&t("room_id = \"r\"")).unwrap(), "r");
    }

    #[test]
    fn the_link_table_round_trips() {
        let c = GebLinkConfig {
            room_id: "r".into(),
            peers: vec!["did:peer:a".into()],
        };
        assert_eq!(GebLinkConfig::from_table(&c.to_table()).unwrap(), c);
    }

    #[test]
    fn the_global_table_defaults_and_refuses_unknown_keys() {
        assert_eq!(
            GebConfig::from_table(None).unwrap().relay_url,
            "wss://nostr.myceli.al"
        );
        assert!(GebConfig::from_table(Some(&t("relay = \"x\""))).is_err());
        // The pre-restructure global deny list moved to the link.
        assert!(GebConfig::from_table(Some(&t("deny_list = [\"did:peer:x\"]"))).is_err());
        assert_eq!(KIND.max_display_name(), Some(40));
    }

    #[test]
    fn settle_ms_is_rejected_and_the_error_says_where_the_window_comes_from() {
        let e = GebConfig::from_table(Some(&t("settle_ms = 3000")))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("settle_ms") && e.contains("room's own 0xF001 policy"),
            "{e}"
        );
    }
}
