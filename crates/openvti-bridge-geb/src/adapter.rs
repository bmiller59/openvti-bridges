//! Geb as a bridge kind: the settings the operator gives in `[bridges.geb]`
//! and in a link's `[links.geb]` table, and the rules the core cannot know.

use crate::{Error, Result};
use openvti_bridge_core::adapter::BridgeKind;
use serde::{Deserialize, Serialize};

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
