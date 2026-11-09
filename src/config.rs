//! Bridge configuration (TOML, snake_case like the other host services).
//! Every table rejects unknown keys. Key material never appears here: it
//! belongs in the `[secrets]` store.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Which way content may flow on a link.
///
/// There is no default: a link that omits `directions` is refused at config
/// load, because absence must mean the most restrictive reading and the
/// operator has to choose which way content may flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Directions {
    /// VTC room to foreign room only.
    ToForeign,
    /// Foreign room to VTC room only.
    FromForeign,
    /// Both ways.
    Both,
}

/// The data room's privacy tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Open.
    Open,
    /// Attributed.
    Attributed,
    /// Private: always refused (not served; bridging would leak plaintext).
    Private,
}

/// One bridged room pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    /// Stable id of the link.
    pub id: String,
    /// VTC room id.
    pub vtc_room: String,
    /// The room host's DID.
    pub host_did: String,
    /// The room host's HTTPS base URL, where signed documents are delivered.
    /// Required to run a link; never resolved or contacted at config load.
    #[serde(default)]
    pub host_url: Option<String>,
    /// The bridge's persona DID in the VTC room.
    pub persona: String,
    /// Foreign room id.
    pub geb_room_id: String,
    /// Geb members (device DIDs) the bridge holds a dyad with and is seated
    /// through. Added by `geb connect`.
    #[serde(default)]
    pub geb_peers: Vec<String>,
    /// Allowed flow. Required: no default (absence is not "both").
    pub directions: Directions,
    /// The room's tier.
    pub tier: Tier,
    /// The owner's explicit opt-in to bridge this tier.
    #[serde(default)]
    pub tier_optin: bool,
    /// Seconds between polls of the VTC room.
    #[serde(default = "default_poll_secs")]
    pub poll_secs: u64,
    /// Whether the link runs. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// The name the bridge presents in the foreign room, 1-40 characters
    /// (Geb's limit). Optional: bridges are welcome unmarked by default. Geb
    /// will later define room-level bridge policy (not welcome / welcome
    /// automatically / ask, and whether to show a mark) and a signed "bridge"
    /// role badge; their shapes are not shared yet and are not implemented.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Post a one-time join announcement line when seated. Off by default.
    #[serde(default)]
    pub announce: bool,
    /// Wording of the notices that stand in for edits and retractions.
    #[serde(default)]
    pub notices: crate::mapping::Notices,
}

/// Longest bridge display name (Geb's limit), in characters.
pub const MAX_DISPLAY_NAME_CHARS: usize = 40;

fn default_poll_secs() -> u64 {
    10
}

/// The `[geb]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GebConfig {
    /// Relay URL.
    #[serde(default = "default_relay")]
    pub relay_url: String,
    /// Device DIDs of other bridges whose lines are never bridged.
    #[serde(default)]
    pub deny_list: Vec<String>,
}

impl Default for GebConfig {
    fn default() -> Self {
        Self {
            relay_url: default_relay(),
            deny_list: Vec::new(),
        }
    }
}

fn default_relay() -> String {
    "wss://nostr.myceli.al".into()
}

/// The `[vta]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VtaConfig {
    /// The VTA's DID.
    pub did: String,
    /// The VTA's REST base URL (what the client credential authenticates to).
    /// Never contacted at config load.
    #[serde(default)]
    pub url: Option<String>,
    /// The context holding the bridge's keys.
    #[serde(default = "default_context")]
    pub context: String,
}

fn default_data_dir() -> std::path::PathBuf {
    "data".into()
}

fn default_context() -> String {
    "geb-bridge".into()
}

/// The `[secrets]` table. Its shape is the shared `vti-secrets` one; it is
/// carried opaquely until that crate is wired in (M1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SecretsConfig(pub toml::Table);

/// Whole configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the bridge keeps its state; relative paths are taken from the
    /// directory holding the config file.
    #[serde(default = "default_data_dir")]
    pub data_dir: std::path::PathBuf,
    /// Links.
    #[serde(default)]
    pub links: Vec<LinkConfig>,
    /// Geb adapter settings.
    #[serde(default)]
    pub geb: GebConfig,
    /// VTA connection.
    pub vta: VtaConfig,
    /// Secret store.
    #[serde(default)]
    pub secrets: SecretsConfig,
}

impl Config {
    /// Read, parse and validate a config file. Reads the file and nothing
    /// else: no DID is resolved and no connection is made.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        Self::from_toml(&raw).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
    }

    /// Write the config (validated first) by replacing the file. Comments in a
    /// hand-edited file are not kept.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        self.validate()?;
        let raw = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        std::fs::write(&tmp, raw)
            .and_then(|()| std::fs::rename(&tmp, path))
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))
    }

    /// `data_dir` resolved against the config file's directory.
    pub fn data_dir_from(&self, config_path: &std::path::Path) -> std::path::PathBuf {
        if self.data_dir.is_absolute() {
            return self.data_dir.clone();
        }
        config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."))
            .join(&self.data_dir)
    }

    /// Parse and validate.
    pub fn from_toml(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s).map_err(|e| {
            let msg = e.to_string();
            // `settle_ms` used to be accepted and was never read: the settle
            // window is the room's own (`0xF001` policy, `settleWindowMs`).
            // Name the key and say where the value really comes from.
            if msg.contains("missing field `directions`") {
                Error::Config(format!(
                    "{msg}\nevery [[links]] must state `directions` (no default: absence means \
                     the most restrictive reading). Allowed values: \"to_foreign\" (VTC room to \
                     Geb only), \"from_foreign\" (Geb to VTC room only), \"both\""
                ))
            } else if msg.contains("settle_ms") {
                Error::Config(format!(
                    "{msg}\n[geb] settle_ms is no longer a setting: the commit settle window is \
                     taken from the room's own 0xF001 policy (settleWindowMs); remove the key"
                ))
            } else {
                Error::Config(msg)
            }
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check the rules the type system cannot state.
    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        let mut personas = std::collections::BTreeMap::new();
        let mut geb_rooms = std::collections::BTreeMap::new();
        for l in &self.links {
            if !seen.insert(l.id.as_str()) {
                return Err(Error::Config(format!("duplicate link id {}", l.id)));
            }
            // One room persona and one Geb room per link: a shared identity
            // correlates every room it sits in (plan section 4).
            if let Some(other) = personas.insert(l.persona.as_str(), l.id.as_str()) {
                return Err(Error::Config(format!(
                    "link {}: persona {} is already used by link {other}; one persona per link",
                    l.id, l.persona
                )));
            }
            if let Some(other) = geb_rooms.insert(l.geb_room_id.as_str(), l.id.as_str()) {
                return Err(Error::Config(format!(
                    "link {}: Geb room {} is already bridged by link {other}",
                    l.id, l.geb_room_id
                )));
            }
            if l.tier == Tier::Private {
                return Err(Error::Config(format!(
                    "link {}: private rooms are never bridged",
                    l.id
                )));
            }
            if !l.tier_optin {
                return Err(Error::Config(format!(
                    "link {}: bridging a {:?} room needs tier_optin = true (the owner's explicit opt-in)",
                    l.id, l.tier
                )));
            }
            if let Some(n) = &l.display_name {
                let c = n.chars().count();
                if c == 0 || c > MAX_DISPLAY_NAME_CHARS {
                    return Err(Error::Config(format!(
                        "link {}: display_name must be 1-{MAX_DISPLAY_NAME_CHARS} characters",
                        l.id
                    )));
                }
            }
            if let Some(u) = &l.host_url
                && !(u.starts_with("https://") || u.starts_with("http://127.0.0.1"))
            {
                return Err(Error::Config(format!(
                    "link {}: host_url must be https:// (plain http only for 127.0.0.1)",
                    l.id
                )));
            }
            l.notices.validate()?;
            if l.poll_secs == 0 {
                return Err(Error::Config(format!(
                    "link {}: poll_secs must be at least 1",
                    l.id
                )));
            }
        }
        // Secrets live in the secret store only; a seed inlined here would put
        // key material in this file.
        if self.secrets.0.contains_key("seed")
            || self.secrets.0.get("backend").and_then(|b| b.as_str()) == Some("config_seed")
        {
            return Err(Error::Config(
                "[secrets] must not inline a seed (config_seed): keys belong in the secret store"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
[vta]
did = "did:webvh:vta.example"

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
persona = "did:key:z6Mkpersona"
geb_room_id = "geb-1"
directions = "both"
tier = "open"
tier_optin = true
"#;

    #[test]
    fn directions_must_be_stated_and_the_error_names_the_key_and_the_values() {
        // Absence means the most restrictive reading, and there is no
        // restrictive default to pick for the operator: it must be stated.
        let bad = BASE.replace("directions = \"both\"\n", "");
        let e = Config::from_toml(&bad).unwrap_err().to_string();
        assert!(
            e.contains("directions")
                && e.contains("to_foreign")
                && e.contains("from_foreign")
                && e.contains("both"),
            "{e}"
        );
        let ok = BASE.replace("\"both\"", "\"to_foreign\"");
        assert_eq!(
            Config::from_toml(&ok).unwrap().links[0].directions,
            Directions::ToForeign
        );
    }

    #[test]
    fn parses_with_defaults() {
        let c = Config::from_toml(BASE).unwrap();
        assert_eq!(c.links[0].directions, Directions::Both);
        assert_eq!(c.links[0].poll_secs, 10);
        assert!(!c.links[0].enabled);
        assert_eq!(c.geb.relay_url, "wss://nostr.myceli.al");
        assert_eq!(c.vta.context, "geb-bridge");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let bad = format!("{BASE}\n[geb]\nrelay = \"x\"\n");
        assert!(Config::from_toml(&bad).is_err());
        let bad = BASE.replace("tier = \"open\"", "tier = \"open\"\nextra = 1");
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn settle_ms_is_rejected_and_the_error_says_where_the_window_comes_from() {
        let bad = format!("{BASE}\n[geb]\nsettle_ms = 3000\n");
        let e = Config::from_toml(&bad).unwrap_err().to_string();
        assert!(
            e.contains("settle_ms") && e.contains("room's own 0xF001 policy"),
            "{e}"
        );
    }

    #[test]
    fn private_tier_is_refused() {
        let bad = BASE.replace("tier = \"open\"", "tier = \"private\"");
        assert!(
            Config::from_toml(&bad)
                .unwrap_err()
                .to_string()
                .contains("private")
        );
    }

    #[test]
    fn optin_is_required() {
        let bad = BASE.replace("tier_optin = true", "tier_optin = false");
        assert!(
            Config::from_toml(&bad)
                .unwrap_err()
                .to_string()
                .contains("opt-in")
        );
    }

    #[test]
    fn display_name_is_optional_and_unmarked_by_default() {
        let c = Config::from_toml(BASE).unwrap();
        assert_eq!(c.links[0].display_name, None);
        assert!(!c.links[0].announce);
        // No "bridge" wording is required.
        let named = BASE.replace(
            "tier = \"open\"",
            "tier = \"open\"\ndisplay_name = \"Ada\"\nannounce = true",
        );
        let c = Config::from_toml(&named).unwrap();
        assert_eq!(c.links[0].display_name.as_deref(), Some("Ada"));
        assert!(c.links[0].announce);
        for bad in ["", &"x".repeat(41)] {
            let t = BASE.replace(
                "tier = \"open\"",
                &format!("tier = \"open\"\ndisplay_name = \"{bad}\""),
            );
            assert!(Config::from_toml(&t).is_err());
        }
        let ok = BASE.replace(
            "tier = \"open\"",
            &format!("tier = \"open\"\ndisplay_name = \"{}\"", "é".repeat(40)),
        );
        assert!(Config::from_toml(&ok).is_ok());
    }

    #[test]
    fn notice_wording_is_configurable() {
        let t = format!("{BASE}\n[links.notices]\nretract = \"withdrawn {{target}}\"\n");
        let c = Config::from_toml(&t).unwrap();
        assert_eq!(c.links[0].notices.retract, "withdrawn {target}");
        assert!(c.links[0].notices.update.contains("{target}"));
    }

    #[test]
    fn duplicate_ids_and_zero_poll_are_refused() {
        let dup = format!(
            "{BASE}{}",
            BASE.split("[[links]]")
                .nth(1)
                .map(|l| format!("[[links]]{l}"))
                .unwrap()
        );
        assert!(Config::from_toml(&dup).is_err());
        let bad = BASE.replace("tier_optin = true", "tier_optin = true\npoll_secs = 0");
        assert!(Config::from_toml(&bad).is_err());
    }

    #[test]
    fn one_persona_and_one_geb_room_per_link() {
        let l2 = |persona: &str, room: &str| {
            format!(
                "{BASE}\n[[links]]\nid = \"l2\"\nvtc_room = \"room-2\"\nhost_did = \"did:webvh:host.example\"\npersona = \"{persona}\"\ngeb_room_id = \"{room}\"\ndirections = \"both\"\ntier = \"open\"\ntier_optin = true\n"
            )
        };
        assert!(Config::from_toml(&l2("did:key:z6Mkother", "geb-2")).is_ok());
        let e = Config::from_toml(&l2("did:key:z6Mkpersona", "geb-2")).unwrap_err();
        assert!(e.to_string().contains("persona"), "{e}");
        let e = Config::from_toml(&l2("did:key:z6Mkother", "geb-1")).unwrap_err();
        assert!(e.to_string().contains("Geb room"), "{e}");
    }

    #[test]
    fn an_inlined_seed_is_refused() {
        let bad = format!("{BASE}\n[secrets]\nseed = \"00\"\n");
        assert!(Config::from_toml(&bad).is_err());
        let bad = format!("{BASE}\n[secrets]\nbackend = \"config_seed\"\n");
        assert!(Config::from_toml(&bad).is_err());
        let ok = format!("{BASE}\n[secrets]\nbackend = \"keyring\"\n");
        assert!(Config::from_toml(&ok).is_ok());
    }
}
