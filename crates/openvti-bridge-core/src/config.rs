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
///
/// Not `deny_unknown_fields` (that cannot be combined with the flattened
/// kind table); [`Config::from_toml`] refuses any table that is not the
/// link's own kind, and a stray scalar key fails to parse as a table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// The bridge kind (an adapter): `geb`, `loopback`, ... Required: absence
    /// names nothing. Checked against the kinds the binary was built with by
    /// [`Config::validate_kinds`].
    pub kind: String,
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
    /// The name the bridge presents in the foreign room: at least 1 character,
    /// at most what the kind allows. Optional: bridges are welcome unmarked by default. Geb
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
    /// Foreign author ids whose lines are never bridged (for example another
    /// bridge's identity in the foreign room, which would otherwise loop).
    /// Per link; what an id looks like is the foreign system's own.
    #[serde(default)]
    pub deny_authors: Vec<String>,
    /// The kind's own settings for this link, from the `[links.<kind>]` table:
    /// at most one entry, keyed by [`LinkConfig::kind`]. The core carries it
    /// without reading it; the kind parses it.
    #[serde(flatten, default)]
    pub adapter: std::collections::BTreeMap<String, toml::Table>,
    /// Days to keep a posted outbox row, a journal row and an expiring
    /// cross-reference before pruning them. At least 1; the default (7)
    /// matches Geb's relay retention. Entries not posted are never pruned.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_retention_days() -> u32 {
    crate::pump::DEFAULT_RETENTION_DAYS
}

fn default_poll_secs() -> u64 {
    10
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
    "openvti-bridges".into()
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
    /// Per-kind global settings, `[bridges.<kind>]`, read only by the kind.
    #[serde(default)]
    pub bridges: std::collections::BTreeMap<String, toml::Table>,
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

    /// Write the config (validated first) by replacing the file, durably:
    /// the temp file is created mode `0600` (the config names the secrets
    /// backend and every link's identifiers), written, fsynced, renamed over
    /// the original, and the directory fsynced, so a crash leaves the old file
    /// or the new one, never an empty or partial one. Comments in a
    /// hand-edited file are not kept. For a read-modify-write use
    /// [`Config::modify`], which also serialises writers.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        use std::io::Write;
        self.validate()?;
        let raw = toml::to_string_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        let io = |what: &str, e: std::io::Error| {
            Error::Config(format!("{what} {}: {e}", path.display()))
        };
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| io("write", e))?;
        // A leftover temp file from a crash keeps its old mode: set it again.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| io("chmod", e))?;
        }
        f.write_all(raw.as_bytes()).map_err(|e| io("write", e))?;
        f.sync_all().map_err(|e| io("sync", e))?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| io("replace", e))?;
        // Make the rename itself durable.
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(dir)
                .and_then(|d| d.sync_all())
                .map_err(|e| io("sync directory of", e))?;
        }
        Ok(())
    }

    /// Read the current file, apply `f`, and save: under an exclusive lock on
    /// `<config>.lock`, so two commands (`link pause`, `link add`, ...) cannot
    /// each overwrite the other's change with a stale copy. Only what `f`
    /// changes changes. The lock is held for the read, `f` and the write, never
    /// across a network call: do the remote work first, then `modify` to
    /// record it. Readers (the running pump's pause check) take no lock; they
    /// see the old file or the new one, as [`Config::save`] replaces it
    /// atomically.
    pub fn modify<R>(
        path: &std::path::Path,
        f: impl FnOnce(&mut Config) -> Result<R>,
    ) -> Result<R> {
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let lock = opts
            .open(&lock_path)
            .map_err(|e| Error::Config(format!("open the config lock: {e}")))?;
        lock.lock()
            .map_err(|e| Error::Config(format!("lock the config: {e}")))?;
        let mut cfg = Self::load(path)?;
        let out = f(&mut cfg)?;
        cfg.save(path)?;
        Ok(out)
        // The lock is released when `lock` is dropped.
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

    /// Parse and validate the rules that do not need to know the kinds. A
    /// kind's own tables are checked by [`Config::validate_kinds`].
    pub fn from_toml(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s).map_err(|e| {
            let msg = e.to_string();
            if msg.contains("missing field `directions`") {
                Error::Config(format!(
                    "{msg}\nevery [[links]] must state `directions` (no default: absence means \
                     the most restrictive reading). Allowed values: \"to_foreign\" (VTC room to \
                     the foreign room only), \"from_foreign\" (foreign room to VTC room only), \
                     \"both\""
                ))
            } else if msg.contains("missing field `kind`") {
                Error::Config(format!(
                    "{msg}\nevery [[links]] must state `kind`, the bridge kind (for example \
                     kind = \"geb\"), with the kind's own settings in a [links.<kind>] table"
                ))
            } else {
                Error::Config(msg)
            }
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check the rules that need the kinds this binary was built with: each
    /// link's kind is one of them, its `[links.<kind>]` table and the kind's
    /// `[bridges.<kind>]` table are valid, `display_name` fits the kind's
    /// limit, and one foreign room is bridged by one link.
    pub fn validate_kinds(&self, kinds: crate::adapter::Kinds<'_>) -> Result<()> {
        let empty = toml::Table::new();
        for name in self.bridges.keys() {
            let Some(k) = crate::adapter::find(kinds, name) else {
                return Err(Error::Config(format!(
                    "[bridges.{name}]: no bridge kind {name:?} in this build (enabled: {})",
                    crate::adapter::names(kinds)
                )));
            };
            k.validate_global(&self.bridges[name])?;
        }
        let mut rooms = std::collections::BTreeMap::new();
        for l in &self.links {
            let Some(k) = crate::adapter::find(kinds, &l.kind) else {
                return Err(Error::Config(format!(
                    "link {}: no bridge kind {:?} in this build (enabled: {})",
                    l.id,
                    l.kind,
                    crate::adapter::names(kinds)
                )));
            };
            let table = l.adapter.get(&l.kind).unwrap_or(&empty);
            k.validate_link(table)
                .map_err(|e| Error::Config(format!("link {}: [links.{}]: {e}", l.id, l.kind)))?;
            if let Some(max) = k.max_display_name()
                && let Some(n) = &l.display_name
                && n.chars().count() > max
            {
                return Err(Error::Config(format!(
                    "link {}: display_name must be 1-{max} characters for kind {}",
                    l.id, l.kind
                )));
            }
            let room = k.foreign_room_key(table)?;
            if let Some(other) = rooms.insert((l.kind.as_str(), room.clone()), l.id.as_str()) {
                return Err(Error::Config(format!(
                    "link {}: {} room {room} is already bridged by link {other}",
                    l.id, l.kind
                )));
            }
        }
        Ok(())
    }

    /// Check the rules the type system cannot state and that do not depend on
    /// a kind.
    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        let mut personas = std::collections::BTreeMap::new();
        for l in &self.links {
            if !seen.insert(l.id.as_str()) {
                return Err(Error::Config(format!("duplicate link id {}", l.id)));
            }
            if l.kind.is_empty() {
                return Err(Error::Config(format!(
                    "link {}: kind must not be empty",
                    l.id
                )));
            }
            // A link has the settings table of its own kind and no other: a
            // leftover table from another kind, or a typo, is an error.
            if let Some(stray) = l.adapter.keys().find(|k| **k != l.kind) {
                return Err(Error::Config(format!(
                    "link {}: unknown table [links.{stray}] (this link's kind is {:?}; its \
                     settings go in [links.{}])",
                    l.id, l.kind, l.kind
                )));
            }
            // One room persona per link: a shared identity correlates every
            // room it sits in (plan section 4).
            if let Some(other) = personas.insert(l.persona.as_str(), l.id.as_str()) {
                return Err(Error::Config(format!(
                    "link {}: persona {} is already used by link {other}; one persona per link",
                    l.id, l.persona
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
            if l.retention_days < 1 {
                return Err(Error::Config(format!(
                    "link {}: retention_days must be at least 1 (default {})",
                    l.id,
                    crate::pump::DEFAULT_RETENTION_DAYS
                )));
            }
            if let Some(n) = &l.display_name {
                let c = n.chars().count();
                if c == 0 {
                    return Err(Error::Config(format!(
                        "link {}: display_name must not be empty",
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
    use crate::adapter::BridgeKind;

    const KINDS: crate::adapter::Kinds<'static> = &[&crate::loopback::KIND];

    /// A loopback-like kind that limits the display name.
    struct Limited(usize);
    impl BridgeKind for Limited {
        fn kind(&self) -> &'static str {
            "loopback"
        }
        fn describe(&self) -> &'static str {
            "limited"
        }
        fn validate_link(&self, _: &toml::Table) -> Result<()> {
            Ok(())
        }
        fn foreign_room_key(&self, t: &toml::Table) -> Result<String> {
            crate::loopback::KIND.foreign_room_key(t)
        }
        fn max_display_name(&self) -> Option<usize> {
            Some(self.0)
        }
    }

    const BASE: &str = r#"
[vta]
did = "did:webvh:vta.example"

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
persona = "did:key:z6Mkpersona"
directions = "both"
tier = "open"
tier_optin = true
kind = "loopback"
loopback = { room = "room-a" }
"#;

    #[test]
    fn retention_days_defaults_to_seven_and_must_be_at_least_one() {
        assert_eq!(Config::from_toml(BASE).unwrap().links[0].retention_days, 7);
        let one = format!("{BASE}\nretention_days = 1\n");
        assert_eq!(Config::from_toml(&one).unwrap().links[0].retention_days, 1);
        let zero = format!("{BASE}\nretention_days = 0\n");
        let e = Config::from_toml(&zero).unwrap_err().to_string();
        assert!(e.contains("retention_days"), "{e}");
    }

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
        assert_eq!(c.links[0].kind, "loopback");
        assert!(c.bridges.is_empty());
        assert_eq!(c.vta.context, "openvti-bridges");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        // The pre-restructure global table is not read.
        let bad = format!("{BASE}\n[geb]\nrelay = \"x\"\n");
        assert!(Config::from_toml(&bad).is_err());
        let bad = BASE.replace("tier = \"open\"", "tier = \"open\"\nextra = 1");
        assert!(Config::from_toml(&bad).is_err());
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
    fn deny_authors_is_per_link_and_the_old_global_deny_list_is_refused() {
        let c = Config::from_toml(BASE).unwrap();
        assert!(c.links[0].deny_authors.is_empty());
        let t = BASE.replace(
            "tier = \"open\"",
            "tier = \"open\"\ndeny_authors = [\"did:peer:other-bridge\"]",
        );
        let c = Config::from_toml(&t).unwrap();
        assert_eq!(c.links[0].deny_authors, ["did:peer:other-bridge"]);
        // The pre-restructure global key is not read: it is an unknown table.
        let old = format!("{BASE}\n[geb]\ndeny_list = [\"did:peer:x\"]\n");
        assert!(Config::from_toml(&old).is_err());
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
        let t = BASE.replace("tier = \"open\"", "tier = \"open\"\ndisplay_name = \"\"");
        assert!(Config::from_toml(&t).is_err());
        // The limit is the kind's own: a kind with none accepts a long name.
        let long = BASE.replace(
            "tier = \"open\"",
            &format!("tier = \"open\"\ndisplay_name = \"{}\"", "é".repeat(400)),
        );
        let c = Config::from_toml(&long).unwrap();
        assert!(c.validate_kinds(KINDS).is_ok());
        // A kind that limits it refuses a longer one, counted in characters.
        let limited: &[&dyn BridgeKind] = &[&Limited(40)];
        assert!(c.validate_kinds(limited).is_err());
        let ok = BASE.replace(
            "tier = \"open\"",
            &format!("tier = \"open\"\ndisplay_name = \"{}\"", "é".repeat(40)),
        );
        let c = Config::from_toml(&ok).unwrap();
        assert!(c.validate_kinds(limited).is_ok());
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
    fn one_persona_and_one_foreign_room_per_link() {
        let l2 = |persona: &str, room: &str| {
            format!(
                "{BASE}\n[[links]]\nid = \"l2\"\nvtc_room = \"room-2\"\nhost_did = \"did:webvh:host.example\"\npersona = \"{persona}\"\ndirections = \"both\"\ntier = \"open\"\ntier_optin = true\nkind = \"loopback\"\nloopback = {{ room = \"{room}\" }}\n"
            )
        };
        let ok = Config::from_toml(&l2("did:key:z6Mkother", "room-b")).unwrap();
        assert!(ok.validate_kinds(KINDS).is_ok());
        let e = Config::from_toml(&l2("did:key:z6Mkpersona", "room-b")).unwrap_err();
        assert!(e.to_string().contains("persona"), "{e}");
        let same_room = Config::from_toml(&l2("did:key:z6Mkother", "room-a")).unwrap();
        let e = same_room.validate_kinds(KINDS).unwrap_err();
        assert!(e.to_string().contains("loopback room room-a"), "{e}");
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

    #[test]
    fn a_link_needs_a_registered_kind_and_only_its_own_table() {
        // No kind at all.
        let bad = BASE.replace("kind = \"loopback\"\n", "");
        let e = Config::from_toml(&bad).unwrap_err().to_string();
        assert!(e.contains("kind"), "{e}");
        // A kind this build does not have names the ones it does.
        let c = Config::from_toml(
            &BASE
                .replace("kind = \"loopback\"", "kind = \"other\"")
                .replace("loopback = {", "other = {"),
        )
        .unwrap();
        let e = c.validate_kinds(KINDS).unwrap_err().to_string();
        assert!(e.contains("\"other\"") && e.contains("loopback"), "{e}");
        // A table of another kind on the link, or a stray scalar, is refused.
        let bad = BASE.replace("loopback = {", "geb = { room = \"x\" }\nloopback = {");
        let e = Config::from_toml(&bad).unwrap_err().to_string();
        assert!(e.contains("[links.geb]"), "{e}");
        let bad = BASE.replace("tier = \"open\"", "tier = \"open\"\nextra = 1");
        assert!(Config::from_toml(&bad).is_err());
        // The kind's own validation runs, with the kind's own unknown-key rule.
        let bad = BASE.replace("{ room = \"room-a\" }", "{ room = \"a\", x = 1 }");
        let c = Config::from_toml(&bad).unwrap();
        assert!(c.validate_kinds(KINDS).is_err());
        let bad = format!("{BASE}\n[bridges.loopback]\nx = 1\n");
        let c = Config::from_toml(&bad).unwrap();
        assert!(c.validate_kinds(KINDS).is_err());
    }

    #[test]
    fn the_kind_table_survives_a_save_and_load() {
        let c = Config::from_toml(BASE).unwrap();
        let dir = std::env::temp_dir().join(format!("ovb-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back, c);
        assert!(back.validate_kinds(KINDS).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
