//! The operator surface behind `src/main.rs` (feature `cli`): two-phase setup
//! after `vti-witness`, link management, `geb connect` / `geb stock-kps`,
//! `status` and `run`. Nothing here runs at config load; each command that
//! touches a network says so in its help.
//!
//! # Setup, in order
//!
//! 1. `vti-geb-bridge setup --setup-key-out setup.key` mints an ephemeral
//!    `did:key`, stores it 0600 and prints the `pnm` grant that makes it admin
//!    of the `geb-bridge` context for an hour.
//! 2. The operator runs that grant at their VTA (or with the keyring tooling).
//!    The setup key can mint and export this context's keys and nothing else.
//! 3. `vti-geb-bridge setup --from setup.toml` authenticates as the setup key,
//!    mints and exports each link's two device keys, stores them in the secret
//!    store, writes `config.toml` and prints the second grant: the bridge's own
//!    long-term client `did:key`, narrowed to `room-present,room-open` and
//!    never an admin. Revoking the bridge is removing that ACL entry.

use crate::config::{Config, Directions, GebConfig, LinkConfig, SecretsConfig, Tier, VtaConfig};
use crate::custody::{BridgeSecrets, ClientCredential, SecretStore, mint_device_identity};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::provision_client::{EphemeralSetupKey, OperatorMessages};

/// The VTA context the bridge's keys live in.
pub const DEFAULT_CONTEXT: &str = "geb-bridge";

/// How setup names the integration, and the grant it asks the operator for.
pub struct BridgeMessages;

impl OperatorMessages for BridgeMessages {
    fn integration_label(&self) -> &str {
        "Geb bridge"
    }
    fn integration_label_lower(&self) -> &str {
        "geb bridge"
    }
    fn pnm_admin_command_hint(&self, context_id: &str, setup_did: &str) -> String {
        format!(
            "pnm contexts create --id {context_id} --name \"Geb bridge\" \\\n  \
             --admin-did {setup_did} --admin-expires 1h\n\n    \
             (if the context already exists:\n     \
             pnm acl create --did {setup_did} --role admin --contexts {context_id} --expires 1h)"
        )
    }
}

/// The grant for the bridge's long-term client credential.
///
/// UNVERIFIED: the role name `initiator` and the exact capability set are
/// taken from the community-rooms guide's example for a VTC; whether a bridge
/// needs `room-present` and `room-open` only, and whether `initiator` is the
/// role to hold them, has not been checked against a VTA.
pub fn client_grant_hint(context: &str, client_did: &str) -> String {
    format!(
        "pnm acl create --did {client_did} --role initiator --contexts {context} \\\n    \
         --capabilities room-present,room-open --label \"geb bridge\""
    )
}

/// Phase 1.
pub async fn setup_phase1(out: &Path, context: &str) -> Result<()> {
    let finalise = format!(
        "vti-geb-bridge setup --from <your-setup.toml>   (with setup_key_file = \"{}\")",
        out.display()
    );
    vta_sdk::provision_client::driver::run_phase1_init(
        &mut std::io::stderr(),
        out,
        context,
        &BridgeMessages,
        Some(&finalise),
    )
    .await
    .map_err(|e| Error::Config(format!("mint the setup key: {e}")))
}

/// The file `setup --from` reads.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInputs {
    /// Where to write `config.toml`. Setup refuses to overwrite one.
    pub config_path: PathBuf,
    /// Defaults to `data` beside `config_path`.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// The operator's VTA.
    pub vta_did: String,
    /// Its REST base URL.
    pub vta_url: String,
    /// The VTA context. Defaults to `geb-bridge`.
    #[serde(default = "default_context")]
    pub context: String,
    /// The phase-1 key file whose DID was granted admin of `context`.
    pub setup_key_file: PathBuf,
    /// The `[geb]` table.
    #[serde(default)]
    pub geb: GebConfig,
    /// Where the keys are kept (same table as `config.toml`'s).
    pub secrets: SecretsConfig,
    /// The links to provision.
    pub links: Vec<LinkConfig>,
}

fn default_context() -> String {
    DEFAULT_CONTEXT.into()
}

impl SetupInputs {
    /// Parse and validate (the links against the config rules).
    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let i: Self = toml::from_str(raw).map_err(|e| Error::Config(e.to_string()))?;
        i.config()?;
        if i.links.is_empty() {
            return Err(Error::Config(
                "name at least one [[links]] to provision".into(),
            ));
        }
        Ok(i)
    }

    /// The config this setup writes.
    pub fn config(&self) -> Result<Config> {
        let cfg = Config {
            data_dir: self.data_dir.clone().unwrap_or_else(|| "data".into()),
            links: self.links.clone(),
            geb: self.geb.clone(),
            vta: VtaConfig {
                did: self.vta_did.clone(),
                url: Some(self.vta_url.clone()),
                context: self.context.clone(),
            },
            secrets: self.secrets.clone(),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

/// Mint the device keys for every link in `links` that has none yet, returning
/// the updated secrets. On failure the error names the key records already
/// minted at the VTA, which nothing references (R2.1: revoke them there).
pub async fn provision(
    client: &VtaClient,
    context: &str,
    links: &[LinkConfig],
    mut secrets: BridgeSecrets,
) -> Result<BridgeSecrets> {
    let mut minted: Vec<String> = Vec::new();
    for l in links {
        if secrets.link(&l.id).is_some() {
            continue;
        }
        match mint_device_identity(client, context, &l.id, &l.persona).await {
            Ok(ls) => {
                minted.push(format!("{}, {}", ls.ed_key_id, ls.x_key_id));
                if let Err(e) = secrets.insert(&l.id, ls) {
                    return Err(orphans(e, &minted));
                }
            }
            Err(e) => return Err(orphans(e, &minted)),
        }
    }
    Ok(secrets)
}

fn orphans(e: Error, minted: &[String]) -> Error {
    if minted.is_empty() {
        return e;
    }
    Error::Foreign(format!(
        "{e}; key records already minted in the VTA and now unreferenced: {}",
        minted.join(" | ")
    ))
}

fn setup_client(
    vta_did: &str,
    vta_url: &str,
    key_file: &Path,
) -> impl std::future::Future<Output = Result<VtaClient>> {
    let loaded = EphemeralSetupKey::load_from(key_file);
    let (vta_did, vta_url, key_file) = (
        vta_did.to_string(),
        vta_url.to_string(),
        key_file.to_path_buf(),
    );
    async move {
        let key = loaded.map_err(|e| {
            Error::Config(format!(
                "load the setup key {}: {e}. Run `vti-geb-bridge setup --setup-key-out <path>` \
                 first and grant the DID it prints.",
                key_file.display()
            ))
        })?;
        let bundle = CredentialBundle {
            did: key.did.clone(),
            private_key_multibase: key.private_key_multibase().to_string(),
            vta_did,
            vta_url: Some(vta_url.clone()),
        };
        VtaClient::from_credential(&bundle, Some(&vta_url))
            .await
            .map_err(|e| Error::Foreign(format!("authenticate to the VTA as the setup key: {e}")))
    }
}

/// Phase 2.
pub async fn setup_from_file(path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let inputs = SetupInputs::from_toml_str(&raw)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    if inputs.config_path.exists() {
        return Err(Error::Config(format!(
            "{} already exists. Setup does not overwrite a configuration; use `link add` to \
             add a link.",
            inputs.config_path.display()
        )));
    }
    let cfg = inputs.config()?;
    let data_dir = cfg.data_dir_from(&inputs.config_path);
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| Error::Config(format!("create {}: {e}", data_dir.display())))?;
    // The store first: a misconfigured backend fails before anything is
    // minted, and it must be empty (these keys are the only copy here).
    let store = SecretStore::open(&cfg.secrets, &data_dir)?;
    if store.load().await?.is_some() {
        return Err(Error::Config(
            "the configured secret store already holds bridge keys. Setup does not overwrite \
             them; point [secrets] at an empty entry."
                .into(),
        ));
    }
    let client = setup_client(&inputs.vta_did, &inputs.vta_url, &inputs.setup_key_file).await?;
    eprintln!("Minting device keys for {} link(s) ...", inputs.links.len());
    let mut secrets = provision(
        &client,
        &inputs.context,
        &inputs.links,
        BridgeSecrets::new(),
    )
    .await?;
    let client_key = EphemeralSetupKey::generate()
        .map_err(|e| Error::Crypto(format!("mint the client key: {e}")))?;
    secrets.set_client(ClientCredential::new(
        &client_key.did,
        client_key.private_key_multibase(),
    ));
    // Keys first, then the config that names them.
    store.save(&secrets).await?;
    if !store.persists() {
        eprintln!("warning: the configured secret store does not survive a restart");
    }
    cfg.save(&inputs.config_path)?;
    eprintln!("\nWrote {}.", inputs.config_path.display());
    eprintln!("\nNow grant the bridge's own client DID, narrowed to the room capabilities:\n");
    eprintln!(
        "    {}\n",
        client_grant_hint(&inputs.context, &client_key.did)
    );
    for l in &inputs.links {
        if let Some(s) = secrets.link(&l.id) {
            eprintln!("link {}: Geb device DID {}", l.id, s.device_did);
        }
    }
    eprintln!(
        "\nThe setup grant expires on its own; remove it sooner with `pnm acl delete` for the \
         setup DID printed in phase 1."
    );
    Ok(())
}

/// Load the config and open the secret store beside it.
pub async fn open(config_path: &Path) -> Result<(Config, PathBuf, SecretStore)> {
    let cfg = Config::load(config_path)?;
    let data_dir = cfg.data_dir_from(config_path);
    let store = SecretStore::open(&cfg.secrets, &data_dir)?;
    Ok((cfg, data_dir, store))
}

fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, v: &str) -> Result<T> {
    toml::Value::String(v.to_string())
        .try_into()
        .map_err(|_| Error::Config(format!("{what}: unknown value {v:?}")))
}

/// `link add` arguments, as strings.
pub struct NewLink {
    /// Link id.
    pub id: String,
    /// VTC room id.
    pub vtc_room: String,
    /// Host DID.
    pub host_did: String,
    /// Host URL.
    pub host_url: String,
    /// Persona DID.
    pub persona: String,
    /// Geb room id.
    pub geb_room_id: String,
    /// `both`, `to_foreign` or `from_foreign`.
    pub directions: String,
    /// `open` or `attributed`.
    pub tier: String,
    /// The owner's opt-in.
    pub tier_optin: bool,
    /// Poll seconds.
    pub poll_secs: u64,
    /// Optional display name.
    pub display_name: Option<String>,
}

/// `link add`: mint this link's keys with a fresh setup key, then record it.
/// The new link starts paused (`enabled = false`).
pub async fn link_add(config_path: &Path, setup_key_file: &Path, n: NewLink) -> Result<()> {
    let (_, _, store) = open(config_path).await?;
    link_add_with(config_path, n, |cfg, link| async move {
        let url = cfg
            .vta
            .url
            .clone()
            .ok_or_else(|| Error::Config("[vta] url is not set".into()))?;
        let secrets = store.load().await?.ok_or_else(|| {
            Error::Config("the secret store holds no bridge keys; run setup".into())
        })?;
        let client = setup_client(&cfg.vta.did, &url, setup_key_file).await?;
        let secrets = provision(&client, &cfg.vta.context, &[link], secrets).await?;
        store.save(&secrets).await
    })
    .await
}

/// The part of `link add` that is not the VTA call. `mint` runs the remote
/// effect (key minting and storing the secrets) and may take seconds; the
/// config is not held across it. See [`Config::modify`].
pub async fn link_add_with<F, Fut>(config_path: &Path, n: NewLink, mint: F) -> Result<()>
where
    F: FnOnce(Config, LinkConfig) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut cfg = Config::load(config_path)?;
    let link = LinkConfig {
        id: n.id,
        vtc_room: n.vtc_room,
        host_did: n.host_did,
        host_url: Some(n.host_url),
        persona: n.persona,
        geb_room_id: n.geb_room_id,
        geb_peers: Vec::new(),
        directions: parse_enum::<Directions>("directions", &n.directions)?,
        tier: parse_enum::<Tier>("tier", &n.tier)?,
        tier_optin: n.tier_optin,
        poll_secs: n.poll_secs,
        enabled: false,
        display_name: n.display_name,
        announce: false,
        notices: Default::default(),
        retention_days: crate::pump::DEFAULT_RETENTION_DAYS,
    };
    cfg.links.push(link.clone());
    cfg.validate()?;
    mint(cfg, link.clone()).await?;
    // Re-read and merge: the config may have changed while `mint` ran (a
    // `link pause` is the kill switch), so only this link is added to what is
    // on disk now, and nothing else is rewritten from the copy loaded above.
    Config::modify(config_path, |cfg| {
        if cfg.links.iter().any(|l| l.id == link.id) {
            return Err(Error::Config(format!(
                "link {} was added while this command ran; its keys were minted: `link remove {}` \
                 and add it again",
                link.id, link.id
            )));
        }
        cfg.links.push(link);
        Ok(())
    })
}

/// `link list`: one line per link.
pub fn link_list(cfg: &Config) -> Vec<String> {
    cfg.links
        .iter()
        .map(|l| {
            format!(
                "{}\t{}\t{} <-> {}\tpeers={}",
                l.id,
                if l.enabled { "running" } else { "paused" },
                l.vtc_room,
                l.geb_room_id,
                l.geb_peers.len()
            )
        })
        .collect()
}

/// How soon a running `run` honours a pause or resume: it reads the config
/// before every tick (so within `poll_secs`) and before every post and write.
pub fn pause_notice(id: &str, poll_secs: u64, enabled: bool) -> String {
    if enabled {
        format!(
            "{id}: resumed in the config. A running `run` picks this up within {poll_secs}s \
             (its poll interval, the time between ticks) and carries on from the saved \
             cursors and outbox, with no loss and no duplicates; if `run` is not running, start \
             it. A halt is not cleared by resume (see `link clear-halt`)."
        )
    } else {
        format!(
            "{id}: paused in the config. A `run` of this version that is already running \
             re-reads the config before every tick ({poll_secs}s apart) and before every post and \
             every write into the VTC room, so it stops posting and writing at once and no later \
             than the next tick, at most {poll_secs}s; it keeps its connections, and its cursors \
             and outbox stay as they were (nothing is dropped or acknowledged). A tick already \
             in flight finishes first. A `run` started by an older build does not read the \
             flag: stop it (SIGTERM). If the config cannot be read the link counts as paused."
        )
    }
}

/// `link pause` / `link resume`. Resuming does not clear a halt. Returns the
/// message to print: what a running process will do about it, and how soon.
pub fn link_set_enabled(config_path: &Path, id: &str, enabled: bool) -> Result<String> {
    let poll = Config::modify(config_path, |cfg| {
        let l = cfg
            .links
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| Error::Config(format!("no link {id}")))?;
        l.enabled = enabled;
        Ok(l.poll_secs)
    })?;
    Ok(pause_notice(id, poll, enabled))
}

/// `link remove`: drop the link and its secrets. The VTA key records are not
/// revoked and the link's data directory is left in place.
pub async fn link_remove(config_path: &Path, id: &str) -> Result<()> {
    let (cfg, _, store) = open(config_path).await?;
    if !cfg.links.iter().any(|l| l.id == id) {
        return Err(Error::Config(format!("no link {id}")));
    }
    if let Some(mut s) = store.load().await?
        && s.remove(id)
    {
        store.save(&s).await?;
    }
    Config::modify(config_path, |cfg| {
        cfg.links.retain(|l| l.id != id);
        Ok(())
    })
}

/// Add a connected peer to a link's `geb_peers`.
pub fn add_peer(config_path: &Path, id: &str, peer: &str) -> Result<()> {
    Config::modify(config_path, |cfg| {
        let l = cfg
            .links
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or_else(|| Error::Config(format!("no link {id}")))?;
        if !l.geb_peers.iter().any(|p| p == peer) {
            l.geb_peers.push(peer.into());
        }
        Ok(())
    })
}
