//! `run`, `geb connect`, `geb stock-kps` and `status` on real components
//! (feature `cli`). Everything network-facing is built here from the config
//! and the secret store; [`crate::wiring::assemble`] does the composing.

use crate::cli::open;
use crate::config::{Config, LinkConfig};
use crate::custody::{BridgeSecrets, SecretStore};
use crate::fjall_store::FjallStore;
use crate::geb::nostr::{NostrConfig, NostrRelay};
use crate::pause::{ConfigFilePause, PauseSource};
use crate::run::{End, Health, LinkTick, Timing, supervise};
use crate::store::BridgeStore;
use crate::vtc::host::HostDelivery;
use crate::wiring::{LinkInputs, LinkParts, assemble, link_dir, system_clock};
use crate::{Error, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;

/// How long a stop waits for the links to wind down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

fn inputs_for(
    cfg: &Config,
    data_dir: &Path,
    secrets: &BridgeSecrets,
    link: &LinkConfig,
    vta: Arc<VtaClient>,
    pause: Option<Arc<dyn PauseSource>>,
) -> Result<(LinkInputs, Arc<FjallStore>)> {
    let ls = secrets
        .link(&link.id)
        .ok_or_else(|| Error::Config(format!("link {}: no keys in the secret store", link.id)))?
        .clone();
    let host_url = link
        .host_url
        .as_deref()
        .ok_or_else(|| Error::Config(format!("link {}: host_url is not set", link.id)))?;
    let dir = link_dir(data_dir, &link.id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Store(format!("create {}: {e}", dir.display())))?;
    let store = Arc::new(FjallStore::open(&dir.join("store"))?);
    let relay = Arc::new(NostrRelay::new(NostrConfig::new(&cfg.geb.relay_url))?);
    Ok((
        LinkInputs {
            link: link.clone(),
            geb: cfg.geb.clone(),
            secrets: ls,
            store_key: secrets.store_key()?,
            dir,
            store: store.clone(),
            relay,
            vta,
            host: HostDelivery::new(host_url)?,
            clock: system_clock(),
            commit_inputs: None,
            pause,
        },
        store,
    ))
}

async fn authenticated_client(cfg: &Config, secrets: &BridgeSecrets) -> Result<Arc<VtaClient>> {
    let cred = secrets.client().ok_or_else(|| {
        Error::Config("no client credential in the secret store; run setup".into())
    })?;
    let url = cfg
        .vta
        .url
        .clone()
        .ok_or_else(|| Error::Config("[vta] url is not set".into()))?;
    let bundle = CredentialBundle {
        did: cred.did.clone(),
        private_key_multibase: cred.private_key_multibase()?.to_string(),
        vta_did: cfg.vta.did.clone(),
        vta_url: Some(url.clone()),
    };
    VtaClient::from_credential(&bundle, Some(&url))
        .await
        .map(Arc::new)
        .map_err(|e| Error::Foreign(format!("authenticate to the VTA: {e}")))
}

async fn secrets_of(store: &SecretStore) -> Result<BridgeSecrets> {
    store
        .load()
        .await?
        .ok_or_else(|| Error::Config("the secret store holds no bridge keys; run setup".into()))
}

fn link_of<'a>(cfg: &'a Config, id: &str) -> Result<&'a LinkConfig> {
    cfg.links
        .iter()
        .find(|l| l.id == id)
        .ok_or_else(|| Error::Config(format!("no link {id}")))
}

/// Parts for the commands that never touch the room side: the VTA client is
/// the unauthenticated constructor and is never used.
async fn offline_parts(config_path: &Path, id: &str) -> Result<(LinkParts, Arc<FjallStore>)> {
    let (cfg, data_dir, store) = open(config_path).await?;
    let secrets = secrets_of(&store).await?;
    let link = link_of(&cfg, id)?;
    let vta = Arc::new(VtaClient::new(
        cfg.vta.url.as_deref().unwrap_or("https://vta.invalid"),
    ));
    let (inputs, fjall) = inputs_for(&cfg, &data_dir, &secrets, link, vta, None)?;
    Ok((assemble(inputs)?, fjall))
}

/// `geb connect`: contacts the Geb relay only.
pub async fn geb_connect(config_path: &Path, id: &str, peer: &str) -> Result<()> {
    let (parts, _keep) = offline_parts(config_path, id).await?;
    let cfg = Config::load(config_path)?;
    let name = link_of(&cfg, id)?.display_name.clone();
    let phase = crate::ops::connect(
        &parts,
        peer,
        name.as_deref(),
        Duration::from_secs(60),
        Duration::from_secs(3),
    )
    .await?;
    println!("{peer}: {phase:?}");
    crate::cli::add_peer(config_path, id, peer)
}

/// `geb stock-kps`: contacts the Geb relay only.
pub async fn geb_stock_kps(config_path: &Path, id: &str) -> Result<()> {
    let (parts, _keep) = offline_parts(config_path, id).await?;
    let state = crate::ops::stock_kps(&parts).await?;
    println!("{id}: {state:?}");
    Ok(())
}

/// `status`: reads local state only, including why a link is halted. Stop
/// `run` first: the store is locked by the running process, and opening it
/// then fails with a message that says so.
pub async fn status(config_path: &Path, only: Option<&str>) -> Result<()> {
    let cfg = Config::load(config_path)?;
    let data_dir = cfg.data_dir_from(config_path);
    println!("{}", crate::geb::status_line());
    for l in cfg.links.iter().filter(|l| only.is_none_or(|o| o == l.id)) {
        let store = FjallStore::open(&link_dir(&data_dir, &l.id).join("store"))?;
        let s = crate::ops::status(&store as &dyn BridgeStore).await?;
        println!(
            "{}: {} browse_version={} foreign_cursor={} outbox_depth={} oversize_failed={} last_relayed={} {}",
            l.id,
            if l.enabled {
                "enabled"
            } else {
                "PAUSED (`link pause`: nothing is posted or written; resume with `link resume`)"
            },
            s.browse_version,
            s.foreign_cursor_secs.map_or("-".into(), |v| v.to_string()),
            s.outbox_depth,
            s.oversize_failed,
            s.last_relayed_secs
                .map_or("never".into(), |v| v.to_string()),
            match &s.halted {
                Some(w) => format!("HALTED ({w})"),
                None => "ok".into(),
            },
        );
        if let Some(f) = &s.fork {
            println!("{}:   {}", l.id, f.describe());
        }
    }
    Ok(())
}

/// `link clear-halt`: say what the link's halt was, then clear it if (and only
/// if) the confirmation is complete. Needs the store, so `run` must be
/// stopped. Clearing does not start anything; `run` does.
pub async fn clear_halt(
    config_path: &Path,
    id: &str,
    confirm: crate::halt::ClearConfirmation,
) -> Result<()> {
    let cfg = Config::load(config_path)?;
    link_of(&cfg, id)?;
    let data_dir = cfg.data_dir_from(config_path);
    let dir = link_dir(&data_dir, id).join("store");
    if !dir.exists() {
        println!("{id}: no state yet, so no halt to clear");
        return Ok(());
    }
    let store = FjallStore::open(&dir)?;
    match crate::halt::read(&store as &dyn BridgeStore).await? {
        None => {
            println!("{id}: not halted");
            return Ok(());
        }
        Some(r) => {
            println!("{id}: HALTED ({r})");
            if matches!(r, crate::halt::HaltReason::UndecidableCommit { .. }) {
                println!(
                    "  This is a Remove of another DID that the bridge cannot decide: it holds no \
                     persona cards and no signed leave covers it. Geb itself would refuse it \
                     and carry on; the bridge halts instead of risking a silent fork (a \
                     deliberate choice). Clearing makes the link read it again; it halts again \
                     at once if nothing has changed."
                );
            }
        }
    }
    match crate::halt::clear(&store as &dyn BridgeStore, confirm).await? {
        crate::halt::Cleared::Cleared(_) => {
            println!("{id}: halt cleared. Start `run` to resume the link.");
        }
        crate::halt::Cleared::NotHalted => println!("{id}: not halted"),
    }
    Ok(())
}

/// `run`: supervise every link until SIGINT or SIGTERM. A link that is paused
/// (`enabled = false`) is supervised too, idle: it sends and writes nothing
/// until `link resume`, which the running process notices on its own (the kill
/// switch re-reads the config, see [`crate::pause`]). Supervising paused links
/// is what lets `link resume` take effect without a restart. A paused link
/// whose parts cannot be built (no keys yet) is skipped with a warning and
/// needs a restart after it is fixed; an enabled one still fails the run.
pub async fn run(config_path: &Path) -> Result<()> {
    let (cfg, data_dir, store) = open(config_path).await?;
    if cfg.links.is_empty() {
        tracing::warn!("no link is configured; nothing to do (see `link add`)");
        return Ok(());
    }
    if !cfg.links.iter().any(|l| l.enabled) {
        tracing::warn!("every link is paused; they idle until `link resume`");
    }
    let secrets = secrets_of(&store).await?;
    let vta = authenticated_client(&cfg, &secrets).await?;
    let (stop, stopped) = watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    for l in &cfg.links {
        let gate: Arc<dyn PauseSource> = Arc::new(ConfigFilePause::new(config_path, &l.id));
        let built = inputs_for(&cfg, &data_dir, &secrets, l, vta.clone(), Some(gate))
            .and_then(|(inputs, fjall)| Ok((assemble(inputs)?, fjall)));
        let (parts, fjall) = match built {
            Ok(p) => p,
            Err(e) if !l.enabled => {
                tracing::warn!(link = %l.id, error = %e, "paused link not started; fix it and restart `run` before resuming");
                continue;
            }
            Err(e) => return Err(e),
        };
        let timing = Timing::for_poll_secs(l.poll_secs);
        let id = l.id.clone();
        let (rx, health) = (stopped.clone(), Arc::new(Health::default()));
        // The store handle and the parts (the relay socket) live with the
        // task: dropping them on the way out closes the socket and releases
        // the store lock.
        tasks.spawn(async move {
            let pump: Arc<dyn LinkTick> = parts.pump.clone();
            let end = supervise(&id, pump, timing, rx, health).await;
            drop((parts, fjall));
            (id, end)
        });
    }
    tracing::info!(links = tasks.len(), "{}", crate::geb::status_line());
    shutdown_signal().await;
    tracing::info!("stopping");
    let _ = stop.send(true);
    let drain = async {
        while let Some(r) = tasks.join_next().await {
            match r {
                Ok((id, End::Halted(why))) => {
                    tracing::error!(link = %id, security_alert = true, %why, "link ended halted")
                }
                Ok((id, End::Stopped)) => tracing::info!(link = %id, "link stopped"),
                Err(e) => tracing::error!(error = %e, "a link task failed"),
            }
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        tracing::warn!("links did not stop within {SHUTDOWN_GRACE:?}; aborting them");
        tasks.abort_all();
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
