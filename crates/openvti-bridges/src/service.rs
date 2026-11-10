//! `run`, `bridge <kind> <verb>`, `status` and `clear-halt` on real components.
//! Everything network-facing is built here from the config and the secret
//! store: the kind builds its foreign side ([`BridgeKind::build`]) and
//! [`crate::wiring::assemble`] does the composing.

use crate::cli::open;
use crate::wiring::{LinkInputs, LinkParts, assemble, link_ctx, link_dir};
use crate::{Error, Result};
use openvti_bridge_core::adapter::{BridgeKind, LinkCtx};
use openvti_bridge_core::config::{Config, LinkConfig};
use openvti_bridge_core::pause::{ConfigFilePause, PauseSource};
use openvti_bridge_core::run::{End, Health, LinkTick, Timing, supervise};
use openvti_bridge_core::secrets::BridgeSecrets;
use openvti_bridge_core::store::BridgeStore;
use openvti_bridge_vtc::custody::SecretStore;
use openvti_bridge_vtc::fjall_store::FjallStore;
use openvti_bridge_vtc::host::HostDelivery;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use vta_sdk::client::VtaClient;
use vta_sdk::credentials::CredentialBundle;

/// How long a stop waits for the links to wind down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// One link's parts, before the kind builds its side.
struct Prepared {
    kind: &'static dyn BridgeKind,
    ctx: LinkCtx,
    inputs: LinkInputs,
    store: Arc<FjallStore>,
}

fn prepare(
    cfg: &Config,
    data_dir: &Path,
    secrets: &BridgeSecrets,
    link: &LinkConfig,
    vta: Arc<VtaClient>,
    pause: Option<Arc<dyn PauseSource>>,
) -> Result<Prepared> {
    let kind = crate::registry::kind_of(&link.kind)?;
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
    let global = cfg
        .bridges
        .get(link.kind.as_str())
        .cloned()
        .unwrap_or_default();
    let ctx = link_ctx(link, global, ls, secrets.store_key()?, dir, store.clone())?;
    Ok(Prepared {
        kind,
        ctx,
        inputs: LinkInputs {
            vta,
            host: HostDelivery::new(host_url)?,
            pause,
        },
        store,
    })
}

/// Let the kind build its side and assemble the link.
async fn build(p: Prepared) -> Result<(LinkParts, Arc<FjallStore>)> {
    let built = p.kind.build(&p.ctx).await?;
    Ok((assemble(p.inputs, &p.ctx, built)?, p.store))
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

/// The kill switch and the persisted halt, for the commands that post to Geb
/// outside `run` (every `bridge <kind> <verb>`). The pause check is the one
/// `run` uses ([`ConfigFilePause`]: an unreadable config counts as PAUSED), and
/// it runs before anything else, so a paused link needs no keys and touches no
/// network. The halt is read from the link's store when one exists.
async fn refuse_if_paused_or_halted(config_path: &Path, id: &str, what: &str) -> Result<()> {
    if ConfigFilePause::new(config_path, id).is_paused() {
        return Err(Error::Config(format!(
            "link {id} is paused (or its config cannot be read, which counts as paused), so \
             `{what}` will not post to Geb. Fix the config if it is unreadable, then run \
             `link resume {id}`"
        )));
    }
    let cfg = crate::registry::load_config(config_path)?;
    let dir = link_dir(&cfg.data_dir_from(config_path), id).join("store");
    if dir.exists() {
        let store = FjallStore::open(&dir)?;
        if let Some(why) = openvti_bridge_core::halt::read(&store as &dyn BridgeStore).await? {
            return Err(Error::Config(format!(
                "link {id} is halted ({why}), so `{what}` will not post to the foreign room. See `status`, \
                 fix the cause, then run `link clear-halt {id} --yes` (add \
                 `--i-have-been-readmitted` only if the foreign room removed the bridge)"
            )));
        }
    }
    Ok(())
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
    build(prepare(&cfg, &data_dir, &secrets, link, vta, None)?).await
}

/// `bridge <kind> <verb> --link <id> [args]`: a verb of the link's kind. The
/// kill switch and the persisted halt are applied here, before the kind is
/// asked anything, so no adapter has to remember to.
pub async fn bridge_verb(
    config_path: &Path,
    kind: &str,
    verb: &str,
    id: &str,
    args: &[String],
) -> Result<()> {
    refuse_if_paused_or_halted(config_path, id, &format!("{kind} {verb}")).await?;
    let cfg = crate::registry::load_config(config_path)?;
    let link = link_of(&cfg, id)?;
    let k = crate::registry::kind_of(kind)?;
    if link.kind != k.kind() {
        return Err(Error::Config(format!(
            "link {id} is a {} link, not {kind}; use `bridge {} <verb> --link {id}`",
            link.kind, link.kind
        )));
    }
    if !k.verbs().iter().any(|v| v.name == verb) {
        let known: Vec<&str> = k.verbs().iter().map(|v| v.name).collect();
        return Err(Error::Config(format!(
            "{kind} has no verb {verb:?} (see `bridge list`; it has: {})",
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        )));
    }
    let (parts, _keep) = offline_parts(config_path, id).await?;
    let out = parts.handle.verb(verb, args).await?;
    for line in &out.lines {
        println!("{line}");
    }
    for (key, value) in &out.remember {
        crate::cli::remember(config_path, id, key, value)?;
    }
    Ok(())
}

/// `bridge list`: the kinds this build has and their verbs.
pub fn bridge_list() -> Vec<String> {
    let mut out = Vec::new();
    for k in crate::registry::kinds() {
        out.push(format!("{}\t{}", k.kind(), k.describe()));
        for v in k.verbs() {
            out.push(format!(
                "  bridge {} {} --link <id> {}\t{}",
                k.kind(),
                v.name,
                v.args,
                v.help
            ));
        }
    }
    out
}

/// `status`: reads local state only, including why a link is halted. Stop
/// `run` first: the store is locked by the running process, and opening it
/// then fails with a message that says so.
pub async fn status(config_path: &Path, only: Option<&str>) -> Result<()> {
    let cfg = crate::registry::load_config(config_path)?;
    let data_dir = cfg.data_dir_from(config_path);
    for k in crate::registry::kinds() {
        println!("{}: {}", k.kind(), k.pinned_reading());
    }
    for l in cfg.links.iter().filter(|l| only.is_none_or(|o| o == l.id)) {
        let store = FjallStore::open(&link_dir(&data_dir, &l.id).join("store"))?;
        let kind = crate::registry::kind_of(&l.kind)?;
        let s = crate::ops::status(&store as &dyn BridgeStore, kind).await?;
        println!(
            "{}: {} browse_version={} foreign_cursor={} outbox_depth={} oversize_failed={} dead_lettered={} last_relayed={} {}",
            l.id,
            if l.enabled {
                "enabled"
            } else {
                "PAUSED (`link pause`: nothing is posted or written; resume with `link resume`)"
            },
            s.browse_version,
            s.foreign_cursor
                .as_deref()
                .map_or("-".into(), |v| kind.describe_cursor(v)),
            s.outbox_depth,
            s.oversize_failed,
            s.dead_lettered,
            s.last_relayed_secs
                .map_or("never".into(), |v| v.to_string()),
            match &s.halted {
                Some(w) => format!("HALTED ({w})"),
                None => "ok".into(),
            },
        );
        for line in &s.adapter_lines {
            println!("{}:   {line}", l.id);
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
    confirm: openvti_bridge_core::halt::ClearConfirmation,
) -> Result<()> {
    let cfg = crate::registry::load_config(config_path)?;
    link_of(&cfg, id)?;
    let data_dir = cfg.data_dir_from(config_path);
    let dir = link_dir(&data_dir, id).join("store");
    if !dir.exists() {
        println!("{id}: no state yet, so no halt to clear");
        return Ok(());
    }
    let store = FjallStore::open(&dir)?;
    match openvti_bridge_core::halt::read(&store as &dyn BridgeStore).await? {
        None => {
            println!("{id}: not halted");
            return Ok(());
        }
        Some(r) => {
            println!("{id}: HALTED ({r})");
            if matches!(r, openvti_bridge_core::halt::HaltReason::VtcRefused { .. }) {
                println!(
                    "  The VTA or the room host refused the bridge; the foreign room did not. Fix the bridge's \
                     ACL grant or room membership at the VTA (the grant `link add` printed), then \
                     clear with --yes. --i-have-been-readmitted is not needed."
                );
            }
            if let openvti_bridge_core::halt::HaltReason::Adapter { code, .. } = &r {
                println!(
                    "  The adapter stopped this link ({code}); its design note says what the code \
                     means. Clearing makes the link read what caused it again; it halts again at \
                     once if nothing has changed."
                );
            }
        }
    }
    match openvti_bridge_core::halt::clear(&store as &dyn BridgeStore, confirm).await? {
        openvti_bridge_core::halt::Cleared::Cleared(_) => {
            println!("{id}: halt cleared. Start `run` to resume the link.");
        }
        openvti_bridge_core::halt::Cleared::NotHalted => println!("{id}: not halted"),
    }
    Ok(())
}

/// `run`: supervise every link until SIGINT or SIGTERM. A link that is paused
/// (`enabled = false`) is supervised too, idle: it sends and writes nothing
/// until `link resume`, which the running process notices on its own (the kill
/// switch re-reads the config, see [`openvti_bridge_core::pause`]). Supervising paused links
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
        let built = match prepare(&cfg, &data_dir, &secrets, l, vta.clone(), Some(gate)) {
            Ok(p) => build(p).await,
            Err(e) => Err(e),
        };
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
    for k in crate::registry::kinds() {
        tracing::info!(
            links = tasks.len(),
            kind = k.kind(),
            "{}",
            k.pinned_reading()
        );
    }
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
