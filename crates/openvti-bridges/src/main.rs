//! `openvti-bridges`: the bridge between a VTC data room and a foreign room.
//! Experimental; see `openvti_bridges::cli`.

use clap::{Args, Parser, Subcommand};
use openvti_bridges::cli::{self, DEFAULT_CONTEXT, NewLink};
use openvti_bridges::{Result, service};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "openvti-bridges",
    version,
    about = "Experimental bridge between a VTC data room and a foreign room"
)]
struct Cli {
    /// The configuration file.
    #[arg(long, short, global = true, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Provision from the operator's VTA in two phases (contacts the VTA).
    Setup(SetupArgs),
    /// Manage links.
    #[command(subcommand)]
    Link(LinkCmd),
    /// Bridge kinds and their verbs: `bridge list`, `bridge <kind> <verb>
    /// --link <id> [args]` (a verb contacts the foreign system only).
    #[command(subcommand)]
    Bridge(BridgeCmd),
    /// Show cursors, outbox depth, last relayed and halted state (local, no
    /// network). Stop `run` first.
    Status {
        /// Only this link.
        #[arg(long)]
        link: Option<String>,
    },
    /// Run every link until SIGINT or SIGTERM (a paused link idles).
    Run,
}

#[derive(Args)]
struct SetupArgs {
    /// Phase 1: mint an ephemeral setup key, store it (0600) and print the grant.
    #[arg(long, conflicts_with = "from")]
    setup_key_out: Option<PathBuf>,
    /// The VTA context the phase-1 grant names.
    #[arg(long, default_value = DEFAULT_CONTEXT)]
    context: String,
    /// Phase 2: provision from this setup file once the grant is in place.
    #[arg(long)]
    from: Option<PathBuf>,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum LinkCmd {
    /// Add a link (mints its device keys with a fresh, granted setup key).
    Add {
        #[arg(long)]
        setup_key_file: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long)]
        vtc_room: String,
        #[arg(long)]
        host_did: String,
        #[arg(long)]
        host_url: String,
        #[arg(long)]
        persona: String,
        /// The bridge kind (see the registry), for example `geb`.
        #[arg(long)]
        kind: String,
        /// A setting of that kind, `key=value`; repeat for more (for Geb:
        /// `--set room_id=<id>`).
        #[arg(long = "set", value_parser = parse_setting)]
        settings: Vec<(String, String)>,
        /// Which way content may flow: `to_foreign`, `from_foreign` or `both`.
        /// Required: there is no default.
        #[arg(long)]
        directions: String,
        #[arg(long, default_value = "open")]
        tier: String,
        /// The room owner's explicit opt-in to bridging this tier.
        #[arg(long)]
        tier_optin: bool,
        #[arg(long, default_value_t = 10)]
        poll_secs: u64,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// List links.
    List,
    /// Pause a link (enabled = false): a running `run` stops posting and
    /// writing within one poll interval, keeping its cursors and outbox.
    Pause { id: String },
    /// Let a paused link run again; a running `run` notices within one poll
    /// interval. Does not clear a halt.
    Resume { id: String },
    /// Remove a link and its keys (does not revoke the VTA key records).
    Remove { id: String },
    /// Clear a link's halt. Prints what the halt was first and clears only
    /// with --yes. A halt from a refusal or removal (the bridge was taken out
    /// of the room) also needs --i-have-been-readmitted. Local; stop `run`
    /// first.
    ClearHalt {
        id: String,
        /// I have read what the halt was and want it cleared.
        #[arg(long)]
        yes: bool,
        /// For a refused/removed link: the bridge has been admitted to the
        /// room again, so clearing will not just repeat the refusal.
        #[arg(long = "i-have-been-readmitted")]
        readmitted: bool,
    },
}

#[derive(Subcommand)]
enum BridgeCmd {
    /// List the bridge kinds built into this binary and their verbs.
    List,
    /// `<kind> <verb> --link <id> [args...]`: run a verb of a kind (see `bridge list`).
    #[command(external_subcommand)]
    Verb(Vec<String>),
}

/// `[kind, verb, ...rest]` with `--link <id>` somewhere in `rest`.
fn parse_verb(argv: Vec<String>) -> Result<(String, String, String, Vec<String>)> {
    let usage = || {
        openvti_bridges::Error::Config(
            "usage: bridge <kind> <verb> --link <id> [args...] (see `bridge list`)".into(),
        )
    };
    let mut it = argv.into_iter();
    let kind = it.next().ok_or_else(usage)?;
    let verb = it.next().ok_or_else(usage)?;
    let (mut link, mut args) = (None, Vec::new());
    while let Some(a) = it.next() {
        if a == "--link" {
            link = Some(it.next().ok_or_else(usage)?);
        } else if let Some(v) = a.strip_prefix("--link=") {
            link = Some(v.to_string());
        } else {
            args.push(a);
        }
    }
    Ok((kind, verb, link.ok_or_else(usage)?, args))
}

fn parse_setting(s: &str) -> std::result::Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.into(), v.into())),
        _ => Err(format!("expected key=value, got {s:?}")),
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    let config = cli.config;
    match cli.command {
        Command::Setup(a) => match (a.setup_key_out, a.from) {
            (Some(out), None) => cli::setup_phase1(&out, &a.context).await,
            (None, Some(from)) => cli::setup_from_file(&from).await,
            _ => Err(openvti_bridges::Error::Config(
                "give --setup-key-out <path> (phase 1) or --from <setup.toml> (phase 2)".into(),
            )),
        },
        Command::Link(c) => match c {
            LinkCmd::Add {
                setup_key_file,
                id,
                vtc_room,
                host_did,
                host_url,
                persona,
                kind,
                settings,
                directions,
                tier,
                tier_optin,
                poll_secs,
                display_name,
            } => {
                cli::link_add(
                    &config,
                    &setup_key_file,
                    NewLink {
                        id,
                        vtc_room,
                        host_did,
                        host_url,
                        persona,
                        kind,
                        settings,
                        directions,
                        tier,
                        tier_optin,
                        poll_secs,
                        display_name,
                    },
                )
                .await
            }
            LinkCmd::List => {
                for line in cli::link_list(&openvti_bridges::registry::load_config(&config)?) {
                    println!("{line}");
                }
                Ok(())
            }
            LinkCmd::Pause { id } => {
                println!("{}", cli::link_set_enabled(&config, &id, false)?);
                Ok(())
            }
            LinkCmd::Resume { id } => {
                println!("{}", cli::link_set_enabled(&config, &id, true)?);
                Ok(())
            }
            LinkCmd::Remove { id } => cli::link_remove(&config, &id).await,
            LinkCmd::ClearHalt {
                id,
                yes,
                readmitted,
            } => {
                service::clear_halt(
                    &config,
                    &id,
                    openvti_bridge_core::halt::ClearConfirmation { yes, readmitted },
                )
                .await
            }
        },
        Command::Bridge(BridgeCmd::List) => {
            for line in service::bridge_list() {
                println!("{line}");
            }
            Ok(())
        }
        Command::Bridge(BridgeCmd::Verb(argv)) => {
            let (kind, verb, link, args) = parse_verb(argv)?;
            service::bridge_verb(&config, &kind, &verb, &link, &args).await
        }
        Command::Status { link } => service::status(&config, link.as_deref()).await,
        Command::Run => service::run(&config).await,
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    vta_sdk::crypto_init::install_default_crypto_provider();
    #[cfg(feature = "keyring")]
    vta_sdk::keyring_init::warn_store_unavailable("openvti-bridges");
    match dispatch(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
