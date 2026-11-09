//! `vti-geb-bridge`: the … room.
//! Experimental. Built only with `--features cli`; see `vti_geb_bridge::cli`.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use vti_geb_bridge::cli::{self, DEFAULT_CONTEXT, NewLink};
use vti_geb_bridge::{Result, service};

#[derive(Parser)]
#[command(
    name = "vti-geb-bridge",
    version,
    about = "Experimental bridge between a VTC data room and a Geb room"
)]
struct Cli {
    /// The configuration file.
    #[arg(long, short, global = true, default_value = "config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Provision from the operator's VTA in two phases (contacts the VTA).
    Setup(SetupArgs),
    /// Manage links.
    #[command(subcommand)]
    Link(LinkCmd),
    /// Geb-side operations (contact the Geb relay only).
    #[command(subcommand)]
    Geb(GebCmd),
    /// Show cursors, outbox depth, last relayed and halted state (local, no
    /// network). Stop `run` first.
    Status {
        /// Only this link.
        #[arg(long)]
        link: Option<String>,
    },
    /// Run every enabled link until SIGINT or SIGTERM.
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
        #[arg(long)]
        geb_room_id: String,
        #[arg(long, default_value = "both")]
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
    /// Stop a link running (set enabled = false).
    Pause { id: String },
    /// Let a link run. Does not clear a halt.
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
enum GebCmd {
    /// Open a dyad with a Geb member's device DID and add it to the link.
    Connect {
        #[arg(long)]
        link: String,
        did: String,
    },
    /// Stock KeyPackages with the link's peers (consent to be added).
    StockKps {
        #[arg(long)]
        link: String,
    },
}

async fn dispatch(cli: Cli) -> Result<()> {
    let config = cli.config;
    match cli.command {
        Command::Setup(a) => match (a.setup_key_out, a.from) {
            (Some(out), None) => cli::setup_phase1(&out, &a.context).await,
            (None, Some(from)) => cli::setup_from_file(&from).await,
            _ => Err(vti_geb_bridge::Error::Config(
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
                geb_room_id,
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
                        geb_room_id,
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
                for line in cli::link_list(&vti_geb_bridge::config::Config::load(&config)?) {
                    println!("{line}");
                }
                Ok(())
            }
            LinkCmd::Pause { id } => cli::link_set_enabled(&config, &id, false),
            LinkCmd::Resume { id } => cli::link_set_enabled(&config, &id, true),
            LinkCmd::Remove { id } => cli::link_remove(&config, &id).await,
            LinkCmd::ClearHalt {
                id,
                yes,
                readmitted,
            } => {
                service::clear_halt(
                    &config,
                    &id,
                    vti_geb_bridge::halt::ClearConfirmation { yes, readmitted },
                )
                .await
            }
        },
        Command::Geb(GebCmd::Connect { link, did }) => {
            service::geb_connect(&config, &link, &did).await
        }
        Command::Geb(GebCmd::StockKps { link }) => service::geb_stock_kps(&config, &link).await,
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
    vta_sdk::keyring_init::warn_store_unavailable("vti-geb-bridge");
    match dispatch(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
