//! The operator surface: setup inputs, provisioning against a fake VTA that
//! serves key create and export, link management on a config file, and the
//! binary itself (offline commands only: no network is reached).
#![cfg(all(feature = "cli", feature = "harness"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::key_vta::KeyVta;
use std::process::Command;
use std::sync::Arc;
use vta_sdk::client::VtaClient;
use vti_geb_bridge::cli::{self, SetupInputs};
use vti_geb_bridge::config::Config;
use vti_geb_bridge::custody::BridgeSecrets;

const SETUP: &str = r#"
config_path = "/nonexistent/config.toml"
vta_did = "did:webvh:vta.example"
vta_url = "https://vta.example"
setup_key_file = "/nonexistent/setup.key"

[secrets]
backend = "plaintext"
allow_plaintext = true

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
host_url = "https://host.example"
persona = "did:key:z6Mkp1"
geb_room_id = "geb-room-0001"
tier = "open"
directions = "both"
tier_optin = true

[[links]]
id = "l2"
vtc_room = "room-2"
host_did = "did:webvh:host.example"
host_url = "https://host.example"
persona = "did:key:z6Mkp2"
geb_room_id = "geb-room-0002"
tier = "attributed"
directions = "to_foreign"
tier_optin = true
"#;

#[test]
fn setup_inputs_are_strict() {
    let s = SetupInputs::from_toml_str(SETUP).unwrap();
    assert_eq!(s.context, "geb-bridge");
    assert_eq!(s.config().unwrap().links.len(), 2);
    assert!(
        SetupInputs::from_toml_str(&SETUP.replace("[secrets]", "extra = 1\n[secrets]")).is_err()
    );
    assert!(
        SetupInputs::from_toml_str(&SETUP.replace("tier = \"open\"", "tier = \"private\""))
            .is_err()
    );
    assert!(
        SetupInputs::from_toml_str(&SETUP.replace("tier_optin = true", "tier_optin = false"))
            .is_err()
    );
    assert!(
        SetupInputs::from_toml_str(&SETUP.replace(
            "persona = \"did:key:z6Mkp2\"",
            "persona = \"did:key:z6Mkp1\""
        ))
        .is_err(),
        "one persona per link"
    );
    assert!(
        SetupInputs::from_toml_str(&SETUP.replace("https://host.example", "http://host.example"))
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn provision_mints_distinct_identities_and_names_orphans_on_failure() {
    let vta = Arc::new(KeyVta::default());
    let client = VtaClient::loopback(vta.clone());
    let s = SetupInputs::from_toml_str(SETUP).unwrap();
    let secrets = cli::provision(&client, &s.context, &s.links, BridgeSecrets::new())
        .await
        .unwrap();
    let (a, b) = (secrets.link("l1").unwrap(), secrets.link("l2").unwrap());
    assert_ne!(a.device_did, b.device_did);
    assert_eq!(
        vta.exported.lock().unwrap().len(),
        4,
        "two keys per link, nothing else"
    );
    // Running it again mints nothing for links that already have keys.
    let again = cli::provision(&client, &s.context, &s.links, secrets)
        .await
        .unwrap();
    assert_eq!(vta.created.lock().unwrap().len(), 4);
    assert_eq!(again.link_ids().count(), 2);
    // A failure after some keys were minted names them.
    let vta2 = Arc::new(KeyVta::default());
    let client2 = VtaClient::loopback(vta2.clone());
    let mut links = s.links.clone();
    links[1].persona = links[0].persona.clone();
    let e = cli::provision(&client2, &s.context, &links, BridgeSecrets::new())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("unreferenced"), "{e}");
}

#[tokio::test(flavor = "multi_thread")]
async fn link_management_edits_the_config_and_the_grant_is_narrow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let s = SetupInputs::from_toml_str(SETUP).unwrap();
    s.config().unwrap().save(&path).unwrap();
    assert_eq!(cli::link_list(&Config::load(&path).unwrap()).len(), 2);
    cli::link_set_enabled(&path, "l1", true).unwrap();
    assert!(Config::load(&path).unwrap().links[0].enabled);
    assert!(cli::link_list(&Config::load(&path).unwrap())[0].contains("running"));
    let said = cli::link_set_enabled(&path, "l1", false).unwrap();
    assert!(!Config::load(&path).unwrap().links[0].enabled);
    // The message says whether a running process honours it and how soon.
    assert!(
        said.contains("already running") && said.contains("10s") && said.contains("next tick"),
        "{said}"
    );
    assert!(
        cli::link_set_enabled(&path, "l1", true)
            .unwrap()
            .contains("within 10s")
    );
    cli::link_set_enabled(&path, "l1", false).unwrap();
    assert!(cli::link_set_enabled(&path, "nope", true).is_err());
    cli::add_peer(&path, "l1", "did:peer:2.peer").unwrap();
    cli::add_peer(&path, "l1", "did:peer:2.peer").unwrap();
    assert_eq!(Config::load(&path).unwrap().links[0].geb_peers.len(), 1);
    let grant = cli::client_grant_hint("geb-bridge", "did:key:zClient");
    assert!(grant.contains("--capabilities room-present,room-open"));
    assert!(!grant.contains("admin"));
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vti-geb-bridge"))
}

#[test]
fn the_binary_lists_and_reports_status_offline_and_refuses_a_bad_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    SetupInputs::from_toml_str(SETUP)
        .unwrap()
        .config()
        .unwrap()
        .save(&path)
        .unwrap();
    let out = bin()
        .args(["-c", path.to_str().unwrap(), "link", "list"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("l1\tpaused"));
    let out = bin()
        .args(["-c", path.to_str().unwrap(), "status"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("geb path B 0.1 (pinned to commit fdf804d)"),
        "{text}"
    );
    assert!(
        text.contains("outbox_depth=0") && text.contains("last_relayed=never"),
        "{text}"
    );
    // A private room in the config: the binary refuses before doing anything.
    let bad = std::fs::read_to_string(&path)
        .unwrap()
        .replace("tier = \"open\"", "tier = \"private\"");
    std::fs::write(&path, bad).unwrap();
    let out = bin()
        .args(["-c", path.to_str().unwrap(), "link", "list"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("private"));
    // `run` with no link enabled is a no-op that touches no network.
    let out = bin()
        .args(["-c", "/nonexistent.toml", "run"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a missing config fails closed");
}

#[tokio::test(flavor = "multi_thread")]
async fn clear_halt_shows_the_halt_needs_yes_and_a_locked_store_says_so() {
    use vti_geb_bridge::fjall_store::FjallStore;
    use vti_geb_bridge::halt::{self, HaltReason};
    use vti_geb_bridge::wiring::link_dir;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let cfg = SetupInputs::from_toml_str(SETUP).unwrap().config().unwrap();
    cfg.save(&path).unwrap();
    let store_dir = link_dir(&cfg.data_dir_from(&path), "l1").join("store");
    std::fs::create_dir_all(&store_dir).unwrap();
    let c = path.to_str().unwrap().to_string();
    let run = |args: &[&str]| {
        let mut full = vec!["-c", c.as_str()];
        full.extend_from_slice(args);
        let out = bin().args(full).output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // An undecidable commit: shown by `status`, cleared with --yes only.
    {
        let s = FjallStore::open(&store_dir).unwrap();
        halt::write(
            &s,
            &HaltReason::undecidable("epoch 4, commit ab12: blocked"),
        )
        .await
        .unwrap();
    }
    let (ok, out, _) = run(&["status", "--link", "l1"]);
    assert!(ok);
    assert!(
        out.contains("HALTED (undecidable commit: epoch 4, commit ab12"),
        "{out}"
    );
    let (ok, out, err) = run(&["link", "clear-halt", "l1"]);
    assert!(!ok);
    assert!(
        out.contains("HALTED") && out.contains("epoch 4, commit ab12"),
        "{out}"
    );
    assert!(err.contains("--yes"), "{err}");
    assert!(run(&["status", "--link", "l1"]).1.contains("HALTED"));
    let (ok, out, err) = run(&["link", "clear-halt", "l1", "--yes"]);
    assert!(ok, "{err}");
    assert!(out.contains("halt cleared"), "{out}");
    assert!(run(&["status", "--link", "l1"]).1.contains(" ok"));
    assert!(
        run(&["link", "clear-halt", "l1", "--yes"])
            .1
            .contains("not halted")
    );

    // A fork split: the unsealed marker is shown by `status` (and a paused
    // link reads PAUSED). No keys are needed to read it.
    {
        use vti_geb_bridge::geb::forkmark::{self, ForkMarker, ForkState};
        let s = FjallStore::open(&store_dir).unwrap();
        forkmark::write(
            &s,
            &ForkMarker {
                v: 1,
                link: "l1".into(),
                state: ForkState::WaitingForReseat,
                fork_epoch: 7,
                our_epoch: 9,
                their_epoch: 8,
                detected_at_ms: 1_700_000_000_000,
                reseated_at_ms: None,
            },
        )
        .await
        .unwrap();
    }
    let (ok, out, err) = run(&["status", "--link", "l1"]);
    assert!(ok, "{err}");
    assert!(
        out.contains("fork waiting-for-reseat (epoch 7, ours 9 theirs 8"),
        "{out}"
    );
    assert!(
        out.contains("PAUSED"),
        "a link that is not enabled reads PAUSED: {out}"
    );

    // A removal needs the extra flag.
    {
        let s = FjallStore::open(&store_dir).unwrap();
        halt::write(&s, &HaltReason::refused("removed from the room"))
            .await
            .unwrap();
    }
    let (ok, _, err) = run(&["link", "clear-halt", "l1", "--yes"]);
    assert!(!ok);
    assert!(err.contains("--i-have-been-readmitted"), "{err}");
    let (ok, _, err) = run(&[
        "link",
        "clear-halt",
        "l1",
        "--yes",
        "--i-have-been-readmitted",
    ]);
    assert!(ok, "{err}");

    // `run` holds the store: the commands that need it say so.
    let _held = FjallStore::open(&store_dir).unwrap();
    let (ok, _, err) = run(&["status", "--link", "l1"]);
    assert!(!ok);
    assert!(err.contains("in use by another process"), "{err}");
    let (ok, _, err) = run(&["link", "clear-halt", "l1", "--yes"]);
    assert!(!ok);
    assert!(err.contains("in use by another process"), "{err}");
}

/// P1-1: `geb connect` and `geb stock-kps` post to Geb, so they obey the kill
/// switch and the persisted halt exactly as `run` does.
#[tokio::test(flavor = "multi_thread")]
async fn geb_connect_and_stock_kps_refuse_a_paused_or_halted_link() {
    use vti_geb_bridge::fjall_store::FjallStore;
    use vti_geb_bridge::halt::{self, HaltReason};
    use vti_geb_bridge::wiring::link_dir;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let cfg = SetupInputs::from_toml_str(SETUP).unwrap().config().unwrap();
    cfg.save(&path).unwrap();
    let c = path.to_str().unwrap().to_string();
    let run = |args: &[&str]| {
        let mut full = vec!["-c", c.as_str()];
        full.extend_from_slice(args);
        // Bounded: a command that does not refuse would go on to the network.
        let out = Command::new("timeout")
            .arg("20")
            .arg(env!("CARGO_BIN_EXE_vti-geb-bridge"))
            .args(full)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let cmds: [&[&str]; 2] = [
        &["geb", "connect", "--link", "l1", "did:peer:2.peer"],
        &["geb", "stock-kps", "--link", "l1"],
    ];
    // Paused (the SETUP default is enabled = false).
    for args in cmds {
        let (ok, err) = run(args);
        assert!(!ok, "{args:?} must refuse a paused link");
        assert!(
            err.contains("paused") && err.contains("link resume"),
            "{args:?}: {err}"
        );
    }
    // Running but halted.
    cli::link_set_enabled(&path, "l1", true).unwrap();
    let store_dir = link_dir(&cfg.data_dir_from(&path), "l1").join("store");
    std::fs::create_dir_all(&store_dir).unwrap();
    {
        let s = FjallStore::open(&store_dir).unwrap();
        halt::write(&s, &HaltReason::refused("removed from the room"))
            .await
            .unwrap();
    }
    for args in cmds {
        let (ok, err) = run(args);
        assert!(!ok, "{args:?} must refuse a halted link");
        assert!(
            err.contains("halted") && err.contains("clear-halt"),
            "{args:?}: {err}"
        );
    }
}

/// P1-2: `directions` has no default on `link add` or in the config file.
#[test]
fn directions_is_required_on_link_add_and_in_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let out = bin()
        .args([
            "-c",
            path.to_str().unwrap(),
            "link",
            "add",
            "--setup-key-file",
            "/nonexistent",
            "--id",
            "l9",
            "--vtc-room",
            "r",
            "--host-did",
            "did:webvh:h.example",
            "--host-url",
            "https://h.example",
            "--persona",
            "did:key:z6Mkp9",
            "--geb-room-id",
            "g",
            "--tier-optin",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--directions"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A hand-written config without it is refused, naming the key and values.
    let cfg = SetupInputs::from_toml_str(SETUP).unwrap().config().unwrap();
    cfg.save(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        text.lines()
            .filter(|l| !l.starts_with("directions"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let out = bin()
        .args(["-c", path.to_str().unwrap(), "link", "list"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("directions") && err.contains("to_foreign"),
        "{err}"
    );
}
