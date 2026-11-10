//! The shell, not the adapter, applies the kill switch and the persisted halt
//! before any `bridge <kind> <verb>` (here with the core's loopback kind and
//! its `echo` verb, so no foreign system is involved).

#![cfg(feature = "loopback")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openvti_bridge_core::config::Config;
use openvti_bridge_core::halt::{self, HaltReason};
use openvti_bridge_vtc::fjall_store::FjallStore;
use openvti_bridges::wiring::link_dir;
use std::process::Command;

const CONFIG: &str = r#"
data_dir = "data"

[vta]
did = "did:webvh:vta.example"
url = "https://vta.example"

[secrets]
backend = "plaintext"
allow_plaintext = true

[[links]]
id = "l1"
vtc_room = "room-1"
host_did = "did:webvh:host.example"
host_url = "https://host.example"
persona = "did:key:z6Mkp1"
kind = "loopback"
loopback = { room = "x" }
tier = "open"
directions = "both"
tier_optin = true
enabled = false
"#;

fn run(config: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new("timeout")
        .arg("20")
        .arg(env!("CARGO_BIN_EXE_openvti-bridges"))
        .args(["-c", config])
        .args(args)
        .output()
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_verb_is_refused_when_the_link_is_paused_or_halted_and_never_reaches_the_kind() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, CONFIG).unwrap();
    let c = path.to_str().unwrap();
    let cmd: &[&str] = &["bridge", "loopback", "echo", "--link", "l1", "hello"];

    // The kind is listed with its verb.
    let (ok, out) = run(c, &["bridge", "list"]);
    assert!(
        ok && out.contains("loopback") && out.contains("echo"),
        "{out}"
    );

    // Paused (`enabled = false`): refused, and no secrets are needed to say so.
    let (ok, out) = run(c, cmd);
    assert!(
        !ok && out.contains("paused") && out.contains("link resume"),
        "{out}"
    );

    // Running but halted: refused with the halt named.
    openvti_bridges::cli::link_set_enabled(&path, "l1", true).unwrap();
    let cfg = Config::load(&path).unwrap();
    let store_dir = link_dir(&cfg.data_dir_from(&path), "l1").join("store");
    std::fs::create_dir_all(&store_dir).unwrap();
    {
        let s = FjallStore::open(&store_dir).unwrap();
        halt::write(&s, &HaltReason::refused("removed from the room"))
            .await
            .unwrap();
    }
    let (ok, out) = run(c, cmd);
    assert!(
        !ok && out.contains("halted") && out.contains("clear-halt"),
        "{out}"
    );

    // A verb the kind does not have is refused by name, after the gate.
    let (ok, out) = run(c, &["bridge", "loopback", "nope", "--link", "l1"]);
    assert!(!ok, "{out}");
}
