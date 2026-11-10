//! Identity and key custody against a fake VTA that serves only key create and
//! export (plan section 4): the VTA-backed `KeyMinter` and the secret store,
//! with the Geb adapter's minting on top. The fake is the test's own reading of
//! the two tasks; it is not a real VTA.
#![cfg(feature = "harness")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::key_vta::KeyVta;
use openvti_bridges::config::SecretsConfig;
use openvti_bridges::custody::{SecretStore, VtaKeyMinter};
use openvti_bridges::geb::crypto::did_peer;
use openvti_bridges::geb::custody::{GebLinkSecrets, mint_device_identity};
use openvti_bridges::geb::traits::GebSigner;
use openvti_bridges::secrets::{BridgeSecrets, ClientCredential};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use vta_sdk::client::VtaClient;

fn client(vta: &Arc<KeyVta>) -> VtaClient {
    VtaClient::loopback(vta.clone())
}

/// What `provision` does for one link: mint, then wrap with the persona.
async fn mint(
    vta: &Arc<KeyVta>,
    link: &str,
    persona: &str,
) -> openvti_bridges::Result<(GebLinkSecrets, openvti_bridges::secrets::LinkSecrets)> {
    let c = client(vta);
    let g = mint_device_identity(&VtaKeyMinter(&c), "openvti-bridges", link).await?;
    let ls = g.into_link_secrets(persona)?;
    Ok((g, ls))
}

fn plaintext_cfg() -> SecretsConfig {
    let t: toml::Table =
        toml::from_str("backend = \"plaintext\"\nallow_plaintext = true\ncache_ttl_secs = 0\n")
            .unwrap();
    SecretsConfig(t)
}

#[tokio::test(flavor = "multi_thread")]
async fn mints_two_separate_keys_and_builds_the_did_locally() {
    let vta = Arc::new(KeyVta::default());
    let (s, _) = mint(&vta, "l1", "did:key:persona1").await.unwrap();
    // Two creates, one per type, in the bridge context.
    let created = vta.created.lock().unwrap().clone();
    assert_eq!(created.len(), 2);
    assert_eq!(created[0]["keyType"], "ed25519");
    assert_eq!(created[1]["keyType"], "x25519");
    assert!(created.iter().all(|c| c["contextId"] == "openvti-bridges"));
    assert!(created.iter().all(|c| c.get("internal").is_none()));
    // Exactly those two were exported, once each; nothing for the persona.
    let exported = vta.exported.lock().unwrap().clone();
    assert_eq!(exported, vec![s.ed_key_id.clone(), s.x_key_id.clone()]);
    // The DID is `did:peer:2.A.V.E` with the same Ed25519 under A and V, no .S.
    let d = did_peer::decode(&s.device_did).unwrap();
    assert_eq!(d.assertion, d.authentication);
    assert!(d.assertion.is_some() && d.key_agreement.is_some() && d.service.is_none());
    assert!(s.device_did.starts_with("did:peer:2.A"));
    // The identity rebuilt from the stored secrets signs as that DID.
    let id = s.identity().unwrap();
    assert_eq!(id.did(), s.device_did);
    assert_eq!(id.e_public(), d.key_agreement.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_lying_or_unexportable_vta_and_stores_nothing() {
    let vta = Arc::new(KeyVta::default());
    vta.refuse_export.store(true, Ordering::SeqCst);
    assert!(mint(&vta, "l1", "did:key:p").await.is_err());
    vta.refuse_export.store(false, Ordering::SeqCst);
    vta.lie_about_public.store(true, Ordering::SeqCst);
    let e = mint(&vta, "l1", "did:key:p").await.unwrap_err();
    assert!(e.to_string().contains("does not match"), "{e}");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_device_did_and_one_persona_per_link() {
    let vta = Arc::new(KeyVta::default());
    let mut secrets = BridgeSecrets::new();
    let (_, a) = mint(&vta, "l1", "did:key:p1").await.unwrap();
    let (_, b) = mint(&vta, "l2", "did:key:p2").await.unwrap();
    secrets.insert("l1", a.clone()).unwrap();
    secrets.insert("l2", b).unwrap();
    // Same link twice, same device on another link, same persona: all refused.
    assert!(secrets.insert("l1", a.clone()).is_err());
    assert!(secrets.insert("l3", a).is_err());
    let (_, c) = mint(&vta, "l3", "did:key:p1").await.unwrap();
    let e = secrets.insert("l3", c).unwrap_err();
    assert!(e.to_string().contains("persona"), "{e}");
    assert_eq!(secrets.link_ids().count(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_round_trip_the_store_and_never_print() {
    let dir = tempfile::tempdir().unwrap();
    let vta = Arc::new(KeyVta::default());
    let store = SecretStore::open(&plaintext_cfg(), dir.path()).unwrap();
    assert!(store.load().await.unwrap().is_none());
    let mut secrets = BridgeSecrets::new();
    let (g, ls) = mint(&vta, "l1", "did:key:p1").await.unwrap();
    secrets.insert("l1", ls.clone()).unwrap();
    secrets.set_client(ClientCredential::new(
        "did:key:zClient",
        "z-secret-client-key",
    ));
    store.save(&secrets).await.unwrap();

    let back = SecretStore::open(&plaintext_cfg(), dir.path())
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        back.store_key().unwrap()[..],
        secrets.store_key().unwrap()[..]
    );
    assert_eq!(
        GebLinkSecrets::from_link_secrets(back.link("l1").unwrap())
            .unwrap()
            .identity()
            .unwrap()
            .did(),
        g.device_did
    );
    assert_eq!(
        &**back.client().unwrap().private_key_multibase().unwrap(),
        "z-secret-client-key"
    );
    // No Debug form carries a secret.
    let dbg = format!("{back:?} {ls:?} {g:?} {:?}", back.client().unwrap());
    assert!(!dbg.contains("z-secret-client-key"));
    let ed_hex = hex_of_ed(&g);
    assert!(!dbg.contains(&ed_hex));
}

fn hex_of_ed(ls: &GebLinkSecrets) -> String {
    // The serialised form is the only place the secret appears.
    let v = serde_json::to_value(ls).unwrap();
    v["ed_secret"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn config_seed_is_refused_and_a_tampered_blob_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let t: toml::Table = toml::from_str("backend = \"config_seed\"\nseed = \"00\"\n").unwrap();
    assert!(SecretStore::open(&SecretsConfig(t), dir.path()).is_err());
    let store = SecretStore::open(&plaintext_cfg(), dir.path()).unwrap();
    store.save(&BridgeSecrets::new()).await.unwrap();
    // A blob of another layout version is refused with what to do.
    let mut old: serde_json::Value =
        serde_json::from_slice(&serde_json::to_vec(&BridgeSecrets::new()).unwrap()).unwrap();
    old["version"] = 1.into();
    let raw = serde_json::to_vec(&old).unwrap();
    let p = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().contains("plaintext"))
        .unwrap();
    // (the plaintext backend keeps the blob as hex)
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&p, hex).unwrap();
    let e = store.load().await.unwrap_err().to_string();
    assert!(e.contains("version 1") && e.contains("setup"), "{e}");
    // Corrupt the stored bytes: load fails closed, with no secret in the error.
    let p = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().contains("plaintext"))
        .unwrap();
    std::fs::write(&p, b"{not json").unwrap();
    assert!(store.load().await.is_err());
}
