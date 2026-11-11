//! Geb's path B test vectors, round 1 (`geb-path-b-vectors.json`).
//!
//! Two sets can run (see `common/mod.rs`). Geb's own file, generated at Geb
//! substrate commit release 0.5.14 (round 1, release 0.5.14; the crate is pinned to
//! `fdf804d`, 0.5.15, and nothing in it is a 0.5.15 output), is not redistributed
//! here: when it is present locally (`$GEB_VECTORS_DIR`, or
//! `tests/fixtures/private/`) these tests run against it, and that run is the real
//! interop check. Otherwise they run against the committed STAND-IN vectors, which
//! this crate generated from fresh throwaway keys (`gen_standin_vectors.rs`): a stand-in
//! run proves the crate agrees with itself and that the fixture structure is what these
//! tests expect, and nothing about agreement with Geb.
//!
//! In Geb's file every value was produced by Geb's own code from fixed, labelled
//! test keys and it holds test keys and public outputs only. Where Geb draws
//! randomness it cannot fix (sealed box, mailbox envelope, ratchet nonces) the vector
//! gives a ciphertext to OPEN, and these checks open it. Nothing here is computed by
//! this crate and then compared with itself except where a vector pins a byte-exact
//! output (and in a stand-in run, everything is).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use openvti_bridge_geb::crypto::{
    did_peer, frame_id, inbox, leaf, line_id, pair, ratchet, rendezvous, sealed, sign,
};
use openvti_bridge_geb::wire::{LineBody, signing_doc};
use serde_json::Value;

mod common;

fn all() -> Value {
    serde_json::from_str(&common::load(common::V1)).expect("fixture is JSON")
}

fn vec_of(name: &str) -> Value {
    all()["vectors"][name].clone()
}

fn s(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn h32(v: &Value) -> [u8; 32] {
    hex::decode(s(v)).unwrap().try_into().unwrap()
}

fn identity(v: &Value, label: &str) -> Value {
    v["identities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["label"] == label)
        .unwrap()
        .clone()
}

#[test]
fn every_promised_vector_is_present() {
    let v = all();
    for k in [
        "did_peer_2",
        "inbox_derivation",
        "sealed_box",
        "pair_rendezvous",
        "mailbox_envelope",
        "ratchet_frames",
        "sign_json",
        "leaf_binding",
        "room_line",
        "frame_id",
    ] {
        assert!(v["vectors"].get(k).is_some(), "fixture lacks `{k}`");
    }
}

#[test]
fn did_peer_2_encode_decode_and_document() {
    let v = vec_of("did_peer_2");
    for label in ["alice", "bob"] {
        let id = identity(&v, label);
        let ed = h32(&id["ed25519_pub_hex"]);
        let x = h32(&id["x25519_pub_hex"]);
        // Byte-exact encode.
        assert_eq!(did_peer::encode(&ed, &x, None).unwrap(), s(&id["did"]));
        // Decode.
        let d = did_peer::decode(s(&id["did"])).unwrap();
        assert_eq!(d.assertion, Some(ed));
        assert_eq!(d.authentication, Some(ed));
        assert_eq!(d.key_agreement, Some(x));
        // The X25519 public from the labelled secret.
        assert_eq!(rendezvous::e_public(&h32(&id["x25519_secret_hex"])), x);
        // The Ed25519 public from the labelled seed.
        let sk = SigningKey::from_bytes(&h32(&id["ed25519_seed_hex"]));
        assert_eq!(sk.verifying_key().to_bytes(), ed);
    }
    // The DID document, including the `#key-N` ids (N counts elements in DID
    // order: A, V, E), compared as JSON values.
    let alice = identity(&v, "alice");
    let doc = did_peer::document(s(&alice["did"])).unwrap();
    assert_eq!(doc, v["did_document_alice"]);
}

#[test]
fn inbox_derivation_is_byte_exact() {
    let v = vec_of("inbox_derivation");
    let x = h32(&v["input"]["ikm_x25519_pub_hex"]);
    // The IKM is the raw X25519 key inside the DID, too.
    let d = did_peer::decode(s(&v["input"]["did"])).unwrap();
    assert_eq!(d.key_agreement, Some(x));
    assert_eq!(
        hex::encode(inbox::inbox_secret(&x).unwrap()),
        s(&v["output"]["nostrSecret"])
    );
    let pk = hex::encode(inbox::inbox_pubkey(&x).unwrap());
    assert_eq!(pk, s(&v["output"]["nostrPubkey"]));
    assert_eq!(pk, s(&v["output"]["inbox_pubkey_of"]));
}

#[test]
fn sealed_box_opens_with_bobs_secret() {
    let v = vec_of("sealed_box");
    let bob_secret = h32(&v["input"]["recipient_x25519_secret_hex"]);
    assert_eq!(
        rendezvous::e_public(&bob_secret),
        h32(&v["input"]["recipient_x25519_pub_hex"])
    );
    let blob = sealed::open(&bob_secret, s(&v["output"]["content_b64"])).unwrap();
    assert_eq!(blob, s(&v["input"]["plaintext"]).as_bytes());
    // The stated layout.
    let raw = openvti_bridge_geb::crypto::b64_decode(s(&v["output"]["content_b64"])).unwrap();
    assert_eq!(hex::encode(&raw[..32]), s(&v["output"]["eph_pub_hex"]));
    assert_eq!(hex::encode(&raw[32..44]), s(&v["output"]["nonce_hex"]));
    assert_eq!(
        raw.len() - 44,
        v["output"]["ct_and_tag_len"].as_u64().unwrap() as usize
    );
}

fn pair_keys_for(v: &Value) -> (rendezvous::RelayKeys, rendezvous::RelayKeys) {
    let ids = vec_of("did_peer_2");
    let (a, b) = (identity(&ids, "alice"), identity(&ids, "bob"));
    assert_eq!(s(&v["input"]["alice_did"]), s(&a["did"]));
    assert_eq!(s(&v["input"]["bob_did"]), s(&b["did"]));
    let ka =
        rendezvous::pair_keys(&h32(&a["x25519_secret_hex"]), &h32(&b["x25519_pub_hex"])).unwrap();
    let kb =
        rendezvous::pair_keys(&h32(&b["x25519_secret_hex"]), &h32(&a["x25519_pub_hex"])).unwrap();
    (ka, kb)
}

#[test]
fn pair_rendezvous_is_byte_exact_and_symmetric() {
    let v = vec_of("pair_rendezvous");
    let (ka, kb) = pair_keys_for(&v);
    for k in [&ka, &kb] {
        assert_eq!(hex::encode(*k.aead_key), s(&v["output"]["aeadKey"]));
        assert_eq!(hex::encode(*k.nostr_secret), s(&v["output"]["nostrSecret"]));
        assert_eq!(k.pubkey_hex().unwrap(), s(&v["output"]["nostrPubkey"]));
    }
    assert_eq!(v["output"]["same_both_sides"], true);
}

#[test]
fn mailbox_envelope_opens_with_the_given_key_and_aad() {
    let v = vec_of("mailbox_envelope");
    let i = &v["input"];
    let keys = rendezvous::RelayKeys::from_parts(
        // The mailbox pubkey in the AAD is the pair's; take the pair secret.
        h32(&vec_of("pair_rendezvous")["output"]["nostrSecret"]),
        h32(&i["aead_key_hex"]),
    );
    let kind = i["kind"].as_u64().unwrap() as u32;
    assert_eq!(keys.pubkey_hex().unwrap(), s(&i["pair_pubkey_hex"]));
    assert_eq!(
        pair::aad(s(&i["pair_pubkey_hex"]), kind),
        s(&i["aad_utf8"]).as_bytes()
    );
    let pt = pair::open(&keys, kind, s(&v["output"]["content_b64"])).unwrap();
    assert_eq!(pt, s(&i["envelope_json"]).as_bytes());
    // The nonce is the first 12 bytes.
    let raw = openvti_bridge_geb::crypto::b64_decode(s(&v["output"]["content_b64"])).unwrap();
    assert_eq!(hex::encode(&raw[..12]), s(&v["output"]["nonce_hex"]));
    // The AAD binds the kind.
    assert!(pair::open(&keys, kind + 1, s(&v["output"]["content_b64"])).is_err());
}

#[test]
fn ratchet_frames_open_out_of_order_and_replay_fails() {
    let v = vec_of("ratchet_frames");
    let ids = vec_of("did_peer_2");
    let (a, b) = (identity(&ids, "alice"), identity(&ids, "bob"));
    assert_eq!(s(&v["input"]["sender_did"]), s(&a["did"]));
    assert_eq!(s(&v["input"]["receiver_did"]), s(&b["did"]));
    // Alice's DID sorts lower, so she sends on lo2hi.
    assert_eq!(v["input"]["sender_is_lower_did"], true);
    let alice_side = ratchet::my_side(s(&a["did"]), s(&b["did"])).unwrap();
    assert_eq!(alice_side, ratchet::Side::Lo);
    assert_eq!(v["input"]["sender_sends_on"], "lo2hi");

    // Bob's view: ECDH with alice, receive on the chain alice sends on.
    let shared =
        openvti_bridge_geb::crypto::ecdh(&h32(&b["x25519_secret_hex"]), &h32(&a["x25519_pub_hex"]))
            .unwrap();
    let ck = ratchet::channel_key(&shared).unwrap();
    let mut recv = ratchet::RecvChain::new(&ck, alice_side).unwrap();

    let frames = v["output"]["frames"].as_array().unwrap();
    let pts = v["input"]["plaintexts"].as_array().unwrap();
    // Counters are in the frame header, and the frame ids follow frame_id().
    for (n, f) in frames.iter().enumerate() {
        let raw = openvti_bridge_geb::crypto::b64_decode(s(&f["frame_b64"])).unwrap();
        assert_eq!(hex::encode(&raw[..4]), s(&f["counter_hex"]));
        assert_eq!(u32::from_be_bytes(raw[..4].try_into().unwrap()), n as u32);
        assert_eq!(frame_id::frame_id(s(&f["frame_b64"])), s(&f["frame_id"]));
    }
    for step in v["output"]["receiver_open_order"].as_array().unwrap() {
        let i = step["i"].as_u64().unwrap() as usize;
        let got = recv.open_b64(s(&frames[i]["frame_b64"])).unwrap();
        assert_eq!(got, s(&step["plaintext"]).as_bytes());
        assert_eq!(got, s(&pts[i]).as_bytes());
    }
    // A second open of frame 0 is a replay and must fail.
    let err = recv.open_b64(s(&frames[0]["frame_b64"])).unwrap_err();
    assert!(
        err.to_string().contains("replay"),
        "replay not named: {err}"
    );
    assert!(
        v["output"]["second_open_of_frame_0"]
            .as_str()
            .unwrap()
            .contains("replay")
    );
}

#[test]
fn sign_json_is_byte_exact() {
    let v = vec_of("sign_json");
    let i = &v["input"];
    let sk = SigningKey::from_bytes(&h32(&i["signer_ed25519_seed_hex"]));
    let doc: Value = serde_json::from_str(s(&i["json"])).unwrap();
    let jcs = serde_json_canonicalizer::to_vec(&doc).unwrap();
    assert_eq!(jcs, s(&v["output"]["jcs_utf8"]).as_bytes());
    let sig = sign::sign_json(&sk, &doc).unwrap();
    assert_eq!(sig, s(&v["output"]["sig_b64url"]));
    sign::verify_json(&sk.verifying_key(), &doc, &sig).unwrap();
    // The verifying key a peer takes from the DID.
    let did = did_peer::decode(s(&i["signer_did"])).unwrap();
    sign::verify_json(&did.verifying_key().unwrap(), &doc, &sig).unwrap();
    assert_eq!(v["output"]["verify_json"], true);
}

#[test]
fn leaf_binding_is_byte_exact() {
    let v = vec_of("leaf_binding");
    let i = &v["input"];
    let ids = vec_of("did_peer_2");
    let alice = identity(&ids, "alice");
    let sk = SigningKey::from_bytes(&h32(&alice["ed25519_seed_hex"]));
    let did = s(&i["did"]);
    let k = h32(&i["k_hex"]);
    // The payload as passed canonicalises to the signed string.
    let passed: Value = serde_json::from_str(s(&i["payload_json_as_passed"])).unwrap();
    assert_eq!(passed, leaf::binding_doc(did, &k));
    let signed = leaf::signed_bytes(did, &k).unwrap();
    assert_eq!(signed, s(&v["output"]["jcs_utf8_signed"]).as_bytes());
    let b = leaf::binding(&sk, did, &k).unwrap();
    assert_eq!(b, s(&v["output"]["binding_string"]));
    assert_eq!(b.len(), leaf::BINDING_LEN);
    assert_eq!(
        hex::encode(leaf::extension_value(&b)),
        s(&v["output"]["extension_0xF002_bytes_hex"])
    );
    leaf::verify(&sk.verifying_key(), did, &k, &b).unwrap();
    // The live (random-key) check: the binding string is the same shape.
    let live = &v["live_check"];
    let lk = h32(&live["k"]);
    let lb = leaf::binding(&sk, did, &lk).unwrap();
    leaf::verify(&sk.verifying_key(), did, &lk, &lb).unwrap();
    assert!(leaf::verify(&sk.verifying_key(), did, &lk, &b).is_err());
}

#[test]
fn room_line_signature_and_derived_id() {
    let v = vec_of("room_line");
    let i = &v["input"];
    let o = &v["output"];
    let ids = vec_of("did_peer_2");
    let alice = identity(&ids, "alice");
    let sk = SigningKey::from_bytes(&h32(&alice["ed25519_seed_hex"]));
    let (room, author) = (s(&i["room"]), s(&i["author_did"]));
    let line = LineBody::new(i["at"].as_u64().unwrap(), s(&i["text"]).to_string());

    // The unsigned plaintext is `{t,at,text}` in that order.
    assert_eq!(
        serde_json::to_string(&openvti_bridge_geb::wire::RoomPlaintext::Line(line.clone()))
            .unwrap(),
        s(&o["plaintext_unsigned"])
    );
    let doc = signing_doc(room, author, &line).unwrap();
    let passed: Value = serde_json::from_str(s(&o["sig_payload_json_as_passed"])).unwrap();
    assert_eq!(doc, passed);
    assert_eq!(
        serde_json::json!(
            String::from_utf8(serde_json_canonicalizer::to_vec(&doc).unwrap()).unwrap()
        ),
        o["sig_payload_jcs_utf8"]
    );
    let sg = sign::sign_json(&sk, &doc).unwrap();
    let signed: Value = serde_json::from_str(s(&o["plaintext_signed"])).unwrap();
    assert_eq!(sg, s(&signed["sg"]));
    // The signed plaintext parses as our line and carries that signature.
    let parsed: LineBody = serde_json::from_value(signed).unwrap();
    assert_eq!(parsed.sg.as_deref(), Some(sg.as_str()));

    let id = line_id::line_id(room, author, line.at, &line.text).unwrap();
    assert_eq!(id, s(&o["line_id"]));
}

#[test]
fn frame_id_cases() {
    for c in vec_of("frame_id")["cases"].as_array().unwrap() {
        assert_eq!(frame_id::frame_id(s(&c["input"])), s(&c["frame_id"]));
    }
}
