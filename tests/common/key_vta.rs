//! A fake VTA that serves only `keys/create/0.1` and `keys/export-secret/0.1`,
//! for the custody tests. It mints random keys and records every request, so a
//! test can assert exactly which keys were exported (the persona never is).
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use vta_sdk::client::loopback::LoopbackSink;
use vta_sdk::error::VtaError;

#[derive(Default)]
pub struct KeyVta {
    keys: Mutex<HashMap<String, (String, [u8; 32])>>,
    pub created: Mutex<Vec<Value>>,
    pub exported: Mutex<Vec<String>>,
    /// Refuse every export (the key is not exportable).
    pub refuse_export: std::sync::atomic::AtomicBool,
    /// Report a public key that does not match the secret.
    pub lie_about_public: std::sync::atomic::AtomicBool,
}

fn public_of(kind: &str, secret: &[u8; 32]) -> Vec<u8> {
    match kind {
        "ed25519" => {
            let mut v = vec![0xed, 0x01];
            v.extend_from_slice(
                &ed25519_dalek::SigningKey::from_bytes(secret)
                    .verifying_key()
                    .to_bytes(),
            );
            v
        }
        _ => {
            let mut v = vec![0xec, 0x01];
            v.extend_from_slice(
                &x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret))
                    .to_bytes(),
            );
            v
        }
    }
}

impl LoopbackSink for KeyVta {
    fn dispatch(&self, type_uri: &str, payload: &Value) -> Result<Value, VtaError> {
        if type_uri == vta_sdk::trust_tasks::TASK_KEYS_CREATE_0_1 {
            let kind = payload["keyType"].as_str().unwrap_or("").to_string();
            let mut secret = [0u8; 32];
            rand::fill(&mut secret[..]);
            let mut keys = self.keys.lock().unwrap();
            let id = format!("key-{}", keys.len() + 1);
            keys.insert(id.clone(), (kind.clone(), secret));
            self.created.lock().unwrap().push(payload.clone());
            return Ok(json!({ "key": {
                "keyId": id,
                "keyType": kind,
                "derivationPath": format!("m/44'/{}'", keys.len()),
                "publicKey": multibase::encode(multibase::Base::Base58Btc, public_of(&kind, &secret)),
                "status": "active",
                "label": payload.get("label").cloned().unwrap_or(Value::Null),
                "origin": "derived",
                "createdAt": "2026-01-01T00:00:00Z",
            }}));
        }
        if type_uri == vta_sdk::trust_tasks::TASK_KEYS_EXPORT_SECRET_0_1 {
            let id = payload["keyId"].as_str().unwrap_or("").to_string();
            self.exported.lock().unwrap().push(id.clone());
            if self.refuse_export.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(VtaError::Forbidden("key is not exportable".into()));
            }
            let keys = self.keys.lock().unwrap();
            let (kind, secret) = keys
                .get(&id)
                .ok_or_else(|| VtaError::NotFound(id.clone()))?;
            let mut public = public_of(kind, secret);
            if self
                .lie_about_public
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                public[5] ^= 1;
            }
            return Ok(json!({
                "keyId": id,
                "keyType": kind,
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, public),
                "privateKeyMultibase": multibase::encode(multibase::Base::Base58Btc, secret),
            }));
        }
        Err(VtaError::Other(format!(
            "key fake does not serve {type_uri}"
        )))
    }
}
