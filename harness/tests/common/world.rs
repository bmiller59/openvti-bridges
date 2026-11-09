//! The harness world shared by `harness.rs` and `e2e.rs`: a real `room-host`
//! on a TCP port, a room fixture, and a fake VTA (`TestVta`) that signs as the
//! persona and fetches from the host as the member.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use chrono::{Duration, Utc};
use dtg_credentials::{DTGCredential, IssuerScope};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use vta_sdk::client::VtaClient;
use vta_sdk::client::loopback::LoopbackSink;
use vta_sdk::error::VtaError;
use vtc_client::VtcClient;
use vtc_client::rooms::CleartextContent;
use vti_geb_bridge::config::Directions;
use vti_geb_bridge::pump::LinkRuntime;
use vti_geb_bridge::room::{RoomRecord, RoomSide};
use vti_geb_bridge::vtc::host::HostDelivery;
use vti_geb_bridge::vtc::{VtcRoom, VtcRoomConfig};
use vti_rooms_dtg::test_support::{Party, RoomFixture};

pub const HOST_DID: &str = "did:key:zHost";

// ---------------------------------------------------------------- the host

pub struct Host {
    pub url: String,
    pub _dir: tempfile::TempDir,
}

pub async fn start_host() -> Host {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = room_host::open_state(dir.path()).unwrap();
    let app = room_host::router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Host {
        url: format!("http://{addr}"),
        _dir: dir,
    }
}

// ------------------------------------------------------------ the members

pub struct Member {
    pub party: Party,
    pub presentation: Value,
}

/// A second member of the fixture's room, admitted with `actions`.
pub async fn mint_member(f: &RoomFixture, actions: &[&str]) -> Member {
    let party = Party::new();
    let now = Utc::now();
    let mut vac = DTGCredential::new_vac(
        f.room_key.did.clone(),
        IssuerScope::Public,
        party.did.clone(),
        f.room_key.did.clone(),
        actions.iter().map(|a| a.to_string()).collect(),
        now - Duration::minutes(1),
        now + Duration::days(30),
    )
    .unwrap()
    .with_id(format!(
        "urn:uuid:vac-{}",
        &party.did[party.did.len() - 8..]
    ));
    vac.sign(&f.room_key.secret, None).await.unwrap();
    let mut vmc = DTGCredential::new_vmc(
        f.room_key.did.clone(),
        party.did.clone(),
        now - Duration::minutes(1),
        Some(now + Duration::days(30)),
        false,
    );
    vmc.sign(&f.room_key.secret, None).await.unwrap();
    let presentation = json!({
        "membership": serde_json::to_string(&vmc).unwrap(),
        "authority": [serde_json::to_string(&vac).unwrap()],
    });
    Member {
        party,
        presentation,
    }
}

// --------------------------------------------------------------- fake VTA

/// The user's VTA, as far as the bridge can tell: signs as the persona and
/// fetches from the host as the member. Records what it was asked.
pub struct TestVta {
    pub handle: tokio::runtime::Handle,
    pub host: VtcClient,
    pub room_id: String,
    pub persona: Member,
    pub seen: Mutex<Vec<String>>,
}

impl TestVta {
    pub async fn signed(&self, type_uri: &str, mut payload: Value) -> Value {
        payload["presentation"] = self.persona.presentation.clone();
        let doc = vta_sdk::trust_task_sign::build_signed(
            type_uri,
            payload,
            &self.persona.party.did,
            &self.persona.party.secret_multibase,
            HOST_DID,
        )
        .await
        .unwrap();
        serde_json::from_str(&doc).unwrap()
    }

    pub async fn host_call(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> std::result::Result<Value, VtaError> {
        let doc = self.signed(type_uri, payload).await;
        self.host
            .send_signed_room_document(&doc)
            .await
            .map_err(|e| VtaError::Other(e.to_string()))
    }

    pub async fn dispatch_async(
        &self,
        type_uri: &str,
        payload: &Value,
    ) -> std::result::Result<Value, VtaError> {
        self.seen.lock().unwrap().push(type_uri.to_string());
        if type_uri == vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_11 {
            let doc = &payload["document"];
            let signed = self
                .signed(doc["type"].as_str().unwrap(), doc["payload"].clone())
                .await;
            return Ok(json!({ "principal": self.persona.party.did, "document": signed }));
        }
        if type_uri == vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_4 {
            let list = <vti_specs::rooms::records::list::v0_6::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let mut records: Vec<Value> = Vec::new();
            let mut cursor: Option<String> = None;
            let head;
            loop {
                let mut p = json!({ "roomId": self.room_id });
                if let Some(s) = payload.get("sinceVersion") {
                    p["sinceVersion"] = s.clone();
                }
                if let Some(c) = &cursor {
                    p["cursor"] = json!(c);
                }
                let page = self.host_call(list, p).await?;
                records.extend(page["records"].as_array().cloned().unwrap_or_default());
                match page["nextCursor"].as_str() {
                    Some(c) if payload.get("limit").is_none() => cursor = Some(c.to_string()),
                    _ => {
                        head = json!({
                            "dataCommitment": page["dataCommitment"],
                            "headVersion": page["headVersion"],
                            "recordCount": page["recordCount"],
                        });
                        break;
                    }
                }
            }
            let mut verification = json!({ "priorRoots": "notChecked" });
            if head.values_all_present() {
                verification["head"] = head;
            }
            return Ok(json!({
                "roomId": self.room_id,
                "records": records,
                "complete": true,
                "verification": verification,
            }));
        }
        if type_uri == vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_2 {
            let get = <vti_specs::rooms::records::get::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI;
            let keys: Vec<String> = payload["keys"]
                .as_array()
                .map(|k| {
                    k.iter()
                        .filter_map(|k| k.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let mut results = Vec::new();
            for key in keys {
                let rec = self
                    .host_call(get, json!({ "roomId": self.room_id, "key": key }))
                    .await?;
                let mut entry = json!({ "key": key });
                for f in [
                    "version",
                    "status",
                    "cleartext",
                    "createdBy",
                    "createdAt",
                    "updatedAt",
                    "bodyStoredAt",
                    "author",
                ] {
                    if let Some(v) = rec.get(f) {
                        entry[f] = v.clone();
                    }
                }
                results.push(entry);
            }
            return Ok(json!({ "roomId": self.room_id, "results": results }));
        }
        Err(VtaError::Other(format!(
            "test VTA does not serve {type_uri}"
        )))
    }
}

pub trait HeadComplete {
    fn values_all_present(&self) -> bool;
}
impl HeadComplete for Value {
    fn values_all_present(&self) -> bool {
        self.as_object()
            .is_some_and(|o| o.values().all(|v| !v.is_null()))
    }
}

impl LoopbackSink for TestVta {
    fn dispatch(&self, type_uri: &str, payload: &Value) -> std::result::Result<Value, VtaError> {
        tokio::task::block_in_place(|| self.handle.block_on(self.dispatch_async(type_uri, payload)))
    }
}

// ----------------------------------------------------------- the scenario

pub struct World {
    pub host: Host,
    pub fixture: RoomFixture,
    pub human_client: VtcClient,
    pub vta: Arc<TestVta>,
}

impl World {
    pub async fn new(host: &Host) -> World {
        let fixture = RoomFixture::new(vti_rooms::Visibility::Open).await;
        let human_client = VtcClient::anonymous(&host.url, HOST_DID);
        human_client
            .create_room(
                &fixture.room.room_id,
                &fixture.owner.did,
                vtc_client::rooms::Visibility::Open,
                Some(90),
                &fixture.owner.did,
                &fixture.owner.secret_multibase,
            )
            .await
            .unwrap();
        let persona = mint_member(&fixture, &["read", "write"]).await;
        let vta = Arc::new(TestVta {
            handle: tokio::runtime::Handle::current(),
            host: VtcClient::anonymous(&host.url, HOST_DID),
            room_id: fixture.room.room_id.clone(),
            persona,
            seen: Mutex::new(Vec::new()),
        });
        World {
            host: Host {
                url: host.url.clone(),
                _dir: tempfile::tempdir().unwrap(),
            },
            fixture,
            human_client,
            vta,
        }
    }

    pub fn persona(&self) -> &str {
        &self.vta.persona.party.did
    }

    pub fn room(&self) -> Arc<VtcRoom> {
        let client = Arc::new(VtaClient::loopback(self.vta.clone()));
        let delivery = HostDelivery::for_loopback_tests(&self.host.url);
        Arc::new(VtcRoom::new(
            client,
            delivery,
            VtcRoomConfig {
                room_id: self.fixture.room.room_id.clone(),
                host_did: HOST_DID.into(),
                persona: self.persona().to_string(),
            },
        ))
    }

    /// A human member writes a record (the fixture's owner).
    pub async fn human_writes(&self, key: &str, title: &str, body: &str) {
        self.human_puts(key, title, body, 0).await
    }

    /// The same human edits a record they wrote, at `version`.
    pub async fn human_edits(&self, key: &str, title: &str, body: &str, version: u64) {
        self.human_puts(key, title, body, version).await
    }

    /// The same human retracts a record (a tombstone at the next version).
    pub async fn human_retracts(&self, key: &str) {
        let session = vtc_client::rooms::RoomSession::new(
            &self.fixture.room.room_id,
            self.fixture.membership.clone(),
            self.fixture.owner_chain.clone(),
        )
        .unwrap();
        self.human_client
            .curate_record(
                &session,
                key,
                Some("retracted".into()),
                None,
                None,
                &self.fixture.owner.did,
                &self.fixture.owner.secret_multibase,
            )
            .await
            .unwrap();
    }

    async fn human_puts(&self, key: &str, title: &str, body: &str, expected: u64) {
        let session = vtc_client::rooms::RoomSession::new(
            &self.fixture.room.room_id,
            self.fixture.membership.clone(),
            self.fixture.owner_chain.clone(),
        )
        .unwrap();
        self.human_client
            .put_record(
                &session,
                key,
                None,
                Some(CleartextContent {
                    title: Some(title.into()),
                    body: body.into(),
                    ..Default::default()
                }),
                Some(expected),
                &self.fixture.owner.did,
                &self.fixture.owner.secret_multibase,
            )
            .await
            .unwrap();
    }

    pub fn link(&self) -> LinkRuntime {
        LinkRuntime::new(
            "l1",
            self.persona(),
            b"link-secret".to_vec(),
            Directions::Both,
        )
    }

    /// Everything in the room, as the bridge's own read path sees it.
    pub async fn records(&self) -> Vec<RoomRecord> {
        self.room().browse(0).await.unwrap()
    }
}
