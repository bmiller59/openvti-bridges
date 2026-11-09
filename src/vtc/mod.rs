//! The VTC data-room side over the user's VTA: a [`RoomSide`] for the pump.
//!
//! The bridge never holds the persona key. Everything signed as the persona is
//! produced by the user's VTA:
//!
//! - **Reads** (`rooms/keys/browse/0.4`, `rooms/keys/read/0.2`) are VTA-side
//!   tasks: the VTA fetches from the host as the member, checks, and opens. The
//!   bridge delivers nothing to the host for a read.
//! - **Writes** are `rooms/keys/act` (and, on a sealed tier,
//!   `rooms/keys/seal/0.3` with `signAsPrincipal`): the VTA returns the signed
//!   document and the bridge posts it, unaltered, to the host
//!   ([`host::HostDelivery`]).
//!
//! Bridged text is untrusted: a record is written with `basis: "observed"`
//! (a sealed tier carries it as the body's own `basis`; an open tier's
//! cleartext has no such member, so there the provenance block in the body is
//! the only mark).
//!
//! Retry is never owned here: no `VtaClient` call is looped. A failed tick
//! returns a typed [`Error`] and the next tick resumes from the durable cursor
//! and outbox. The one rewrite this module performs is the sealed-put
//! re-seal at the version the host assigned, which is a different request, not
//! a retry.

pub mod host;

use crate::room::{PutOutcome, RecordWrite, RoomRecord, RoomSide, SkippedRecord};
use crate::{Error, Result};
use async_trait::async_trait;
use base64::Engine;
use host::{HostDelivery, from_vta, is_version_conflict};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::OnceCell;
use trust_tasks_rs::Payload as _;
use vta_sdk::client::{RoomBrowse, VtaClient, unsigned_room_request_v0_11};

/// The most times one sealed write is sealed: the first, plus a re-seal at the
/// version the host assigned when another write took the predicted one.
const SEALED_ATTEMPTS: usize = 3;
/// Keys per `rooms/keys/read/0.2` batch (the task's own bound).
const READ_BATCH: usize = vta_sdk::client::ROOM_READ_MAX_KEYS;

/// Where and as whom the bridge acts in one VTC room.
#[derive(Debug, Clone)]
pub struct VtcRoomConfig {
    /// The room's DID.
    pub room_id: String,
    /// The host's DID: the `recipient` of every document.
    pub host_did: String,
    /// The persona the room admitted (`P_b`), held by the user's VTA.
    pub persona: String,
}

/// A room's tier as far as the bridge cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// Cleartext records; the host can read them.
    Open,
    /// `attributed` (the only other tier served): sealed under the room epoch
    /// and signed by the author.
    Sealed,
}

/// The VTC data room, as the pump sees it.
pub struct VtcRoom {
    client: Arc<VtaClient>,
    host: HostDelivery,
    cfg: VtcRoomConfig,
    tier: OnceCell<Tier>,
    /// Records the last browse could not read for good (see
    /// [`RoomSide::take_skipped`]).
    skipped: std::sync::Mutex<Vec<SkippedRecord>>,
}

fn type_put() -> &'static str {
    #[allow(deprecated)]
    {
        vti_specs::rooms::records::put::v0_5::Payload::TYPE_URI
    }
}

fn type_info() -> &'static str {
    vti_specs::rooms::info::v0_3::Payload::TYPE_URI
}

/// A retracted record: no content, the version of the retraction. The author
/// is whoever the host names (it may be nobody; the pump labels that).
///
/// UNVERIFIED: that the host gives a retraction a version above the cursor
/// (the room-host's `curate` does: the room-wide counter moves), and that a
/// retracted listing row names `createdBy`/`author` at all.
fn tombstone(key: &str, version: u64, author: Option<&str>, row: &Value) -> RoomRecord {
    RoomRecord {
        key: key.to_string(),
        version,
        author: author.unwrap_or_default().to_string(),
        title: None,
        body: String::new(),
        at: row
            .get("updatedAt")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| u64::try_from(d.timestamp_millis()).unwrap_or(0))
            .unwrap_or(0),
        retracted: true,
    }
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

impl VtcRoom {
    /// Build the room side. `client` is the bridge's authenticated `VtaClient`
    /// (its own `did:key`, narrowed to `room-present,room-open` in the
    /// `geb-bridge` context).
    pub fn new(client: Arc<VtaClient>, host: HostDelivery, cfg: VtcRoomConfig) -> Self {
        Self {
            client,
            host,
            cfg,
            tier: OnceCell::new(),
            skipped: std::sync::Mutex::default(),
        }
    }

    /// Have the VTA complete one host-bound request as the persona
    /// (`rooms/keys/act/0.11`) and deliver it. Returns the host's payload.
    async fn act(&self, type_uri: &str, payload: Value) -> Result<Value> {
        let document = unsigned_room_request_v0_11(
            type_uri,
            &self.cfg.host_did,
            Some(&self.cfg.persona),
            payload,
        )
        .map_err(from_vta)?;
        #[allow(deprecated)]
        let completed = self
            .client
            .room_act_v0_11(&document)
            .await
            .map_err(from_vta)?;
        #[allow(deprecated)] // `document` is superseded by act/0.12 only; 0.11 is what is sent
        let signed =
            serde_json::to_value(&completed.document).map_err(|e| Error::Wire(e.to_string()))?;
        self.host.send(&signed).await
    }

    async fn tier(&self) -> Result<Tier> {
        self.tier
            .get_or_try_init(|| async {
                let reply = self
                    .act(type_info(), json!({ "roomId": self.cfg.room_id }))
                    .await?;
                match reply.get("visibility").and_then(Value::as_str) {
                    Some("open") => Ok(Tier::Open),
                    Some("attributed") => Ok(Tier::Sealed),
                    // `private` is not served yet (data-rooms.md); an unknown
                    // tier is refused rather than guessed.
                    other => Err(Error::Config(format!(
                        "room tier {other:?} is not bridged (open and attributed only)"
                    ))),
                }
            })
            .await
            .copied()
    }

    /// The room's head version, so a sealed write can predict the version the
    /// host will assign.
    async fn head_version(&self) -> Result<u64> {
        let opts = RoomBrowse {
            limit: Some(1),
            ..Default::default()
        };
        let resp = self
            .client
            .room_browse(
                &self.cfg.room_id,
                &self.cfg.host_did,
                &opts,
                Some(&self.cfg.persona),
            )
            .await
            .map_err(from_vta)?;
        let v = serde_json::to_value(&resp).map_err(|e| Error::Wire(e.to_string()))?;
        // UNVERIFIED: `verification.head.headVersion` is offered only by hosts
        // that commit to a tree; a host that does not leaves the prediction at
        // 1, and the re-seal at the assigned version corrects it.
        Ok(v.pointer("/verification/head/headVersion")
            .and_then(Value::as_u64)
            .unwrap_or(0))
    }

    /// Read one record back (author and body) for the already-exists check.
    async fn read_one(&self, key: &str) -> Result<Option<RoomRecord>> {
        let resp = self
            .client
            .room_read_batch(
                &self.cfg.room_id,
                &self.cfg.host_did,
                &[key],
                Some(&self.cfg.persona),
            )
            .await
            .map_err(from_vta)?;
        let v = serde_json::to_value(&resp).map_err(|e| Error::Wire(e.to_string()))?;
        match v["results"].as_array().and_then(|r| r.first()) {
            // A retracted key reads back as no record: for the already-exists
            // check a tombstone is not the write that was attempted.
            Some(entry) => Ok(self.entry_to_record(entry)?.filter(|r| !r.retracted)),
            None => Ok(None),
        }
    }

    /// A `rooms/keys/read/0.2` result entry as a record (a tombstone is a
    /// record with `retracted` set). A per-key error is returned typed.
    fn entry_to_record(&self, entry: &Value) -> Result<Option<RoomRecord>> {
        if let Some(err) = entry.get("error") {
            let code = err["code"].as_str().unwrap_or("rooms/keys/read:unknown");
            let message = err["message"].as_str().unwrap_or_default();
            let retryable = err["retryable"].as_bool().unwrap_or(false);
            return Err(host::typed(
                code,
                message,
                retryable,
                err.get("details").cloned(),
            ));
        }
        let key = entry["key"]
            .as_str()
            .ok_or_else(|| Error::Wire("read result without a key".into()))?
            .to_string();
        let version = entry["version"]
            .as_u64()
            .ok_or_else(|| Error::Wire("read result without a version".into()))?;
        let host_author = entry
            .get("author")
            .or_else(|| entry.get("createdBy"))
            .and_then(Value::as_str);
        if entry["status"] == "retracted" {
            return Ok(Some(tombstone(&key, version, host_author, entry)));
        }
        let (author, title, body) = if let Some(clear) = entry.get("cleartext") {
            (
                host_author.unwrap_or_default().to_string(),
                clear["title"].as_str().map(str::to_string),
                clear["body"].as_str().unwrap_or_default().to_string(),
            )
        } else if let Some(p) = entry.get("plaintext").and_then(Value::as_str) {
            let bytes = b64()
                .decode(p)
                .map_err(|e| Error::Wire(format!("plaintext is not base64url: {e}")))?;
            let sealed: Value = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Wire(format!("sealed record body is not JSON: {e}")))?;
            // The body's own `author` is the signer the VTA checked.
            let author = sealed["author"]
                .as_str()
                .or(host_author)
                .unwrap_or_default()
                .to_string();
            (
                author,
                sealed["title"].as_str().map(str::to_string),
                sealed["body"].as_str().unwrap_or_default().to_string(),
            )
        } else {
            return Err(Error::Wire(format!(
                "record {key} carries neither cleartext nor plaintext"
            )));
        };
        let at = entry
            .get("createdAt")
            .or_else(|| entry.get("updatedAt"))
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| u64::try_from(d.timestamp_millis()).unwrap_or(0))
            .unwrap_or(0);
        Ok(Some(RoomRecord {
            key,
            version,
            author,
            title,
            body,
            at,
            retracted: false,
        }))
    }

    async fn put_open(&self, write: &RecordWrite) -> Result<u64> {
        let payload = json!({
            "roomId": self.cfg.room_id,
            "key": write.key,
            "cleartext": { "body": write.body },
            "expectedVersion": write.expected_version,
        });
        let reply = self.act(type_put(), payload).await?;
        reply["version"]
            .as_u64()
            .ok_or_else(|| Error::Wire("put answered no version".into()))
    }

    async fn put_sealed(&self, write: &RecordWrite) -> Result<u64> {
        // The record's AEAD and signed body name the version, which the host
        // assigns from a room-wide counter: predict it from the head, and
        // rewrite at the assigned version when another write took it.
        let mut intended = self.head_version().await?.saturating_add(1);
        let mut expected = write.expected_version;
        let mut landed = 0;
        for _ in 0..SEALED_ATTEMPTS {
            let body = json!({
                "roomId": self.cfg.room_id,
                "key": write.key,
                "version": intended,
                "author": self.cfg.persona,
                "body": write.body,
                "basis": write.basis,
            });
            let bytes = serde_json::to_vec(&body).map_err(|e| Error::Wire(e.to_string()))?;
            let sealed = self
                .client
                .room_seal_as_principal_v0_3(&self.cfg.room_id, &write.key, intended, &bytes)
                .await
                .map_err(from_vta)?;
            let sealed =
                serde_json::to_value(sealed.sealed).map_err(|e| Error::Wire(e.to_string()))?;
            let payload = json!({
                "roomId": self.cfg.room_id,
                "key": write.key,
                "sealed": {
                    "ciphertext": sealed["ciphertext"],
                    "nonce": sealed["nonce"],
                    "epoch": sealed["epoch"],
                },
                "expectedVersion": expected,
            });
            let reply = self.act(type_put(), payload).await?;
            landed = reply["version"]
                .as_u64()
                .ok_or_else(|| Error::Wire("put answered no version".into()))?;
            if landed == intended {
                return Ok(landed);
            }
            // Stored but sealed for the wrong version: it does not open until
            // rewritten, over exactly what just landed.
            expected = landed;
            intended = landed.saturating_add(1);
        }
        Err(Error::Room {
            code: "sealedVersionRace".into(),
            message: format!(
                "{} is stored at version {landed} but sealed for another version; the room kept \
                 moving under {SEALED_ATTEMPTS} attempts",
                write.key
            ),
            retryable: true,
            details: Some(json!({ "key": write.key, "landedVersion": landed })),
        })
    }
}

#[async_trait]
impl RoomSide for VtcRoom {
    fn take_skipped(&self) -> Vec<SkippedRecord> {
        self.skipped
            .lock()
            .map(|mut g| std::mem::take(&mut *g))
            .unwrap_or_default()
    }

    async fn browse(&self, since_version: u64) -> Result<Vec<RoomRecord>> {
        if let Ok(mut sk) = self.skipped.lock() {
            sk.clear();
        }
        let opts = RoomBrowse {
            since_version: Some(since_version),
            ..Default::default()
        };
        let resp = self
            .client
            .room_browse(
                &self.cfg.room_id,
                &self.cfg.host_did,
                &opts,
                Some(&self.cfg.persona),
            )
            .await
            .map_err(from_vta)?;
        let v = serde_json::to_value(&resp).map_err(|e| Error::Wire(e.to_string()))?;
        // The host lists in version order, so an incomplete listing is a
        // contiguous prefix: it is processed and the next tick continues from
        // the cursor. (`complete: false` is not an error.)
        let listing = v["records"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        // A retracted row is a tombstone: it has no content to read, and the
        // pump decides from the key whether it ever crossed.
        let mut out: Vec<RoomRecord> = listing
            .iter()
            .filter(|r| r["status"] == "retracted")
            .filter_map(|r| {
                let author = r
                    .get("author")
                    .or_else(|| r.get("createdBy"))
                    .and_then(Value::as_str);
                Some(tombstone(
                    r["key"].as_str()?,
                    r["version"].as_u64().filter(|v| *v > since_version)?,
                    author,
                    r,
                ))
            })
            .collect();
        let mut rows: Vec<(u64, String)> = listing
            .iter()
            .filter(|r| r["status"] != "retracted")
            .filter_map(|r| Some((r["version"].as_u64()?, r["key"].as_str()?.to_string())))
            .filter(|(ver, _)| *ver > since_version)
            .collect();
        rows.sort();
        for chunk in rows.chunks(READ_BATCH) {
            let keys: Vec<&str> = chunk.iter().map(|(_, k)| k.as_str()).collect();
            let read = self
                .client
                .room_read_batch(
                    &self.cfg.room_id,
                    &self.cfg.host_did,
                    &keys,
                    Some(&self.cfg.persona),
                )
                .await
                .map_err(from_vta)?;
            let read = serde_json::to_value(&read).map_err(|e| Error::Wire(e.to_string()))?;
            let results = read["results"]
                .as_array()
                .ok_or_else(|| Error::Wire("batch read answered no results".into()))?;
            for (i, entry) in results.iter().enumerate() {
                match self.entry_to_record(entry) {
                    Ok(Some(rec)) => out.push(rec),
                    Ok(None) => {}
                    // A key the persona can never read (a non-retryable typed
                    // error, or a body that is not a record): reported to the
                    // pump to journal and pass, so it cannot stop the listing
                    // and hold the cursor behind it for ever.
                    Err(
                        e @ (Error::Room {
                            retryable: false, ..
                        }
                        | Error::Wire(_)),
                    ) => {
                        let Some((version, key)) = chunk.get(i) else {
                            return Err(e);
                        };
                        tracing::error!(key = %key, error = %e, "a room record cannot be read; skipped");
                        if let Ok(mut sk) = self.skipped.lock() {
                            sk.push(SkippedRecord {
                                key: key.clone(),
                                version: *version,
                                reason: e.to_string(),
                            });
                        }
                    }
                    // A key not come to (`notAttempted`), a transient error or
                    // a refusal that ends the link ends this browse with its
                    // typed error: the cursor does not pass it.
                    Err(e) => return Err(e),
                }
            }
        }
        out.sort_by_key(|r| r.version);
        Ok(out)
    }

    async fn put(&self, write: &RecordWrite) -> Result<PutOutcome> {
        let tier = self.tier().await?;
        let attempt = match tier {
            Tier::Open => self.put_open(write).await,
            Tier::Sealed => self.put_sealed(write).await,
        };
        match attempt {
            Ok(_) => Ok(PutOutcome::Created),
            Err(Error::Room {
                ref code,
                ref message,
                ref retryable,
                ref details,
            }) if write.expected_version == 0
                && !retryable
                && (is_version_conflict(code) || code == "taskFailed") =>
            {
                // A create-only write was refused. The spec names the refusal
                // `rooms/records/put:versionConflict`, but the room host in this
                // workspace answers a bare `taskFailed` with the reason only in
                // its message (UNVERIFIED against other hosts), so the message
                // is never parsed: the key is read back, and the read decides.
                // Same author and same body means an earlier attempt landed (a
                // safe replay); a different record is a collision the bridge
                // must not paper over; no record means the refusal was
                // something else, and is returned as it came.
                let original = || Error::Room {
                    code: code.clone(),
                    message: message.clone(),
                    retryable: *retryable,
                    details: details.clone(),
                };
                match self.read_one(&write.key).await {
                    Ok(Some(rec)) if rec.author == self.cfg.persona && rec.body == write.body => {
                        Ok(PutOutcome::AlreadyExists)
                    }
                    Ok(Some(rec)) => Err(Error::Room {
                        code: "keyCollision".into(),
                        message: format!(
                            "record {} exists with a different author or body (author {})",
                            write.key, rec.author
                        ),
                        retryable: false,
                        details: None,
                    }),
                    Ok(None) => Err(original()),
                    // The key is there but cannot be read (for instance a
                    // sealed record left at the wrong version by an earlier
                    // crash): the typed read error is the more useful one.
                    //
                    // On a sealed tier that is exactly what an earlier
                    // `put_sealed` leaves when it ran out of attempts: the
                    // record is stored at the version the host reported
                    // (`currentVersion`, the same number as the
                    // `landedVersion` of that failure) but sealed for another.
                    // Continue from there: rewrite it as an UPDATE over what
                    // landed, the same request `put_sealed` makes in-call (a
                    // different request, not a retry of the failed one). The
                    // key is the link's own HMAC, so it is ours: nobody else
                    // can name it.
                    Err(read_err @ Error::Room { .. })
                        if tier == Tier::Sealed
                            && let Some(landed) =
                                details.as_ref().and_then(|d| d["currentVersion"].as_u64()) =>
                    {
                        tracing::warn!(key = %write.key, landed, error = %read_err,
                            "a sealed record was left at the wrong version; rewriting it \
                             over the version that landed");
                        let rewrite = RecordWrite {
                            expected_version: landed,
                            ..write.clone()
                        };
                        self.put_sealed(&rewrite).await.map(|_| PutOutcome::Created)
                    }
                    Err(read_err) if !matches!(read_err, Error::Refused(_)) => Err(read_err),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}
