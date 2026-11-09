//! Delivery of a document the VTA completed to the room host, and the typed
//! reading of every refusal on the room side.
//!
//! The host authenticates a room document by its proof alone (the signer must
//! be the document's `issuer`), so the document the VTA returns is posted,
//! unaltered and unauthenticated, to `POST {base}/trust-tasks` over HTTPS. A
//! DIDComm or TSP delivery would be refused because the deliverer (this
//! bridge) is not the issuer (the persona). This is the same flow as
//! `vtc_client::VtcClient::send_signed_room_document`, which this crate does
//! not depend on.
//!
//! This module never retries: a write's retry has one owner (the pump's next
//! tick over a durable outbox), and a hand-rolled loop could not hold the
//! document's `id` stable.

use crate::{Error, Result};
use serde_json::Value;
use vta_sdk::error::VtaError;
use vta_sdk::http::{EndpointPolicy, ForeignFetchError};

/// Largest response body read from the host (bytes). Records are capped well
/// below this at the host; the cap is the bridge's own defence.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Posts completed room documents to one host.
#[derive(Clone)]
pub struct HostDelivery {
    http: reqwest::Client,
    base: String,
}

impl HostDelivery {
    /// A delivery to `base_url` (no trailing slash needed) under the process
    /// endpoint policy: a private or loopback host is refused unless the
    /// operator opted in (`vta_sdk::http::ALLOW_PRIVATE_ENDPOINTS_ENV`).
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_policy(base_url, EndpointPolicy::process_default())
    }

    /// [`HostDelivery::new`] under an explicit endpoint policy.
    pub fn with_policy(base_url: &str, policy: EndpointPolicy) -> Result<Self> {
        let base = base_url.trim_end_matches('/').to_string();
        vta_sdk::http::guard_foreign_url(&base, policy)
            .map_err(|e: ForeignFetchError| Error::Config(format!("room host URL: {e}")))?;
        Ok(Self {
            // The shared hardened client (no redirects, finite timeouts); never
            // `reqwest::Client::new()`.
            http: vta_sdk::http::foreign_fetch_client_for(policy),
            base,
        })
    }

    /// Plain-HTTP delivery to a loopback host, for the harness only: the
    /// production constructors refuse anything but https. The client still
    /// refuses redirects and has finite timeouts.
    #[cfg(feature = "harness")]
    #[doc(hidden)]
    pub fn for_loopback_tests(base_url: &str) -> Self {
        Self {
            http: vta_sdk::http::foreign_fetch_client_for(EndpointPolicy::private_allowed()),
            base: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Send the document exactly as the VTA returned it; return the response
    /// document's `payload`.
    pub async fn send(&self, document: &Value) -> Result<Value> {
        let body = serde_json::to_vec(document).map_err(|e| Error::Wire(e.to_string()))?;
        let resp = self
            .http
            .post(format!("{}/trust-tasks", self.base))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| unreachable_host(&e.to_string()))?;
        let status = resp.status();
        let bytes = vta_sdk::http::read_body_capped(resp, MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| unreachable_host(&e.to_string()))?;
        if !status.is_success() {
            return Err(host_refusal(status.as_u16(), &bytes));
        }
        let doc: Value = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Wire(format!("host answered something other than JSON: {e}")))?;
        doc.get("payload")
            .cloned()
            .ok_or_else(|| Error::Wire("host answered a document with no payload".into()))
    }
}

fn unreachable_host(why: &str) -> Error {
    Error::Room {
        code: "hostUnreachable".into(),
        message: why.to_string(),
        retryable: true,
        details: None,
    }
}

/// Whether `code` is a refusal that ends the link rather than a failure to
/// retry: the persona may not do this (`permissionDenied`,
/// `...:actionNotHeld`) or is no longer in the room (`...:notAMember`).
pub fn is_link_ending(code: &str) -> bool {
    code == "permissionDenied" || code.ends_with(":actionNotHeld") || code.ends_with(":notAMember")
}

/// Whether `code` is the host's answer to a create-only write on a key that
/// already exists (`expectedVersion` did not match).
pub fn is_version_conflict(code: &str) -> bool {
    code.ends_with(":versionConflict")
}

/// A typed [`Error`] from a code, message and details.
pub fn typed(code: &str, message: &str, retryable: bool, details: Option<Value>) -> Error {
    if is_link_ending(code) {
        return Error::Refused(format!("{code}: {message}"));
    }
    Error::Room {
        code: code.to_string(),
        message: message.to_string(),
        retryable,
        details,
    }
}

/// The error for a non-2xx host answer: the `trust-task-error` document's
/// `code`, `message` and `details` when it is one.
fn host_refusal(status: u16, body: &[u8]) -> Error {
    let doc: Option<Value> = serde_json::from_slice(body).ok();
    let payload = doc.as_ref().and_then(|d| d.get("payload"));
    let code = payload.and_then(|p| p.get("code")).and_then(Value::as_str);
    match code {
        Some(code) => {
            let message = payload
                .and_then(|p| p.get("message"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let details = payload.and_then(|p| p.get("details")).cloned();
            // The host says 429 for a rate it refused before running the task.
            typed(code, message, status == 429 || status >= 500, details)
        }
        None => Error::Room {
            code: format!("http{status}"),
            message: String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned(),
            retryable: status == 429 || status >= 500,
            details: None,
        },
    }
}

/// A typed [`Error`] from a failed call to the user's VTA. The variant is
/// kept as data (`code`, `retryable`, `details`); it is never flattened into a
/// string the pump has to parse.
pub fn from_vta(e: VtaError) -> Error {
    match e {
        VtaError::Forbidden(m) => Error::Refused(format!("the VTA refused the bridge: {m}")),
        VtaError::Rejected {
            code,
            message,
            details,
        } => {
            let retryable = code.ends_with(":hostUnreachable") || code.ends_with(":notAttempted");
            typed(&code, &message, retryable, details)
        }
        VtaError::Unavailable { .. } | VtaError::RateLimited { .. } | VtaError::Network(_) => {
            Error::Room {
                code: "vtaUnavailable".into(),
                message: e.to_string(),
                retryable: true,
                details: None,
            }
        }
        VtaError::UnsupportedTaskType { .. } => Error::Room {
            code: "unsupportedTaskType".into(),
            message: e.to_string(),
            retryable: false,
            details: None,
        },
        other => Error::Room {
            code: "vta".into(),
            message: other.to_string(),
            retryable: false,
            details: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_ending_codes_become_refused() {
        for c in [
            "permissionDenied",
            "rooms/keys/act:actionNotHeld",
            "rooms/keys/browse:notAMember",
        ] {
            assert!(
                matches!(typed(c, "no", false, None), Error::Refused(_)),
                "{c}"
            );
        }
        assert!(matches!(
            typed("rooms/records/put:versionConflict", "x", false, None),
            Error::Room { ref code, .. } if is_version_conflict(code)
        ));
    }

    #[test]
    fn a_host_refusal_document_is_read_into_its_code() {
        let body = br#"{"payload":{"code":"permissionDenied","message":"no"}}"#;
        assert!(matches!(host_refusal(403, body), Error::Refused(_)));
        let body = br#"{"payload":{"code":"rooms/records/put:versionConflict","message":"v","details":{"currentVersion":3}}}"#;
        match host_refusal(409, body) {
            Error::Room {
                code,
                details,
                retryable,
                ..
            } => {
                assert!(is_version_conflict(&code));
                assert!(!retryable);
                assert_eq!(details.unwrap()["currentVersion"], 3);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            host_refusal(503, b"busy"),
            Error::Room {
                retryable: true,
                ..
            }
        ));
    }

    #[test]
    fn vta_errors_keep_their_type() {
        assert!(matches!(
            from_vta(VtaError::Forbidden("acl".into())),
            Error::Refused(_)
        ));
        let e = from_vta(VtaError::Rejected {
            code: "rooms/keys/act:actionNotHeld".into(),
            message: "m".into(),
            details: None,
        });
        assert!(matches!(e, Error::Refused(_)));
        let e = from_vta(VtaError::Rejected {
            code: "rooms/keys/read:hostUnreachable".into(),
            message: "m".into(),
            details: None,
        });
        assert!(matches!(
            e,
            Error::Room {
                retryable: true,
                ..
            }
        ));
    }
}
