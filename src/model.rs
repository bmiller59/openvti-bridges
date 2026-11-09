//! The adapter-neutral event the whole core speaks.

use serde::{Deserialize, Serialize};

/// Which side an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Origin {
    /// A record in the VTC data room.
    Vtc,
    /// A message in the foreign room.
    Foreign,
}

/// What an event does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EventKind {
    /// A new post.
    Post,
    /// A new version of an earlier post (`replaces` is its `origin_id`).
    Supersede { replaces: String },
    /// A retraction of an earlier post (`target` is its `origin_id`).
    Retract { target: String },
}

/// Result of checking a foreign author's signature. Bridged content is never
/// presented as verified unless this says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorCheck {
    /// The signature verified against the author's key.
    Verified,
    /// A signature was present and did not verify (or the key was unusable).
    Unverified,
    /// No signature at all.
    Unsigned,
}

/// Where a foreign message came from, carried into the VTC record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// The foreign room's id.
    pub foreign_room: String,
    /// The author's device identifier in the foreign system.
    pub author_device: String,
    /// Signature result.
    pub check: AuthorCheck,
    /// The message's original timestamp (ms), as claimed by its author.
    pub original_at: u64,
    /// Stable hash of the message (the dedup id).
    pub msg_hash: String,
}

/// One thing moving across the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeEvent {
    /// Where it came from.
    pub origin: Origin,
    /// Stable id on its origin side (`record|version` or message hash).
    pub origin_id: String,
    /// The link this event travels on.
    pub link: String,
    /// Author as the origin names them (a persona DID, a device DID).
    pub author: String,
    /// Timestamp in ms.
    pub at: u64,
    /// Optional title (VTC records).
    pub title: Option<String>,
    /// Body text. Untrusted when `origin` is `Foreign`.
    pub text: String,
    /// What the event does.
    pub kind: EventKind,
    /// The foreign-room id of the post this one answers. Set on an outbound
    /// retraction or supersede that is expressed as an ordinary reply, and on
    /// an inbound line that answers another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// The VTC record key this event carries content of. Set on an outbound
    /// post or supersede that came from a record, so that once it is posted
    /// the key is marked bridged (a later version of that key is then an
    /// edit, a tombstone of it a retraction). Never set on a retraction, an
    /// announcement or an inbound event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_key: Option<String>,
    /// Present on events that came from the foreign room.
    pub provenance: Option<Provenance>,
}
