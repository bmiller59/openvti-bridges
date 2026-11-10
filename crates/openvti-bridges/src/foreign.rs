//! The one seam between the bridge core and a foreign room.
//!
//! The core (pump, mapping, outbox, journal) depends on this module and on
//! nothing foreign-specific. An adapter implements [`ForeignRoom`] and
//! describes itself with [`RoomCapabilities`].

use crate::Result;
use crate::model::BridgeEvent;
use async_trait::async_trait;

/// An opaque, resumable position in the foreign room's inbound stream. Only
/// the adapter that produced it can interpret it; the core stores and returns
/// it unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cursor(pub Vec<u8>);

/// How strongly the foreign system lets the bridge check who wrote a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifiability {
    /// Authors cannot be checked at all.
    None,
    /// Authors are stated but the check can fail or be absent per message.
    PerMessage,
    /// Every accepted message is attributable by the transport itself.
    Transport,
}

/// What the foreign room can do. Mapping chooses its behaviour from this, never
/// from the adapter's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomCapabilities {
    /// Largest message body the room accepts, in UTF-16 code units (a
    /// JavaScript string's `length`: a character outside the BMP counts 2, so
    /// this is neither bytes nor `char`s). [`crate::mapping::utf16_units`]
    /// counts it.
    pub max_message_units: usize,
    /// A post can be edited in place.
    pub supports_edit: bool,
    /// A post can be deleted.
    pub supports_delete: bool,
    /// A post can point at an earlier one as a reply (`BridgeEvent::reply_to`).
    pub supports_replies: bool,
    /// How far authors can be verified.
    pub authors_verifiable: Verifiability,
}

/// Where joining the foreign room stands. "Ask" rooms may leave seating
/// pending until a member approves; that is a state, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinState {
    /// The bridge is a member and may read and post.
    Seated,
    /// Seating has been requested and is awaiting approval. Nothing is read or
    /// posted; ask again later. (Rooms will later choose between not welcome,
    /// welcome automatically and ask; none of those settings exists yet.)
    Pending,
}

/// The outcome of a post: how far it got, and the foreign room's id for the
/// line when it has one (a Geb room line's derived id), which the bridge keeps
/// so a later retraction can answer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posted {
    /// Evidence of how far the post got.
    pub receipt: Receipt,
    /// The foreign id of the posted line, if the room has one.
    pub foreign_ref: Option<String>,
}

/// How far a post got. Ordered: later is stronger evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Receipt {
    /// Accepted locally; nothing shows it left.
    Accepted,
    /// Seen at the relay or transport.
    Relayed,
    /// Acknowledged by the other side.
    Delivered,
}

/// The identity the bridge presents in the foreign room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignIdentity {
    /// Opaque, stable identifier (compared against event authors to suppress
    /// echoes).
    pub id: String,
}

/// An inbound event with the cursor to resume after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polled {
    /// The event, with `link` left empty for the pump to fill.
    pub event: BridgeEvent,
    /// Resume after this event.
    pub cursor: Cursor,
}

/// A foreign room as the bridge core sees it.
#[async_trait]
pub trait ForeignRoom: Send + Sync {
    /// Become a member (idempotent; may be called again to check a pending
    /// seating). A refusal or removal is `Error::Refused`.
    async fn join(&self) -> Result<JoinState>;
    /// Stop being a member.
    async fn leave(&self) -> Result<()>;
    /// Events after `after` (all retained events when `None`), oldest first.
    /// May return events at or before the cursor again: the core deduplicates.
    async fn poll(&self, after: Option<&Cursor>) -> Result<Vec<Polled>>;
    /// Post an event already shaped for this room's capabilities.
    async fn post(&self, event: &BridgeEvent) -> Result<Posted>;
    /// The identity the bridge presents.
    fn identity(&self) -> ForeignIdentity;
    /// What this room can do.
    fn capabilities(&self) -> RoomCapabilities;
}
