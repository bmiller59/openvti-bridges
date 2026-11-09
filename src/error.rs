//! One error type for the crate.

/// Everything that can go wrong in the bridge.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A capability that is deliberately not built, or blocked on an answer
    /// from the foreign system's authors. Never a silent no-op.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// Malformed or unrecognised bytes from outside. Fail closed.
    #[error("wire: {0}")]
    Wire(String),
    /// A cryptographic operation failed (bad key, bad tag, bad signature).
    #[error("crypto: {0}")]
    Crypto(String),
    /// The foreign room refused or could not be reached.
    #[error("foreign: {0}")]
    Foreign(String),
    /// Invalid configuration.
    #[error("config: {0}")]
    Config(String),
    /// The foreign room refused to seat the bridge, or removed its leaf. The
    /// link stops and alerts; there is no retry. A pending seating is not this
    /// error (see [`crate::foreign::JoinState::Pending`]).
    #[error("refused: {0}")]
    Refused(String),
    /// The VTI side refused the bridge: the user's VTA answered 403 or the room
    /// host answered `permissionDenied` / `actionNotHeld` / `notAMember`. The
    /// link stops like [`Error::Refused`], but the cause is the bridge's own
    /// ACL grant or room membership, not Geb: the fix is on the VTA, and the
    /// halt is cleared with `--yes` alone.
    #[error("vtc refused: {0}")]
    VtcRefused(String),
    /// A Geb commit that can be neither merged nor skipped without a persona
    /// card this bridge cannot hold (a deliberate bridge-side halt; Geb
    /// itself refuses such a commit and goes on). The link
    /// halts (persisted) and stays halted until an operator clears it; the
    /// text names the commit's epoch and hash. Not retried: re-reading the
    /// same commit decides nothing new.
    #[error("undecidable commit: {0}")]
    UndecidableCommit(String),
    /// A typed failure from the VTC room side (the user's VTA or the room
    /// host), kept as data: `code` is what a caller matches on, never the
    /// message. A refusal that must stop the link is [`Error::Refused`]
    /// or [`Error::VtcRefused`] instead; this is everything else, and `retryable` says whether the
    /// next tick may simply try again (the bridge never loops on it itself).
    #[error("room: [{code}] {message}")]
    Room {
        /// The Trust Task error code as sent (`rooms/records/put:versionConflict`),
        /// or a short code of this crate's own for a transport failure.
        code: String,
        /// The message as sent.
        message: String,
        /// Whether the peer said, or the transport implies, a later try may pass.
        retryable: bool,
        /// The peer's `details`, as sent.
        details: Option<serde_json::Value>,
    },
    /// A store operation failed.
    #[error("store: {0}")]
    Store(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
