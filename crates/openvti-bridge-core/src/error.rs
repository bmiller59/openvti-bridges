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
    /// ACL grant or room membership, not the foreign room: the fix is on the VTA, and the
    /// halt is cleared with `--yes` alone.
    #[error("vtc refused: {0}")]
    VtcRefused(String),
    /// An adapter's own reason to stop the link, which the core persists and
    /// treats like any halt: the link halts (persisted), is never retried and
    /// stays halted until an operator clears it. `code` is stable, lower-kebab
    /// and `<kind>.<reason>` (for example `geb.undecidable-commit`), declared
    /// and documented by the adapter, never reused; `detail` is for the
    /// operator.
    #[error("{code}: {detail}")]
    AdapterHalt {
        /// The adapter's stable halt code.
        code: String,
        /// What happened, for the operator.
        detail: String,
    },
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

impl Error {
    /// An adapter halt with the adapter's `code`.
    pub fn adapter_halt(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::AdapterHalt {
            code: code.into(),
            detail: detail.into(),
        }
    }

    /// Whether this failure stops the link for good (a persisted halt) rather
    /// than ending one tick: a foreign refusal, a VTI-side refusal or an
    /// adapter halt.
    pub fn is_halting(&self) -> bool {
        matches!(
            self,
            Self::Refused(_) | Self::VtcRefused(_) | Self::AdapterHalt { .. }
        )
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
