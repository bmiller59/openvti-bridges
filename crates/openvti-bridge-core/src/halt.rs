//! Why a link is halted, and how an operator clears it.
//!
//! A halt is persisted (the `halt` cursor of the link's store) so a restart
//! stays halted without touching the foreign room. There are three kinds, and
//! they are told apart because clearing them means different things:
//!
//! - [`HaltReason::Refused`]: the foreign room refused seating, or a merged
//!   commit removed our leaf. This is permanent: until an operator has seen to
//!   it that the bridge was admitted to the room again, retrying only repeats
//!   the refusal.
//! - [`HaltReason::VtcRefused`]: the VTI side refused the bridge; the fix is
//!   its ACL grant or room membership.
//! - [`HaltReason::Adapter`]: a halt the adapter chose, named by its stable
//!   `<kind>.<reason>` code (for example `geb.undecidable-commit`, documented
//!   in the adapter's own design note). The core persists and gates it like any
//!   other and never interprets the code. Clearing needs `--yes` alone;
//!   clearing makes the link read what caused it again, so a cause that is
//!   still there halts it again at once.

use crate::store::BridgeStore;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// The persisted halt record's name (a cursor of the link's store).
pub const HALT: &str = "halt";

/// Why a link stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum HaltReason {
    /// Seating refused or our leaf removed. `detail` is the room's reason.
    Refused {
        /// What the foreign room said.
        detail: String,
    },
    /// The VTI side refused the bridge (the VTA's 403, the room host's
    /// `permissionDenied`, `actionNotHeld`, `notAMember`). Not the foreign
    /// room's doing: the bridge's ACL grant or room membership must be fixed at
    /// the VTA.
    VtcRefused {
        /// What the VTA or the host said.
        detail: String,
    },
    /// The adapter stopped the link. Serialised as
    /// `{"kind":"adapter","code":..,"detail":..}`.
    Adapter {
        /// The adapter's stable `<kind>.<reason>` code.
        code: String,
        /// What the adapter said, for the operator.
        detail: String,
    },
}

impl HaltReason {
    /// A refusal or removal.
    pub fn refused(detail: impl Into<String>) -> Self {
        Self::Refused {
            detail: detail.into(),
        }
    }

    /// A refusal by the VTA or the room host.
    pub fn vtc_refused(detail: impl Into<String>) -> Self {
        Self::VtcRefused {
            detail: detail.into(),
        }
    }

    /// An adapter's halt, with its stable code.
    pub fn adapter(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Adapter {
            code: code.into(),
            detail: detail.into(),
        }
    }

    /// The detail text.
    pub fn detail(&self) -> &str {
        match self {
            Self::Refused { detail }
            | Self::VtcRefused { detail }
            | Self::Adapter { detail, .. } => detail,
        }
    }

    /// The adapter's halt code, for an [`HaltReason::Adapter`] halt.
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Adapter { code, .. } => Some(code),
            _ => None,
        }
    }

    /// One line on what the operator does about this halt, for the log and
    /// `link clear-halt`. It names no foreign system: an adapter's own words
    /// are in the halt's detail.
    pub fn operator_hint(&self) -> &'static str {
        match self {
            Self::Refused { .. } => {
                "the foreign room refused or removed the bridge; link stopped, not retrying"
            }
            Self::VtcRefused { .. } => {
                "the VTA or room host refused the bridge (not the foreign room); link stopped, \
                 not retrying: fix the bridge's ACL grant, then `link clear-halt --yes`"
            }
            Self::Adapter { .. } => {
                "the adapter stopped the link and it is not retrying (see `link clear-halt`)"
            }
        }
    }

    /// Bytes for the store.
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Store(format!("encode halt: {e}")))
    }

    /// Read a stored halt. A record that is not this format (written before
    /// halts had kinds, a bare reason) is a [`HaltReason::Refused`]: the only
    /// halt that existed then.
    pub fn decode(bytes: &[u8]) -> Self {
        serde_json::from_slice(bytes)
            .unwrap_or_else(|_| Self::refused(String::from_utf8_lossy(bytes).into_owned()))
    }

    /// The error a halted link answers with, without touching the foreign
    /// room. The supervisor treats both kinds as a halt.
    pub fn stopped_error(&self) -> Error {
        match self {
            Self::Refused { detail } => Error::Refused(format!("link stopped: {detail}")),
            Self::VtcRefused { detail } => Error::VtcRefused(format!("link stopped: {detail}")),
            Self::Adapter { code, detail } => {
                Error::adapter_halt(code.clone(), format!("link stopped: {detail}"))
            }
        }
    }

    /// The error that stops the link for this reason, as first raised.
    pub fn raised_error(&self) -> Error {
        match self {
            Self::Refused { detail } => Error::Refused(detail.clone()),
            Self::VtcRefused { detail } => Error::VtcRefused(detail.clone()),
            Self::Adapter { code, detail } => Error::adapter_halt(code.clone(), detail.clone()),
        }
    }
}

impl std::fmt::Display for HaltReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { detail } => {
                write!(
                    f,
                    "the foreign room refused or removed the bridge: {detail}"
                )
            }
            Self::VtcRefused { detail } => {
                write!(
                    f,
                    "refused by the VTA or room host (not the other side): {detail}"
                )
            }
            Self::Adapter { code, detail } => write!(f, "{code}: {detail}"),
        }
    }
}

/// The halt recorded in `store`, if any. The store has no delete, so a cleared
/// halt is an empty record, which reads as no halt.
pub async fn read(store: &dyn BridgeStore) -> Result<Option<HaltReason>> {
    Ok(store
        .cursor(HALT)
        .await?
        .filter(|b| !b.is_empty())
        .map(|b| HaltReason::decode(&b)))
}

/// Record a halt.
pub async fn write(store: &dyn BridgeStore, reason: &HaltReason) -> Result<()> {
    store.set_cursor(HALT, &reason.encode()?).await
}

/// What the operator has confirmed on the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClearConfirmation {
    /// `--yes`: the operator has read what the halt was.
    pub yes: bool,
    /// `--i-have-been-readmitted`: needed in addition for a
    /// [`HaltReason::Refused`] halt (a foreign-side one; a
    /// [`HaltReason::VtcRefused`] or [`HaltReason::Adapter`] halt needs `--yes` only). The bridge was refused or removed; the
    /// operator states it has been admitted to the room again (re-seated by
    /// the room's members), because clearing without that only repeats it.
    pub readmitted: bool,
}

/// What [`clear`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cleared {
    /// There was no halt.
    NotHalted,
    /// The halt was removed; this is what it was.
    Cleared(HaltReason),
}

/// Describe the halt and, only when the confirmation is complete, clear it.
///
/// Returns the halt as an error when it is not (the message names the flag
/// that is missing), so a caller prints what the halt was either way.
pub async fn clear(store: &dyn BridgeStore, confirm: ClearConfirmation) -> Result<Cleared> {
    let Some(reason) = read(store).await? else {
        return Ok(Cleared::NotHalted);
    };
    if !confirm.yes {
        let how = if matches!(reason, HaltReason::VtcRefused { .. }) {
            ". The foreign room did not remove the bridge: fix the bridge's ACL grant or room membership at \
             the VTA (the grant `link add` printed), then re-run with --yes to clear it"
        } else {
            ". Re-run with --yes to clear it"
        };
        return Err(Error::Config(format!("the link is halted: {reason}{how}")));
    }
    if matches!(reason, HaltReason::Refused { .. }) && !confirm.readmitted {
        return Err(Error::Config(format!(
            "the link is halted: {reason}. The foreign room refused or removed the bridge; \
             clearing this only repeats the refusal unless the bridge has been admitted to the \
             room again. Re-run with --yes --i-have-been-readmitted once it has"
        )));
    }
    store.set_cursor(HALT, &[]).await?;
    Ok(Cleared::Cleared(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn yes() -> ClearConfirmation {
        ClearConfirmation {
            yes: true,
            readmitted: false,
        }
    }

    #[test]
    fn a_halt_round_trips_and_an_old_bare_reason_is_a_refusal() {
        for r in [
            HaltReason::refused("leaf removed"),
            HaltReason::adapter("test.blocked", "epoch 4, commit ab12: needs persona"),
        ] {
            assert_eq!(HaltReason::decode(&r.encode().unwrap()), r);
        }
        assert_eq!(
            HaltReason::decode(b"removed from the room"),
            HaltReason::refused("removed from the room")
        );
    }

    #[test]
    fn an_adapter_halt_is_persisted_with_its_stable_code() {
        let r = HaltReason::adapter("loopback.blocked", "epoch 1");
        let v: serde_json::Value = serde_json::from_slice(&r.encode().unwrap()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"kind":"adapter","code":"loopback.blocked","detail":"epoch 1"})
        );
        assert_eq!(r.code(), Some("loopback.blocked"));
        assert_eq!(HaltReason::refused("x").code(), None);
        assert_eq!(r.to_string(), "loopback.blocked: epoch 1");
        assert!(!r.operator_hint().contains("Geb"));
    }

    #[test]
    fn the_kinds_stop_with_distinct_errors() {
        assert!(matches!(
            HaltReason::refused("x").stopped_error(),
            Error::Refused(_)
        ));
        assert!(matches!(
            HaltReason::adapter("test.blocked", "x").stopped_error(),
            Error::AdapterHalt { ref code, .. } if code == "test.blocked"
        ));
    }

    #[tokio::test]
    async fn clearing_needs_yes_and_says_what_the_halt_was() {
        let s = MemoryStore::new();
        assert_eq!(
            clear(&s, yes()).await.unwrap(),
            Cleared::NotHalted,
            "nothing to clear"
        );
        write(
            &s,
            &HaltReason::adapter("test.blocked", "epoch 9, commit ff: blocked"),
        )
        .await
        .unwrap();
        let e = clear(&s, ClearConfirmation::default()).await.unwrap_err();
        assert!(
            e.to_string().contains("epoch 9, commit ff") && e.to_string().contains("--yes"),
            "{e}"
        );
        assert!(
            read(&s).await.unwrap().is_some(),
            "not cleared without --yes"
        );
        let c = clear(&s, yes()).await.unwrap();
        assert_eq!(
            c,
            Cleared::Cleared(HaltReason::adapter(
                "test.blocked",
                "epoch 9, commit ff: blocked"
            ))
        );
        assert_eq!(read(&s).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_removal_needs_the_extra_readmitted_flag() {
        let s = MemoryStore::new();
        write(
            &s,
            &HaltReason::refused("removed from the room by a merged commit"),
        )
        .await
        .unwrap();
        let e = clear(&s, yes()).await.unwrap_err();
        assert!(e.to_string().contains("--i-have-been-readmitted"), "{e}");
        assert!(
            clear(
                &s,
                ClearConfirmation {
                    yes: false,
                    readmitted: true
                }
            )
            .await
            .is_err(),
            "the extra flag does not replace --yes"
        );
        assert!(read(&s).await.unwrap().is_some());
        let c = clear(
            &s,
            ClearConfirmation {
                yes: true,
                readmitted: true,
            },
        )
        .await
        .unwrap();
        assert!(matches!(c, Cleared::Cleared(HaltReason::Refused { .. })));
        assert_eq!(read(&s).await.unwrap(), None);
    }
}
