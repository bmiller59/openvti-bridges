//! The Geb adapter: everything specific to Geb path B lives under here, and
//! the bridge core sees only [`room::GebRoom`] as a `ForeignRoom`.
//!
//! Pinned to Geb's authoritative answers (`Geb's path B answers, round 1`,
//! read from their code at commit [`PATH_B_PINNED_COMMIT`]), which supersede
//! the implementer's guide (`Geb's implementer's guide (2026-11-07)`) where they differ. Not
//! built by default (M3): the MLS group stays `UnsupportedGroup` and returns
//! `Error::Unsupported`; feature `geb-mls` adds `mls::MlsGroupClient`, the
//! settle rule ([`settle`]) and the commit check ([`policy::valid_commit`],
//! which needs persona cards and signed leaves the bridge lacks). The stateful dyad is [`dyad`]; the Nostr client
//! (`nostr`, feature `geb-live`) and the event primitives ([`event`]) exist.
//!
//! Bridges are welcome in Geb rooms with no marking required by default. Geb
//! will later define room-level bridge policy (not welcome / welcome
//! automatically / ask, and whether to show a mark) and a signed "bridge" role
//! badge; their shapes are not shared yet and nothing here implements them.
//! Seating may be refused, may be pending ("ask"), and a leaf may later be
//! removed: see `JoinState` and `Error::Refused`.

/// Version of this crate's reading of the Geb path B wire. Geb has no
/// versioned spec; this counts our pinned reading, not a Geb version.
pub const PATH_B_VERSION: &str = "0.1";
/// The Geb substrate commit the answers were read from.
pub const PATH_B_PINNED_COMMIT: &str = "release 0.5.14";

/// One line for status output and logs.
pub fn status_line() -> String {
    format!("geb path B {PATH_B_VERSION} (pinned to commit {PATH_B_PINNED_COMMIT})")
}

#[cfg(test)]
mod tests {
    #[test]
    fn status_names_the_version_and_commit() {
        assert_eq!(
            super::status_line(),
            "geb path B 0.1 (pinned to commit release 0.5.14)"
        );
    }
}

pub mod codec;
pub mod crypto;
pub mod dyad;
pub mod event;
pub mod fake;
#[cfg(feature = "geb-mls")]
pub mod mls;
#[cfg(feature = "geb-live")]
pub mod nostr;
pub mod policy;
pub mod room;
pub mod settle;
#[cfg(feature = "geb-live")]
pub mod test_relay;
pub mod traits;
pub mod vrc;
pub mod wire;
