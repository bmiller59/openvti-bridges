//! The Geb adapter: everything specific to Geb path B lives under here, and
//! the bridge core sees only [`room::GebRoom`] as a `ForeignRoom`.
//!
//! Pinned to Geb's authoritative answers, rounds 1 to 4
//! (`Geb's path B answers, round 1`, round 2, round 3, round 4), read from
//! their code at release 0.5.15, commit [`PATH_B_PINNED_COMMIT`] (`fdf804d`;
//! round 1 was first read at release 0.5.14, and the fixture vectors come from
//! release 0.5.14 for round 1 and the round 2 reading for round 2). They supersede the
//! implementer's guide (`Geb's implementer's guide (2026-11-07)`) where they differ. Not
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
/// The Geb substrate commit this reading is pinned to: release 0.5.15. Round 1
/// of the answers was read at release 0.5.14 (0.5.14); round 2, which carries the
/// 0.5.15 rules this crate builds to, at `fdf804d`.
pub const PATH_B_PINNED_COMMIT: &str = "fdf804d";

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
            "geb path B 0.1 (pinned to commit fdf804d)"
        );
    }
}

#[cfg(feature = "geb-mls")]
mod atrest_mls;
pub mod codec;
pub mod crypto;
pub mod dyad;
pub mod event;
pub mod fake;
pub mod forkmark;
pub mod leave;
#[cfg(feature = "geb-mls")]
pub mod mls;
#[cfg(feature = "geb-live")]
pub mod nostr;
pub mod policy;
pub mod room;
pub mod settle;
pub mod status;
#[cfg(feature = "geb-live")]
pub mod test_relay;
pub mod traits;
pub mod vrc;
pub mod wire;
