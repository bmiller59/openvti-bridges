//! Experimental … foreign room.
//!
//! The core (`config`, `model`, `foreign`, `mapping`, `room`, `store`, `pump`)
//! knows nothing about any foreign system: it talks to one seam,
//! [`foreign::ForeignRoom`], and reads what that adapter can do from
//! [`foreign::RoomCapabilities`]. Everything specific to a foreign system lives
//! in an adapter module. The first is [`geb`]; [`loopback`] is a trivial
//! in-memory adapter that proves the core is adapter-agnostic.
//!
//! The Geb side is a foreign-protocol interface (workspace `CLAUDE.md`,
//! exceptions to "every remote operation is a Trust Task"). Geb path B has no
//! versioned specification: the adapter pins to Geb's answers
//! (`Geb's path B answers, round 1`, commit release 0.5.14, see
//! [`geb::status_line`]) and fails closed on anything it does not recognise.
//!
//! Status: experimental. M0, M1 (the VTC room side and the durable store, behind
//! feature `vtc`), M2 (the stateful dyad, the Nostr client behind `geb-live`,
//! tested only offline), and the offline groundwork of M3 (the settle rule, the
//! commit check and, behind `geb-mls`, the Geb-side MLS client; tested only
//! against an in-process second OpenMLS client).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod atrest;
#[cfg(feature = "cli")]
pub mod cli;
pub mod config;
#[cfg(feature = "vtc")]
pub mod custody;
pub mod error;
#[cfg(feature = "vtc")]
pub mod fjall_store;
pub mod foreign;
pub mod geb;
pub mod halt;
pub mod loopback;
pub mod mapping;
pub mod model;
#[cfg(all(feature = "vtc", feature = "geb-mls"))]
pub mod ops;
pub mod pump;
pub mod room;
#[cfg(feature = "vtc")]
pub mod run;
#[cfg(feature = "cli")]
pub mod service;
pub mod store;
#[cfg(feature = "vtc")]
pub mod vtc;
#[cfg(all(feature = "vtc", feature = "geb-mls"))]
pub mod wiring;

pub use error::{Error, Result};
