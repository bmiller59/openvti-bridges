//! The bridge-neutral core of the openvti bridges.
//!
//! The core (`config`, `model`, `foreign`, `mapping`, `room`, `store`, `pump`,
//! `halt`, `pause`, `run`, `atrest`) knows nothing about any foreign system: it
//! talks to one seam, [`foreign::ForeignRoom`], and reads what that adapter can
//! do from [`foreign::RoomCapabilities`]. Everything specific to a foreign
//! system lives in an adapter crate (`openvti-bridge-<kind>`); [`loopback`] is a
//! trivial in-memory adapter that proves the core is adapter-agnostic. The VTI
//! side lives in `openvti-bridge-vtc`.
//!
//! Status: experimental.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod adapter;
pub mod atrest;
pub mod config;
pub mod error;
pub mod foreign;
pub mod halt;
pub mod loopback;
pub mod mapping;
pub mod model;
pub mod pause;
pub mod pump;
pub mod room;
pub mod run;
pub mod secrets;
pub mod store;

pub use error::{Error, Result};
