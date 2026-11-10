//! The `openvti-bridges` shell: the operator CLI, setup, the supervisor service
//! and the assembly of a running link from the core, the VTI side and the
//! bridge kinds this build registers ([`registry`]).
//!
//! Experimental. Nothing here names a foreign system: a kind arrives through
//! the registry and the core's [`BridgeKind`](openvti_bridge_core::adapter::BridgeKind)
//! trait, behind a cargo feature (`geb`, `loopback`).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod cli;
pub mod ops;
pub mod registry;
pub mod service;
pub mod wiring;

pub use openvti_bridge_core::{Error, Result};
