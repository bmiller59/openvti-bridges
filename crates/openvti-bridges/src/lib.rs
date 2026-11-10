//! The `openvti-bridges` shell: the operator CLI, setup, the supervisor service
//! and the assembly of a running link from the core, the VTI side and an
//! adapter.
//!
//! Experimental. The crate re-exports the modules that used to live here so
//! existing paths (`openvti_bridges::pump`, `::geb`) keep resolving while the
//! shell is made adapter-neutral; the re-exports go when the registry lands.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod cli;
pub mod ops;
pub mod service;
pub mod wiring;

pub use openvti_bridge_core::{
    Error, Result, atrest, config, error, foreign, halt, loopback, mapping, model, pause, pump,
    room, run, secrets, store,
};
pub use openvti_bridge_geb as geb;
pub use openvti_bridge_vtc as vtc;
pub use openvti_bridge_vtc::{custody, fjall_store};
