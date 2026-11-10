//! Shared test doubles for the room-host harness. The key-serving fake VTA is
//! shared with the root crate's tests rather than copied.
#![allow(dead_code)]
#[path = "../../../crates/openvti-bridges/tests/common/key_vta.rs"]
pub mod key_vta;
pub mod world;
