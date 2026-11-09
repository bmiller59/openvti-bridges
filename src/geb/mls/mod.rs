//! The Geb-side MLS client (feature `geb-mls`): OpenMLS 0.9, ciphersuite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`), group id = the
//! room id as UTF-8, BasicCredential = the device DID as UTF-8, ratchet tree
//! in the Welcome, external joins never used. Its own provider and store,
//! separate from `vti-rooms` (which this crate does not depend on).
//!
//! - [`identity`]: the random MLS signature key (vault hook point), the
//!   KeyPackage with leaf capabilities `[0xF001, 0xF002]` and the `0xF002`
//!   binding signed by the Geb device key through `GebSigner`.
//! - [`client`]: [`MlsGroupClient`], the `GebGroup`: seating over the dyad
//!   (`kp-stock`, `kp-req` / `kp`, `welcome`), per-epoch relay keys from the
//!   exporter (`geb/room/v2/nostr`, `geb/room/v2/aead`, context = room id),
//!   sealing and opening lines, and running the settle rule.
//! - [`commit`]: testing a candidate commit and the reasoning behind merging
//!   with partial local knowledge.
//!
//! The pure parts (settle queue, `validCommit`) live outside this feature, in
//! `geb::settle` and `geb::policy`, and are tested in every build.
//!
//! What this proves and does not: the tests run against an in-process second
//! OpenMLS client that plays a Geb member. That shows this client is
//! self-consistent with the MLS profile in the guide and answers. It does NOT
//! show byte-compatibility with Geb's own MLS code (Rust `mls.rs`, TypeScript
//! Geb's source / Geb's source), which was not available.
//!
//! # UNVERIFIED (Geb's MLS source was not available; each is a choice)
//!
//! - Framing (SETTLED by answers round 2, section 2, no longer a choice): `m`
//!   of `mc` / `ml` is an `MLSMessage` whose body is a PrivateMessage; …
//!   … Welcome; each KeyPackage is a
//!   bare `KeyPackage` in standard padded base64. We READ only those forms: a
//!   PublicMessage, a bare PrivateMessage / Welcome, trailing bytes, and a
//!   base64url KeyPackage are refused (`commit::parse_message`,
//!   `parse_welcome`, `parse_key_package`). The commit hash that orders
//!   candidates is SHA-256 over the `MLSMessage` bytes (round 2 section 6).
//! - (settled: Geb never sets a wire-format policy, so the OpenMLS default,
//!   everything a PrivateMessage, applies; a PublicMessage is refused.)
//! - The OpenMLS 0.9 defaults for the capability lists other than extensions
//!   (answer 7 says to check them against our stack).
//! - The `{k:"g", op:"rs"}` body (we send `room:{id}`) and its reply.
//! - Settle window start: local first sight of the epoch's earliest commit.
//! - A commit made from an epoch below ours is ignored; one made from an
//!   epoch ahead of ours is held, never tested.
//! - A Welcome whose header names another room is ignored; one whose group has
//!   no `0xF001` is ignored; a Welcome received while already seated (a
//!   re-seat) is NOT processed: re-seating after a fork is not built.
//! - A leaf binding we cannot check because the DID does not decode is
//!   "forged" when present and "missing" when absent.
//! - Where seating frames come from: every configured peer's dyad is read for
//!   `kp-req` / `welcome` while unseated, and `GebDyad::recv` clears what it
//!   hands over, so the dyad must not be shared with another consumer of group
//!   frames meanwhile.
//! - Leaving: Geb's leave is a signed `{t:"lv"}` (leave code), which is
//!   not built; `leave` fails closed.
//! - State is in memory unless `MlsGroupClient::with_state_store` is used; then a
//!   restart resumes seated (see there for what is saved and what a restart
//!   still loses: the settle queue and the dedup window).
//! - UNVERIFIED: persistence snapshots OpenMLS's `MemoryStorage` entries; a
//!   future OpenMLS storage layout change is covered by the snapshot version.

mod client;
mod commit;
mod identity;

/// Test doubles (a second OpenMLS client playing a Geb member). Compiled for
/// unit tests and for the `harness` feature's end-to-end test only.
#[cfg(any(test, feature = "harness"))]
pub mod sim;
#[cfg(test)]
mod tests;

pub use client::{
    DEFAULT_STOCK, GroupStateStore, LABEL_AEAD, LABEL_NOSTR, MAX_STOCK, MlsConfig, MlsGroupClient,
};
pub use commit::{BindingStatus, binding_status, group_policy, parse_key_package};
pub use identity::{MemoryVault, MlsIdentity, SUITE, SignatureKeyVault, leaf_capabilities};
