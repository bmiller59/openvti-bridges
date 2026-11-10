//! Census: every bridge kind registered in this build is held to the shared
//! conformance suite. `loopback` is run by `openvti-bridge-conformance`
//! itself; every other kind has its own crate with a `tests/conformance.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn every_registered_kind_has_a_conformance_run() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for k in openvti_bridges::registry::kinds() {
        let name = k.kind();
        let file = if name == "loopback" {
            crates.join("openvti-bridge-conformance/tests/loopback.rs")
        } else {
            crates.join(format!("openvti-bridge-{name}/tests/conformance.rs"))
        };
        assert!(
            file.exists(),
            "kind {name} is registered but {} does not exist",
            file.display()
        );
    }
}
