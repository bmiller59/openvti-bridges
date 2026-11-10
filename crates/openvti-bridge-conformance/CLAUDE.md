# CLAUDE.md — openvti-bridge-conformance

The shared suite every adapter runs against its `ForeignRoom` (`run_all(&Fixture)`). A fixture gives a
fresh room, a `Peer` that speaks as another member, and `Knobs` that stage faults. A case an adapter
cannot stage is `Outcome::Unsupported(reason)`: listed, with a written reason, and capped by the adapter's
test. Never delete a case to make an adapter pass. Depends on the core only. `tests/loopback.rs` runs it
against the in-memory room (nothing unsupported); each adapter adds `tests/conformance.rs`.
