# CLAUDE.md — openvti-bridge-core

The adapter-neutral core: the foreign-room seam (`foreign.rs`: `ForeignRoom`, `RoomCapabilities`,
`SizeLimit`), the kind seam (`adapter.rs`: `BridgeKind`, `AdapterHandle`, `LinkCtx`, `BuiltLink`), `model`,
`mapping`, `pump`, `store`, `room`, `halt`, `pause`, `run`, `config`, `secrets`, `atrest` and the in-memory
`loopback` kind. Read the root `CLAUDE.md` first.

- **The core never names a foreign system.** It depends on `foreign::ForeignRoom` and
  `foreign::RoomCapabilities` only. Behaviour that varies by room (retraction as a notice line, the size
  limit) is chosen from the capabilities, never from an adapter's name. `loopback` is the second, trivial
  kind that keeps the core honest. `cargo tree -p openvti-bridge-core` shows no adapter, MLS, websocket or
  VTI client crate (the isolation CI job).
- **`BridgeKind` has default methods only**, so adding one later does not break an implementer.
- **Halts are persisted and stay.** `HaltReason` is `Refused`, `VtcRefused` or `Adapter { code, detail }`;
  clearing needs `--yes` (and `--i-have-been-readmitted` for a refusal). A halt is read from the store
  before anything is posted.
- **State is the adapter's by namespace**: `BridgeStore::state_get/put("<kind>/<name>", key)`, sealed at
  rest by `EncryptedState`; the core never reads an adapter's records.
- **Secrets**: `BridgeSecrets` v2 holds an opaque payload per adapter kind and the public identifiers that
  may belong to one link only. Nothing is exported from the VTA but the adapter's device keys.
- A change to the seam is its own pull request, proven with the loopback kind and the conformance suite.
