# CLAUDE.md — openvti-bridges (the shell)

The binary and its library: the registry of bridge kinds (`registry.rs`, features `geb` and `loopback`),
`cli` (setup and link management), `service` (`run`, `status`, `bridge <kind> <verb>`, `clear-halt`),
`ops` (the data behind `status`) and `wiring` (assembling a link: the VTC side and the pump around what a
kind builds). Read the root `CLAUDE.md` first. The shell names no foreign system: a kind arrives through
`registry::kinds()`. It applies the kill switch and the persisted halt before every kind verb
(`tests/verbs.rs` proves it with the loopback kind and `tests/cli.rs` with Geb). Names below that say
`bridge geb connect` are now `bridge geb connect`.

## Operational shell (custody, sealed state, CLI)

- **Custody** (`custody`, feature `vtc`): the VTA mints two key records in the
  `openvti-bridges` context (Ed25519, and a separately derived X25519), the bridge
  exports each once (`keys/export-secret/0.1`), builds `did:peer:2.A.V.E`
  itself (no `.S`) and keeps the secrets only in its `vti-secrets` store
  (`SecretStore`, one blob: `BridgeSecrets`). The room persona is only
  recorded, never exported. One device DID and one persona per link, enforced
  in the store and in `Config::validate`. `config_seed` is refused.
- **Sealed at rest** (`atrest`): XChaCha20-Poly1305, key = HKDF of the store
  key per purpose, record name as AAD. `EncryptedState` wraps a `BridgeStore`
  (dyad/ratchet state); `SealedFile` holds the MLS signature key and the
  OpenMLS key-store snapshot. `MlsGroupClient::with_state_store` resumes
  seated; it saves before a KeyPackage leaves, after joining, before a sealed
  line is returned and after a merged commit. A restart still loses the settle
  queue (re-read from the relay: the cursor barrier holds the position) and the
  dedup window (the journal covers it). Cursors, journal, outbox and xref are
  not secrets and stay in clear.
- **CLI** (`crates/openvti-bridges/src/main.rs`, `cli`, `service`; not a default
  feature): two-phase `setup`
  (`--setup-key-out`, then `--from`), `link add|list|pause|resume|remove`,
  `bridge geb connect|stock-kps`, `status`, `run`. One fjall store per link under
  `<data_dir>/links/<id>/`. `run` supervises each pump, paused links included (idle; kill switch: `pause.rs`, `ConfigFilePause` re-reads the config on every check, anything unreadable counts as PAUSED, the pump checks before every post and room write; DESIGN section 9) (`run`: stop observed at
  every wait, `close` on every exit, backoff reset only after a healthy session,
  `Refused` and `UndecidableCommit` halt for good and the halt is persisted, health derived from the
  time of the last good tick). Config load reads one file and contacts nothing.
- **Fork marker** (`geb::forkmark`, store cursor `fork`, unsealed, numbers only): the MLS client
  mirrors a recorded split (`heal::Split`, sealed snapshot) so `status` can show it without
  keys: `waiting-for-reseat` / `branch-won` -> `reseated` when a re-seat Welcome is accepted
  (`MlsGroupClient::with_fork_marker`, `sync_fork_marker`). Never add a secret to it.
- `wiring::assemble` builds a link; the end-to-end test (`harness/tests/e2e.rs`) uses the same assembly. Its header says
  what it does not prove (byte-compatibility with real Geb).
- **Edit and retraction are decided by the record KEY, never by `version`**
  (the host's version is room-wide arrival order). `xref` holds
  `vtkey:<key>` -> `origin_id` of the newest bridged version of that key
  (written after the post, before the outbox entry is marked posted) and
  `vtc:<origin_id>` -> the foreign line id. A content record whose key was
  bridged is a `Supersede` of that `origin_id`, otherwise a plain `Post` at any
  version. A room tombstone (`RoomRecord::retracted`) of a bridged key is a
  `Retract` of it (an ordinary signed `{t:"l"}` with `re`, notice wording from
  `[links.notices]`); a tombstone of a key never bridged is ignored.

