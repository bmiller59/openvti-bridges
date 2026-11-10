# CLAUDE.md — openvti-bridge-vtc

The VTI side of the bridges: the VTC room side over the user's VTA, HTTPS delivery to the room host, the
durable fjall store and key custody (`SecretStore`, `VtaKeyMinter`). Read the root `CLAUDE.md` first. It
depends on the core and `vta-sdk`, never on an adapter (the isolation CI job checks it).

## VTC room side rules

- The bridge never holds the persona key. Reads (`rooms/keys/browse/0.4`,
  `rooms/keys/read/0.2`) are VTA-side tasks: the VTA fetches from the host as
  the member, so the bridge delivers nothing for a read. Writes are
  `rooms/keys/act/0.11` (and `rooms/keys/seal/0.3` with `signAsPrincipal` on
  the sealed tier); the returned document is POSTed unaltered and
  unauthenticated to `{host}/trust-tasks` over HTTPS (`vtc::host`), because the
  host authenticates by the document's proof alone.
- Never loop a `VtaClient` call. The only repeat is the sealed put's re-seal at
  the version the host assigned (a different request, bounded at three).
- Typed errors stay typed: `permissionDenied`, `...:actionNotHeld`,
  `...:notAMember` and a VTA `Forbidden` become `Error::Refused` (the pump
  halts the link); everything else is `Error::Room { code, retryable, .. }`.
- A refused create-only put is resolved by reading the key back, never by
  parsing a message: this workspace's `room-host` answers a bare `taskFailed`
  where the specification says `rooms/records/put:versionConflict`.
- The host URL is guarded (https only, no private ranges unless the operator
  opted in) and the HTTP client is the shared foreign-fetch client.

