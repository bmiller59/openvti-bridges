# Bridge documents

One document per bridge kind, named for the kind: `docs/bridges/<kind>.md`. Written before the code
(see [`../ADDING-A-BRIDGE.md`](../ADDING-A-BRIDGE.md)) and kept current with it. Whatever is not
specific to one foreign system is in [`../core.md`](../core.md).

| Kind | Document | Notes |
|---|---|---|
| `geb` | [`geb.md`](geb.md) | The Geb adapter. Its original plan and companion notes are in [`geb/`](geb/): written inside the VTI repository, partly superseded; a note at the top of `geb/plan.md` lists what changed. |
| `loopback` | (none) | The core's in-memory kind, the conformance reference; described in [`../core.md`](../core.md). |

Each bridge document says: purpose and non-goals; the foreign protocol summary and the exact pin it
was read at; the mapping (what crosses, what is lossy); the capabilities; identity and custody;
state keys and files; halt codes; failure handling; the threat model; the test inventory; the
operational runbook; open questions.
