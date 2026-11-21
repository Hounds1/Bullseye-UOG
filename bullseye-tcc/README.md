# Telemetry Control Center

UOG enables TCC by default. Set `bullseye.uog.tcc.enabled=false` to disable
telemetry reception and its archive handoff. The latest-record store defaults
to `var/tcc/latest` and can be changed with `bullseye.uog.tcc.latest-directory`.
On the Core host, enable `bullseye.tcc.enabled=true` alongside the
[CCC connection settings](../bullseye-ccc/README.md).

Core sends `TCC_SNAPSHOT` on the approved TLS connection. TCC binds the
snapshot's `nodeId` and `runId` to the admitted session, checks the v1
schema and diagnostic data, and responds with `TCC_ACK` carrying the
snapshot's `sequence`. Valid initializing and stale observations can be
stored. CCC continues to handle heartbeat traffic during TCC processing.

| ACK status | UOG meaning |
| --- | --- |
| `ACCEPTED` | The eligible snapshot passed validation and committed to the node's local latest-record store. |
| `DUPLICATE` | The same record and content are already stored for the node. |
| `REJECTED` | The record is invalid, has an inactive or different session identity, or conflicts with the remembered ordering or content. |
| `RETRYABLE` | A local write failed while replacing the latest record or preserving its predecessor for archive delivery. |

Each node has one stored JSON object named by the SHA-256 hash of its
`nodeId`. TCC atomically replaces that file and checks the stored record
on retries and after restart. A newly admitted run may restart sequencing.
Use one UOG process per store directory.

## Archive handoff

With AMC enabled, the latest file also holds the current snapshot for archive
delivery. Before replacing it, TCC preserves the previous snapshot in
`.amc-pending` under the latest-record directory if its archive delivery is
still unconfirmed. A background worker sends current and pending snapshots to
AMC and removes a pending file after AMC confirms storage.

`ACCEPTED` confirms TCC's local commit. During an AMC outage, TCC continues
accepting snapshots while its local store can preserve pending records. If
that preservation fails, TCC returns `RETRYABLE` and keeps the previous
latest record.

After restart, the worker resumes delivery from the latest and pending files
on disk. AMC handles any duplicate deliveries. On upgrade, archive history
starts with records still available in the store and grows with subsequent
accepted snapshots. With AMC disabled, TCC uses its latest-only mode.
[AMC archive settings and file layout](../bullseye-amc/README.md)
