# Telemetry Control Center

UOG enables TCC by default. Set `bullseye.uog.tcc.enabled=false` for a
CCC-only listener. The store defaults to `var/tcc/latest` and can be changed
with `bullseye.uog.tcc.latest-directory`. Enable `bullseye.tcc.enabled=true`
on the Core host as well as its [CCC connection settings](../bullseye-ccc/README.md).

Core sends `TCC_SNAPSHOT` on the approved TLS connection. TCC binds the
snapshot's `nodeId` and `runId` to the admitted session, checks the v1
schema and diagnostic data, and responds with `TCC_ACK` carrying the
snapshot's `sequence`. Valid initializing and stale observations can be
stored. CCC continues to handle heartbeat traffic during TCC processing.

| ACK status | UOG meaning |
| --- | --- |
| `ACCEPTED` | The eligible snapshot passed validation and replaced the node's latest record. |
| `DUPLICATE` | The same record and content are already stored for the node. |
| `REJECTED` | The record is invalid, has an inactive or different session identity, or conflicts with the remembered ordering or content. |
| `RETRYABLE` | The latest-record store could not complete the operation. |

Each node has one stored JSON object named by the SHA-256 hash of its
`nodeId`. TCC atomically replaces that file and checks the stored record
on retries and after restart. A newly admitted run may restart sequencing.
Use one UOG process per store directory.
Transition history and AMC retention use a separate integration.
