# Bullseye UOG

Bullseye Unified Operations Group is the central service for Bullseye Core
instances. Core runs on monitored Linux hosts and connects to UOG.

| Gradle module | Responsibility |
| --- | --- |
| `bullseye-uog-app` | UOG entry point, configuration, and application distribution. |
| `bullseye-ccc` | Cluster Control Center. Authenticates Core instances, decides admission, manages active connections, and records its decisions. |
| `bullseye-tcc` | Telemetry Control Center. Validates incoming snapshots, stores the latest record per node, and sends the admission result. |

The application module wires CCC sessions to the TCC receiver. AMC owns
long-term archive storage and queries, and JTC coordinates work that spans
centers. The CCC audit log is produced locally and gives AMC an event stream
to receive when archive integration is implemented.

## Build

Use JDK 25 and the included Gradle wrapper.

```sh
sh ./gradlew test :bullseye-uog-app:installDist
```

On Windows, run `gradlew.bat test :bullseye-uog-app:installDist`. The resulting
application and example configuration are under
`bullseye-uog-app/build/install/bullseye-uog`.

## Configure CCC

UOG binds to `127.0.0.1:7443` by default. Set
`bullseye.uog.ccc.bind-host` to the interface where Core connects. Set one
`bullseye.uog.ccc.allow.<nodeId>` entry per node with its leaf client
certificate's SHA-256 fingerprint as 64 hexadecimal characters. Use
`keytool -list -v` on the client's key store to obtain the fingerprint, then
remove the colons. The sample configuration includes the default heartbeat
interval, admission timeout, connection limit, and audit file location.
Relative file paths resolve from the process working directory.

Configure the JVM's `javax.net.ssl.keyStore` and
`javax.net.ssl.trustStore` before starting UOG. The key store contains the
listener certificate and private key. The trust store contains the trusted
client certificates or their issuing CA. Supply the appropriate JSSE store
types and passwords to the launcher for the stores in use.

From the installed distribution, run
`./bin/bullseye-uog config/bullseye-uog.properties`. Configure Core's
`bullseye.ccc.host`, `bullseye.ccc.port`, and `bullseye.ccc.node-id` to match,
and enable `bullseye.ccc.enabled`. The Core JVM uses its client key store
and a trust store for the UOG certificate. The host in Core's config must
match the UOG certificate.

## Admission and sessions

CCC implements the [Core v1 join protocol](https://github.com/Hounds1/Bullseye-Core/blob/main/docs/ccc-join-v1.md)
over mutual TLS. Each message has a four-byte big-endian body length and one
UTF-8 JSON object. CCC binds the claimed `nodeId` to the authenticated client
certificate before granting a session. Each approved node has at most one
active session. CCC sends `PING` and checks the matching `PONG` sequence.
Missed heartbeats close the connection. The join response includes
`tcc.snapshot.v1` when the TCC receiver is enabled.

CCC appends `JOIN_REQUESTED`, `JOIN_ACCEPTED`, `JOIN_REJECTED`, and
`SESSION_CLOSED` events to the configured UTF-8 JSON Lines file. Events
include their own IDs, UTC timestamps, and available request, node, run,
session, certificate, and reason fields. CCC flushes the approval record
before sending the approval response. The local file serves the initial CCC
deployment. AMC will own long-term retention and access when archive
handoff is implemented.

## Receive TCC snapshots

UOG enables TCC by default. Set `bullseye.uog.tcc.enabled=false` for a
CCC-only listener. The store defaults to `var/tcc/latest` and can be changed
with `bullseye.uog.tcc.latest-directory`. Enable `bullseye.tcc.enabled=true`
on the Core host as well as its CCC connection settings.

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

## License

Bullseye UOG is available under the [MIT license](LICENSE).
