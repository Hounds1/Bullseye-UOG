# Bullseye UOG

Bullseye Unified Operations Group is the central service for Bullseye Core
instances. Core runs on monitored Linux hosts and connects to UOG.

| Gradle module | Responsibility |
| --- | --- |
| `bullseye-uog-app` | UOG entry point, configuration, and application distribution. |
| `bullseye-ccc` | Cluster Control Center. Authenticates Core instances, decides admission, manages active connections, and records its decisions. |

TCC owns telemetry admission, AMC owns long-term archive storage and queries,
and JTC coordinates work that spans centers. The CCC audit log is produced
locally and gives AMC an event stream to receive when archive integration is
implemented.

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
Missed heartbeats close the connection. TCC support will be included in the
join response when the TCC receiver is available.

CCC appends `JOIN_REQUESTED`, `JOIN_ACCEPTED`, `JOIN_REJECTED`, and
`SESSION_CLOSED` events to the configured UTF-8 JSON Lines file. Events
include their own IDs, UTC timestamps, and available request, node, run,
session, certificate, and reason fields. CCC flushes the approval record
before sending the approval response. The local file serves the initial CCC
deployment. AMC will own long-term retention and access when archive
handoff is implemented.
