# Cluster Control Center

## Configuration

UOG binds to `127.0.0.1:7443` by default. Set
`bullseye.uog.ccc.bind-host` to the interface where Core connects. Set one
`bullseye.uog.ccc.allow.<nodeId>` entry per node with its leaf client
certificate's SHA-256 fingerprint as 64 hexadecimal characters. Use
`keytool -list -v` on the client's key store to obtain the fingerprint, then
remove the colons. The [sample configuration](../config/bullseye-uog.properties)
includes the heartbeat interval, admission timeout, connection limit, and
audit file location.

Configure the JVM's `javax.net.ssl.keyStore` and
`javax.net.ssl.trustStore` before starting UOG. The key store contains the
listener certificate and private key. The trust store contains the trusted
client certificates or their issuing CA. Supply the appropriate JSSE store
types and passwords to the launcher for the stores in use.

Configure Core's `bullseye.ccc.host`, `bullseye.ccc.port`, and
`bullseye.ccc.node-id` to match, and enable `bullseye.ccc.enabled`.
The Core JVM uses its client key store and a trust store for the UOG
certificate. The host in Core's config must match the UOG certificate.

## Admission and sessions

CCC implements the [Core v1 join protocol](https://github.com/Hounds1/Bullseye-Core/blob/main/docs/ccc-join-v1.md)
over mutual TLS. Each message has a four-byte big-endian body length and one
UTF-8 JSON object. CCC binds the claimed `nodeId` to the authenticated client
certificate before granting a session. Each approved node has at most one
active session. CCC sends `PING` and checks the matching `PONG` sequence.
Missed heartbeats close the connection. The join response includes
`tcc.snapshot.v1` when the [TCC receiver](../bullseye-tcc/README.md) is enabled.

UOG code can call `CccServer.revokeSession(nodeId, sessionId, reasonCode,
retryAfterMs)` to revoke an exact live session. The method returns `true`
when it selects that session for revocation. CCC serializes `SESSION_REVOKED`
with heartbeat and telemetry replies and closes the connection even if
delivery fails. An optional nonnegative `retryAfterMs` lets Core request
approval again after the delay. Omit it to revoke until the Core process is
restarted. Reason codes match `[A-Z][A-Z0-9_]{0,63}`.

## Audit events and handoff

CCC appends `JOIN_REQUESTED`, `JOIN_ACCEPTED`, `JOIN_REJECTED`, and
`SESSION_CLOSED` events to the configured UTF-8 JSON Lines file. Events
include their own IDs, UTC timestamps, and available request, node, run,
session, certificate, and reason fields. CCC flushes the approval record
before sending the approval response.

CCC releases a closed session and retries its `SESSION_CLOSED` write in the
background. Retries preserve the event ID, timestamp, and body. At startup,
CCC reconciles admitted sessions without a closing record and records them
as `RECOVERED_AFTER_RESTART`. The timestamp of a recovery record is the
reconciliation time. CCC preserves all complete audit records and repairs
an incomplete final line before continuing.

When [AMC](../bullseye-amc/README.md) is enabled, a worker reads completed audit
records and hands them off in file order. The worker calls the archive outside
the audit writer's lock. After the archive confirms storage, the worker
saves the next byte offset and uses it when UOG restarts. Read, archive, and
checkpoint failures are retried while CCC admission continues independently.

The checkpoint path defaults to the audit file path with the
`.amc-offset` suffix. Use `bullseye.uog.ccc.audit-checkpoint` to set a different
path. Keep the live source file append-only while handoff is active. The source
file and its checkpoint refer to the same archive destination.
