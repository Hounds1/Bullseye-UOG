# Archive Management Center

AMC archives CCC audit events and TCC-accepted telemetry snapshots. UOG wires
each producer's background worker to its archive.

| Setting | Default |
| --- | --- |
| `bullseye.uog.amc.enabled` | `true` |
| `bullseye.uog.amc.ccc-audit-directory` | `var/amc/ccc-audit` |
| `bullseye.uog.amc.tcc-telemetry-directory` | `var/amc/tcc-telemetry` |

Set `bullseye.uog.amc.enabled=false` to disable both archive handoffs. With
TCC enabled, it continues to store the latest snapshot per node. With TCC
disabled, AMC can still archive CCC audit events. Use one UOG process per
archive directory.

## CCC audit events

AMC validates the event ID and UTC time and stores one UTF-8 JSON file named
`<eventId>.json` per event. It flushes an incoming record to a temporary file
and installs it atomically. Replaying a stored event with the same content
confirms the existing file. Reusing its ID with different content raises an
error and preserves the existing record.

If storage is temporarily unavailable, the CCC worker retries from the same
position. It advances the checkpoint only after AMC confirms storage. If
UOG stops after archive storage and before the checkpoint is saved, AMC
deduplicates the replay after restart.

## TCC telemetry snapshots

AMC stores the complete accepted v1 telemetry envelope as one UTF-8 JSON file
per `(nodeId, runId, sequence)`. Paths are relative to the telemetry archive
directory.

```text
<sha256(nodeId)>/<runId>/<sequence>.json
```

AMC flushes a new file before installing it atomically. Replaying the same
identity and content confirms the existing file. A replay with different
content preserves the existing file and reports a conflict. If AMC storage
is unavailable, the TCC worker keeps the record available for retry. The
worker can replay current and pending records after restart.
[TCC acceptance and handoff behavior](../bullseye-tcc/README.md#archive-handoff)

## Capacity monitoring

With AMC and capacity monitoring enabled, UOG starts the first scan at
service startup and repeats it at the configured interval. Monitoring is
read-only and reports its results in the UOG logs.

| Setting | Default | Effect |
| --- | --- | --- |
| `bullseye.uog.amc.capacity.enabled` | `true` | Enable periodic capacity scans when AMC is enabled. |
| `bullseye.uog.amc.capacity.interval-seconds` | `60` | Time between scans, in seconds. |
| `bullseye.uog.amc.capacity.min-free-bytes` | `1073741824` | Minimum usable bytes per distinct filesystem volume. Set to `0` to disable low-space warnings. |

Each `[UOG] Archive storage usage.` entry reports `.records` and `.bytes`
for these locations.

| Location | Counted data |
| --- | --- |
| `cccArchive` | Committed regular `.json` files directly under the CCC audit archive directory. |
| `tccArchive` | Committed regular `.json` files at the node/run depth in the TCC telemetry archive. |
| `cccSource` | The original CCC audit JSONL file. `.records` is `0` or `1` and `.bytes` covers the whole file. |
| `tccPending` | Regular `.json` files in `.amc-pending` under the TCC latest-record directory. |

Counts and logical bytes report zero until a location exists. A failed
measurement is reported as unavailable. Logical bytes measure file content
size. Each distinct filesystem volume also reports its usable bytes. UOG
logs one warning per volume per low-space episode and a recovery when its
usable space reaches the configured minimum again.

The monitor consumes storage usage probes. The current probes scan files,
and a database-backed archive can provide the same measurements through
that probe contract.
