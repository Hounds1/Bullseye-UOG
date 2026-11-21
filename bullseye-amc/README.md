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
