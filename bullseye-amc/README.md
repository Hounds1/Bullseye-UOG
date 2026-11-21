# Archive Management Center

AMC currently accepts audit events from [CCC](../bullseye-ccc/README.md).
The UOG application wires the CCC handoff worker to the archive.

| Setting | Default |
| --- | --- |
| `bullseye.uog.amc.enabled` | `true` |
| `bullseye.uog.amc.ccc-audit-directory` | `var/amc/ccc-audit` |

AMC validates the event ID and UTC time and stores one UTF-8 JSON file named
`<eventId>.json` per event. It flushes an incoming record to a temporary file
and installs it atomically. Replaying a stored event with the same content
confirms the existing file. Reusing its ID with different content raises an
error and preserves the existing record. Run one UOG process per archive
directory.

If storage is temporarily unavailable, the CCC worker retries from the same
position. It advances the checkpoint only after AMC confirms storage. If
UOG stops after archive storage and before the checkpoint is saved, AMC
deduplicates the replay after restart.
