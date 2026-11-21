# Bullseye UOG

Bullseye Unified Operations Group is the central service for Bullseye Core
instances. Core runs on monitored Linux hosts and connects to UOG.

| Gradle module | Responsibility |
| --- | --- |
| `bullseye-uog-app` | UOG entry point, configuration, and application distribution. |
| [bullseye-ccc](bullseye-ccc/README.md) | Cluster Control Center. Authenticates Core, manages sessions, and produces audit records. |
| [bullseye-tcc](bullseye-tcc/README.md) | Telemetry Control Center. Validates snapshots and stores the latest record per node. |
| [bullseye-amc](bullseye-amc/README.md) | Archive Management Center. Stores and deduplicates CCC audit events. |

The application module connects CCC sessions to the TCC receiver and passes
CCC audit events to the AMC archive.

## Build

Use JDK 25 and the included Gradle wrapper.

```sh
sh ./gradlew test :bullseye-uog-app:installDist
```

On Windows, run `gradlew.bat test :bullseye-uog-app:installDist`. The resulting
application and example configuration are under
`bullseye-uog-app/build/install/bullseye-uog`.

## Run

Start with the [sample configuration](config/bullseye-uog.properties) and
configure the [CCC listener and TLS stores](bullseye-ccc/README.md).
Relative file paths resolve from the process working directory. From the
installed distribution, run the following command.

```sh
./bin/bullseye-uog config/bullseye-uog.properties
```

## License

Bullseye UOG is available under the [MIT license](LICENSE).
