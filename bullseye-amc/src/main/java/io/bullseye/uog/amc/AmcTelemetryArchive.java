package io.bullseye.uog.amc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

/** Stores TCC-accepted telemetry in a directory owned by one archive instance in one UOG process. */
public final class AmcTelemetryArchive {
    private final Path directory;

    public AmcTelemetryArchive(Path directory) {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
    }

    /** Installs a complete telemetry envelope, or succeeds when it is already stored. */
    public synchronized void store(String telemetryJson) throws IOException {
        ObjectNode telemetry = AmcArchiveFiles.parseObject(
                Objects.requireNonNull(telemetryJson, "telemetryJson"),
                "Expected one TCC telemetry envelope");
        JsonNode schemaVersion = telemetry.path("schemaVersion");
        String nodeId = telemetry.path("nodeId").textValue();
        JsonNode sequence = telemetry.path("sequence");
        if (!schemaVersion.isIntegralNumber() || !schemaVersion.canConvertToInt()
                || schemaVersion.intValue() != 1
                || nodeId == null || nodeId.isBlank()
                || !sequence.isIntegralNumber() || !sequence.canConvertToLong()
                || sequence.longValue() < 1
                || !telemetry.path("snapshot").isObject()) {
            throw new IOException("Invalid TCC telemetry envelope");
        }
        UUID runId = AmcArchiveFiles.canonicalUuid(telemetry.path("runId"), "TCC telemetry runId");

        Path destination = directory.resolve(nodeFileKey(nodeId))
                .resolve(runId.toString())
                .resolve(sequence.longValue() + ".json");
        AmcArchiveFiles.store(destination, telemetryJson, telemetry,
                "Conflicting TCC telemetry record " + runId + "/" + sequence.longValue());
    }

    private static String nodeFileKey(String nodeId) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(AmcArchiveFiles.utf8(nodeId));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime", unavailable);
        }
    }
}
