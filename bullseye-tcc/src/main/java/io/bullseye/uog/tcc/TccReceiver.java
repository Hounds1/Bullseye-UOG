package io.bullseye.uog.tcc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;
import java.util.function.BooleanSupplier;

public final class TccReceiver implements AutoCloseable {
    public static final String CAPABILITY = "tcc.snapshot.v1";

    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final Path latestDirectory;
    private final Object storeLock = new Object();
    private final TccTelemetryHandoff handoff;

    public TccReceiver(Path latestDirectory) throws IOException {
        this(latestDirectory, null);
    }

    public TccReceiver(Path latestDirectory, TccTelemetryHandoff.Sink archive) throws IOException {
        this.latestDirectory = Objects.requireNonNull(latestDirectory, "latestDirectory")
                .toAbsolutePath().normalize();
        this.handoff = archive == null ? null : new TccTelemetryHandoff(this.latestDirectory, archive);
    }

    public void startHandoff() {
        if (handoff != null) {
            handoff.start();
        }
    }

    public TccTelemetryHandoff.Progress handoffProgress() throws IOException {
        if (handoff == null) {
            throw new IOException("TCC telemetry handoff is disabled");
        }
        return handoff.progress();
    }

    @Override
    public void close() {
        if (handoff != null) {
            handoff.close();
        }
    }

    /**
     * Receives telemetry from an admitted CCC session.
     * A frame with no positive integral sequence cannot be acknowledged.
     */
    public ObjectNode receive(
            String nodeId, UUID runId, ObjectNode frame, BooleanSupplier sessionActive)
            throws IOException {
        Objects.requireNonNull(nodeId, "nodeId");
        String expectedRunId = Objects.requireNonNull(runId, "runId").toString();
        Objects.requireNonNull(sessionActive, "sessionActive");
        JsonNode candidate = Objects.requireNonNull(frame, "frame").path("telemetry");
        long sequence = TccSnapshotV1.sequence(candidate);
        if (sequence == 0) {
            throw new IOException("Cannot acknowledge telemetry without a positive sequence");
        }
        if (!"TCC_SNAPSHOT".equals(frame.path("type").textValue())
                || !TccSnapshotV1.versionOne(frame.path("protocolVersion"))) {
            return acknowledgement(sequence, "REJECTED", "INVALID_FRAME");
        }
        if (!(candidate instanceof ObjectNode telemetry)
                || !TccSnapshotV1.valid(telemetry, nodeId, expectedRunId)) {
            return acknowledgement(sequence, "REJECTED", "INVALID_TELEMETRY");
        }

        boolean consistent = TccSnapshotV1.consistentObservations(telemetry.path("snapshot"));
        Path latestFile = latestDirectory.resolve(fileName(nodeId));
        synchronized (storeLock) {
            if (!sessionActive.getAsBoolean()) {
                return acknowledgement(sequence, "REJECTED", "SESSION_INACTIVE");
            }
            try {
                if (consistent) {
                    Files.createDirectories(latestDirectory);
                }
                StoredTelemetry previous = readLatest(latestFile, nodeId);
                ObjectNode latest = previous == null ? null : previous.telemetry();
                boolean sameRun = latest != null && expectedRunId.equals(latest.path("runId").textValue());
                long latestSequence = sameRun ? TccSnapshotV1.sequence(latest) : 0;
                // An older accepted record can predate the current observation checks.
                if (sameRun && sequence == latestSequence && compatible(telemetry, latest)) {
                    return acknowledgement(sequence, "DUPLICATE", null);
                }
                if (!consistent) {
                    return acknowledgement(sequence, "REJECTED", "INVALID_TELEMETRY");
                }
                if (sameRun) {
                    if (sequence < latestSequence) {
                        return acknowledgement(sequence, "REJECTED", "SEQUENCE_OLDER");
                    }
                    if (sequence == latestSequence) {
                        return acknowledgement(sequence, "REJECTED", "SEQUENCE_CONFLICT");
                    }
                    if (timelineRegressed(telemetry.path("snapshot"), latest.path("snapshot"))) {
                        return acknowledgement(sequence, "REJECTED", "TIMELINE_REGRESSION");
                    }
                }
                return replaceLatest(latestFile, telemetry, previous, sessionActive)
                        ? acknowledgement(sequence, "ACCEPTED", null)
                        : acknowledgement(sequence, "REJECTED", "SESSION_INACTIVE");
            } catch (IOException failure) {
                return acknowledgement(sequence, "RETRYABLE", "PERSISTENCE_UNAVAILABLE");
            }
        }
    }

    private static boolean compatible(ObjectNode first, ObjectNode second) {
        return first.equals((left, right) -> {
            if (left.isNumber() && right.isNumber()
                    && Double.isFinite(left.doubleValue()) && Double.isFinite(right.doubleValue())) {
                return left.decimalValue().compareTo(right.decimalValue());
            }
            return left.equals(right) ? 0 : 1;
        }, second);
    }

    private static boolean timelineRegressed(JsonNode submitted, JsonNode latest) {
        return submitted.path("evaluatedAt").longValue() < latest.path("evaluatedAt").longValue()
                || submitted.path("version").longValue() < latest.path("version").longValue();
    }

    private static StoredTelemetry readLatest(Path file, String nodeId) throws IOException {
        try {
            byte[] contents = Files.readAllBytes(file);
            JsonNode previous = JSON.readTree(contents);
            if (previous instanceof ObjectNode telemetry
                    && TccSnapshotV1.sequence(telemetry) > 0) {
                String runId = telemetry.path("runId").textValue();
                if (canonicalUuid(runId) && TccSnapshotV1.valid(telemetry, nodeId, runId)) {
                    return new StoredTelemetry(telemetry, contents);
                }
            }
            throw new IOException("Invalid persisted telemetry");
        } catch (NoSuchFileException missing) {
            return null;
        }
    }

    private boolean replaceLatest(
            Path latestFile, ObjectNode telemetry, StoredTelemetry previous,
            BooleanSupplier sessionActive) throws IOException {
        Path temporary = Files.createTempFile(latestDirectory, ".tcc-", ".tmp");
        try {
            writeAndForce(temporary, JSON.writeValueAsBytes(telemetry));
            if (handoff != null && previous != null) {
                handoff.preserve(latestFile, previous.contents());
            }
            if (!sessionActive.getAsBoolean()) {
                return false;
            }
            Files.move(temporary, latestFile,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            forceDirectoryBestEffort(latestDirectory);
            return true;
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    static void writeAndForce(Path file, byte[] contents) throws IOException {
        ByteBuffer content = ByteBuffer.wrap(contents);
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            while (content.hasRemaining()) {
                channel.write(content);
            }
            channel.force(true);
        }
    }

    static void forceDirectoryBestEffort(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // Forcing directory entries is not supported by every filesystem.
        }
    }

    private record StoredTelemetry(ObjectNode telemetry, byte[] contents) {}

    private static boolean canonicalUuid(String value) {
        try {
            return value != null && UUID.fromString(value).toString().equals(value);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static String fileName(String nodeId) {
        return sha256(nodeId.getBytes(StandardCharsets.UTF_8)) + ".json";
    }

    static String sha256(byte[] contents) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(contents);
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime", unavailable);
        }
    }

    private static ObjectNode acknowledgement(long sequence, String status, String reasonCode) {
        ObjectNode ack = JSON.createObjectNode()
                .put("protocolVersion", 1)
                .put("type", "TCC_ACK")
                .put("sequence", sequence)
                .put("status", status);
        if (reasonCode != null) {
            ack.put("reasonCode", reasonCode);
        }
        return ack;
    }
}
