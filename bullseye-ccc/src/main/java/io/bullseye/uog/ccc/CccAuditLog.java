package io.bullseye.uog.ccc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Local JSON Lines audit log for one CCC process. Unavailable metadata is JSON null. */
final class CccAuditLog {
    private static final ObjectMapper JSON = new ObjectMapper();

    private final Path file;

    CccAuditLog(Path file) throws IOException {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        Path parent = this.file.getParent();
        if (parent == null) {
            throw new IOException("CCC audit log path must name a file");
        }
        Files.createDirectories(parent);
    }

    synchronized void append(
            String event,
            String nodeId,
            UUID requestId,
            UUID runId,
            UUID sessionId,
            String certificateSha256,
            String reasonCode) throws IOException {
        var entry = JSON.createObjectNode()
                .put("eventId", UUID.randomUUID().toString())
                .put("occurredAt", Instant.now().toString())
                .put("event", Objects.requireNonNull(event, "event"))
                .put("nodeId", nodeId)
                .put("requestId", id(requestId))
                .put("runId", id(runId))
                .put("sessionId", id(sessionId))
                .put("certificateSha256", certificateSha256)
                .put("reasonCode", reasonCode);
        String line = JSON.writeValueAsString(entry) + "\n";
        ByteBuffer bytes = ByteBuffer.wrap(line.getBytes(StandardCharsets.UTF_8));

        try (FileChannel channel = FileChannel.open(
                file, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
            long end = channel.size();
            channel.position(end);
            try {
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            } catch (IOException failure) {
                try {
                    channel.truncate(end);
                    channel.force(true);
                } catch (IOException rollbackFailure) {
                    failure.addSuppressed(rollbackFailure);
                }
                throw failure;
            }
        }
    }

    private static String id(UUID value) {
        return value == null ? null : value.toString();
    }
}
