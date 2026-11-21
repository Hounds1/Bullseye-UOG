package io.bullseye.uog.ccc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Local JSON Lines audit log for one CCC process. Unavailable metadata is JSON null. */
final class CccAuditLog {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int BLOCK_BYTES = 4_096;

    record CommittedLine(String json, long nextOffset) {}

    private final Path file;

    CccAuditLog(Path file) throws IOException {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        Path parent = this.file.getParent();
        if (parent == null) {
            throw new IOException("CCC audit log path must name a file");
        }
        Files.createDirectories(parent);
    }

    Path path() {
        return file;
    }

    synchronized void append(
            String event,
            String nodeId,
            UUID requestId,
            UUID runId,
            UUID sessionId,
            String certificateSha256,
            String reasonCode) throws IOException {
        appendLine(record(event, nodeId, requestId, runId, sessionId, certificateSha256, reasonCode));
    }

    static String closeRecord(String nodeId, UUID requestId, UUID runId, UUID sessionId,
            String certificateSha256, String reasonCode) {
        return record("SESSION_CLOSED", nodeId, requestId, runId, sessionId, certificateSha256, reasonCode);
    }

    private static String record(String event, String nodeId, UUID requestId, UUID runId,
            UUID sessionId, String certificateSha256, String reasonCode) {
        return JSON.createObjectNode()
                .put("eventId", UUID.randomUUID().toString())
                .put("occurredAt", Instant.now().toString())
                .put("event", Objects.requireNonNull(event, "event"))
                .put("nodeId", nodeId)
                .put("requestId", id(requestId))
                .put("runId", id(runId))
                .put("sessionId", id(sessionId))
                .put("certificateSha256", certificateSha256)
                .put("reasonCode", reasonCode)
                .toString();
    }

    synchronized void appendLine(String line) throws IOException {
        ByteBuffer bytes = ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8));
        try (FileChannel channel = FileChannel.open(
                file, StandardOpenOption.CREATE, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long end = committedSize(channel);
            channel.truncate(end);
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

    synchronized void reconcileSessions() throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            long end = committedSize(channel);
            if (end < channel.size()) {
                channel.truncate(end);
                channel.force(true);
            }
        } catch (NoSuchFileException missing) {
            return;
        }

        Map<UUID, ObjectNode> openSessions = new LinkedHashMap<>();
        try (var reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!(JSON.readTree(line) instanceof ObjectNode entry)) {
                    throw new IOException("Invalid committed CCC audit record");
                }
                switch (entry.path("event").asText()) {
                    case "JOIN_ACCEPTED" -> openSessions.put(requiredUuid(entry, "sessionId"), entry);
                    case "SESSION_CLOSED" -> openSessions.remove(requiredUuid(entry, "sessionId"));
                    default -> { }
                }
            }
        }

        for (var open : openSessions.entrySet()) {
            ObjectNode entry = open.getValue();
            appendLine(closeRecord(entry.path("nodeId").textValue(), requiredUuid(entry, "requestId"),
                    requiredUuid(entry, "runId"), open.getKey(), entry.path("certificateSha256").textValue(),
                    "RECOVERED_AFTER_RESTART"));
        }
    }

    private static UUID requiredUuid(ObjectNode entry, String field) throws IOException {
        String value = entry.path(field).textValue();
        if (value != null) {
            try {
                UUID parsed = UUID.fromString(value);
                if (parsed.toString().equals(value)) {
                    return parsed;
                }
            } catch (IllegalArgumentException failure) {
                // Report the field without disclosing its value.
            }
        }
        throw new IOException("Invalid CCC audit " + field);
    }

    synchronized long committedSize() throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            return committedSize(channel);
        } catch (NoSuchFileException missing) {
            return 0;
        }
    }

    synchronized boolean isCommittedOffset(long offset) throws IOException {
        if (offset == 0) {
            return true;
        }
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            return offset > 0 && offset <= channel.size() && newlineAt(channel, offset - 1);
        } catch (NoSuchFileException missing) {
            return false;
        }
    }

    synchronized CommittedLine readCommitted(long offset) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ)) {
            channel.position(offset);
            ByteBuffer block = ByteBuffer.allocate(BLOCK_BYTES);
            var line = new ByteArrayOutputStream();
            int count;
            while ((count = channel.read(block)) > 0) {
                for (int index = 0; index < count; index++) {
                    if (block.get(index) == '\n') {
                        line.write(block.array(), 0, index);
                        String json = StandardCharsets.UTF_8.newDecoder()
                                .decode(ByteBuffer.wrap(line.toByteArray())).toString();
                        return new CommittedLine(json, offset + line.size() + 1);
                    }
                }
                line.write(block.array(), 0, count);
                block.clear();
            }
            return null;
        } catch (NoSuchFileException missing) {
            return null;
        }
    }

    private static long committedSize(FileChannel channel) throws IOException {
        long size = channel.size();
        if (size == 0 || newlineAt(channel, size - 1)) {
            return size;
        }

        ByteBuffer block = ByteBuffer.allocate(BLOCK_BYTES);
        long end = size;
        while (end > 0) {
            long start = Math.max(0, end - BLOCK_BYTES);
            block.clear().limit((int) (end - start));
            readFully(channel, block, start);
            for (int index = block.limit() - 1; index >= 0; index--) {
                if (block.get(index) == '\n') {
                    return start + index + 1;
                }
            }
            end = start;
        }
        return 0;
    }

    private static boolean newlineAt(FileChannel channel, long offset) throws IOException {
        ByteBuffer character = ByteBuffer.allocate(1);
        readFully(channel, character, offset);
        return character.get(0) == '\n';
    }

    private static void readFully(FileChannel channel, ByteBuffer block, long offset) throws IOException {
        while (block.hasRemaining()) {
            int count = channel.read(block, offset + block.position());
            if (count < 0) {
                throw new IOException("CCC audit log changed while reading");
            }
        }
    }

    private static String id(UUID value) {
        return value == null ? null : value.toString();
    }
}
