package io.bullseye.uog.amc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.UUID;

/** Stores CCC audit records in a directory owned by one archive instance in one UOG process. */
public final class AmcAuditArchive {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final Path directory;

    public AmcAuditArchive(Path directory) {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
    }

    /**
     * Installs an audit record, or succeeds when the same event is already stored.
     * Directory creation is deferred until this method runs.
     */
    public synchronized void store(String eventJson) throws IOException {
        ObjectNode event = parseEvent(Objects.requireNonNull(eventJson, "eventJson"));
        UUID eventId = eventId(event.path("eventId"));
        requireUtcTime(event.path("occurredAt"));

        Path destination = directory.resolve(eventId + ".json");
        Files.createDirectories(directory);
        ObjectNode existing = readExisting(destination);
        if (existing != null) {
            if (!existing.equals(event)) {
                throw new IOException("Conflicting CCC audit event " + eventId);
            }
            return;
        }

        ByteBuffer content = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(eventJson));
        install(destination, content);
    }

    private static ObjectNode parseEvent(String eventJson) throws IOException {
        JsonNode parsed = JSON.readTree(eventJson);
        if (!(parsed instanceof ObjectNode event)
                || !event.path("event").isTextual()
                || event.path("event").textValue().isBlank()) {
            throw new IOException("Expected one CCC audit event with a nonempty event type");
        }
        return event;
    }

    private static UUID eventId(JsonNode field) throws IOException {
        String value = field.textValue();
        if (value != null) {
            try {
                UUID parsed = UUID.fromString(value);
                if (parsed.toString().equals(value)) {
                    return parsed;
                }
            } catch (IllegalArgumentException invalid) {
                throw new IOException("Invalid CCC audit eventId", invalid);
            }
        }
        throw new IOException("CCC audit eventId must be a canonical UUID");
    }

    private static void requireUtcTime(JsonNode field) throws IOException {
        String value = field.textValue();
        if (value == null || !value.endsWith("Z")) {
            throw new IOException("CCC audit occurredAt must be a UTC instant");
        }
        try {
            Instant.parse(value);
        } catch (DateTimeParseException invalid) {
            throw new IOException("Invalid CCC audit occurredAt", invalid);
        }
    }

    private static ObjectNode readExisting(Path destination) throws IOException {
        try {
            return parseEvent(Files.readString(destination, StandardCharsets.UTF_8));
        } catch (NoSuchFileException missing) {
            return null;
        }
    }

    private void install(Path destination, ByteBuffer content) throws IOException {
        Path temporary = Files.createTempFile(directory, "amc-audit-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                while (content.hasRemaining()) {
                    channel.write(content);
                }
                channel.force(true);
            }
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            forceDirectoryBestEffort();
        } catch (IOException failure) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    private void forceDirectoryBestEffort() {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // Directory syncing depends on the host filesystem and provider.
        }
    }
}
