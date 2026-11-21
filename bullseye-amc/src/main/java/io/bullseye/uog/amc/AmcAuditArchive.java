package io.bullseye.uog.amc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.UUID;

/** Stores CCC audit records in a directory owned by one archive instance in one UOG process. */
public final class AmcAuditArchive {
    private static final String INVALID_EVENT = "Expected one CCC audit event with a nonempty event type";
    private final Path directory;

    public AmcAuditArchive(Path directory) {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
    }

    /**
     * Installs an audit record, or succeeds when the same event is already stored.
     * Directory creation is deferred until this method runs.
     */
    public synchronized void store(String eventJson) throws IOException {
        ObjectNode event = AmcArchiveFiles.parseObject(
                Objects.requireNonNull(eventJson, "eventJson"), INVALID_EVENT);
        String type = event.path("event").textValue();
        if (type == null || type.isBlank()) {
            throw new IOException(INVALID_EVENT);
        }
        UUID eventId = AmcArchiveFiles.canonicalUuid(event.path("eventId"), "CCC audit eventId");
        requireUtcTime(event.path("occurredAt"));

        Path destination = directory.resolve(eventId + ".json");
        AmcArchiveFiles.store(destination, eventJson, event, "Conflicting CCC audit event " + eventId);
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
}
