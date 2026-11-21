package io.bullseye.uog.amc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

class AmcAuditArchiveTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String EVENT_ID = "46e5fffd-6650-452d-8476-ac41e2453c2a";
    private static final String NEXT_EVENT_ID = "4bc0fb0c-159f-4165-b000-4e2e377ac3c7";
    private static final String UTC_TIME = "2026-11-21T05:29:01.058142767Z";

    @TempDir Path temporaryDirectory;

    @Test
    void replayAfterRestartKeepsFirstFileAndArchivesTheNextEventSeparately() throws Exception {
        Path directory = temporaryDirectory.resolve("archive");
        String first = event(EVENT_ID, "JOIN_ACCEPTED", UTC_TIME);
        new AmcAuditArchive(directory).store(first);

        var restarted = new AmcAuditArchive(directory);
        String reformatted = JSON.readTree(first).toString();
        restarted.store(reformatted);
        String next = event(NEXT_EVENT_ID, "SESSION_CLOSED", UTC_TIME);
        restarted.store(next);

        assertEquals(first, Files.readString(directory.resolve(EVENT_ID + ".json")));
        assertEquals(next, Files.readString(directory.resolve(NEXT_EVENT_ID + ".json")));
        try (var files = Files.list(directory)) {
            assertEquals(List.of(EVENT_ID + ".json", NEXT_EVENT_ID + ".json"),
                    files.map(file -> file.getFileName().toString()).sorted().toList());
        }
    }

    @Test
    void rejectsConflictingEventIdAndPreservesArchivedBytes() throws Exception {
        var archive = new AmcAuditArchive(temporaryDirectory);
        String first = event(EVENT_ID, "JOIN_ACCEPTED", UTC_TIME);
        archive.store(first);

        IOException failure = assertThrows(IOException.class,
                () -> archive.store(event(EVENT_ID, "SESSION_CLOSED", UTC_TIME)));
        assertTrue(failure.getMessage().contains("Conflicting CCC audit event"));
        Path original = temporaryDirectory.resolve(EVENT_ID + ".json");
        assertEquals(first, Files.readString(original));
        try (var files = Files.list(temporaryDirectory)) {
            assertEquals(List.of(original), files.toList());
        }
    }

    @Test
    void rejectsIllegalIdMalformedTimestampAndNonStrictJsonBeforeWriting() {
        Path directory = temporaryDirectory.resolve("archive");
        var archive = new AmcAuditArchive(directory);
        String valid = event(EVENT_ID, "JOIN_ACCEPTED", UTC_TIME);
        List<String> invalid = List.of(
                "[]",
                "{}",
                event("../outside", "JOIN_ACCEPTED", UTC_TIME),
                event("1-2-3-4-5", "JOIN_ACCEPTED", UTC_TIME),
                event(EVENT_ID.toUpperCase(Locale.ROOT), "JOIN_ACCEPTED", UTC_TIME),
                event(EVENT_ID, "JOIN_ACCEPTED", "2026-11-21T14:29:01+09:00"),
                event(EVENT_ID, "JOIN_ACCEPTED", "not-a-dateZ"),
                event(EVENT_ID, " ", UTC_TIME),
                "{\"eventId\":\"" + EVENT_ID + "\"," + valid.stripLeading().substring(1),
                valid + "{}");
        for (String candidate : invalid) {
            assertThrows(IOException.class, () -> archive.store(candidate), candidate);
        }
        assertFalse(Files.exists(directory));
    }

    @Test
    void opensLazilyAndCanWriteAfterUnavailableDirectoryRecovers() throws Exception {
        Path directory = temporaryDirectory.resolve("archive");
        Files.writeString(directory, "temporarily blocking the archive path");
        var archive = new AmcAuditArchive(directory);
        String record = event(EVENT_ID, "JOIN_REQUESTED", UTC_TIME);

        assertThrows(IOException.class, () -> archive.store(record));
        assertEquals("temporarily blocking the archive path", Files.readString(directory));
        Files.delete(directory);

        archive.store(record);
        Path stored = directory.resolve(EVENT_ID + ".json");
        assertEquals(record, Files.readString(stored));
        try (var files = Files.list(directory)) {
            assertEquals(List.of(stored), files.toList());
        }
    }

    private static String event(String eventId, String event, String occurredAt) {
        return """
                {
                  "eventId": "%s",
                  "occurredAt": "%s",
                  "event": "%s",
                  "nodeId": "서울-01",
                  "requestId": null,
                  "runId": null,
                  "sessionId": null,
                  "certificateSha256": null,
                  "reasonCode": null
                }
                """.formatted(eventId, occurredAt, event);
    }
}
