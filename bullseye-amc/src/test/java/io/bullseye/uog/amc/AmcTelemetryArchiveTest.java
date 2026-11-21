package io.bullseye.uog.amc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

class AmcTelemetryArchiveTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String NODE = "../서울/edge-01";
    private static final String RUN_ID = "46e5fffd-6650-452d-8476-ac41e2453c2a";
    private static final String NEXT_RUN_ID = "4bc0fb0c-159f-4165-b000-4e2e377ac3c7";
    private static final String FIRST = envelope(NODE, RUN_ID, "1");

    @TempDir Path temporaryDirectory;

    @Test
    void archivesUnchangedEnvelopesByNodeRunAndSequence() throws Exception {
        Path directory = temporaryDirectory.resolve("archive");
        var archive = new AmcTelemetryArchive(directory);
        assertFalse(Files.exists(directory));

        String nextSequence = envelope(NODE, RUN_ID, "2");
        String nextRun = envelope(NODE, NEXT_RUN_ID, "1");
        String anotherNode = envelope("edge-02", RUN_ID, "1");
        archive.store(FIRST);
        archive.store(nextSequence);
        archive.store(nextRun);
        archive.store(anotherNode);

        Path firstFile = archiveFile(directory, NODE, RUN_ID, "1");
        Path nextFile = archiveFile(directory, NODE, RUN_ID, "2");
        Path nextRunFile = archiveFile(directory, NODE, NEXT_RUN_ID, "1");
        Path otherNodeFile = archiveFile(directory, "edge-02", RUN_ID, "1");
        assertEquals(FIRST, Files.readString(firstFile));
        assertEquals(nextSequence, Files.readString(nextFile));
        assertEquals(nextRun, Files.readString(nextRunFile));
        assertEquals(anotherNode, Files.readString(otherNodeFile));
        assertEquals(Set.of(firstFile, nextFile, nextRunFile, otherNodeFile), filesUnder(directory));
    }

    @Test
    void replayAfterRestartKeepsOriginalAndConflictCannotOverwriteIt() throws Exception {
        new AmcTelemetryArchive(temporaryDirectory).store(FIRST);
        var restarted = new AmcTelemetryArchive(temporaryDirectory);
        String reformatted = JSON.readTree(FIRST).toString();
        restarted.store(reformatted);

        String conflicting = FIRST.replace("STALE", "FRESH");
        IOException failure = assertThrows(IOException.class, () -> restarted.store(conflicting));
        assertTrue(failure.getMessage().contains("Conflicting TCC telemetry record"));

        Path stored = archiveFile(temporaryDirectory, NODE, RUN_ID, "1");
        assertEquals(FIRST, Files.readString(stored));
        assertEquals(Set.of(stored), filesUnder(temporaryDirectory));
    }

    @Test
    void rejectsInvalidEnvelopeIdentityBeforeCreatingDirectories() {
        Path directory = temporaryDirectory.resolve("archive");
        var archive = new AmcTelemetryArchive(directory);
        List<String> invalid = List.of(
                "[]",
                "{}",
                FIRST.replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"),
                FIRST.replace("\"schemaVersion\": 1", "\"schemaVersion\": 1.0"),
                envelope("  ", RUN_ID, "1"),
                envelope(NODE, "../outside", "1"),
                envelope(NODE, RUN_ID.toUpperCase(Locale.ROOT), "1"),
                envelope(NODE, RUN_ID, "0"),
                envelope(NODE, RUN_ID, "-1"),
                envelope(NODE, RUN_ID, "1.0"),
                envelope(NODE, RUN_ID, "9223372036854775808"),
                FIRST.replace("\"snapshot\": {", "\"snapshot\": null, \"other\": {"),
                FIRST + "{}");
        for (String telemetry : invalid) {
            assertThrows(IOException.class, () -> archive.store(telemetry), telemetry);
        }
        assertFalse(Files.exists(directory));
    }

    @Test
    void canRetryWhenArchiveDirectoryBecomesAvailable() throws Exception {
        Path directory = temporaryDirectory.resolve("archive");
        Files.writeString(directory, "temporarily blocking the archive path");
        var archive = new AmcTelemetryArchive(directory);

        assertThrows(IOException.class, () -> archive.store(FIRST));
        assertEquals("temporarily blocking the archive path", Files.readString(directory));
        Files.delete(directory);

        archive.store(FIRST);
        Path stored = archiveFile(directory, NODE, RUN_ID, "1");
        assertEquals(FIRST, Files.readString(stored));
        assertEquals(Set.of(stored), filesUnder(directory));
    }

    private static String envelope(String nodeId, String runId, String sequence) {
        return """
                {
                  "schemaVersion": 1,
                  "nodeId": "%s",
                  "runId": "%s",
                  "sequence": %s,
                  "snapshot": {
                    "observationStatus": "STALE",
                    "extension": {"note": "수집 중", "value": 19.25}
                  }
                }
                """.formatted(nodeId, runId, sequence);
    }

    private static Path archiveFile(Path directory, String nodeId, String runId, String sequence)
            throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(nodeId.getBytes(StandardCharsets.UTF_8));
        return directory.resolve(HexFormat.of().formatHex(digest))
                .resolve(runId).resolve(sequence + ".json");
    }

    private static Set<Path> filesUnder(Path directory) throws IOException {
        try (var files = Files.walk(directory)) {
            return files.filter(Files::isRegularFile).collect(Collectors.toSet());
        }
    }
}
