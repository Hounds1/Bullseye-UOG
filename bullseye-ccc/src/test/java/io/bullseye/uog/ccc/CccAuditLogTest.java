package io.bullseye.uog.ccc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

class CccAuditLogTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir Path temporaryDirectory;

    @Test
    void appendsUtf8JsonLinesAndPreservesEarlierRecordsWhenReopened() throws Exception {
        Path file = temporaryDirectory.resolve("ccc/audit/events.jsonl");
        CccAuditLog log = new CccAuditLog(file);
        assertTrue(Files.isDirectory(file.getParent()));

        String nodeId = "서울 노드 \"edge\"\n01";
        UUID requestId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        String certificate = "a0".repeat(32);
        log.append("JOIN_ACCEPTED", nodeId, requestId, runId, sessionId, certificate, null);
        String firstWrite = Files.readString(file, StandardCharsets.UTF_8);

        new CccAuditLog(file).append(
                "SESSION_REVOKED", nodeId, null, runId, sessionId, certificate, "OPERATOR_REVOKED");
        String contents = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(contents.startsWith(firstWrite));
        assertTrue(contents.endsWith("\n"));
        List<String> lines = contents.lines().toList();
        assertEquals(2, lines.size());

        JsonNode first = JSON.readTree(lines.get(0));
        assertEquals("JOIN_ACCEPTED", first.get("event").textValue());
        assertEquals(nodeId, first.get("nodeId").textValue());
        assertEquals(requestId.toString(), first.get("requestId").textValue());
        assertEquals(runId.toString(), first.get("runId").textValue());
        assertEquals(sessionId.toString(), first.get("sessionId").textValue());
        assertEquals(certificate, first.get("certificateSha256").textValue());
        assertTrue(first.get("reasonCode").isNull());
        Instant.parse(first.get("occurredAt").textValue());
        assertTrue(first.get("occurredAt").textValue().endsWith("Z"));

        JsonNode second = JSON.readTree(lines.get(1));
        assertEquals("SESSION_REVOKED", second.get("event").textValue());
        assertTrue(second.get("requestId").isNull());
        assertEquals("OPERATOR_REVOKED", second.get("reasonCode").textValue());
        assertNotEquals(
                UUID.fromString(first.get("eventId").textValue()),
                UUID.fromString(second.get("eventId").textValue()));
    }

    @Test
    void readsCommittedByteOffsetsAndRepairsAnInterruptedAppend() throws Exception {
        Path file = temporaryDirectory.resolve("events.jsonl");
        CccAuditLog log = new CccAuditLog(file);
        log.append("JOIN_REQUESTED", "서울-노드", null, null, null, null, null);
        var first = log.readCommitted(0);
        long firstOffset = Files.size(file);
        assertEquals(firstOffset, first.nextOffset());
        assertTrue(firstOffset > first.json().length() + 1L);
        assertEquals("서울-노드", JSON.readTree(first.json()).path("nodeId").textValue());

        Files.writeString(file, "{\"incomplete\":\"" + "x".repeat(8_000), StandardOpenOption.APPEND);
        Files.write(file, new byte[] {(byte) 0xED}, StandardOpenOption.APPEND);
        assertTrue(log.isCommittedOffset(firstOffset));
        assertFalse(log.isCommittedOffset(Files.size(file)));
        assertNull(log.readCommitted(firstOffset));

        CccAuditLog reopened = new CccAuditLog(file);
        reopened.append("JOIN_ACCEPTED", "서울-노드", null, null, null, null, null);
        assertEquals(first, reopened.readCommitted(0));
        var second = reopened.readCommitted(firstOffset);
        assertEquals("JOIN_ACCEPTED", JSON.readTree(second.json()).path("event").textValue());
        assertEquals(Files.size(file), second.nextOffset());
        assertNull(reopened.readCommitted(second.nextOffset()));
    }

    @Test
    void concurrentAppendsKeepEveryRecordInItsOwnLine() throws Exception {
        Path file = temporaryDirectory.resolve("events.jsonl");
        CccAuditLog log = new CccAuditLog(file);
        List<Callable<Void>> writes = new ArrayList<>();
        for (int index = 0; index < 16; index++) {
            String nodeId = "node-" + index;
            writes.add(() -> {
                log.append("JOIN_REJECTED", nodeId, null, null, null, null, "UNAUTHORIZED_NODE");
                return null;
            });
        }

        try (var writers = Executors.newFixedThreadPool(4)) {
            for (var write : writers.invokeAll(writes)) {
                write.get();
            }
        }

        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        assertEquals(writes.size(), lines.size());
        var eventIds = new HashSet<UUID>();
        var nodeIds = new HashSet<String>();
        for (String line : lines) {
            JsonNode entry = JSON.readTree(line);
            assertTrue(eventIds.add(UUID.fromString(entry.get("eventId").textValue())));
            assertTrue(nodeIds.add(entry.get("nodeId").textValue()));
        }
    }
}
