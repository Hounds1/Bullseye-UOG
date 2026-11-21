package io.bullseye.uog.tcc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

class TccReceiverTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String NODE = "node-001";
    private static final UUID RUN = UUID.fromString("46e5fffd-6650-452d-8476-ac41e2453c2a");
    private static final UUID NEXT_RUN = UUID.fromString("4bc0fb0c-159f-4165-b000-4e2e377ac3c7");

    @TempDir Path latestDirectory;

    @Test
    void createsStoreOnlyForValidActiveTelemetryAndThenDeliversToArchive() throws Exception {
        Path store = latestDirectory.resolve("not-created/latest");
        ObjectNode first = fixture("initializing");
        var archived = new CompletableFuture<ObjectNode>();
        try (var receiver = new TccReceiver(store,
                json -> archived.complete((ObjectNode) JSON.readTree(json)))) {
            receiver.startHandoff();
            assertFalse(Files.exists(store.getParent()));

            ObjectNode wrongVersion = first.deepCopy().put("schemaVersion", 2);
            assertAck(receiver.receive(NODE, RUN, frame(wrongVersion), () -> true),
                    1, "REJECTED", "INVALID_TELEMETRY");
            assertAck(receiver.receive(NODE, RUN, frame(first), () -> false),
                    1, "REJECTED", "SESSION_INACTIVE");
            assertFalse(Files.exists(store.getParent()));

            assertAck(receiver.receive(NODE, RUN, frame(first), () -> true), 1, "ACCEPTED", null);
            assertEquals(first, archived.get(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void recoversUnavailableOrRemovedStoreWithoutRestartingReceiver() throws Exception {
        Path store = Files.writeString(latestDirectory.resolve("blocked"), "blocking file");
        ObjectNode first = fixture("initializing");
        ObjectNode second = fixture("evaluated");
        Path stored = store.resolve(latestFile(NODE).getFileName());

        try (var receiver = new TccReceiver(store)) {
            assertAck(receiver.receive(NODE, RUN, frame(first), () -> true),
                    1, "RETRYABLE", "PERSISTENCE_UNAVAILABLE");
            assertEquals("blocking file", Files.readString(store));

            Files.delete(store);
            assertAck(receiver.receive(NODE, RUN, frame(first), () -> true), 1, "ACCEPTED", null);
            assertEquals(first, JSON.readTree(Files.readString(stored)));

            Files.delete(stored);
            Files.delete(store);
            assertAck(receiver.receive(NODE, RUN, frame(second), () -> true), 2, "ACCEPTED", null);
            assertEquals(second, JSON.readTree(Files.readString(stored)));
        }
    }

    @Test
    void acceptsCoreFixturesIncludingInitializingStaleAndWallClockBacksteps() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode initializing = fixture("initializing");
        ObjectNode evaluated = fixture("evaluated");
        snapshot(evaluated).put("wallClockAt", 999);

        assertAck(receiver.receive(NODE, RUN, frame(initializing), () -> true), 1, "ACCEPTED", null);
        Path latest = latestFile(NODE);
        assertEquals(initializing, JSON.readTree(Files.readString(latest)));

        assertAck(receiver.receive(NODE, RUN, frame(evaluated), () -> true), 2, "ACCEPTED", null);
        assertEquals(evaluated, JSON.readTree(Files.readString(latest)));
        try (var files = Files.list(latestDirectory)) {
            assertEquals(List.of(latest), files.toList());
        }
    }

    @Test
    void rejectsInconsistentObservationFieldsWithoutCreatingTheStore() throws Exception {
        Path store = latestDirectory.resolve("not-created");
        var receiver = new TccReceiver(store);
        ObjectNode evaluated = fixture("evaluated");
        List<Consumer<ObjectNode>> contradictions = List.of(
                telemetry -> snapshot(telemetry).put("observationStatus", "FRESH"),
                telemetry -> object(object(snapshot(telemetry), "observations"), "HOST_CPU")
                        .putNull("lastSampleAt"),
                telemetry -> object(snapshot(telemetry), "observations").remove("HOST_CPU"),
                telemetry -> {
                    object(snapshot(telemetry), "observations").remove("HOST_CPU");
                    object(snapshot(telemetry), "resources").remove("DISK_IO");
                });
        for (Consumer<ObjectNode> change : contradictions) {
            ObjectNode invalid = evaluated.deepCopy();
            change.accept(invalid);
            assertAck(receiver.receive(NODE, RUN, frame(invalid), () -> true),
                    2, "REJECTED", "INVALID_TELEMETRY");
        }
        assertFalse(Files.exists(store));
    }

    @Test
    void acceptsConsistentInitializingStaleAndFreshObservations() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode warmingUp = fixture("evaluated");
        snapshot(warmingUp).put("observationStatus", "INITIALIZING");
        ObjectNode observations = object(snapshot(warmingUp), "observations");
        object(observations, "DISK_IO").put("status", "INITIALIZING").putNull("lastSampleAt");
        assertAck(receiver.receive(NODE, RUN, frame(warmingUp), () -> true), 2, "ACCEPTED", null);

        ObjectNode stale = warmingUp.deepCopy().put("sequence", 3);
        snapshot(stale).put("observationStatus", "STALE");
        ObjectNode staleObservations = object(snapshot(stale), "observations");
        object(staleObservations, "HOST_CPU").put("status", "STALE")
                .putNull("lastSampleAt").putArray("metrics");
        assertAck(receiver.receive(NODE, RUN, frame(stale), () -> true), 3, "ACCEPTED", null);

        ObjectNode fresh = fixture("evaluated").put("sequence", 4);
        snapshot(fresh).put("observationStatus", "FRESH");
        ObjectNode io = object(object(snapshot(fresh), "observations"), "DISK_IO");
        io.put("status", "FRESH").put("lastSampleAt", 1_950);
        io.putArray("metrics").addObject().put("metric", "HOST_IO_PSI_SOME_AVG10")
                .put("value", 12.5).put("unit", "%");
        assertAck(receiver.receive(NODE, RUN, frame(fresh), () -> true), 4, "ACCEPTED", null);
    }

    @Test
    void keepsLegacyStoredRecordReplayableAndCanReplaceItWithConsistentTelemetry() throws Exception {
        ObjectNode legacy = fixture("evaluated");
        snapshot(legacy).put("observationStatus", "FRESH");
        Path stored = latestFile(NODE);
        String contents = JSON.writeValueAsString(legacy);
        Files.writeString(stored, contents);

        try (var receiver = new TccReceiver(latestDirectory, ignored -> {})) {
            assertAck(receiver.receive(NODE, RUN, frame(legacy), () -> true), 2, "DUPLICATE", null);
            assertEquals(contents, Files.readString(stored));
            assertFalse(Files.exists(TccTelemetryHandoff.pendingDirectory(latestDirectory)));

            ObjectNode changed = legacy.deepCopy();
            snapshot(changed).put("host", "changed");
            assertAck(receiver.receive(NODE, RUN, frame(changed), () -> true),
                    2, "REJECTED", "INVALID_TELEMETRY");

            ObjectNode corrected = fixture("evaluated");
            assertAck(receiver.receive(NODE, RUN, frame(corrected), () -> true),
                    2, "REJECTED", "SEQUENCE_CONFLICT");
            corrected.put("sequence", 3);
            assertAck(receiver.receive(NODE, RUN, frame(corrected), () -> true),
                    3, "ACCEPTED", null);
            assertEquals(corrected, JSON.readTree(Files.readString(stored)));
        }
    }

    @Test
    void usesPersistedTelemetryForDeduplicationAndSequenceOrderingAfterRestart() throws Exception {
        ObjectNode evaluated = fixture("evaluated");
        var receiver = new TccReceiver(latestDirectory);
        assertAck(receiver.receive(NODE, RUN, frame(evaluated), () -> true), 2, "ACCEPTED", null);

        var restarted = new TccReceiver(latestDirectory);
        ObjectNode retry = evaluated.deepCopy();
        retry.put("sequence", 2L);
        assertAck(restarted.receive(NODE, RUN, frame(retry), () -> true), 2, "DUPLICATE", null);

        snapshot(retry).put("host", "changed");
        assertAck(restarted.receive(NODE, RUN, frame(retry), () -> true),
                2, "REJECTED", "SEQUENCE_CONFLICT");
        ObjectNode older = fixture("initializing");
        assertAck(restarted.receive(NODE, RUN, frame(older), () -> true),
                1, "REJECTED", "SEQUENCE_OLDER");
        assertEquals(evaluated, JSON.readTree(Files.readString(latestFile(NODE))));

        ObjectNode newRun = older.put("runId", NEXT_RUN.toString());
        assertAck(restarted.receive(NODE, NEXT_RUN, frame(newRun), () -> true), 1, "ACCEPTED", null);
        assertEquals(newRun, JSON.readTree(Files.readString(latestFile(NODE))));
    }

    @Test
    void rejectsSameRunTimelineRegressionsAndAllowsUnchangedEvaluationAndVersion() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode evaluated = fixture("evaluated");
        assertAck(receiver.receive(NODE, RUN, frame(evaluated), () -> true), 2, "ACCEPTED", null);

        ObjectNode heartbeat = evaluated.deepCopy().put("sequence", 3);
        snapshot(heartbeat).put("wallClockAt", 1_000);
        assertAck(receiver.receive(NODE, RUN, frame(heartbeat), () -> true), 3, "ACCEPTED", null);

        ObjectNode regressedTime = heartbeat.deepCopy().put("sequence", 4);
        snapshot(regressedTime).put("evaluatedAt", 1_999);
        assertAck(receiver.receive(NODE, RUN, frame(regressedTime), () -> true),
                4, "REJECTED", "TIMELINE_REGRESSION");

        ObjectNode regressedVersion = heartbeat.deepCopy().put("sequence", 5);
        snapshot(regressedVersion).put("version", 6);
        assertAck(receiver.receive(NODE, RUN, frame(regressedVersion), () -> true),
                5, "REJECTED", "TIMELINE_REGRESSION");
        assertEquals(heartbeat, JSON.readTree(Files.readString(latestFile(NODE))));
    }

    @Test
    void rejectsMalformedTelemetryAndIdentitiesWithoutWriting() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode evaluated = fixture("evaluated");
        List<Consumer<ObjectNode>> mutations = List.of(
                telemetry -> telemetry.put("schemaVersion", 2),
                telemetry -> telemetry.put("nodeId", "different-node"),
                telemetry -> telemetry.put("runId", NEXT_RUN.toString()),
                telemetry -> snapshot(telemetry).remove("host"),
                telemetry -> snapshot(telemetry).put("evaluatedAt", -1),
                telemetry -> snapshot(telemetry).put("wallClockAt", "yesterday"),
                telemetry -> snapshot(telemetry).put("state", "NOT_A_CORE_STATE"),
                telemetry -> snapshot(telemetry).putArray("observations"),
                telemetry -> object(snapshot(telemetry), "resources").putObject("UNKNOWN"),
                telemetry -> object(object(snapshot(telemetry), "observations"), "DISK_IO")
                        .put("lastSampleAt", 2_001),
                telemetry -> object(snapshot(telemetry), "attributionCoverage").put("complete", true),
                telemetry -> object(object(snapshot(telemetry), "resources"), "HOST_CPU")
                        .put("attributionConfidence", "MEDIUM"));
        for (Consumer<ObjectNode> change : mutations) {
            ObjectNode rejected = evaluated.deepCopy();
            change.accept(rejected);
            assertAck(receiver.receive(NODE, RUN, frame(rejected), () -> true),
                    2, "REJECTED", "INVALID_TELEMETRY");
        }

        ObjectNode wrongType = frame(evaluated).put("type", "PONG");
        assertAck(receiver.receive(NODE, RUN, wrongType, () -> true),
                2, "REJECTED", "INVALID_FRAME");
        ObjectNode wrongProtocol = frame(evaluated).put("protocolVersion", 2);
        assertAck(receiver.receive(NODE, RUN, wrongProtocol, () -> true),
                2, "REJECTED", "INVALID_FRAME");
        assertThrows(IOException.class,
                () -> receiver.receive(NODE, RUN, frame(evaluated.put("sequence", 0)), () -> true));
        assertFalse(Files.exists(latestFile(NODE)));
    }

    @Test
    void usesOnlyHashedFileNamesForNodeIdentity() throws Exception {
        String node = "../outside/서버-01";
        ObjectNode telemetry = fixture("initializing").put("nodeId", node);
        var receiver = new TccReceiver(latestDirectory);

        assertAck(receiver.receive(node, RUN, frame(telemetry), () -> true), 1, "ACCEPTED", null);
        try (var files = Files.list(latestDirectory)) {
            assertEquals(List.of(latestFile(node)), files.toList());
        }
    }

    @Test
    void retriesStorageFailureAndRemovesTheTemporaryFile() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode telemetry = fixture("initializing");
        Path latest = latestFile(NODE);
        var checks = new AtomicInteger();

        ObjectNode retryable = receiver.receive(NODE, RUN, frame(telemetry), () -> {
            if (checks.incrementAndGet() == 2) {
                try {
                    Files.createDirectory(latest);
                } catch (IOException failure) {
                    throw new UncheckedIOException(failure);
                }
            }
            return true;
        });

        assertAck(retryable, 1, "RETRYABLE", "PERSISTENCE_UNAVAILABLE");
        try (var files = Files.list(latestDirectory)) {
            assertEquals(List.of(latest), files.toList());
        }
        Files.delete(latest);
        assertAck(receiver.receive(NODE, RUN, frame(telemetry), () -> true), 1, "ACCEPTED", null);
    }

    @Test
    void keepsNewRunWhenAnOldSessionIsInactiveOrExpiresBeforeReplacement() throws Exception {
        var receiver = new TccReceiver(latestDirectory);
        ObjectNode newRun = fixture("initializing").put("runId", NEXT_RUN.toString());
        assertAck(receiver.receive(NODE, NEXT_RUN, frame(newRun), () -> true), 1, "ACCEPTED", null);

        ObjectNode oldRun = fixture("evaluated");
        assertAck(receiver.receive(NODE, RUN, frame(oldRun), () -> false),
                2, "REJECTED", "SESSION_INACTIVE");
        var checks = new AtomicInteger();
        assertAck(receiver.receive(NODE, RUN, frame(oldRun), () -> checks.incrementAndGet() == 1),
                2, "REJECTED", "SESSION_INACTIVE");

        Path latest = latestFile(NODE);
        assertEquals(newRun, JSON.readTree(Files.readString(latest)));
        try (var files = Files.list(latestDirectory)) {
            assertEquals(List.of(latest), files.toList());
        }
    }

    @Test
    void handsOffEveryAcceptedSnapshotAfterRestartIncludingTheExistingLatest() throws Exception {
        ObjectNode first = fixture("initializing");
        ObjectNode second = fixture("evaluated");
        ObjectNode third = second.deepCopy().put("sequence", 3);

        var legacy = new TccReceiver(latestDirectory);
        assertAck(legacy.receive(NODE, RUN, frame(first), () -> true), 1, "ACCEPTED", null);

        try (var receiver = new TccReceiver(latestDirectory, ignored -> {})) {
            assertAck(receiver.receive(NODE, RUN, frame(second), () -> true), 2, "ACCEPTED", null);
            assertAck(receiver.receive(NODE, RUN, frame(third), () -> true), 3, "ACCEPTED", null);
            assertAck(receiver.receive(NODE, RUN, frame(third), () -> true), 3, "DUPLICATE", null);
            ObjectNode conflict = third.deepCopy();
            snapshot(conflict).put("host", "changed");
            assertAck(receiver.receive(NODE, RUN, frame(conflict), () -> true),
                    3, "REJECTED", "SEQUENCE_CONFLICT");
        }

        Set<ObjectNode> received = ConcurrentHashMap.newKeySet();
        var receivedAll = new CountDownLatch(3);
        try (var restarted = new TccReceiver(latestDirectory, json -> {
            if (received.add((ObjectNode) JSON.readTree(json))) {
                receivedAll.countDown();
            }
        })) {
            restarted.startHandoff();
            assertTrue(receivedAll.await(5, TimeUnit.SECONDS));
            assertEquals(Set.of(first, second, third), received);
        }
    }

    @Test
    void keepsPreviousLatestIfTheLocalHandoffQueueCannotBeWritten() throws Exception {
        ObjectNode first = fixture("initializing");
        ObjectNode second = fixture("evaluated");
        try (var receiver = new TccReceiver(latestDirectory, ignored -> {})) {
            assertAck(receiver.receive(NODE, RUN, frame(first), () -> true), 1, "ACCEPTED", null);
            Path pending = latestDirectory.resolve(".amc-pending");
            Files.createFile(pending);

            assertAck(receiver.receive(NODE, RUN, frame(second), () -> true),
                    2, "RETRYABLE", "PERSISTENCE_UNAVAILABLE");
            assertEquals(first, JSON.readTree(Files.readString(latestFile(NODE))));

            Files.delete(pending);
            assertAck(receiver.receive(NODE, RUN, frame(second), () -> true), 2, "ACCEPTED", null);
            try (var files = Files.list(pending)) {
                List<Path> queued = files.toList();
                assertEquals(1, queued.size());
                assertEquals(first, JSON.readTree(Files.readString(queued.getFirst())));
            }
        }
    }

    @Test
    void continuesAcceptingWhileTheArchiveIsUnavailableAndRetriesTheSameSnapshot() throws Exception {
        ObjectNode first = fixture("initializing");
        ObjectNode second = fixture("evaluated");
        var firstAttempt = new CountDownLatch(1);
        var recovered = new CountDownLatch(1);
        var receivedAll = new CountDownLatch(2);
        Set<ObjectNode> received = ConcurrentHashMap.newKeySet();

        try (var receiver = new TccReceiver(latestDirectory, json -> {
            if (recovered.getCount() != 0) {
                firstAttempt.countDown();
                throw new IOException("Archive temporarily unavailable");
            }
            if (received.add((ObjectNode) JSON.readTree(json))) {
                receivedAll.countDown();
            }
        })) {
            assertAck(receiver.receive(NODE, RUN, frame(first), () -> true), 1, "ACCEPTED", null);
            receiver.startHandoff();
            assertTrue(firstAttempt.await(5, TimeUnit.SECONDS));
            assertAck(receiver.receive(NODE, RUN, frame(second), () -> true), 2, "ACCEPTED", null);

            recovered.countDown();
            assertTrue(receivedAll.await(5, TimeUnit.SECONDS));
            assertEquals(Set.of(first, second), received);
        }
    }

    private static void assertAck(ObjectNode ack, long sequence, String status, String reason) {
        assertEquals("TCC_ACK", ack.path("type").textValue());
        assertEquals(1, ack.path("protocolVersion").intValue());
        assertEquals(sequence, ack.path("sequence").longValue());
        assertEquals(status, ack.path("status").textValue());
        assertEquals(reason, ack.path("reasonCode").textValue());
    }

    private static ObjectNode fixture(String name) throws IOException {
        var fixture = TccReceiverTest.class.getResourceAsStream("/tcc/v1/" + name + ".json");
        try (var input = Objects.requireNonNull(fixture, name)) {
            return (ObjectNode) JSON.readTree(input);
        }
    }

    private static ObjectNode frame(ObjectNode telemetry) {
        return JSON.createObjectNode().put("protocolVersion", 1).put("type", "TCC_SNAPSHOT")
                .set("telemetry", telemetry);
    }

    private static ObjectNode snapshot(ObjectNode telemetry) {
        return object(telemetry, "snapshot");
    }

    private static ObjectNode object(ObjectNode owner, String key) {
        return (ObjectNode) owner.path(key);
    }

    private Path latestFile(String node) throws Exception {
        byte[] bytes = MessageDigest.getInstance("SHA-256")
                .digest(node.getBytes(StandardCharsets.UTF_8));
        return latestDirectory.resolve(HexFormat.of().formatHex(bytes) + ".json");
    }
}
