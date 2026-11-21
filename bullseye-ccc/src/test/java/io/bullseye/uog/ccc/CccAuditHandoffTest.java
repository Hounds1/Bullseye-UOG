package io.bullseye.uog.ccc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Timeout(15)
class CccAuditHandoffTest {
    private static final long POLL_MILLIS = 10;

    @TempDir Path directory;

    @Test
    void retriesTheSameLineAndResumesAtTheCommittedByteOffsetAfterRestart() throws Exception {
        Path source = directory.resolve("audit.jsonl");
        Path checkpoint = directory.resolve("handoff.offset");
        var audit = new CccAuditLog(source);
        append(audit, "첫 번째 노드");
        long firstOffset = Files.size(source);
        var attempted = new LinkedBlockingQueue<String>();
        var attempts = new AtomicInteger();
        var allowSuccess = new CountDownLatch(1);

        try (var handoff = new CccAuditHandoff(audit, checkpoint, json -> {
            attempted.add(json);
            if (attempts.incrementAndGet() == 1) {
                throw new IOException("Archive acknowledgement unavailable");
            }
            awaitRelease(allowSuccess);
        }, POLL_MILLIS)) {
            handoff.start();
            String firstAttempt = attempted.poll(5, TimeUnit.SECONDS);
            assertNotNull(firstAttempt);
            assertEquals(firstAttempt, attempted.poll(5, TimeUnit.SECONDS));
            assertFalse(Files.exists(checkpoint));
            allowSuccess.countDown();
            awaitCheckpoint(checkpoint, firstOffset);
        } finally {
            allowSuccess.countDown();
        }

        var reopened = new CccAuditLog(source);
        append(reopened, "두 번째 노드");
        String second = reopened.readCommitted(firstOffset).json();
        try (var restarted = new CccAuditHandoff(reopened, checkpoint, attempted::add, POLL_MILLIS)) {
            restarted.start();
            assertEquals(second, attempted.poll(5, TimeUnit.SECONDS));
            awaitCheckpoint(checkpoint, Files.size(source));
            assertNull(attempted.poll(60, TimeUnit.MILLISECONDS));
        }
    }

    @Test
    void replaysAStoredEventIfTheCheckpointCannotBeReplaced() throws Exception {
        Path source = directory.resolve("audit.jsonl");
        Path checkpoint = directory.resolve("handoff.offset");
        Path marker = checkpoint.resolve("not-a-checkpoint");
        var audit = new CccAuditLog(source);
        append(audit, "core");
        var attempts = new AtomicInteger();
        var stored = new LinkedBlockingQueue<String>();

        try (var handoff = new CccAuditHandoff(audit, checkpoint, json -> {
            stored.add(json);
            if (attempts.incrementAndGet() == 1) {
                Files.createDirectory(checkpoint);
                Files.createFile(marker);
            } else {
                Files.delete(marker);
                Files.delete(checkpoint);
            }
        }, POLL_MILLIS)) {
            handoff.start();
            String first = stored.poll(5, TimeUnit.SECONDS);
            assertNotNull(first);
            assertEquals(first, stored.poll(5, TimeUnit.SECONDS));
            awaitCheckpoint(checkpoint, Files.size(source));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"broken", "1", "9223372036854775808", "999999", "-1"})
    void replaysFromStartForAnInvalidCheckpoint(String invalidCheckpoint) throws Exception {
        Path source = directory.resolve("audit.jsonl");
        Path checkpoint = directory.resolve("handoff.offset");
        Files.writeString(checkpoint, invalidCheckpoint);
        var audit = new CccAuditLog(source);
        append(audit, "core");
        var stored = new LinkedBlockingQueue<String>();

        try (var handoff = new CccAuditHandoff(audit, checkpoint, stored::add, POLL_MILLIS)) {
            handoff.start();
            assertEquals(audit.readCommitted(0).json(), stored.poll(5, TimeUnit.SECONDS));
            awaitCheckpoint(checkpoint, Files.size(source));
        }
    }

    @Test
    void rejectsUsingTheAuditLogAsACheckpoint() throws Exception {
        Path source = directory.resolve("audit.jsonl");
        var audit = new CccAuditLog(source);
        assertThrows(IllegalArgumentException.class,
                () -> new CccAuditHandoff(audit, source, ignored -> {}, POLL_MILLIS));
    }

    @Test
    void reportsCommittedLagBeyondCheckpointAndClearsItAfterTransfer() throws Exception {
        Path source = directory.resolve("audit.jsonl");
        Path checkpoint = directory.resolve("handoff.offset");
        var audit = new CccAuditLog(source);
        append(audit, "already archived");
        long checkpointOffset = Files.size(source);
        Files.writeString(checkpoint, checkpointOffset + "\n");
        append(audit, "대기 중");
        long committedEnd = Files.size(source);
        Files.writeString(source, "uncommitted tail", StandardOpenOption.APPEND);

        var attempting = new CountDownLatch(1);
        var allowSuccess = new CountDownLatch(1);
        try (var handoff = new CccAuditHandoff(audit, checkpoint, json -> {
            attempting.countDown();
            awaitRelease(allowSuccess);
        }, POLL_MILLIS)) {
            assertThrows(IOException.class, handoff::progress);
            handoff.start();
            if (!attempting.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("CCC audit transfer did not start");
            }
            assertEquals(new CccAuditHandoff.Progress(committedEnd - checkpointOffset, null),
                    handoff.progress());

            allowSuccess.countDown();
            awaitCheckpoint(checkpoint, committedEnd);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (handoff.progress().lastSuccessAt() == null && System.nanoTime() - deadline < 0) {
                Thread.sleep(POLL_MILLIS);
            }
            var progress = handoff.progress();
            assertEquals(0, progress.pendingBytes());
            assertNotNull(progress.lastSuccessAt());
        } finally {
            allowSuccess.countDown();
        }
    }

    private static void append(CccAuditLog audit, String nodeId) throws IOException {
        audit.append("JOIN_REQUESTED", nodeId, null, null, null, null, null);
    }

    private static void awaitCheckpoint(Path file, long offset) throws Exception {
        String expected = offset + "\n";
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() - deadline < 0) {
            if (Files.isRegularFile(file) && expected.equals(Files.readString(file))) {
                return;
            }
            Thread.sleep(POLL_MILLIS);
        }
        assertEquals(expected, Files.readString(file));
    }

    private static void awaitRelease(CountDownLatch latch) throws IOException {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IOException("Archive acknowledgement was not released");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Archive acknowledgement wait interrupted", failure);
        }
    }
}
