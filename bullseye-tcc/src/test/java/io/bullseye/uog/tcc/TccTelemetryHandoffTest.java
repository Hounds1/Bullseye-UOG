package io.bullseye.uog.tcc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

@Timeout(10)
class TccTelemetryHandoffTest {
    @TempDir Path directory;

    @Test
    void reportsLatestOnlyBacklogAndMatchesConfirmedDigestAfterRecovery() throws Exception {
        Path latestDirectory = directory.resolve("latest");
        var available = new AtomicBoolean();
        var attempted = new CountDownLatch(1);
        try (var handoff = new TccTelemetryHandoff(latestDirectory, json -> {
            attempted.countDown();
            if (!available.get()) {
                throw new IOException("Archive unavailable");
            }
        })) {
            assertEquals(new TccTelemetryHandoff.Progress(0, null), handoff.progress());
            Files.createDirectories(latestDirectory);
            Path latest = latestDirectory.resolve("core.json");
            Files.writeString(latest, "{\"snapshot\":1}");
            handoff.start();
            assertTrue(attempted.await(4, TimeUnit.SECONDS));
            assertFalse(Files.exists(TccTelemetryHandoff.pendingDirectory(latestDirectory)));
            assertEquals(new TccTelemetryHandoff.Progress(1, null), handoff.progress());

            available.set(true);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
            while (handoff.progress().pendingLatest() != 0 && System.nanoTime() - deadline < 0) {
                Thread.sleep(10);
            }
            var recovered = handoff.progress();
            assertEquals(0, recovered.pendingLatest());
            assertNotNull(recovered.lastSuccessAt());

            available.set(false);
            Files.writeString(latest, "{\"snapshot\":1}");
            assertEquals(recovered, handoff.progress());
            Files.writeString(latest, "{\"snapshot\":2}");
            assertEquals(new TccTelemetryHandoff.Progress(1, recovered.lastSuccessAt()),
                    handoff.progress());
        }
    }

    @Test
    void reportsAnUnreadableLatestLocationAsAProbeFailure() throws IOException {
        Path notDirectory = Files.createFile(directory.resolve("blocked"));
        try (var handoff = new TccTelemetryHandoff(notDirectory, ignored -> {})) {
            assertThrows(IOException.class, handoff::progress);
        }
    }

    @Test
    void reportsMissingLatestLocationOnlyAfterItWasOpened() throws IOException {
        Path latestDirectory = Files.createDirectory(directory.resolve("latest"));
        try (var handoff = new TccTelemetryHandoff(latestDirectory, ignored -> {})) {
            assertEquals(0, handoff.progress().pendingLatest());
            Files.delete(latestDirectory);
            assertThrows(IOException.class, handoff::progress);
        }
    }
}
