package io.bullseye.uog.amc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

class AmcCapacityMonitorTest {
    @TempDir Path directory;

    @Test
    void reportsAlternateUsageProbesAndKeepsSamplingAfterASourceFails() {
        var entries = new ArrayList<LogEntry>();
        Map<String, AmcCapacityMonitor.UsageProbe> probes = Map.of(
                "databaseArchive", () -> new AmcCapacityMonitor.Usage(42, 16_384),
                "failedArchive", () -> { throw new IOException("Store unavailable"); },
                "pending", () -> new AmcCapacityMonitor.Usage(2, 600));
        try (var monitor = new AmcCapacityMonitor(probes, Map.of(), 60, 0,
                (level, message) -> entries.add(new LogEntry(level, message)))) {
            monitor.check();
        }

        assertEquals(List.of(new LogEntry(System.Logger.Level.INFO,
                "[UOG] Archive storage usage. databaseArchive.records=42 databaseArchive.bytes=16384 "
                        + "failedArchive.status=UNAVAILABLE pending.records=2 pending.bytes=600")), entries);
    }

    @Test
    void warnsOnceForTwoPathsOnTheSameVolumeAcrossSuccessiveChecks() throws IOException {
        var entries = new ArrayList<LogEntry>();
        Path existing = Files.createDirectory(directory.resolve("archive"));
        try (var monitor = new AmcCapacityMonitor(Map.of(),
                Map.of("archive", existing, "pending", directory.resolve("missing/pending")),
                60, Long.MAX_VALUE, (level, message) -> entries.add(new LogEntry(level, message)))) {
            monitor.check();
            monitor.check();
        }

        List<LogEntry> warnings = entries.stream()
                .filter(entry -> entry.level() == System.Logger.Level.WARNING).toList();
        assertEquals(1, warnings.size());
        assertTrue(warnings.getFirst().message().contains("Archive disk space low. locations=archive,pending"));
        assertEquals(2, entries.stream()
                .filter(entry -> entry.message().contains("disk[archive,pending].usableBytes=")).count());
    }

    private record LogEntry(System.Logger.Level level, String message) {}
}
