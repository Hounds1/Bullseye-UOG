package io.bullseye.uog.amc;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

/** Reports archive and handoff usage independently of their storage format. */
public final class AmcCapacityMonitor implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(AmcCapacityMonitor.class.getName());

    @FunctionalInterface
    public interface UsageProbe {
        Usage read() throws IOException;
    }

    public record Usage(long records, long bytes) {
        public Usage {
            if (records < 0 || bytes < 0) {
                throw new IllegalArgumentException("Capacity usage cannot be negative");
            }
        }
    }

    private final Map<String, UsageProbe> sources;
    private final Map<String, Path> volumePaths;
    private final long intervalSeconds;
    private final long minimumUsableBytes;
    private final BiConsumer<System.Logger.Level, String> log;
    private final Set<FileStore> lowVolumes = new HashSet<>();
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("bullseye-amc-capacity").factory());
    private boolean started;

    public AmcCapacityMonitor(Map<String, UsageProbe> sources, Map<String, Path> volumePaths,
            long intervalSeconds, long minimumUsableBytes) {
        this(sources, volumePaths, intervalSeconds, minimumUsableBytes, LOGGER::log);
    }

    AmcCapacityMonitor(Map<String, UsageProbe> sources, Map<String, Path> volumePaths,
            long intervalSeconds, long minimumUsableBytes, BiConsumer<System.Logger.Level, String> log) {
        if (intervalSeconds <= 0 || minimumUsableBytes < 0) {
            throw new IllegalArgumentException("Capacity interval must be positive and minimum bytes nonnegative");
        }
        this.sources = new TreeMap<>(Map.copyOf(sources));
        this.volumePaths = new TreeMap<>(Map.copyOf(volumePaths));
        this.intervalSeconds = intervalSeconds;
        this.minimumUsableBytes = minimumUsableBytes;
        this.log = Objects.requireNonNull(log, "log");
    }

    public synchronized void start() {
        if (!started && !executor.isShutdown()) {
            executor.scheduleWithFixedDelay(this::check, 0, intervalSeconds, TimeUnit.SECONDS);
            started = true;
        }
    }

    @Override
    public synchronized void close() {
        executor.shutdownNow();
    }

    void check() {
        var status = new StringJoiner(" ", "[UOG] Archive storage usage. ", "");
        for (var source : sources.entrySet()) {
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            String name = source.getKey();
            try {
                Usage usage = source.getValue().read();
                status.add(name + ".records=" + usage.records());
                status.add(name + ".bytes=" + usage.bytes());
            } catch (IOException | RuntimeException unavailable) {
                status.add(name + ".status=UNAVAILABLE");
            }
        }
        checkVolumes(status);
        if (!Thread.currentThread().isInterrupted()) {
            log.accept(System.Logger.Level.INFO, status.toString());
        }
    }

    private void checkVolumes(StringJoiner status) {
        Map<FileStore, List<String>> volumes = new LinkedHashMap<>();
        for (var location : volumePaths.entrySet()) {
            if (Thread.currentThread().isInterrupted()) {
                return;
            }
            String name = location.getKey();
            try {
                FileStore store = AmcFileCapacity.fileStore(location.getValue());
                volumes.computeIfAbsent(store, ignored -> new ArrayList<>()).add(name);
            } catch (IOException | SecurityException unavailable) {
                status.add("disk[" + name + "].status=UNAVAILABLE");
            }
        }
        for (var volume : volumes.entrySet()) {
            FileStore store = volume.getKey();
            String locations = String.join(",", volume.getValue());
            try {
                long usableBytes = store.getUsableSpace();
                status.add("disk[" + locations + "].usableBytes=" + usableBytes);
                checkThreshold(store, locations, usableBytes);
            } catch (IOException | SecurityException unavailable) {
                status.add("disk[" + locations + "].status=UNAVAILABLE");
            }
        }
    }

    private void checkThreshold(FileStore store, String locations, long usableBytes) {
        String details = " locations=" + locations + " usableBytes=" + usableBytes
                + " minimumUsableBytes=" + minimumUsableBytes;
        if (usableBytes < minimumUsableBytes) {
            if (lowVolumes.add(store)) {
                log.accept(System.Logger.Level.WARNING, "[UOG] Archive disk space low." + details);
            }
        } else if (lowVolumes.remove(store)) {
            log.accept(System.Logger.Level.INFO, "[UOG] Archive disk space recovered." + details);
        }
    }
}
