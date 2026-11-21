package io.bullseye.uog.tcc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.ConcurrentHashMap;

/** Retries archive delivery for committed latest and superseded TCC records. */
public final class TccTelemetryHandoff implements AutoCloseable {
    private static final long POLL_MILLIS = 1_000;
    private static final System.Logger LOGGER = System.getLogger(TccTelemetryHandoff.class.getName());

    @FunctionalInterface
    public interface Sink {
        /** Confirms storage. The same committed snapshot can be delivered again. */
        void store(String telemetryJson) throws IOException;
    }

    private final Path latestDirectory;
    private final Path pendingDirectory;
    private final Sink sink;
    private final ConcurrentHashMap<Path, String> delivered = new ConcurrentHashMap<>();
    private final Thread worker = Thread.ofPlatform().daemon().name("bullseye-tcc-telemetry-handoff")
            .unstarted(this::run);
    private volatile boolean closed;

    TccTelemetryHandoff(Path latestDirectory, Sink sink) {
        this.latestDirectory = latestDirectory;
        this.pendingDirectory = latestDirectory.resolve(".amc-pending");
        this.sink = sink;
    }

    /**
     * Preserve an already accepted latest record before TCC replaces it.
     * Pending files are immutable and named by the content they hold.
     */
    void preserve(Path latestFile, byte[] contents) throws IOException {
        String digest = TccReceiver.sha256(contents);
        if (digest.equals(delivered.get(latestFile))) {
            return;
        }

        Path pendingFile = pendingDirectory.resolve(digest + ".json");
        Files.createDirectories(pendingDirectory);
        if (Files.isRegularFile(pendingFile)) {
            return;
        }

        Path temporary = Files.createTempFile(pendingDirectory, ".tcc-", ".tmp");
        try {
            TccReceiver.writeAndForce(temporary, contents);
            Files.move(temporary, pendingFile, StandardCopyOption.ATOMIC_MOVE);
            TccReceiver.forceDirectoryBestEffort(pendingDirectory);
            TccReceiver.forceDirectoryBestEffort(latestDirectory);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    synchronized void start() {
        if (!closed && worker.getState() == Thread.State.NEW) {
            worker.start();
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        notifyAll();
    }

    private void run() {
        boolean interrupted = false;
        while (!closed) {
            IOException pendingFailure = deliverDirectory(pendingDirectory, true);
            IOException latestFailure = deliverDirectory(latestDirectory, false);
            IOException failure = pendingFailure == null ? latestFailure : pendingFailure;
            if (failure != null && !interrupted && !closed) {
                LOGGER.log(System.Logger.Level.WARNING, "TCC telemetry handoff interrupted", failure);
            }
            interrupted = failure != null;
            waitForPoll();
        }
    }

    private synchronized void waitForPoll() {
        if (!closed) {
            try {
                wait(POLL_MILLIS);
            } catch (InterruptedException stopping) {
                closed = true;
                Thread.currentThread().interrupt();
            }
        }
    }

    private IOException deliverDirectory(Path directory, boolean pending) {
        IOException firstFailure = null;
        try (var files = Files.newDirectoryStream(directory, "*.json")) {
            for (Path file : files) {
                if (closed) {
                    break;
                }
                try {
                    deliver(file, pending);
                } catch (IOException failure) {
                    if (firstFailure == null) {
                        firstFailure = failure;
                    }
                }
            }
        } catch (NoSuchFileException missing) {
            return pending ? null : missing;
        } catch (DirectoryIteratorException failure) {
            return failure.getCause();
        } catch (IOException failure) {
            return failure;
        }
        return firstFailure;
    }

    private void deliver(Path file, boolean pending) throws IOException {
        byte[] contents = Files.readAllBytes(file);
        if (pending) {
            sink.store(new String(contents, StandardCharsets.UTF_8));
            Files.deleteIfExists(file);
            return;
        }

        String digest = TccReceiver.sha256(contents);
        if (!digest.equals(delivered.get(file))) {
            sink.store(new String(contents, StandardCharsets.UTF_8));
            delivered.put(file, digest);
        }
    }
}
