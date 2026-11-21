package io.bullseye.uog.ccc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Delivers durable CCC audit lines in order with at-least-once delivery. */
public final class CccAuditHandoff implements AutoCloseable {
    private static final long DEFAULT_POLL_MILLIS = Duration.ofSeconds(1).toMillis();
    private static final System.Logger LOGGER = System.getLogger(CccAuditHandoff.class.getName());

    @FunctionalInterface
    public interface Sink {
        /** Returns after storing the event. The same event ID can be delivered again. */
        void store(String eventJson) throws IOException;
    }

    public record Progress(long pendingBytes, Instant lastSuccessAt) {}

    private record CommittedCheckpoint(long offset, Instant lastSuccessAt) {}

    private final CccAuditLog audit;
    private final Path checkpoint;
    private final Sink sink;
    private final long pollMillis;
    private final Object lifecycle = new Object();
    private final Thread worker = Thread.ofPlatform().daemon().name("bullseye-ccc-audit-handoff")
            .unstarted(this::run);
    private volatile boolean closed;
    private volatile CommittedCheckpoint committedCheckpoint;

    CccAuditHandoff(CccAuditLog audit, Path checkpoint, Sink sink) {
        this(audit, checkpoint, sink, DEFAULT_POLL_MILLIS);
    }

    CccAuditHandoff(CccAuditLog audit, Path checkpoint, Sink sink, long pollMillis) {
        this.audit = Objects.requireNonNull(audit, "audit");
        this.checkpoint = Objects.requireNonNull(checkpoint, "checkpoint").toAbsolutePath().normalize();
        this.sink = Objects.requireNonNull(sink, "sink");
        if (this.checkpoint.getParent() == null || this.checkpoint.equals(audit.path())) {
            throw new IllegalArgumentException("CCC audit checkpoint must name a separate file");
        }
        if (pollMillis <= 0) {
            throw new IllegalArgumentException("CCC audit poll interval must be positive");
        }
        this.pollMillis = pollMillis;
    }

    public void start() {
        synchronized (lifecycle) {
            if (!closed && worker.getState() == Thread.State.NEW) {
                worker.start();
            }
        }
    }

    /** Stops scheduling work without waiting for a sink call already in progress. */
    @Override
    public void close() {
        synchronized (lifecycle) {
            closed = true;
            lifecycle.notifyAll();
        }
    }

    /** Returns committed source bytes beyond the handoff's durable checkpoint. */
    public Progress progress() throws IOException {
        CommittedCheckpoint checkpointState = committedCheckpoint;
        if (checkpointState == null) {
            throw new IOException("CCC audit handoff checkpoint is not initialized");
        }
        long sourceBytes = audit.committedSize();
        if (sourceBytes < checkpointState.offset()) {
            throw new IOException("CCC audit source is behind its handoff checkpoint");
        }
        return new Progress(sourceBytes - checkpointState.offset(), checkpointState.lastSuccessAt());
    }

    private void run() {
        long offset = -1;
        boolean interrupted = false;
        while (!closed) {
            try {
                if (offset < 0) {
                    prepareCheckpoint();
                    offset = loadCheckpoint();
                    committedCheckpoint = new CommittedCheckpoint(offset, null);
                }
                CccAuditLog.CommittedLine line = audit.readCommitted(offset);
                if (line != null && !closed) {
                    sink.store(line.json());
                    saveCheckpoint(line.nextOffset());
                    offset = line.nextOffset();
                    committedCheckpoint = new CommittedCheckpoint(offset, Instant.now());
                    interrupted = false;
                    continue;
                }
            } catch (IOException | RuntimeException failure) {
                if (!closed && !interrupted) {
                    LOGGER.log(System.Logger.Level.WARNING, "CCC audit handoff interrupted", failure);
                    interrupted = true;
                }
            }
            if (!awaitPoll()) {
                return;
            }
        }
    }

    private boolean awaitPoll() {
        synchronized (lifecycle) {
            if (!closed) {
                try {
                    lifecycle.wait(pollMillis);
                } catch (InterruptedException stopping) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return !closed;
        }
    }

    private void prepareCheckpoint() throws IOException {
        Path parent = Files.createDirectories(checkpoint.getParent());
        Path source = audit.path();
        boolean sameEntry = checkpoint.getFileName().equals(source.getFileName())
                && Files.isSameFile(parent, source.getParent());
        if (sameEntry || (Files.exists(checkpoint) && Files.exists(source)
                && Files.isSameFile(checkpoint, source))) {
            throw new IOException("CCC audit checkpoint must name a separate file");
        }
    }

    private long loadCheckpoint() throws IOException {
        String value;
        try (var input = Files.newInputStream(checkpoint)) {
            byte[] contents = input.readNBytes(65);
            if (contents.length > 64) {
                return 0;
            }
            value = new String(contents, StandardCharsets.US_ASCII).strip();
        } catch (NoSuchFileException missing) {
            return 0;
        }
        if (!value.matches("[0-9]{1,19}")) {
            return 0;
        }
        try {
            long offset = Long.parseLong(value);
            return audit.isCommittedOffset(offset) ? offset : 0;
        } catch (NumberFormatException malformed) {
            return 0;
        }
    }

    private void saveCheckpoint(long offset) throws IOException {
        Path parent = checkpoint.getParent();
        Path temporary = Files.createTempFile(parent, ".ccc-audit-checkpoint-", ".tmp");
        try {
            ByteBuffer data = StandardCharsets.US_ASCII.encode(offset + "\n");
            try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                while (data.hasRemaining()) {
                    output.write(data);
                }
                output.force(true);
            }
            Files.move(temporary, checkpoint,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            forceDirectoryBestEffort(parent);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void forceDirectoryBestEffort(Path parent) {
        try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
            directory.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // A lost checkpoint after process restart is handled by replay.
        }
    }
}
