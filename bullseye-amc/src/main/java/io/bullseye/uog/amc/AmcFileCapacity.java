package io.bullseye.uog.amc;

import io.bullseye.uog.amc.AmcCapacityMonitor.Usage;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.file.FileStore;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;

public final class AmcFileCapacity {
    private AmcFileCapacity() {}

    public static Usage records(Path directory, int depth) throws IOException {
        if (depth < 1) {
            throw new IllegalArgumentException("Record depth must be positive");
        }
        checkInterrupted();
        LocatedPath located = locate(directory);
        if (!located.exact()) {
            return new Usage(0, 0);
        }
        if (!located.attributes().isDirectory()) {
            throw new NotDirectoryException(directory.toString());
        }

        Path root = located.path().toRealPath();
        var scan = new RecordScan(root, depth);
        Files.walkFileTree(root, Set.of(), depth, scan);
        return new Usage(scan.records, scan.bytes);
    }

    public static Usage sourceFile(Path file) throws IOException {
        LocatedPath located = locate(file);
        if (!located.exact()) {
            return new Usage(0, 0);
        }
        if (!located.attributes().isRegularFile()) {
            throw new IOException("Expected a regular file: " + file);
        }
        return new Usage(1, located.attributes().size());
    }

    public static FileStore fileStore(Path path) throws IOException {
        LocatedPath located = locate(path);
        if (!located.attributes().isDirectory() && !located.attributes().isRegularFile()) {
            throw new IOException("Expected a file or directory: " + located.path());
        }
        return Files.getFileStore(located.path().toRealPath());
    }

    private static LocatedPath locate(Path path) throws IOException {
        Path requested = path.toAbsolutePath().normalize();
        for (Path candidate = requested; candidate != null; candidate = candidate.getParent()) {
            BasicFileAttributes attributes;
            try {
                attributes = Files.readAttributes(
                        candidate, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            } catch (NoSuchFileException missing) {
                continue;
            }
            if (attributes.isSymbolicLink()) {
                attributes = Files.readAttributes(candidate, BasicFileAttributes.class);
            }
            boolean exact = candidate.equals(requested);
            if (!exact && !attributes.isDirectory()) {
                throw new NotDirectoryException(candidate.toString());
            }
            return new LocatedPath(candidate, attributes, exact);
        }
        throw new NoSuchFileException(requested.toString());
    }

    private static void checkInterrupted() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("AMC capacity scan interrupted");
        }
    }

    private record LocatedPath(Path path, BasicFileAttributes attributes, boolean exact) {}

    private static final class RecordScan extends SimpleFileVisitor<Path> {
        private final Path root;
        private final int depth;
        private long records;
        private long bytes;

        private RecordScan(Path root, int depth) {
            this.root = root;
            this.depth = depth;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                throws IOException {
            checkInterrupted();
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                throws IOException {
            checkInterrupted();
            if (file.equals(root)) {
                throw new NotDirectoryException(root.toString());
            }
            if (attributes.isRegularFile()
                    && file.getNameCount() - root.getNameCount() == depth
                    && file.getFileName().toString().endsWith(".json")) {
                try {
                    records = Math.incrementExact(records);
                    bytes = Math.addExact(bytes, attributes.size());
                } catch (ArithmeticException overflow) {
                    throw new IOException("AMC record usage exceeds the supported range", overflow);
                }
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException failure) throws IOException {
            return continueUnlessUnavailable(file, failure);
        }

        @Override
        public FileVisitResult postVisitDirectory(Path directory, IOException failure)
                throws IOException {
            return continueUnlessUnavailable(directory, failure);
        }

        private FileVisitResult continueUnlessUnavailable(Path path, IOException failure)
                throws IOException {
            checkInterrupted();
            if (failure != null && (path.equals(root) || !(failure instanceof NoSuchFileException))) {
                throw failure;
            }
            return FileVisitResult.CONTINUE;
        }
    }
}
