package io.bullseye.uog.amc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.bullseye.uog.amc.AmcCapacityMonitor.Usage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

class AmcFileCapacityTest {
    @TempDir Path temporaryDirectory;

    @Test
    void countsLogicalBytesOfRegularJsonFilesOnlyAtRequestedDepth() throws IOException {
        Path archive = temporaryDirectory.resolve("archive");
        Path audit = write(archive.resolve("event.json"), "감사");
        write(archive.resolve("empty.json"), "");
        write(archive.resolve("incomplete.tmp"), "ignored");
        Files.createDirectory(archive.resolve("directory.json"));
        write(archive.resolve("node/misplaced.json"), "too shallow");
        Path snapshot = write(archive.resolve("node/run/1.json"), "텔레메트리");
        write(archive.resolve("node/run/2.json.tmp"), "not installed");
        write(archive.resolve("node/run/staging/deeper.json"), "too deep");

        assertEquals(new Usage(2, Files.size(audit)), AmcFileCapacity.records(archive, 1));
        assertEquals(new Usage(1, Files.size(snapshot)), AmcFileCapacity.records(archive, 3));
        assertEquals(new Usage(1, Files.size(audit)), AmcFileCapacity.sourceFile(audit));
    }

    @Test
    void distinguishesMissingPathsFromWrongTypes() throws IOException {
        Path absent = temporaryDirectory.resolve("no-data/yet");
        assertEquals(new Usage(0, 0), AmcFileCapacity.records(absent, 1));
        assertEquals(new Usage(0, 0), AmcFileCapacity.sourceFile(absent));
        assertFalse(Files.exists(absent.getParent()));
        assertThrows(IOException.class, () -> AmcFileCapacity.sourceFile(temporaryDirectory));

        Path file = write(temporaryDirectory.resolve("not-a-directory"), "exists");
        assertThrows(IOException.class, () -> AmcFileCapacity.records(file, 1));
        assertThrows(IOException.class, () -> AmcFileCapacity.records(file.resolve("absent"), 1));
        assertThrows(IOException.class, () -> AmcFileCapacity.sourceFile(file.resolve("absent")));
        assertThrows(IOException.class, () -> AmcFileCapacity.fileStore(file.resolve("absent")));
    }

    @Test
    void findsFileStoreForExistingFileAndMissingDescendantWithoutCreatingPaths() throws IOException {
        Path file = write(temporaryDirectory.resolve("existing.json"), "{}");
        Path absent = temporaryDirectory.resolve("not-created/subdir/events.json");
        var expected = Files.getFileStore(temporaryDirectory.toRealPath());

        assertEquals(expected, AmcFileCapacity.fileStore(file));
        assertEquals(expected, AmcFileCapacity.fileStore(absent));
        assertFalse(Files.exists(temporaryDirectory.resolve("not-created")));
    }

    @Test
    void followsExplicitRootAndSourceLinksWithoutFollowingLinksInsideArchive() throws IOException {
        Path actual = temporaryDirectory.resolve("actual");
        Path local = write(actual.resolve("event.json"), "{}");
        Path outside = write(temporaryDirectory.resolve("outside/run/2.json"), "{\"outside\":true}");
        Path rootLink = temporaryDirectory.resolve("archive-link");
        Path fileLink = actual.resolve("external.json");
        try {
            Files.createSymbolicLink(rootLink, actual);
            Files.createSymbolicLink(fileLink, outside);
            Files.createSymbolicLink(actual.resolve("outside-node"), outside.getParent().getParent());
        } catch (IOException | UnsupportedOperationException unavailable) {
            assumeTrue(false, "Symbolic links are unavailable: " + unavailable.getMessage());
        }

        assertEquals(new Usage(1, Files.size(local)), AmcFileCapacity.records(rootLink, 1));
        assertEquals(new Usage(0, 0), AmcFileCapacity.records(rootLink, 3));
        assertEquals(new Usage(1, Files.size(outside)), AmcFileCapacity.sourceFile(fileLink));
        assertEquals(Files.getFileStore(actual), AmcFileCapacity.fileStore(rootLink));

        Path dangling = temporaryDirectory.resolve("dangling");
        Files.createSymbolicLink(dangling, temporaryDirectory.resolve("missing-target"));
        assertThrows(IOException.class, () -> AmcFileCapacity.records(dangling, 1));
        assertThrows(IOException.class, () -> AmcFileCapacity.fileStore(dangling.resolve("absent")));
    }

    @Test
    void keepsInterruptStatusWhenCancellingRecordScan() {
        Thread.currentThread().interrupt();
        try {
            assertThrows(InterruptedIOException.class,
                    () -> AmcFileCapacity.records(temporaryDirectory, 3));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    private static Path write(Path file, String contents) throws IOException {
        Files.createDirectories(file.getParent());
        return Files.writeString(file, contents);
    }
}
