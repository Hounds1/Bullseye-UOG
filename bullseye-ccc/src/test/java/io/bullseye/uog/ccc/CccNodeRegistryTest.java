package io.bullseye.uog.ccc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

@Timeout(10)
class CccNodeRegistryTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String FIRST_PIN = "ab".repeat(32);
    private static final String SECOND_PIN = "cd".repeat(32);

    @TempDir
    Path temporaryDirectory;

    @Test
    void missingFileStartsWithNoDynamicBindings() throws Exception {
        var registry = new CccNodeRegistry(
                temporaryDirectory.resolve("new/registry.json"),
                Map.of("manual-node", FIRST_PIN));

        assertNull(registry.fingerprint("edge-01"));
        assertNull(registry.fingerprint("manual-node"));
    }

    @Test
    void persistsVersionedBindingsAndRestoresThemAfterRestart() throws Exception {
        Path file = temporaryDirectory.resolve("ccc/registry/nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());

        assertTrue(registry.register("edge-01", FIRST_PIN.toUpperCase(Locale.ROOT)));
        assertTrue(registry.register("edge-02", SECOND_PIN));
        assertEquals(FIRST_PIN, registry.fingerprint("edge-01"));

        JsonNode stored = JSON.readTree(Files.readString(file, StandardCharsets.UTF_8));
        assertEquals(1, stored.path("schemaVersion").intValue());
        assertTrue(stored.path("nodes").isObject());
        assertEquals(2, stored.path("nodes").size());
        assertEquals(FIRST_PIN, stored.path("nodes").path("edge-01").textValue());
        assertEquals(SECOND_PIN, stored.path("nodes").path("edge-02").textValue());

        var reopened = new CccNodeRegistry(file, Map.of());
        assertEquals(FIRST_PIN, reopened.fingerprint("edge-01"));
        assertEquals(SECOND_PIN, reopened.fingerprint("edge-02"));
        assertNull(reopened.fingerprint("unknown"));
    }

    @Test
    void replayIsIdempotentAndDifferentCertificateCannotReplaceAnExistingBinding()
            throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        assertTrue(registry.register("edge-01", FIRST_PIN));
        byte[] committed = Files.readAllBytes(file);

        assertFalse(registry.register("edge-01", FIRST_PIN));
        assertThrows(IllegalArgumentException.class,
                () -> registry.register("edge-01", SECOND_PIN));
        assertEquals(FIRST_PIN, registry.fingerprint("edge-01"));
        assertArrayEquals(committed, Files.readAllBytes(file));

        var reopened = new CccNodeRegistry(file, Map.of());
        assertFalse(reopened.register("edge-01", FIRST_PIN));
        assertEquals(FIRST_PIN, reopened.fingerprint("edge-01"));
    }

    @Test
    void manualNodeIdsAreReservedEvenWhenTheCertificateMatches() throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of("manual-node", FIRST_PIN));
        assertTrue(registry.register("edge-01", SECOND_PIN));
        byte[] committed = Files.readAllBytes(file);

        assertThrows(IllegalArgumentException.class,
                () -> registry.register("manual-node", FIRST_PIN));
        assertThrows(IllegalArgumentException.class,
                () -> registry.register("manual-node", SECOND_PIN));

        assertNull(registry.fingerprint("manual-node"));
        assertEquals(SECOND_PIN, registry.fingerprint("edge-01"));
        assertArrayEquals(committed, Files.readAllBytes(file));
    }

    @Test
    void failedPersistenceDoesNotPublishTheNewBindingAndCanBeRetried() throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        Path backup = temporaryDirectory.resolve("committed-nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        assertTrue(registry.register("edge-01", FIRST_PIN));
        byte[] committed = Files.readAllBytes(file);

        Files.move(file, backup);
        Files.createDirectory(file);
        Path blocker = file.resolve("must-not-be-replaced.txt");
        Files.writeString(blocker, "occupied", StandardCharsets.UTF_8);

        assertThrows(IOException.class, () -> registry.register("edge-02", SECOND_PIN));
        assertEquals(FIRST_PIN, registry.fingerprint("edge-01"));
        assertNull(registry.fingerprint("edge-02"));
        assertArrayEquals(committed, Files.readAllBytes(backup));
        assertEquals("occupied", Files.readString(blocker));

        Files.delete(blocker);
        Files.delete(file);
        Files.move(backup, file);

        var reopened = new CccNodeRegistry(file, Map.of());
        assertEquals(FIRST_PIN, reopened.fingerprint("edge-01"));
        assertNull(reopened.fingerprint("edge-02"));
        assertTrue(registry.register("edge-02", SECOND_PIN));
        assertEquals(SECOND_PIN, new CccNodeRegistry(file, Map.of()).fingerprint("edge-02"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    void rejectsMissingNodeIdsWithoutChangingCommittedState(String nodeId) throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        assertTrue(registry.register("edge-01", FIRST_PIN));
        byte[] committed = Files.readAllBytes(file);

        assertThrows(IllegalArgumentException.class, () -> registry.register(nodeId, SECOND_PIN));

        assertEquals(FIRST_PIN, registry.fingerprint("edge-01"));
        assertArrayEquals(committed, Files.readAllBytes(file));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "abc", "not-a-sha256-fingerprint"})
    void rejectsInvalidFingerprintsWithoutPublishingABinding(String fingerprint) throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        assertTrue(registry.register("edge-01", FIRST_PIN));
        byte[] committed = Files.readAllBytes(file);

        assertThrows(IllegalArgumentException.class,
                () -> registry.register("edge-02", fingerprint));

        assertNull(registry.fingerprint("edge-02"));
        assertArrayEquals(committed, Files.readAllBytes(file));
    }

    @Test
    void rejectsNonHexFingerprintOfTheCorrectLength() throws Exception {
        var registry = new CccNodeRegistry(temporaryDirectory.resolve("nodes.json"), Map.of());

        assertThrows(IllegalArgumentException.class,
                () -> registry.register("edge-01", "z".repeat(64)));
        assertNull(registry.fingerprint("edge-01"));
    }

    @ParameterizedTest(name = "rejects invalid stored registry: {0}")
    @MethodSource("invalidStores")
    void failsClosedOnMalformedOrInvalidStoredData(String description, String contents)
            throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        Files.writeString(file, contents, StandardCharsets.UTF_8);
        byte[] original = Files.readAllBytes(file);

        assertThrows(IOException.class, () -> new CccNodeRegistry(file, Map.of()));

        assertArrayEquals(original, Files.readAllBytes(file));
    }

    @Test
    void rejectsPersistedNodeIdsThatCollideWithManualPinsEvenWhenCertificatesMatch()
            throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        registry.register("edge-01", FIRST_PIN);
        byte[] original = Files.readAllBytes(file);

        assertThrows(IOException.class,
                () -> new CccNodeRegistry(file, Map.of("edge-01", FIRST_PIN)));
        assertThrows(IOException.class,
                () -> new CccNodeRegistry(file, Map.of("edge-01", SECOND_PIN)));

        assertArrayEquals(original, Files.readAllBytes(file));
    }

    @Test
    void concurrentRegistrationsRetainEveryDistinctBindingOnDisk() throws Exception {
        Path file = temporaryDirectory.resolve("nodes.json");
        var registry = new CccNodeRegistry(file, Map.of());
        List<Callable<Boolean>> registrations = new ArrayList<>();
        for (int index = 0; index < 16; index++) {
            String nodeId = "edge-" + index;
            String fingerprint = String.format(Locale.ROOT, "%064x", index + 1);
            registrations.add(() -> registry.register(nodeId, fingerprint));
        }

        try (var writers = Executors.newFixedThreadPool(4)) {
            for (var result : writers.invokeAll(registrations)) {
                assertTrue(result.get());
            }
        }

        var reopened = new CccNodeRegistry(file, Map.of());
        for (int index = 0; index < registrations.size(); index++) {
            String nodeId = "edge-" + index;
            String fingerprint = String.format(Locale.ROOT, "%064x", index + 1);
            assertEquals(fingerprint, registry.fingerprint(nodeId));
            assertEquals(fingerprint, reopened.fingerprint(nodeId));
        }
        assertEquals(registrations.size(), JSON.readTree(file.toFile()).path("nodes").size());
    }

    private static Stream<Arguments> invalidStores() {
        return Stream.of(
                Arguments.of("empty file", ""),
                Arguments.of("truncated JSON", "{\"schemaVersion\":1,\"nodes\":"),
                Arguments.of("null root", "null"),
                Arguments.of("array root", "[]"),
                Arguments.of("missing schema version", "{\"nodes\":{}}"),
                Arguments.of("unsupported schema version", "{\"schemaVersion\":3,\"nodes\":{}}"),
                Arguments.of("non-numeric schema version", "{\"schemaVersion\":\"1\",\"nodes\":{}}"),
                Arguments.of("missing nodes", "{\"schemaVersion\":1}"),
                Arguments.of("null nodes", "{\"schemaVersion\":1,\"nodes\":null}"),
                Arguments.of("array nodes", "{\"schemaVersion\":1,\"nodes\":[]}"),
                Arguments.of("blank node ID", storedNode(" ", FIRST_PIN)),
                Arguments.of("invalid fingerprint", storedNode("edge-01", "bad")),
                Arguments.of("non-hex fingerprint", storedNode("edge-01", "z".repeat(64))),
                Arguments.of("null fingerprint",
                        "{\"schemaVersion\":1,\"nodes\":{\"edge-01\":null}}"),
                Arguments.of("non-string fingerprint",
                        "{\"schemaVersion\":1,\"nodes\":{\"edge-01\":123}}"),
                Arguments.of("trailing invalid content",
                        "{\"schemaVersion\":1,\"nodes\":{}} garbage"));
    }

    private static String storedNode(String nodeId, String fingerprint) {
        return "{\"schemaVersion\":1,\"nodes\":{\"" + nodeId + "\":\"" + fingerprint + "\"}}";
    }
}
