package io.bullseye.uog.ccc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Timeout(10)
class CccNodeRegistryEnrollmentTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PIN = "ab".repeat(32);
    private static final String OTHER_PIN = "cd".repeat(32);
    private static final String CSR = "ef".repeat(32);
    private static final String RESPONSE = "{\n  \"certificate\": \"exact response\"\n}\n";

    @TempDir
    Path temporaryDirectory;

    @Test
    void migratesV1ToV2AndStoresOnlyTheCodeDigest() throws Exception {
        Path file = file();
        var clock = new MutableClock();
        var registry = new CccNodeRegistry(file, Map.of(), clock);
        registry.register("legacy node", PIN);
        assertEquals(1, JSON.readTree(file.toFile()).path("schemaVersion").intValue());

        var invite = registry.issueInvite("edge-01");
        assertEquals(43, invite.code().length());
        assertEquals(32, Base64.getUrlDecoder().decode(invite.code()).length);
        assertFalse(invite.code().contains("="));
        assertEquals(clock.instant().plus(Duration.ofMinutes(15)), invite.expiresAt());
        String stored = Files.readString(file);
        assertFalse(stored.contains(invite.code()));
        var document = JSON.readTree(stored);
        assertEquals(2, document.path("schemaVersion").intValue());
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(invite.code().getBytes(StandardCharsets.US_ASCII)));
        assertEquals("edge-01", document.path("invites").path(digest).path("nodeId").textValue());

        var reopened = new CccNodeRegistry(file, Map.of(), clock);
        assertEquals(PIN, reopened.fingerprint("legacy node"));
        assertEquals(RESPONSE, reopened.redeemInvite(invite.code(), UUID.randomUUID(), CSR,
                node -> new CccNodeRegistry.Issued(OTHER_PIN, RESPONSE)));
        assertEquals(OTHER_PIN, new CccNodeRegistry(file, Map.of(), clock).fingerprint("edge-01"));
    }

    @Test
    void replacingAnUnusedInvitationInvalidatesOnlyItsPreviousCode() throws Exception {
        var registry = registry(new MutableClock());
        var first = registry.issueInvite("edge-01");
        var other = registry.issueInvite("edge-02");
        var replacement = registry.issueInvite("edge-01");
        assertNotEquals(first.code(), replacement.code());
        var calls = new AtomicInteger();
        CccNodeRegistry.Issuer issuer = node -> {
            calls.incrementAndGet();
            return new CccNodeRegistry.Issued(PIN, RESPONSE);
        };

        assertEquals("INVALID_OR_EXPIRED_CODE", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.redeemInvite(first.code(), UUID.randomUUID(), CSR, issuer)).code());
        assertEquals(0, calls.get());
        assertEquals(RESPONSE, registry.redeemInvite(replacement.code(), UUID.randomUUID(), CSR, issuer));
        assertEquals(RESPONSE, registry.redeemInvite(other.code(), UUID.randomUUID(), CSR, issuer));
        assertEquals(2, calls.get());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "edge node", "../edge", "-edge", "한글", "edge\n01"})
    void refusesInvalidEnrollmentNodeIds(String nodeId) throws Exception {
        var registry = registry(new MutableClock());
        assertEquals("INVALID_NODE_ID", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.issueInvite(nodeId)).code());
        assertFalse(Files.exists(file()));
    }

    @Test
    void enforcesNodeIdLengthAndReservesBothManualAndRegisteredIds() throws Exception {
        var registry = new CccNodeRegistry(file(), Map.of("manual", PIN));
        registry.register("registered", OTHER_PIN);
        assertEquals("NODE_ID_IN_USE", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.issueInvite("manual")).code());
        assertEquals("NODE_ID_IN_USE", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.issueInvite("registered")).code());
        assertEquals("INVALID_NODE_ID", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.issueInvite("x".repeat(129))).code());
        registry.issueInvite("x".repeat(128));
    }

    @Test
    void expiredCodeDoesNotInvokeIssuerOrRegisterANode() throws Exception {
        var clock = new MutableClock();
        var registry = registry(clock);
        var invite = registry.issueInvite("edge-01");
        clock.advance(Duration.ofMinutes(15));
        var calls = new AtomicInteger();

        assertEquals("INVALID_OR_EXPIRED_CODE", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.redeemInvite(invite.code(), UUID.randomUUID(), CSR, node -> {
                    calls.incrementAndGet();
                    return new CccNodeRegistry.Issued(PIN, RESPONSE);
                })).code());
        assertEquals(0, calls.get());
        assertNull(registry.fingerprint("edge-01"));
        registry.issueInvite("edge-02");
        assertEquals(1, JSON.readTree(file().toFile()).path("invites").size());
    }

    @Test
    void committedResponseReplaysAfterRestartUntilTwentyFourHoursFromCommit() throws Exception {
        var clock = new MutableClock();
        var registry = registry(clock);
        var invite = registry.issueInvite("edge-01");
        clock.advance(Duration.ofMinutes(10));
        UUID request = UUID.randomUUID();
        var calls = new AtomicInteger();
        CccNodeRegistry.Issuer issuer = node -> {
            assertEquals("edge-01", node);
            calls.incrementAndGet();
            return new CccNodeRegistry.Issued(PIN, RESPONSE);
        };
        assertEquals(RESPONSE, registry.redeemInvite(invite.code(), request, CSR, issuer));
        clock.advance(Duration.ofHours(23));

        var reopened = registry(clock);
        assertEquals(RESPONSE, reopened.redeemInvite(invite.code(), request, CSR, issuer));
        assertEquals(1, calls.get());
        assertEquals(PIN, reopened.fingerprint("edge-01"));
        clock.advance(Duration.ofHours(1));
        assertEquals("INVALID_OR_EXPIRED_CODE", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> reopened.redeemInvite(invite.code(), request, CSR, issuer)).code());
        assertEquals(1, calls.get());
        assertEquals(PIN, reopened.fingerprint("edge-01"));

        reopened.issueInvite("edge-02");
        assertEquals(0, JSON.readTree(file().toFile()).path("redemptions").size());
    }

    @Test
    void committedCodeRejectsChangedRequestOrCsrWithoutReissuing() throws Exception {
        var registry = registry(new MutableClock());
        var invite = registry.issueInvite("edge-01");
        UUID request = UUID.randomUUID();
        registry.redeemInvite(invite.code(), request, CSR,
                node -> new CccNodeRegistry.Issued(PIN, RESPONSE));
        byte[] committed = Files.readAllBytes(file());
        CccNodeRegistry.Issuer mustNotIssue = node -> {
            throw new AssertionError("Committed code must not issue another certificate");
        };

        assertEquals("REQUEST_CONFLICT", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.redeemInvite(invite.code(), UUID.randomUUID(), CSR, mustNotIssue)).code());
        assertEquals("REQUEST_CONFLICT", assertThrows(CccNodeRegistry.EnrollmentException.class,
                () -> registry.redeemInvite(invite.code(), request, OTHER_PIN, mustNotIssue)).code());
        assertEquals(RESPONSE, registry.redeemInvite(invite.code(), request, CSR, mustNotIssue));
        assertArrayEquals(committed, Files.readAllBytes(file()));
    }

    @Test
    void issuerFailureLeavesInvitationUnconsumedForRetry() throws Exception {
        var registry = registry(new MutableClock());
        var invite = registry.issueInvite("edge-01");
        UUID request = UUID.randomUUID();
        byte[] pending = Files.readAllBytes(file());

        assertThrows(IllegalArgumentException.class,
                () -> registry.redeemInvite(invite.code(), request, CSR, node -> {
                    throw new IllegalArgumentException("Invalid CSR");
                }));
        assertThrows(IOException.class,
                () -> registry.redeemInvite(invite.code(), request, CSR, node -> {
                    throw new IOException("Issuer unavailable");
                }));
        assertNull(registry.fingerprint("edge-01"));
        assertArrayEquals(pending, Files.readAllBytes(file()));
        assertEquals(RESPONSE, registry.redeemInvite(invite.code(), request, CSR,
                node -> new CccNodeRegistry.Issued(PIN, RESPONSE)));
    }

    @Test
    void failedAtomicSavePublishesNeitherPinNorConsumedCode() throws Exception {
        var clock = new MutableClock();
        var registry = registry(clock);
        var invite = registry.issueInvite("edge-01");
        UUID request = UUID.randomUUID();
        Path backup = temporaryDirectory.resolve("pending.json");
        Files.move(file(), backup);
        Files.createDirectory(file());
        Path blocker = file().resolve("occupied");
        Files.writeString(blocker, "keep");

        assertThrows(IOException.class,
                () -> registry.redeemInvite(invite.code(), request, CSR,
                        node -> new CccNodeRegistry.Issued(PIN, RESPONSE)));
        assertNull(registry.fingerprint("edge-01"));
        assertEquals("keep", Files.readString(blocker));
        assertEquals(0, JSON.readTree(backup.toFile()).path("redemptions").size());

        Files.delete(blocker);
        Files.delete(file());
        Files.move(backup, file());
        assertNull(registry(clock).fingerprint("edge-01"));
        assertEquals(RESPONSE, registry.redeemInvite(invite.code(), request, CSR,
                node -> new CccNodeRegistry.Issued(OTHER_PIN, RESPONSE)));
        assertEquals(OTHER_PIN, registry(clock).fingerprint("edge-01"));
    }

    @Test
    void failedInvitationReplacementLeavesThePreviousCodeUsable() throws Exception {
        var clock = new MutableClock();
        var registry = registry(clock);
        var original = registry.issueInvite("edge-01");
        Path backup = temporaryDirectory.resolve("previous-invite.json");
        Files.move(file(), backup);
        Files.createDirectory(file());
        Path blocker = file().resolve("occupied");
        Files.writeString(blocker, "keep");

        assertThrows(IOException.class, () -> registry.issueInvite("edge-01"));

        Files.delete(blocker);
        Files.delete(file());
        Files.move(backup, file());
        assertEquals(RESPONSE, registry.redeemInvite(original.code(), UUID.randomUUID(), CSR,
                node -> new CccNodeRegistry.Issued(PIN, RESPONSE)));
        assertEquals(PIN, registry(clock).fingerprint("edge-01"));
    }

    @Test
    void competingRedemptionsHaveOneWinnerAndOneCertificate() throws Exception {
        var registry = registry(new MutableClock());
        var invite = registry.issueInvite("edge-01");
        var calls = new AtomicInteger();
        Callable<String> redeem = () -> {
            try {
                return registry.redeemInvite(invite.code(), UUID.randomUUID(), CSR, node -> {
                    calls.incrementAndGet();
                    return new CccNodeRegistry.Issued(PIN, RESPONSE);
                });
            } catch (CccNodeRegistry.EnrollmentException rejected) {
                return rejected.code();
            }
        };
        try (var workers = Executors.newFixedThreadPool(2)) {
            var results = workers.invokeAll(List.of(redeem, redeem));
            var responses = List.of(results.get(0).get(), results.get(1).get());
            assertTrue(responses.contains(RESPONSE));
            assertTrue(responses.contains("REQUEST_CONFLICT"));
        }
        assertEquals(1, calls.get());
        assertEquals(PIN, registry.fingerprint("edge-01"));
    }

    @Test
    void committedPinReadsDoNotWaitForCertificateIssuance() throws Exception {
        var registry = registry(new MutableClock());
        registry.register("existing", OTHER_PIN);
        var invite = registry.issueInvite("edge-01");
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var worker = Executors.newSingleThreadExecutor()) {
            var result = worker.submit(() -> registry.redeemInvite(
                    invite.code(), UUID.randomUUID(), CSR, node -> {
                        entered.countDown();
                        try {
                            if (!release.await(3, TimeUnit.SECONDS)) {
                                throw new IOException("Timed out waiting for test release");
                            }
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IOException(interrupted);
                        }
                        return new CccNodeRegistry.Issued(PIN, RESPONSE);
                    }));
            try {
                assertTrue(entered.await(3, TimeUnit.SECONDS));
                assertEquals(OTHER_PIN, registry.fingerprint("existing"));
                assertNull(registry.fingerprint("edge-01"));
            } finally {
                release.countDown();
            }
            assertEquals(RESPONSE, result.get(3, TimeUnit.SECONDS));
        }
    }

    @Test
    void corruptedV2RecordsFailClosedWithoutModifyingDisk() throws Exception {
        var clock = new MutableClock();
        var registry = registry(clock);
        registry.issueInvite("edge-01");
        ObjectNode document = (ObjectNode) JSON.readTree(file().toFile());
        ObjectNode invite = (ObjectNode) document.path("invites").elements().next();
        invite.put("expiresAt", "not-an-instant");
        Files.writeString(file(), JSON.writeValueAsString(document));
        byte[] corrupt = Files.readAllBytes(file());
        assertThrows(IOException.class, () -> registry(clock));
        assertArrayEquals(corrupt, Files.readAllBytes(file()));
    }

    private Path file() {
        return temporaryDirectory.resolve("nodes.json");
    }

    private CccNodeRegistry registry(Clock clock) throws IOException {
        return new CccNodeRegistry(file(), Map.of(), clock);
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-11-23T00:00:00Z");

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
