package io.bullseye.uog.ccc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Pattern;

/** Durable node bindings for one UOG process. Manual node IDs are reserved. */
public final class CccNodeRegistry {
    private static final Duration INVITE_TTL = Duration.ofMinutes(15);
    private static final Duration REPLAY_TTL = Duration.ofHours(24);
    private static final Pattern NODE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern INVITE_CODE = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Pattern CERTIFICATE_SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final Path file;
    private final Set<String> manualNodeIds;
    private final Clock clock;
    private volatile State state;

    public record Invite(String code, Instant expiresAt) {}

    public record Issued(String fingerprint, String responseJson) {}

    @FunctionalInterface
    public interface Issuer {
        Issued issue(String nodeId) throws IOException;
    }

    public static final class EnrollmentException extends Exception {
        private final String code;

        private EnrollmentException(String code) {
            super(code);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private record PendingInvite(String nodeId, Instant expiresAt) {}

    private record Redemption(
            String nodeId, UUID requestId, String csrSha256, String fingerprint,
            String responseJson, Instant replayUntil) {}

    private record State(
            int version, Map<String, String> nodes, Map<String, PendingInvite> invites,
            Map<String, Redemption> redemptions) {
        private State {
            nodes = Map.copyOf(nodes);
            invites = Map.copyOf(invites);
            redemptions = Map.copyOf(redemptions);
        }
    }

    public CccNodeRegistry(Path file, Map<String, String> manualPins) throws IOException {
        this(file, manualPins, Clock.systemUTC());
    }

    CccNodeRegistry(Path file, Map<String, String> manualPins, Clock clock) throws IOException {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        this.clock = Objects.requireNonNull(clock, "clock");
        if (this.file.getParent() == null) {
            throw new IllegalArgumentException("CCC registration path must name a file");
        }
        manualPins.forEach(CccNodeRegistry::validateBinding);
        manualNodeIds = Set.copyOf(manualPins.keySet());
        state = load();
    }

    /** Returns the committed registration pin, or null for a node outside this store. */
    public String fingerprint(String nodeId) {
        return state.nodes().get(Objects.requireNonNull(nodeId, "nodeId"));
    }

    /** Publishes a new binding after saving it. A replay of the same binding returns false. */
    public synchronized boolean register(String nodeId, String certificateSha256) throws IOException {
        validateBinding(nodeId, certificateSha256);
        if (manualNodeIds.contains(nodeId)) {
            throw new IllegalArgumentException("CCC node ID is reserved by a manual pin");
        }

        String fingerprint = certificateSha256.toLowerCase(Locale.ROOT);
        String existing = state.nodes().get(nodeId);
        if (existing != null) {
            if (existing.equals(fingerprint)) {
                return false;
            }
            throw new IllegalArgumentException("CCC node ID already has a different registration pin");
        }

        var updated = new TreeMap<>(state.nodes());
        updated.put(nodeId, fingerprint);
        var invites = activeInvites(clock.instant());
        invites.values().removeIf(invite -> invite.nodeId().equals(nodeId));
        commit(new State(state.version(), updated, invites, activeRedemptions(clock.instant())));
        return true;
    }

    /** Issues a one-use code. Reissuing replaces this node's previous unused code. */
    public synchronized Invite issueInvite(String nodeId) throws IOException, EnrollmentException {
        if (nodeId == null || !NODE_ID.matcher(nodeId).matches()) {
            throw new EnrollmentException("INVALID_NODE_ID");
        }
        if (manualNodeIds.contains(nodeId) || state.nodes().containsKey(nodeId)) {
            throw new EnrollmentException("NODE_ID_IN_USE");
        }

        Instant now = clock.instant();
        var invites = activeInvites(now);
        var redemptions = activeRedemptions(now);
        invites.values().removeIf(invite -> invite.nodeId().equals(nodeId));
        String code;
        String digest;
        do {
            byte[] random = new byte[32];
            RANDOM.nextBytes(random);
            code = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            digest = digest(code);
        } while (invites.containsKey(digest) || redemptions.containsKey(digest));
        Instant expiresAt = now.plus(INVITE_TTL);
        invites.put(digest, new PendingInvite(nodeId, expiresAt));
        commit(new State(2, state.nodes(), invites, redemptions));
        return new Invite(code, expiresAt);
    }

    /** Commits the consumed code, new pin and exact response in the same atomic replacement. */
    public synchronized String redeemInvite(
            String code, UUID requestId, String csrSha256, Issuer issuer)
            throws IOException, EnrollmentException {
        if (code == null || !INVITE_CODE.matcher(code).matches()) {
            throw new EnrollmentException("INVALID_OR_EXPIRED_CODE");
        }
        String codeDigest = digest(code);
        Instant now = clock.instant();
        Redemption previous = state.redemptions().get(codeDigest);
        if (previous != null && previous.replayUntil().isAfter(now)) {
            if (!previous.requestId().equals(requestId)
                    || csrSha256 == null || !previous.csrSha256().equalsIgnoreCase(csrSha256)) {
                throw new EnrollmentException("REQUEST_CONFLICT");
            }
            return previous.responseJson();
        }

        PendingInvite invite = state.invites().get(codeDigest);
        if (invite == null || !invite.expiresAt().isAfter(now)) {
            throw new EnrollmentException("INVALID_OR_EXPIRED_CODE");
        }
        if (requestId == null || csrSha256 == null
                || !CERTIFICATE_SHA256.matcher(csrSha256).matches()) {
            throw new EnrollmentException("REQUEST_CONFLICT");
        }
        if (manualNodeIds.contains(invite.nodeId()) || state.nodes().containsKey(invite.nodeId())) {
            throw new EnrollmentException("NODE_ID_IN_USE");
        }

        Issued issued = Objects.requireNonNull(issuer, "issuer").issue(invite.nodeId());
        if (issued == null || issued.responseJson() == null || issued.responseJson().isBlank()) {
            throw new IOException("Certificate issuer returned no enrollment response");
        }
        validateBinding(invite.nodeId(), issued.fingerprint());
        String fingerprint = issued.fingerprint().toLowerCase(Locale.ROOT);
        Instant committedAt = clock.instant();
        var nodes = new TreeMap<>(state.nodes());
        nodes.put(invite.nodeId(), fingerprint);
        var invites = activeInvites(committedAt);
        invites.remove(codeDigest);
        var redemptions = activeRedemptions(committedAt);
        redemptions.put(codeDigest, new Redemption(
                invite.nodeId(), requestId, csrSha256.toLowerCase(Locale.ROOT), fingerprint,
                issued.responseJson(), committedAt.plus(REPLAY_TTL)));
        commit(new State(2, nodes, invites, redemptions));
        return issued.responseJson();
    }

    private TreeMap<String, PendingInvite> activeInvites(Instant now) {
        // Keep expired records out of each new snapshot; no background writer is required.
        var active = new TreeMap<>(state.invites());
        active.values().removeIf(invite -> !invite.expiresAt().isAfter(now));
        return active;
    }

    private TreeMap<String, Redemption> activeRedemptions(Instant now) {
        var active = new TreeMap<>(state.redemptions());
        active.values().removeIf(redemption -> !redemption.replayUntil().isAfter(now));
        return active;
    }

    private void commit(State updated) throws IOException {
        save(updated);
        state = updated;
    }

    private static String digest(String code) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(code.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    boolean reserves(Set<String> manualNodes) {
        return manualNodeIds.equals(manualNodes);
    }

    static void validateBinding(String nodeId, String fingerprint) {
        if (nodeId == null || nodeId.isBlank()
                || fingerprint == null || !CERTIFICATE_SHA256.matcher(fingerprint).matches()) {
            throw new IllegalArgumentException("Invalid CCC node or certificate fingerprint");
        }
    }

    private State load() throws IOException {
        try (var input = Files.newInputStream(file)) {
            JsonNode root = JSON.readTree(input);
            if (root == null || !root.isObject() || !root.path("nodes").isObject()) {
                throw new IOException("Invalid CCC registration file schema: " + file);
            }
            JsonNode version = root.path("schemaVersion");
            if (!version.isIntegralNumber()
                    || !version.canConvertToInt()
                    || (version.intValue() != 1 && version.intValue() != 2)
                    || root.size() != (version.intValue() == 1 ? 2 : 4)) {
                throw new IOException("Invalid CCC registration file schema: " + file);
            }

            var nodes = new TreeMap<String, String>();
            for (var entry : root.path("nodes").properties()) {
                String nodeId = entry.getKey();
                String fingerprint = entry.getValue().textValue();
                try {
                    validateBinding(nodeId, fingerprint);
                } catch (IllegalArgumentException invalid) {
                    throw new IOException("Invalid CCC registration binding: " + file, invalid);
                }
                if (manualNodeIds.contains(nodeId)) {
                    throw new IOException("CCC registration file contains a manually configured node ID: " + file);
                }
                nodes.put(nodeId, fingerprint.toLowerCase(Locale.ROOT));
            }
            if (version.intValue() == 1) {
                return new State(1, nodes, Map.of(), Map.of());
            }
            return loadEnrollmentState(root, nodes);
        } catch (NoSuchFileException missing) {
            return new State(1, Map.of(), Map.of(), Map.of());
        }
    }

    private State loadEnrollmentState(JsonNode root, Map<String, String> nodes) throws IOException {
        if (!root.path("invites").isObject() || !root.path("redemptions").isObject()) {
            throw new IOException("Invalid CCC enrollment file schema: " + file);
        }
        var invites = new TreeMap<String, PendingInvite>();
        var redemptions = new TreeMap<String, Redemption>();
        var pendingNodes = new HashSet<String>();
        var redeemedNodes = new HashSet<String>();
        try {
            for (var entry : root.path("invites").properties()) {
                requireDigest(entry.getKey());
                JsonNode value = entry.getValue();
                String nodeId = text(value, "nodeId");
                if (!value.isObject() || value.size() != 2 || !NODE_ID.matcher(nodeId).matches()
                        || manualNodeIds.contains(nodeId) || nodes.containsKey(nodeId)
                        || !pendingNodes.add(nodeId)) {
                    throw new IllegalArgumentException("Invalid pending invitation");
                }
                invites.put(entry.getKey(), new PendingInvite(
                        nodeId, Instant.parse(text(value, "expiresAt"))));
            }
            for (var entry : root.path("redemptions").properties()) {
                requireDigest(entry.getKey());
                JsonNode value = entry.getValue();
                String nodeId = text(value, "nodeId");
                String fingerprint = text(value, "fingerprint");
                String csrSha256 = text(value, "csrSha256");
                requireDigest(csrSha256);
                validateBinding(nodeId, fingerprint);
                if (!value.isObject() || value.size() != 6 || !NODE_ID.matcher(nodeId).matches()
                        || !fingerprint.equals(nodes.get(nodeId))
                        || invites.containsKey(entry.getKey()) || !redeemedNodes.add(nodeId)) {
                    throw new IllegalArgumentException("Invalid committed enrollment");
                }
                String rawRequestId = text(value, "requestId");
                UUID requestId = UUID.fromString(rawRequestId);
                if (!requestId.toString().equals(rawRequestId)) {
                    throw new IllegalArgumentException("Invalid enrollment request ID");
                }
                redemptions.put(entry.getKey(), new Redemption(
                        nodeId, requestId, csrSha256, fingerprint, text(value, "responseJson"),
                        Instant.parse(text(value, "replayUntil"))));
            }
        } catch (IllegalArgumentException | DateTimeException invalid) {
            throw new IOException("Invalid CCC enrollment record: " + file, invalid);
        }
        return new State(2, nodes, invites, redemptions);
    }

    private static void requireDigest(String value) {
        if (!CERTIFICATE_SHA256.matcher(value).matches()
                || !value.equals(value.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Invalid SHA-256 digest");
        }
    }

    private static String text(JsonNode value, String field) {
        JsonNode text = value.path(field);
        if (!text.isTextual() || text.textValue().isBlank()) {
            throw new IllegalArgumentException("Invalid enrollment field: " + field);
        }
        return text.textValue();
    }

    private void save(State state) throws IOException {
        var document = JSON.createObjectNode().put("schemaVersion", state.version());
        var bindings = document.putObject("nodes");
        new TreeMap<>(state.nodes()).forEach(bindings::put);
        if (state.version() == 2) {
            var invites = document.putObject("invites");
            new TreeMap<>(state.invites()).forEach((digest, invite) -> invites.putObject(digest)
                    .put("nodeId", invite.nodeId()).put("expiresAt", invite.expiresAt().toString()));
            var redemptions = document.putObject("redemptions");
            new TreeMap<>(state.redemptions()).forEach((digest, redemption) ->
                    redemptions.putObject(digest)
                            .put("nodeId", redemption.nodeId())
                            .put("requestId", redemption.requestId().toString())
                            .put("csrSha256", redemption.csrSha256())
                            .put("fingerprint", redemption.fingerprint())
                            .put("responseJson", redemption.responseJson())
                            .put("replayUntil", redemption.replayUntil().toString()));
        }
        ByteBuffer bytes = ByteBuffer.wrap(JSON.writeValueAsBytes(document));
        Path parent = Files.createDirectories(file.getParent());
        Path temporary = Files.createTempFile(parent, ".ccc-nodes-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            }
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException failure) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
        try (FileChannel directory = FileChannel.open(parent, StandardOpenOption.READ)) {
            directory.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // Directory forcing is provider-specific. The file itself has already been forced.
        }
    }
}
