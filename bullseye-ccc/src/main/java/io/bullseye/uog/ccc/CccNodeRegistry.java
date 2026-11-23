package io.bullseye.uog.ccc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Durable node bindings for one UOG process. Manual node IDs are reserved. */
public final class CccNodeRegistry {
    private static final int SCHEMA_VERSION = 1;
    private static final Pattern CERTIFICATE_SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final Path file;
    private final Set<String> manualNodeIds;
    private volatile Map<String, String> registered;

    public CccNodeRegistry(Path file, Map<String, String> manualPins) throws IOException {
        this.file = Objects.requireNonNull(file, "file").toAbsolutePath().normalize();
        if (this.file.getParent() == null) {
            throw new IllegalArgumentException("CCC registration path must name a file");
        }
        manualPins.forEach(CccNodeRegistry::validateBinding);
        manualNodeIds = Set.copyOf(manualPins.keySet());
        registered = load();
    }

    /** Returns the committed registration pin, or null for a node outside this store. */
    public String fingerprint(String nodeId) {
        return registered.get(Objects.requireNonNull(nodeId, "nodeId"));
    }

    /** Publishes a new binding after saving it. A replay of the same binding returns false. */
    public synchronized boolean register(String nodeId, String certificateSha256) throws IOException {
        validateBinding(nodeId, certificateSha256);
        if (manualNodeIds.contains(nodeId)) {
            throw new IllegalArgumentException("CCC node ID is reserved by a manual pin");
        }

        String fingerprint = certificateSha256.toLowerCase(Locale.ROOT);
        String existing = registered.get(nodeId);
        if (existing != null) {
            if (existing.equals(fingerprint)) {
                return false;
            }
            throw new IllegalArgumentException("CCC node ID already has a different registration pin");
        }

        var updated = new TreeMap<>(registered);
        updated.put(nodeId, fingerprint);
        Map<String, String> snapshot = Map.copyOf(updated);
        save(updated);
        registered = snapshot;
        return true;
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

    private Map<String, String> load() throws IOException {
        try (var input = Files.newInputStream(file)) {
            JsonNode root = JSON.readTree(input);
            if (root == null || !root.isObject() || root.size() != 2 || !root.path("nodes").isObject()) {
                throw new IOException("Invalid CCC registration file schema: " + file);
            }
            JsonNode version = root.path("schemaVersion");
            if (!version.isIntegralNumber()
                    || !version.canConvertToInt() || version.intValue() != SCHEMA_VERSION) {
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
            return Map.copyOf(nodes);
        } catch (NoSuchFileException missing) {
            return Map.of();
        }
    }

    private void save(Map<String, String> nodes) throws IOException {
        var document = JSON.createObjectNode().put("schemaVersion", SCHEMA_VERSION);
        var bindings = document.putObject("nodes");
        nodes.forEach(bindings::put);
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
