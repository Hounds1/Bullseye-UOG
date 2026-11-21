package io.bullseye.uog.amc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

final class AmcArchiveFiles {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private AmcArchiveFiles() {}

    static ObjectNode parseObject(String json, String invalidMessage) throws IOException {
        if (JSON.readTree(json) instanceof ObjectNode object) {
            return object;
        }
        throw new IOException(invalidMessage);
    }

    static UUID canonicalUuid(JsonNode field, String label) throws IOException {
        String value = field.textValue();
        if (value != null) {
            try {
                UUID parsed = UUID.fromString(value);
                if (parsed.toString().equals(value)) {
                    return parsed;
                }
            } catch (IllegalArgumentException invalid) {
                throw new IOException("Invalid " + label, invalid);
            }
        }
        throw new IOException(label + " must be a canonical UUID");
    }

    static void store(Path destination, String json, ObjectNode record, String conflictMessage)
            throws IOException {
        Path directory = destination.getParent();
        Files.createDirectories(directory);
        ObjectNode existing = readExisting(destination);
        if (existing != null) {
            if (!existing.equals(record)) {
                throw new IOException(conflictMessage);
            }
            return;
        }
        install(directory, destination, utf8(json));
    }

    static ByteBuffer utf8(String value) throws IOException {
        return StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
    }

    private static ObjectNode readExisting(Path destination) throws IOException {
        try {
            return parseObject(Files.readString(destination, StandardCharsets.UTF_8),
                    "Expected one archived JSON object");
        } catch (NoSuchFileException missing) {
            return null;
        }
    }

    private static void install(Path directory, Path destination, ByteBuffer content)
            throws IOException {
        Path temporary = Files.createTempFile(directory, "amc-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                while (content.hasRemaining()) {
                    channel.write(content);
                }
                channel.force(true);
            }
            Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            forceDirectoryBestEffort(directory);
        } catch (IOException failure) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            }
            throw failure;
        }
    }

    private static void forceDirectoryBestEffort(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // Directory syncing depends on the host filesystem and provider.
        }
    }
}
