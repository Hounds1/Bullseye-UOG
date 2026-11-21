package io.bullseye.uog.ccc;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

final class CccProtocol {
    private static final int VERSION = 1;
    private static final int MAX_FRAME_BYTES = 65_536;
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private CccProtocol() {}

    record JoinRequest(String nodeId, UUID requestId, UUID runId) {}

    static JoinRequest readJoin(InputStream input) throws IOException {
        ObjectNode message = read(input, "JOIN_REQUEST");
        return new JoinRequest(
                text(message, "nodeId"), uuid(message, "requestId"), uuid(message, "runId"));
    }

    static void writeAccepted(OutputStream output, UUID requestId, UUID sessionId, int interval)
            throws IOException {
        write(output, message("JOIN_ACCEPTED")
                .put("requestId", requestId.toString())
                .put("sessionId", sessionId.toString())
                .put("heartbeatIntervalMs", interval));
    }

    static void writeRejected(OutputStream output, UUID requestId, String reason, Integer retryMillis)
            throws IOException {
        ObjectNode message = message("JOIN_REJECTED")
                .put("requestId", requestId.toString())
                .put("reasonCode", reason);
        if (retryMillis != null) {
            message.put("retryAfterMs", retryMillis);
        }
        write(output, message);
    }

    static void writePing(OutputStream output, long sequence) throws IOException {
        write(output, message("PING").put("sequence", sequence));
    }

    static void readPong(InputStream input, long expectedSequence) throws IOException {
        JsonNode sequence = read(input, "PONG").path("sequence");
        if (!sequence.isIntegralNumber() || !sequence.canConvertToLong()
                || sequence.longValue() != expectedSequence) {
            throw new IOException("Unexpected CCC heartbeat sequence");
        }
    }

    private static ObjectNode read(InputStream input, String expectedType) throws IOException {
        DataInputStream frame = new DataInputStream(input);
        int length = frame.readInt();
        requireFrameLength(length);
        byte[] payload = new byte[length];
        frame.readFully(payload);

        String json;
        try {
            json = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(payload)).toString();
        } catch (CharacterCodingException failure) {
            throw new IOException("Invalid CCC UTF-8 payload");
        }

        JsonNode parsed;
        try {
            parsed = JSON.readTree(json);
        } catch (JsonProcessingException failure) {
            throw new IOException("Invalid CCC JSON payload");
        }
        if (!(parsed instanceof ObjectNode message)) {
            throw new IOException("Expected a CCC JSON object");
        }
        JsonNode version = message.path("protocolVersion");
        if (!version.isIntegralNumber() || !version.canConvertToInt() || version.intValue() != VERSION) {
            throw new IOException("Unsupported CCC protocol version");
        }
        if (!expectedType.equals(text(message, "type"))) {
            throw new IOException("Unexpected CCC message type");
        }
        return message;
    }

    private static String text(ObjectNode message, String field) throws IOException {
        JsonNode value = message.path(field);
        if (!value.isTextual() || value.textValue().isBlank()) {
            throw new IOException("Invalid CCC field: " + field);
        }
        return value.textValue();
    }

    private static UUID uuid(ObjectNode message, String field) throws IOException {
        String value = text(message, field);
        try {
            UUID parsed = UUID.fromString(value);
            if (parsed.toString().equals(value)) {
                return parsed;
            }
        } catch (IllegalArgumentException failure) {
            // Rejected below without logging the untrusted field contents.
        }
        throw new IOException("Invalid CCC field: " + field);
    }

    private static ObjectNode message(String type) {
        return JSON.createObjectNode().put("protocolVersion", VERSION).put("type", type);
    }

    private static void write(OutputStream output, ObjectNode message) throws IOException {
        byte[] payload = JSON.writeValueAsBytes(message);
        requireFrameLength(payload.length);
        DataOutputStream frame = new DataOutputStream(output);
        frame.writeInt(payload.length);
        frame.write(payload);
        frame.flush();
    }

    private static void requireFrameLength(int length) throws IOException {
        if (length < 1 || length > MAX_FRAME_BYTES) {
            throw new IOException("Invalid CCC frame length");
        }
    }
}
