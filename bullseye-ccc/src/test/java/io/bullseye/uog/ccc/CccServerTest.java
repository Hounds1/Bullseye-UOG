package io.bullseye.uog.ccc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(15)
class CccServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String NODE_ID = "registered-core";
    private static final String TEST_PASSWORD = "fixture-only";
    private static final int HEARTBEAT_MILLIS = 250;
    private static final int APPLICATION_HEARTBEAT_MILLIS = 500;
    private static final int SOCKET_TIMEOUT_MILLIS = 5_000;

    @TempDir
    private static Path certificates;

    private static SSLContext serverContext;
    private static SSLContext registeredClient;
    private static SSLContext otherClient;
    private static SSLContext noClientCertificate;
    private static String registeredFingerprint;

    @TempDir
    private Path output;

    @BeforeAll
    static void createTlsIdentities() throws Exception {
        KeyStore server = keyStore("server", "SAN=dns:localhost", "EKU=serverAuth");
        KeyStore registered = keyStore("registered", "EKU=clientAuth");
        KeyStore other = keyStore("other", "EKU=clientAuth");
        Certificate serverCertificate = server.getCertificate("server");
        Certificate registeredCertificate = registered.getCertificate("registered");
        Certificate otherCertificate = other.getCertificate("other");
        serverContext = tls(server, registeredCertificate, otherCertificate);
        registeredClient = tls(registered, serverCertificate);
        otherClient = tls(other, serverCertificate);
        noClientCertificate = tls(null, serverCertificate);
        registeredFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(registeredCertificate.getEncoded()));
    }

    @Test
    void acceptsRegisteredCertificateAndKeepsSessionAliveAcrossHeartbeats() throws Exception {
        try (CccServer server = server();
                SSLSocket connection = connect(server, registeredClient)) {
            ObjectNode request = join(NODE_ID);
            send(connection, request);
            JsonNode accepted = read(connection);
            assertEquals("JOIN_ACCEPTED", accepted.path("type").asText());
            assertEquals(request.path("requestId"), accepted.path("requestId"));
            assertFalse(accepted.path("sessionId").asText().isBlank());
            assertEquals(HEARTBEAT_MILLIS, accepted.path("heartbeatIntervalMs").asInt());
            assertFalse(accepted.has("capabilities"));

            long first = receivePing(connection);
            send(connection, message("PONG").put("sequence", first));
            long second = receivePing(connection);
            assertTrue(second > first);
            send(connection, message("PONG").put("sequence", second));

            List<JsonNode> audit = awaitAudit(2);
            assertEquals(List.of("JOIN_REQUESTED", "JOIN_ACCEPTED"), eventTypes(audit));
            assertIdentifiers(audit, request);
            assertEquals(registeredFingerprint, audit.getFirst().path("certificateSha256").asText());
            assertEquals(registeredFingerprint, audit.getLast().path("certificateSha256").asText());
            assertEquals(accepted.path("sessionId"), audit.getLast().path("sessionId"));
        }
    }

    @Test
    void keepsHeartbeatLiveWhileAnApplicationHandlerWaits() throws Exception {
        var entered = new CountDownLatch(1);
        var finish = new CountDownLatch(1);
        var admittedNode = new AtomicReference<String>();
        var admittedRun = new AtomicReference<UUID>();
        var sessionActive = new AtomicReference<BooleanSupplier>();
        CccServer.SessionHandler handler = (nodeId, runId, frame, active) -> {
            admittedNode.set(nodeId);
            admittedRun.set(runId);
            sessionActive.set(active);
            entered.countDown();
            await(finish);
            return message("APP_ACK").put("sequence", frame.path("sequence").longValue());
        };

        try (CccServer server = server(handler);
                SSLSocket connection = connect(server, registeredClient)) {
            ObjectNode request = join(NODE_ID);
            send(connection, request);
            JsonNode accepted = read(connection);
            assertEquals("JOIN_ACCEPTED", accepted.path("type").asText());
            assertEquals("app.v1", accepted.path("capabilities").get(0).asText());
            replyToPing(connection);

            send(connection, message("APP_FRAME").put("sequence", 12));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            assertEquals(NODE_ID, admittedNode.get());
            assertEquals(UUID.fromString(request.path("runId").asText()), admittedRun.get());
            assertTrue(sessionActive.get().getAsBoolean());
            replyToPing(connection);
            replyToPing(connection);
            finish.countDown();

            JsonNode reply = read(connection);
            if ("PING".equals(reply.path("type").asText())) {
                send(connection, message("PONG").put("sequence", reply.path("sequence").longValue()));
                reply = read(connection);
            }
            assertEquals("APP_ACK", reply.path("type").asText());
            assertEquals(12, reply.path("sequence").longValue());
        } finally {
            finish.countDown();
        }
        assertFalse(sessionActive.get().getAsBoolean());
    }

    @Test
    void closesWhenAnotherApplicationFrameArrivesBeforeTheHandlerFinishes() throws Exception {
        var entered = new CountDownLatch(1);
        var finish = new CountDownLatch(1);
        CccServer.SessionHandler handler = (nodeId, runId, frame, active) -> {
            entered.countDown();
            await(finish);
            return message("APP_ACK");
        };

        try (CccServer server = server(handler);
                SSLSocket connection = connect(server, registeredClient)) {
            send(connection, join(NODE_ID));
            assertEquals("JOIN_ACCEPTED", read(connection).path("type").asText());
            replyToPing(connection);
            send(connection, message("APP_FRAME").put("sequence", 1));
            assertTrue(entered.await(3, TimeUnit.SECONDS));
            send(connection, message("APP_FRAME").put("sequence", 2));
            var closed = awaitAudit(3).getLast();
            assertEquals("SESSION_CLOSED", closed.path("event").asText());
            assertEquals("CONNECTION_CLOSED", closed.path("reasonCode").asText());
        } finally {
            finish.countDown();
        }
    }

    private static void replyToPing(SSLSocket connection) throws IOException {
        send(connection, message("PONG").put("sequence", receivePing(connection)));
    }

    private static void await(CountDownLatch finish) throws IOException {
        try {
            if (!finish.await(5, TimeUnit.SECONDS)) {
                throw new IOException("Application handler was not released");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IOException("Application handler interrupted", failure);
        }
    }

    @Test
    void rejectsUnknownNodeEvenWithARegisteredCertificate() throws Exception {
        assertRejected(registeredClient, "unknown-core");
    }

    @Test
    void rejectsMismatchedCertificateEvenThoughItsIssuerIsTrusted() throws Exception {
        assertRejected(otherClient, NODE_ID);
    }

    @Test
    void requiresClientCertificateBeforeAdmission() throws Exception {
        try (CccServer server = server();
                SSLSocket connection = connect(server, noClientCertificate)) {
            IOException failure = assertThrows(IOException.class, () -> {
                connection.startHandshake();
                send(connection, join(NODE_ID));
                read(connection);
            });
            assertFalse(failure instanceof SocketTimeoutException);
        }
        assertTrue(eventTypes(readAudit()).stream().noneMatch(event -> event.startsWith("JOIN_")));
    }

    @Test
    void endsApprovedSessionAfterMissedHeartbeat() throws Exception {
        try (CccServer server = server();
                SSLSocket connection = connect(server, registeredClient)) {
            ObjectNode request = join(NODE_ID);
            send(connection, request);
            JsonNode accepted = read(connection);
            assertEquals("JOIN_ACCEPTED", accepted.path("type").asText());
            receivePing(connection);
            assertSessionEnded(connection);

            List<JsonNode> audit = awaitAudit(3);
            assertEquals(
                    List.of("JOIN_REQUESTED", "JOIN_ACCEPTED", "SESSION_CLOSED"),
                    eventTypes(audit));
            assertIdentifiers(audit, request);
            JsonNode closed = audit.getLast();
            assertEquals("HEARTBEAT_TIMEOUT", closed.path("reasonCode").asText());
            assertEquals(accepted.path("sessionId"), closed.path("sessionId"));
        }
    }

    private void assertRejected(SSLContext context, String nodeId) throws Exception {
        try (CccServer server = server(); SSLSocket connection = connect(server, context)) {
            ObjectNode request = join(nodeId);
            send(connection, request);
            JsonNode response = read(connection);
            assertEquals("JOIN_REJECTED", response.path("type").asText());
            assertEquals(request.path("requestId"), response.path("requestId"));
            assertTrue(response.path("reasonCode").asText().matches("[A-Z][A-Z0-9_]{0,63}"));
            assertFalse(response.has("retryAfterMs"));
            assertSessionEnded(connection);

            List<JsonNode> audit = awaitAudit(2);
            assertEquals(List.of("JOIN_REQUESTED", "JOIN_REJECTED"), eventTypes(audit));
            assertIdentifiers(audit, request);
            assertEquals(response.path("reasonCode"), audit.getLast().path("reasonCode"));
        }
    }

    private CccServer server() throws IOException {
        return server(null);
    }

    private CccServer server(CccServer.SessionHandler handler) throws IOException {
        CccServer.Settings settings = new CccServer.Settings(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                Map.of(NODE_ID, registeredFingerprint),
                auditPath(),
                handler == null ? HEARTBEAT_MILLIS : APPLICATION_HEARTBEAT_MILLIS,
                3_000,
                8);
        CccServer server = handler == null
                ? new CccServer(serverContext, settings)
                : new CccServer(serverContext, settings, "app.v1", handler);
        server.start();
        return server;
    }

    private Path auditPath() {
        return output.resolve("ccc-audit.jsonl");
    }

    private List<JsonNode> awaitAudit(int count) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
        List<JsonNode> events;
        do {
            events = readAudit();
            if (events.size() >= count) {
                return events;
            }
            Thread.sleep(10);
        } while (System.nanoTime() - deadline < 0);
        throw new AssertionError("Expected " + count + " audit events, received " + events.size());
    }

    private List<JsonNode> readAudit() throws IOException {
        if (!Files.exists(auditPath())) {
            return List.of();
        }
        String ledger = Files.readString(auditPath());
        int lastLine = ledger.lastIndexOf('\n');
        List<JsonNode> events = new ArrayList<>();
        for (String line : ledger.substring(0, lastLine + 1).lines().toList()) {
            events.add(JSON.readTree(line));
        }
        return events;
    }

    private static List<String> eventTypes(List<JsonNode> audit) {
        return audit.stream().map(record -> record.path("event").asText()).toList();
    }

    private static void assertIdentifiers(List<JsonNode> audit, ObjectNode request) {
        assertEquals(audit.size(), audit.stream().map(event -> event.path("eventId")).distinct().count());
        for (JsonNode event : audit) {
            assertFalse(event.path("eventId").asText().isBlank());
            assertFalse(event.path("occurredAt").asText().isBlank());
            assertEquals(request.path("requestId"), event.path("requestId"));
            assertEquals(request.path("nodeId"), event.path("nodeId"));
            assertEquals(request.path("runId"), event.path("runId"));
        }
    }

    private static SSLSocket connect(CccServer server, SSLContext context) throws IOException {
        InetSocketAddress address = server.localAddress();
        SSLSocket connection = (SSLSocket) context.getSocketFactory()
                .createSocket(address.getAddress(), address.getPort());
        connection.setSoTimeout(SOCKET_TIMEOUT_MILLIS);
        return connection;
    }

    private static long receivePing(SSLSocket connection) throws IOException {
        JsonNode ping = read(connection);
        assertEquals("PING", ping.path("type").asText());
        JsonNode sequence = ping.path("sequence");
        assertTrue(sequence.isIntegralNumber() && sequence.longValue() >= 0);
        return sequence.longValue();
    }

    private static void assertSessionEnded(SSLSocket connection) throws IOException {
        DataInputStream input = new DataInputStream(connection.getInputStream());
        try {
            int first = input.read();
            if (first != -1) {
                int length = (first << 24) | (input.readUnsignedByte() << 16)
                        | (input.readUnsignedByte() << 8) | input.readUnsignedByte();
                JsonNode end = readPayload(input, length);
                assertEquals("SESSION_REVOKED", end.path("type").asText());
                assertEquals(-1, input.read());
            }
        } catch (SocketException closed) {
            // The server may close the TCP connection without another application frame.
        }
    }

    private static ObjectNode join(String nodeId) {
        return message("JOIN_REQUEST")
                .put("requestId", UUID.randomUUID().toString())
                .put("nodeId", nodeId)
                .put("runId", UUID.randomUUID().toString());
    }

    private static ObjectNode message(String type) {
        return JSON.createObjectNode().put("protocolVersion", 1).put("type", type);
    }

    private static void send(SSLSocket socket, ObjectNode message) throws IOException {
        byte[] payload = JSON.writeValueAsBytes(message);
        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
        output.writeInt(payload.length);
        output.write(payload);
        output.flush();
    }

    private static JsonNode read(SSLSocket socket) throws IOException {
        DataInputStream input = new DataInputStream(socket.getInputStream());
        return readPayload(input, input.readInt());
    }

    private static JsonNode readPayload(DataInputStream input, int length) throws IOException {
        assertTrue(length > 0 && length <= 65_536);
        byte[] payload = new byte[length];
        input.readFully(payload);
        JsonNode message = JSON.readTree(payload);
        assertEquals(1, message.path("protocolVersion").asInt());
        return message;
    }

    private static KeyStore keyStore(String alias, String... extensions) throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
        Path store = certificates.resolve(alias + ".p12");
        Path log = certificates.resolve(alias + ".log");
        var command = new ArrayList<>(List.of(
                keytool.toString(), "-genkeypair", "-alias", alias, "-dname", "CN=" + alias,
                "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "365",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", TEST_PASSWORD, "-noprompt"));
        for (String extension : extensions) {
            command.add("-ext");
            command.add(extension);
        }
        Process process = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(log.toFile()).start();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("keytool did not finish");
        }
        assertEquals(0, process.exitValue(), () -> "keytool failed for " + alias + ": " + log);
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) {
            keys.load(input, TEST_PASSWORD.toCharArray());
        }
        return keys;
    }

    private static SSLContext tls(KeyStore keys, Certificate... trustedCertificates) throws Exception {
        KeyManager[] keyManagers = new KeyManager[0];
        if (keys != null) {
            KeyManagerFactory keyFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFactory.init(keys, TEST_PASSWORD.toCharArray());
            keyManagers = keyFactory.getKeyManagers();
        }

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        int index = 0;
        for (Certificate certificate : trustedCertificates) {
            trust.setCertificateEntry("trusted-" + index, certificate);
            index++;
        }
        TrustManagerFactory trustFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trust);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(keyManagers, trustFactory.getTrustManagers(), null);
        return ssl;
    }
}
