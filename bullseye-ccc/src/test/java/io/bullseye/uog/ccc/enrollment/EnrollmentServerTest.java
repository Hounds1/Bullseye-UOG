package io.bullseye.uog.ccc.enrollment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bullseye.uog.ccc.CccNodeRegistry;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

@Timeout(20)
class EnrollmentServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ADMIN_TOKEN = "a".repeat(64);
    private static final String INVITATIONS = "/api/enrollment/v1/invitations";
    private static final String REDEEM = "/api/enrollment/v1/redeem";
    private static final String NODE_ID = "edge-01";
    private static final URI PUBLIC_ORIGIN = URI.create("https://enrollment.example:8443");
    private static final char[] STORE_PASSWORD = "fixture-only".toCharArray();

    @TempDir
    private static Path certificates;
    @TempDir
    private Path output;

    private static SSLContext serverTls;
    private static SSLContext clientTls;
    private static EnrollmentIssuer issuer;
    private static String csrPem;
    private static String serverCaPem;

    @BeforeAll
    static void createTlsFixtures() throws Exception {
        Path serverStore = generateKey("server", "SAN=ip:127.0.0.1", "EKU=serverAuth");
        Path issuerStore = generateKey("issuer", "BC:critical=ca:true", "KU:critical=keyCertSign");
        Path clientStore = generateKey("core");
        Path request = certificates.resolve("core.csr");
        keytool("-certreq", "-alias", "core", "-keystore", clientStore.toString(), "-storepass",
                String.valueOf(STORE_PASSWORD), "-sigalg", "SHA256withECDSA", "-file", request.toString());
        csrPem = Files.readString(request);
        issuer = new EnrollmentIssuer(issuerStore, STORE_PASSWORD, "issuer");

        KeyStore serverKeys = KeyStore.getInstance("PKCS12");
        try (var stream = Files.newInputStream(serverStore)) {
            serverKeys.load(stream, STORE_PASSWORD);
        }
        var serverCertificate = serverKeys.getCertificate("server");
        var export = Base64.getMimeEncoder(64, new byte[] {'\n'});
        serverCaPem = "-----BEGIN CERTIFICATE-----\n"
                + export.encodeToString(serverCertificate.getEncoded()) + "\n-----END CERTIFICATE-----\n";

        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(serverKeys, STORE_PASSWORD);
        serverTls = SSLContext.getInstance("TLS");
        serverTls.init(keys.getKeyManagers(), null, null);

        KeyStore trusted = KeyStore.getInstance("PKCS12");
        trusted.load(null, null);
        trusted.setCertificateEntry("server", serverCertificate);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trusted);
        clientTls = SSLContext.getInstance("TLS");
        clientTls.init(new javax.net.ssl.KeyManager[0], trust.getTrustManagers(), null);
    }

    @Test
    void enrollsOverHttpsWithoutAClientCertificateAndReplaysTheSameRequest() throws Exception {
        var registry = new CccNodeRegistry(output.resolve("nodes.json"), Map.of());
        try (var server = server(registry); var client = client()) {
            String invitation = JSON.createObjectNode().put("nodeId", NODE_ID).toString();
            var denied = send(client, server, "POST", INVITATIONS, "b".repeat(64), invitation);
            assertError(denied, 401, "UNAUTHORIZED");

            var accepted = send(client, server, "POST", INVITATIONS, ADMIN_TOKEN, invitation);
            assertEquals(201, accepted.statusCode());
            JsonNode invite = JSON.readTree(accepted.body());
            assertEquals(1, invite.path("apiVersion").asInt());
            assertEquals(PUBLIC_ORIGIN.resolve(REDEEM).toString(), invite.path("enrollmentUrl").asText());
            assertEquals(NODE_ID, invite.path("nodeId").asText());
            assertEquals(serverCaPem, invite.path("serverCaPem").asText());
            assertTrue(Instant.parse(invite.path("expiresAt").asText()).isAfter(Instant.now()));
            String code = invite.path("code").asText();
            assertTrue(code.matches("[A-Za-z0-9_-]{43}"));

            String requestId = UUID.randomUUID().toString();
            String payload = redeemRequest(requestId, csrPem);
            var first = send(client, server, "POST", REDEEM, code, payload);
            assertEquals(200, first.statusCode(), first::body);
            JsonNode enrollment = JSON.readTree(first.body());
            assertEquals(1, enrollment.path("apiVersion").asInt());
            assertEquals(NODE_ID, enrollment.path("nodeId").asText());
            assertEquals("ccc.example", enrollment.path("ccc").path("host").asText());
            assertEquals(7443, enrollment.path("ccc").path("port").asInt());
            assertEquals(serverCaPem, enrollment.path("ccc").path("serverCaPem").asText());
            var chain = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(
                    enrollment.path("certificateChainPem").asText().getBytes(StandardCharsets.US_ASCII)));
            assertEquals(2, chain.size());
            var leaf = chain.iterator().next();
            String pin = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded()));
            assertEquals(pin, registry.fingerprint(NODE_ID));

            var replay = send(client, server, "POST", REDEEM, code, payload);
            assertEquals(200, replay.statusCode());
            assertEquals(first.body(), replay.body());
            assertError(send(client, server, "POST", REDEEM, code,
                    redeemRequest(requestId, csrPem + "\n")), 409, "REQUEST_CONFLICT");
        }
    }

    @Test
    void validatesRoutesAuthorizationAndBodiesBeforeChangingAdmissionState() throws Exception {
        var registry = new CccNodeRegistry(output.resolve("nodes.json"), Map.of());
        try (var server = server(registry); var client = client()) {
            var wrongMethod = send(client, server, "GET", INVITATIONS, null, "");
            assertError(wrongMethod, 405, "METHOD_NOT_ALLOWED");
            assertEquals("POST", wrongMethod.headers().firstValue("Allow").orElseThrow());
            assertError(send(client, server, "POST", INVITATIONS + "/extra", ADMIN_TOKEN, "{}"),
                    404, "NOT_FOUND");
            assertError(send(client, server, "POST", INVITATIONS, ADMIN_TOKEN,
                    "{\"nodeId\":\"edge-01\",\"nodeId\":\"edge-02\"}"), 400, "INVALID_REQUEST");
            assertError(send(client, server, "POST", INVITATIONS, ADMIN_TOKEN,
                    "{\"nodeId\":\"" + "a".repeat(17_000) + "\"}"), 413, "BODY_TOO_LARGE");
            assertError(send(client, server, "POST", REDEEM, ADMIN_TOKEN, "{}"),
                    401, "INVALID_OR_EXPIRED_CODE");

            String invitation = JSON.createObjectNode().put("nodeId", NODE_ID).toString();
            var accepted = send(client, server, "POST", INVITATIONS, ADMIN_TOKEN, invitation);
            assertEquals(201, accepted.statusCode());
            String code = JSON.readTree(accepted.body()).path("code").asText();
            assertError(send(client, server, "POST", REDEEM, code, redeemRequest("1-1-1-1-1", csrPem)),
                    400, "INVALID_REQUEST");
            String requestId = UUID.randomUUID().toString();
            assertError(send(client, server, "POST", REDEEM, code, redeemRequest(requestId, "bad csr")),
                    400, "INVALID_CSR");
            var success = send(client, server, "POST", REDEEM, code, redeemRequest(requestId, csrPem));
            assertEquals(200, success.statusCode(), success::body);
            assertNotNull(registry.fingerprint(NODE_ID));
        }
    }

    @Test
    void requiresAnHttpsOriginWithoutPathsOrCredentials() {
        for (String value : List.of("http://example.com", "https://example.com/path",
                "https://secret@example.com", "https://example.com?foo=bar", "https://example.com#frag")) {
            assertThrows(IllegalArgumentException.class, () -> new EnrollmentServer.Settings(
                    new InetSocketAddress("127.0.0.1", 0), URI.create(value), "ccc.example", 7443, serverCaPem));
        }
    }

    private static EnrollmentServer server(CccNodeRegistry registry) throws Exception {
        var settings = new EnrollmentServer.Settings(new InetSocketAddress("127.0.0.1", 0),
                PUBLIC_ORIGIN, "ccc.example", 7443, serverCaPem);
        var server = new EnrollmentServer(serverTls, settings, ADMIN_TOKEN, registry, issuer);
        server.start();
        return server;
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().sslContext(clientTls).connectTimeout(Duration.ofSeconds(5)).build();
    }

    private static HttpResponse<String> send(HttpClient client, EnrollmentServer server, String method,
            String path, String token, String body) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(
                "https://127.0.0.1:" + server.localAddress().getPort() + path))
                .timeout(Duration.ofSeconds(5))
                .method(method, body.isEmpty() ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        var response = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        return response;
    }

    private static void assertError(HttpResponse<String> response, int status, String code) throws Exception {
        assertEquals(status, response.statusCode(), response::body);
        assertEquals(JSON.createObjectNode().put("code", code), JSON.readTree(response.body()));
    }

    private static String redeemRequest(String requestId, String request) {
        return JSON.createObjectNode().put("requestId", requestId).put("csrPem", request).toString();
    }

    private static Path generateKey(String alias, String... extensions) throws Exception {
        Path store = certificates.resolve(alias + ".p12");
        var arguments = new ArrayList<>(List.of("-genkeypair", "-alias", alias, "-dname", "CN=" + alias,
                "-keyalg", "EC", "-groupname", "secp256r1", "-validity", "365", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", String.valueOf(STORE_PASSWORD), "-noprompt"));
        for (String extension : extensions) {
            arguments.add("-ext");
            arguments.add(extension);
        }
        keytool(arguments.toArray(String[]::new));
        return store;
    }

    private static void keytool(String... arguments) throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
        Path keytool = Path.of(System.getProperty("java.home"), "bin", windows ? "keytool.exe" : "keytool");
        var command = new ArrayList<>(List.of(keytool.toString()));
        command.addAll(List.of(arguments));
        Path log = Files.createTempFile(certificates, "keytool-", ".log");
        Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(10, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("keytool did not finish");
        }
        assertEquals(0, process.exitValue(), () -> "keytool failed: " + log);
    }
}
