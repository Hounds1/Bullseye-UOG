package io.bullseye.uog.ccc.enrollment;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import io.bullseye.uog.ccc.CccNodeRegistry;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/** Server-authenticated HTTPS listener for initial CCC node enrollment. */
public final class EnrollmentServer implements AutoCloseable {
    private static final int API_VERSION = 1;
    private static final int MAX_BODY_BYTES = 16 * 1_024;
    private static final String INVITATIONS = "/api/enrollment/v1/invitations";
    private static final String REDEEM = "/api/enrollment/v1/redeem";
    private static final Pattern ADMIN_SECRET = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern INVITE_CODE = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private final Settings settings;
    private final CccNodeRegistry registry;
    private final EnrollmentIssuer issuer;
    private final byte[] adminSecret;
    private final HttpsServer server;
    private final ExecutorService executor;
    private final AtomicBoolean closed = new AtomicBoolean();

    public record Settings(
            InetSocketAddress address, URI publicOrigin, String cccHost, int cccPort, String serverCaPem) {

        public Settings {
            Objects.requireNonNull(address, "address");
            Objects.requireNonNull(publicOrigin, "publicOrigin");
            String path = publicOrigin.getRawPath();
            if (!"https".equalsIgnoreCase(publicOrigin.getScheme()) || publicOrigin.getHost() == null
                    || publicOrigin.getRawUserInfo() != null || publicOrigin.getRawQuery() != null
                    || publicOrigin.getRawFragment() != null || publicOrigin.getPort() == 0
                    || publicOrigin.getPort() > 65_535
                    || (!"".equals(path) && !"/".equals(path))) {
                throw new IllegalArgumentException("Enrollment public origin must be an HTTPS origin");
            }
            if (cccHost == null || cccHost.isBlank() || cccHost.chars().anyMatch(Character::isWhitespace)
                    || cccPort < 1 || cccPort > 65_535) {
                throw new IllegalArgumentException("Invalid CCC host or port");
            }
            if (serverCaPem == null || serverCaPem.isBlank()) {
                throw new IllegalArgumentException("Enrollment server CA must not be blank");
            }
        }
    }

    public EnrollmentServer(
            SSLContext tls, Settings settings, String adminToken, CccNodeRegistry registry, EnrollmentIssuer issuer)
            throws IOException {
        Objects.requireNonNull(tls, "tls");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        if (adminToken == null || !ADMIN_SECRET.matcher(adminToken).matches()) {
            throw new IllegalArgumentException("Enrollment admin token must be 64 lowercase hex characters");
        }
        adminSecret = adminToken.getBytes(StandardCharsets.US_ASCII);
        server = HttpsServer.create(settings.address(), 32);
        server.setHttpsConfigurator(new HttpsConfigurator(tls) {
            @Override
            public void configure(HttpsParameters request) {
                var parameters = getSSLContext().getDefaultSSLParameters();
                parameters.setProtocols(Arrays.stream(parameters.getProtocols())
                        .filter(protocol -> protocol.equals("TLSv1.2") || protocol.equals("TLSv1.3"))
                        .toArray(String[]::new));
                parameters.setNeedClientAuth(false);
                parameters.setWantClientAuth(false);
                request.setSSLParameters(parameters);
            }
        });
        executor = new ThreadPoolExecutor(
                4, 4, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(16),
                Thread.ofPlatform().daemon().name("bullseye-enrollment-", 0).factory());
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }

    public void start() {
        server.start();
    }

    public InetSocketAddress localAddress() {
        return server.getAddress();
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            server.stop(0);
            executor.shutdownNow();
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            Response response;
            try {
                response = route(exchange);
            } catch (HttpFailure failure) {
                response = error(failure.status, failure.code);
            } catch (CccNodeRegistry.EnrollmentException failure) {
                response = switch (failure.code()) {
                    case "INVALID_NODE_ID" -> error(400, "INVALID_NODE_ID");
                    case "INVALID_OR_EXPIRED_CODE" -> error(401, "INVALID_OR_EXPIRED_CODE");
                    case "NODE_ID_IN_USE" -> error(409, "NODE_ID_IN_USE");
                    case "REQUEST_CONFLICT" -> error(409, "REQUEST_CONFLICT");
                    default -> error(503, "TEMPORARY_UNAVAILABLE");
                };
            } catch (IOException | RuntimeException failure) {
                response = error(503, "TEMPORARY_UNAVAILABLE");
            }
            var headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "application/json; charset=utf-8");
            headers.set("Cache-Control", "no-store");
            if (response.status() == 401) {
                headers.set("WWW-Authenticate", "Bearer");
            }
            if ("HEAD".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(response.status(), -1);
                return;
            }
            byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(response.status(), body.length);
            exchange.getResponseBody().write(body);
        }
    }

    private Response route(HttpExchange exchange) throws IOException, CccNodeRegistry.EnrollmentException {
        URI uri = exchange.getRequestURI();
        String path = uri.getRawPath();
        if (uri.getRawQuery() != null || (!INVITATIONS.equals(path) && !REDEEM.equals(path))) {
            return error(404, "NOT_FOUND");
        }
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Allow", "POST");
            return error(405, "METHOD_NOT_ALLOWED");
        }

        String bearer = bearer(exchange);
        if (INVITATIONS.equals(path)) {
            if (bearer == null || !ADMIN_SECRET.matcher(bearer).matches()
                    || !MessageDigest.isEqual(adminSecret, bearer.getBytes(StandardCharsets.US_ASCII))) {
                return error(401, "UNAUTHORIZED");
            }
            JsonNode request = readObject(exchange, 1);
            String nodeId = readText(request, "nodeId");
            var invite = registry.issueInvite(nodeId);
            var body = JSON.createObjectNode()
                    .put("apiVersion", API_VERSION)
                    .put("enrollmentUrl", settings.publicOrigin().resolve(REDEEM).toString())
                    .put("nodeId", nodeId)
                    .put("expiresAt", invite.expiresAt().toString())
                    .put("code", invite.code())
                    .put("serverCaPem", settings.serverCaPem());
            return new Response(201, body.toString());
        }

        if (bearer == null || !INVITE_CODE.matcher(bearer).matches()) {
            return error(401, "INVALID_OR_EXPIRED_CODE");
        }
        JsonNode request = readObject(exchange, 2);
        UUID requestId = requestId(readText(request, "requestId"));
        String csrPem = readText(request, "csrPem");
        String response = registry.redeemInvite(bearer, requestId, sha256(csrPem),
                nodeId -> issue(nodeId, csrPem));
        return new Response(200, response);
    }

    private CccNodeRegistry.Issued issue(String nodeId, String csrPem) throws IOException {
        EnrollmentIssuer.Certificate certificate;
        try {
            certificate = issuer.issue(nodeId, csrPem);
        } catch (IllegalArgumentException invalid) {
            throw new HttpFailure(400, "INVALID_CSR");
        }
        var body = JSON.createObjectNode()
                .put("apiVersion", API_VERSION)
                .put("nodeId", nodeId)
                .put("certificateChainPem", certificate.chainPem());
        body.putObject("ccc")
                .put("host", settings.cccHost())
                .put("port", settings.cccPort())
                .put("serverCaPem", settings.serverCaPem());
        return new CccNodeRegistry.Issued(certificate.fingerprint(), body.toString());
    }

    private static String bearer(HttpExchange exchange) {
        List<String> values = exchange.getRequestHeaders().get("Authorization");
        if (values == null || values.size() != 1) {
            return null;
        }
        String header = values.getFirst();
        return header.regionMatches(true, 0, "Bearer ", 0, 7) ? header.substring(7) : null;
    }

    private static JsonNode readObject(HttpExchange exchange, int fields) throws IOException {
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
        if (bytes.length > MAX_BODY_BYTES) {
            throw new HttpFailure(413, "BODY_TOO_LARGE");
        }
        try {
            JsonNode node = JSON.readTree(bytes);
            if (node != null && node.isObject() && node.size() == fields) {
                return node;
            }
        } catch (JsonProcessingException invalid) {
            throw new HttpFailure(400, "INVALID_REQUEST");
        }
        throw new HttpFailure(400, "INVALID_REQUEST");
    }

    private static String readText(JsonNode request, String field) {
        String value = request.path(field).textValue();
        if (value == null) {
            throw new HttpFailure(400, "INVALID_REQUEST");
        }
        return value;
    }

    private static UUID requestId(String value) {
        try {
            UUID id = UUID.fromString(value);
            if (id.toString().equals(value)) {
                return id;
            }
        } catch (IllegalArgumentException invalid) {
            throw new HttpFailure(400, "INVALID_REQUEST");
        }
        throw new HttpFailure(400, "INVALID_REQUEST");
    }

    private static String sha256(String body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(body.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is not available", unavailable);
        }
    }

    private static Response error(int status, String code) {
        return new Response(status, JSON.createObjectNode().put("code", code).toString());
    }

    private record Response(int status, String body) {}

    private static final class HttpFailure extends RuntimeException {
        private final int status;
        private final String code;

        private HttpFailure(int status, String code) {
            this.status = status;
            this.code = code;
        }
    }
}
