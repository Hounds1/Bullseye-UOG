package io.bullseye.uog;

import io.bullseye.uog.ccc.CccServer;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Properties;

public final class UogApplication {
    private static final String PREFIX = "bullseye.uog.ccc.";
    private static final String ALLOW_PREFIX = PREFIX + "allow.";

    private UogApplication() {}

    public static void main(String[] args) throws Exception {
        if (args.length > 1) {
            throw new IllegalArgumentException("Expected a single UOG properties file");
        }
        Path config = args.length == 0 ? Path.of("config", "bullseye-uog.properties") : Path.of(args[0]);
        var settings = loadSettings(config);
        requireTlsStore("javax.net.ssl.keyStore");
        requireTlsStore("javax.net.ssl.trustStore");
        try (var server = new CccServer(SSLContext.getDefault(), settings)) {
            Runtime.getRuntime().addShutdownHook(
                    new Thread(() -> shutdown(server), "bullseye-uog-shutdown"));
            server.start();
            System.out.println("[UOG] Cluster control online. address=" + server.localAddress());
            server.awaitTermination();
        }
    }

    static CccServer.Settings loadSettings(Path path) throws IOException {
        var properties = new Properties();
        try (var reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        var allowedNodes = new HashMap<String, String>();
        for (String key : properties.stringPropertyNames()) {
            if (key.startsWith(ALLOW_PREFIX)) {
                String nodeId = key.substring(ALLOW_PREFIX.length());
                allowedNodes.put(nodeId, properties.getProperty(key).strip());
            }
        }
        if (allowedNodes.isEmpty()) {
            throw new IllegalArgumentException("Configure at least one " + ALLOW_PREFIX + "<nodeId>");
        }
        String host = text(properties, "bind-host", "127.0.0.1");
        return new CccServer.Settings(
                new InetSocketAddress(host, integer(properties, "port", 7443)),
                allowedNodes,
                Path.of(text(properties, "audit-file", "var/ccc-audit.jsonl")),
                integer(properties, "heartbeat-ms", 5_000),
                integer(properties, "admission-timeout-ms", 5_000),
                integer(properties, "max-connections", 128));
    }

    private static String text(Properties properties, String key, String defaultValue) {
        String value = properties.getProperty(PREFIX + key, defaultValue).strip();
        if (value.isEmpty()) {
            throw new IllegalArgumentException(PREFIX + key + " must not be blank");
        }
        return value;
    }

    private static int integer(Properties properties, String key, int defaultValue) {
        try {
            return Integer.parseInt(text(properties, key, Integer.toString(defaultValue)));
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException(PREFIX + key + " must be an integer", failure);
        }
    }

    private static void requireTlsStore(String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Configure the JVM TLS property " + property);
        }
    }

    private static void shutdown(CccServer server) {
        server.close();
        try {
            server.awaitTermination();
        } catch (InterruptedException stopping) {
            Thread.currentThread().interrupt();
        }
    }
}
