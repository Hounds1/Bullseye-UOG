package io.bullseye.uog;

import io.bullseye.uog.amc.AmcAuditArchive;
import io.bullseye.uog.amc.AmcCapacityMonitor;
import io.bullseye.uog.amc.AmcFileCapacity;
import io.bullseye.uog.amc.AmcTelemetryArchive;
import io.bullseye.uog.ccc.CccAuditHandoff;
import io.bullseye.uog.ccc.CccServer;
import io.bullseye.uog.tcc.TccReceiver;
import io.bullseye.uog.tcc.TccTelemetryHandoff;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public final class UogApplication {
    private static final String CCC_PREFIX = "bullseye.uog.ccc.";
    private static final String ALLOW_PREFIX = CCC_PREFIX + "allow.";
    private static final String TCC_ENABLED = "bullseye.uog.tcc.enabled";
    private static final String TCC_DIRECTORY = "bullseye.uog.tcc.latest-directory";
    private static final String AMC_ENABLED = "bullseye.uog.amc.enabled";
    private static final String AMC_AUDIT_DIRECTORY = "bullseye.uog.amc.ccc-audit-directory";
    private static final String AMC_TELEMETRY_DIRECTORY = "bullseye.uog.amc.tcc-telemetry-directory";
    private static final String CAPACITY_PREFIX = "bullseye.uog.amc.capacity.";
    private static final String AUDIT_CHECKPOINT = CCC_PREFIX + "audit-checkpoint";

    private UogApplication() {}

    public static void main(String[] args) throws Exception {
        if (args.length > 1) {
            throw new IllegalArgumentException("Expected a single UOG properties file");
        }
        Path config = args.length == 0 ? Path.of("config", "bullseye-uog.properties") : Path.of(args[0]);
        var properties = new Properties();
        try (var reader = Files.newBufferedReader(config, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        var settings = loadCccSettings(properties);
        requireTlsStore("javax.net.ssl.keyStore");
        requireTlsStore("javax.net.ssl.trustStore");
        boolean archiveEnabled = enabled(properties, AMC_ENABLED);
        try (var tcc = createTcc(properties, archiveEnabled);
                var server = createServer(SSLContext.getDefault(), settings, tcc);
                var handoff = createAuditHandoff(server, settings, properties, archiveEnabled);
                var capacity = createCapacityMonitor(settings, properties, handoff, tcc)) {
            Runtime.getRuntime().addShutdownHook(
                    new Thread(() -> shutdown(server, handoff, tcc, capacity), "bullseye-uog-shutdown"));
            if (handoff != null) {
                handoff.start();
            }
            if (tcc != null) {
                tcc.startHandoff();
            }
            server.start();
            System.out.println("[UOG] Cluster control online. address=" + server.localAddress());
            if (capacity != null) {
                capacity.start();
            }
            server.awaitTermination();
        }
    }

    private static TccReceiver createTcc(Properties properties, boolean archiveEnabled) throws IOException {
        if (!enabled(properties, TCC_ENABLED)) {
            return null;
        }
        Path latest = tccDirectory(properties);
        if (!archiveEnabled) {
            return new TccReceiver(latest);
        }
        var archive = new AmcTelemetryArchive(telemetryArchiveDirectory(properties));
        return new TccReceiver(latest, archive::store);
    }

    private static CccServer createServer(
            SSLContext tls, CccServer.Settings settings, TccReceiver tcc) throws IOException {
        if (tcc == null) {
            return new CccServer(tls, settings);
        }
        return new CccServer(tls, settings, TccReceiver.CAPABILITY, tcc::receive);
    }

    private static CccAuditHandoff createAuditHandoff(CccServer server, CccServer.Settings settings,
            Properties properties, boolean archiveEnabled) {
        if (!archiveEnabled) {
            return null;
        }
        var archive = new AmcAuditArchive(auditArchiveDirectory(properties));
        Path checkpoint = Path.of(text(properties, AUDIT_CHECKPOINT,
                settings.auditFile() + ".amc-offset"));
        return server.auditHandoff(checkpoint, archive::store);
    }

    private static AmcCapacityMonitor createCapacityMonitor(
            CccServer.Settings settings, Properties properties, CccAuditHandoff handoff, TccReceiver tcc) {
        if (handoff == null || !enabled(properties, CAPACITY_PREFIX + "enabled")) {
            return null;
        }

        long interval = capacityNumber(properties, "interval-seconds", 60, 1);
        long minimumBytes = capacityNumber(properties, "min-free-bytes", 1_073_741_824L, 0);
        Path cccArchive = auditArchiveDirectory(properties);
        Path tccArchive = telemetryArchiveDirectory(properties);
        Path cccSource = settings.auditFile();
        Path tccPending = TccTelemetryHandoff.pendingDirectory(tccDirectory(properties));

        Map<String, AmcCapacityMonitor.UsageProbe> sources = Map.of(
                "cccArchive", () -> AmcFileCapacity.records(cccArchive, 1),
                "tccArchive", () -> AmcFileCapacity.records(tccArchive, 3),
                "cccSource", () -> AmcFileCapacity.sourceFile(cccSource),
                "tccPending", () -> AmcFileCapacity.records(tccPending, 1));
        Map<String, Path> volumes = Map.of(
                "cccArchive", cccArchive,
                "tccArchive", tccArchive,
                "cccSource", cccSource,
                "tccPending", tccPending);
        Map<String, AmcCapacityMonitor.HandoffProbe> handoffs = new HashMap<>();
        handoffs.put("cccHandoff", () -> {
            var progress = handoff.progress();
            return new AmcCapacityMonitor.HandoffLag(
                    "pendingBytes", progress.pendingBytes(), progress.lastSuccessAt());
        });
        if (tcc != null) {
            handoffs.put("tccHandoff", () -> {
                var progress = tcc.handoffProgress();
                return new AmcCapacityMonitor.HandoffLag("pendingLatest", progress.pendingLatest(),
                        progress.lastSuccessAt());
            });
        }
        return new AmcCapacityMonitor(sources, volumes, handoffs, interval, minimumBytes);
    }

    private static Path auditArchiveDirectory(Properties properties) {
        return Path.of(text(properties, AMC_AUDIT_DIRECTORY, "var/amc/ccc-audit"));
    }

    private static Path telemetryArchiveDirectory(Properties properties) {
        return Path.of(text(properties, AMC_TELEMETRY_DIRECTORY, "var/amc/tcc-telemetry"));
    }

    private static Path tccDirectory(Properties properties) {
        return Path.of(text(properties, TCC_DIRECTORY, "var/tcc/latest"));
    }

    private static long capacityNumber(Properties properties, String name, long fallback, long minimum) {
        String key = CAPACITY_PREFIX + name;
        String error = key + " must be an integer of at least " + minimum;
        try {
            long value = Long.parseLong(text(properties, key, Long.toString(fallback)));
            if (value < minimum) {
                throw new IllegalArgumentException(error);
            }
            return value;
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException(error, failure);
        }
    }

    private static boolean enabled(Properties properties, String key) {
        String value = text(properties, key, "true");
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException(key + " must be true or false");
    }

    private static CccServer.Settings loadCccSettings(Properties properties) {
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
        String host = text(properties, CCC_PREFIX + "bind-host", "127.0.0.1");
        return new CccServer.Settings(
                new InetSocketAddress(host, integer(properties, "port", 7443)),
                allowedNodes,
                Path.of(text(properties, CCC_PREFIX + "audit-file", "var/ccc-audit.jsonl")),
                integer(properties, "heartbeat-ms", 5_000),
                integer(properties, "admission-timeout-ms", 5_000),
                integer(properties, "max-connections", 128));
    }

    private static String text(Properties properties, String key, String defaultValue) {
        String value = properties.getProperty(key, defaultValue).strip();
        if (value.isEmpty()) {
            throw new IllegalArgumentException(key + " must not be blank");
        }
        return value;
    }

    private static int integer(Properties properties, String key, int defaultValue) {
        try {
            return Integer.parseInt(text(properties, CCC_PREFIX + key, Integer.toString(defaultValue)));
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException(CCC_PREFIX + key + " must be an integer", failure);
        }
    }

    private static void requireTlsStore(String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Configure the JVM TLS property " + property);
        }
    }

    private static void shutdown(CccServer server, CccAuditHandoff handoff, TccReceiver tcc,
            AmcCapacityMonitor capacity) {
        if (capacity != null) {
            capacity.close();
        }
        server.close();
        try {
            server.awaitTermination();
        } catch (InterruptedException stopping) {
            Thread.currentThread().interrupt();
        } finally {
            if (handoff != null) {
                handoff.close();
            }
            if (tcc != null) {
                tcc.close();
            }
        }
    }
}
