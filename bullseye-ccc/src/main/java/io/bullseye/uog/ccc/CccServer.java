package io.bullseye.uog.ccc;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.bullseye.uog.ccc.CccProtocol.JoinRequest;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

public final class CccServer implements AutoCloseable {
    private static final System.Logger LOGGER = System.getLogger(CccServer.class.getName());
    private static final Pattern CERTIFICATE_SHA256 = Pattern.compile("[0-9a-fA-F]{64}");

    @FunctionalInterface
    public interface SessionHandler {
        ObjectNode handle(String nodeId, UUID runId, ObjectNode frame, BooleanSupplier sessionActive)
                throws IOException;
    }

    public record Settings(
            InetSocketAddress address,
            Map<String, String> allowedNodes,
            Path auditFile,
            int heartbeatMillis,
            int admissionTimeoutMillis,
            int maxConnections) {

        public Settings {
            Objects.requireNonNull(address, "address");
            Objects.requireNonNull(auditFile, "auditFile");
            allowedNodes = Map.copyOf(allowedNodes);
            allowedNodes.forEach((nodeId, fingerprint) -> {
                if (nodeId.isBlank() || !CERTIFICATE_SHA256.matcher(fingerprint).matches()) {
                    throw new IllegalArgumentException("Invalid CCC node or certificate fingerprint");
                }
            });
            if (heartbeatMillis <= 0 || admissionTimeoutMillis <= 0 || maxConnections <= 0) {
                throw new IllegalArgumentException("CCC timeouts and connection limit must be positive");
            }
        }
    }

    private final ServerSocket listener;
    private final SSLSocketFactory tlsFactory;
    private final Settings settings;
    private final CccAuditLog audit;
    private final CccCloseAudit closeAudit;
    private final ScheduledThreadPoolExecutor deadlines;
    private final String applicationCapability;
    private final SessionHandler applicationHandler;
    private final Semaphore applicationSlots;
    private final Thread acceptor;
    private final Object lock = new Object();
    private final Set<Socket> connections = new HashSet<>();
    private final Map<String, SessionControl> sessions = new HashMap<>();
    private boolean accepting;
    private boolean closed;
    private boolean shutdownCompleted;

    public CccServer(SSLContext tls, Settings settings) throws IOException {
        this(tls, settings, null, null);
    }

    public CccServer(SSLContext tls, Settings settings, String applicationCapability,
            SessionHandler handler) throws IOException {
        if ((handler == null) != (applicationCapability == null)
                || (applicationCapability != null && applicationCapability.isBlank())) {
            throw new IllegalArgumentException("CCC application capability and handler must be supplied together");
        }
        tlsFactory = Objects.requireNonNull(tls, "tls").getSocketFactory();
        this.settings = Objects.requireNonNull(settings, "settings");
        this.applicationCapability = applicationCapability;
        applicationHandler = handler;
        applicationSlots = handler == null ? null : new Semaphore(settings.maxConnections());
        audit = new CccAuditLog(settings.auditFile());
        closeAudit = new CccCloseAudit(audit::appendLine);
        listener = new ServerSocket();
        try {
            listener.bind(settings.address());
            audit.reconcileSessions();
        } catch (IOException | RuntimeException failure) {
            closeQuietly(listener);
            throw failure;
        }
        deadlines = new ScheduledThreadPoolExecutor(
                1, Thread.ofPlatform().daemon().name("bullseye-ccc-deadline").factory());
        deadlines.setRemoveOnCancelPolicy(true);
        acceptor = Thread.ofPlatform().daemon().name("bullseye-ccc-listener")
                .unstarted(this::acceptConnections);
    }

    public void start() {
        synchronized (lock) {
            if (!closed && !accepting) {
                accepting = true;
                closeAudit.start();
                acceptor.start();
            }
        }
    }

    public InetSocketAddress localAddress() {
        return (InetSocketAddress) listener.getLocalSocketAddress();
    }

    public CccAuditHandoff auditHandoff(Path checkpoint, CccAuditHandoff.Sink sink) {
        return new CccAuditHandoff(audit, checkpoint, sink);
    }

    /** Selects a live session for revocation. Delivery of the final frame is best effort. */
    public boolean revokeSession(String nodeId, UUID sessionId, String reasonCode, Integer retryAfterMs) {
        Objects.requireNonNull(nodeId, "nodeId");
        Objects.requireNonNull(sessionId, "sessionId");
        if (!CccProtocol.validReasonCode(reasonCode) || (retryAfterMs != null && retryAfterMs < 0)) {
            throw new IllegalArgumentException("Invalid CCC revocation reason or retry delay");
        }

        synchronized (lock) {
            SessionControl session = sessions.get(nodeId);
            if (closed || session == null || !session.admitted || session.transport.isClosed()
                    || !session.id.equals(sessionId) || session.revocationReason != null) {
                return false;
            }
            session.revocationReason = reasonCode;
            Thread.ofVirtual().name("bullseye-ccc-revocation")
                    .start(() -> sendRevocation(session, reasonCode, retryAfterMs));
            return true;
        }
    }

    public void awaitTermination() throws InterruptedException {
        synchronized (lock) {
            while (!shutdownCompleted || accepting || !connections.isEmpty()) {
                lock.wait();
            }
        }
        closeAudit.awaitDrain();
    }

    @Override
    public void close() {
        Set<Socket> active;
        synchronized (lock) {
            if (closed) {
                return;
            }
            closed = true;
            active = Set.copyOf(connections);
            lock.notifyAll();
        }
        closeQuietly(listener);
        active.forEach(CccServer::closeQuietly);
        deadlines.shutdownNow();
        synchronized (lock) {
            shutdownCompleted = true;
            signalTermination();
        }
    }

    private void acceptConnections() {
        try {
            while (!listener.isClosed()) {
                Socket transport = listener.accept();
                boolean started = false;
                try {
                    started = startConnection(transport);
                } finally {
                    if (!started) {
                        closeQuietly(transport);
                    }
                }
            }
        } catch (IOException failure) {
            if (!isClosed()) {
                LOGGER.log(System.Logger.Level.ERROR, "CCC listener interrupted", failure);
            }
        } finally {
            close();
            synchronized (lock) {
                accepting = false;
                signalTermination();
            }
        }
    }

    private void signalTermination() {
        if (shutdownCompleted && !accepting && connections.isEmpty()) {
            closeAudit.finish();
        }
        lock.notifyAll();
    }

    private boolean startConnection(Socket transport) {
        synchronized (lock) {
            if (closed || connections.size() >= settings.maxConnections()) {
                return false;
            }
            Thread connection = Thread.ofVirtual().name("bullseye-ccc-connection")
                    .unstarted(() -> serve(transport));
            connections.add(transport);
            try {
                connection.start();
            } catch (RuntimeException | Error failure) {
                connections.remove(transport);
                throw failure;
            }
            return true;
        }
    }

    private void serve(Socket transport) {
        SSLSocket channel = null;
        JoinRequest join = null;
        SessionControl session = null;
        String fingerprint = null;
        String closeReason = "CONNECTION_CLOSED";
        boolean accepted = false;
        boolean joined = false;
        try {
            long admissionStartedAt = System.nanoTime();
            ScheduledFuture<?> admissionDeadline = expire(transport, settings.admissionTimeoutMillis());
            InputStream input;
            OutputStream output;
            try {
                channel = openTls(transport);
                fingerprint = fingerprint(channel);
                input = channel.getInputStream();
                output = channel.getOutputStream();
                join = CccProtocol.readJoin(input);
                appendAudit("JOIN_REQUESTED", join, null, fingerprint, null);
                if (!fingerprint.equalsIgnoreCase(settings.allowedNodes().get(join.nodeId()))) {
                    reject(output, join, fingerprint, "UNAUTHORIZED_NODE", null);
                    return;
                }
                var proposed = new SessionControl(UUID.randomUUID(), transport, output);
                if (!claimNode(join.nodeId(), proposed)) {
                    reject(output, join, fingerprint, "NODE_ALREADY_CONNECTED", settings.heartbeatMillis());
                    return;
                }
                session = proposed;
                appendAudit("JOIN_ACCEPTED", join, session.id, fingerprint, null);
                accepted = true;
                requireWithin(admissionStartedAt, settings.admissionTimeoutMillis());
                synchronized (session.writeLock) {
                    synchronized (lock) {
                        if (closed) {
                            throw new SocketException("CCC is closing");
                        }
                        session.admitted = true;
                    }
                    CccProtocol.writeAccepted(output, join.requestId(), session.id,
                            settings.heartbeatMillis(), applicationCapability);
                }
                joined = true;
            } finally {
                admissionDeadline.cancel(false);
            }
            if (applicationHandler == null) {
                channel.setSoTimeout(settings.heartbeatMillis());
                maintainSession(session, input);
            } else {
                channel.setSoTimeout(0);
                new CccApplicationSession(transport, input, output, join, applicationHandler,
                        applicationSlots, deadlines, settings.heartbeatMillis(), session.writeLock,
                        session::allowsApplication).run();
            }
        } catch (SocketTimeoutException failure) {
            closeReason = joined ? "HEARTBEAT_TIMEOUT" : "ADMISSION_TIMEOUT";
        } catch (InterruptedException stopping) {
            closeReason = "SERVER_SHUTDOWN";
            Thread.currentThread().interrupt();
        } catch (IOException failure) {
            // A broken or malformed peer connection never interrupts the listener.
        } finally {
            closeQuietly(transport);
            closeQuietly(channel);
            synchronized (lock) {
                if (accepted) {
                    String reason = session.revocationReason;
                    if (reason == null) {
                        reason = closed ? "SERVER_SHUTDOWN" : closeReason;
                    }
                    closeAudit.offer(CccAuditLog.closeRecord(join.nodeId(), join.requestId(), join.runId(),
                            session.id, fingerprint, reason));
                }
                if (session != null) {
                    sessions.remove(join.nodeId(), session);
                }
                connections.remove(transport);
                signalTermination();
            }
        }
    }

    private SSLSocket openTls(Socket transport) throws IOException {
        SSLSocket socket = (SSLSocket) tlsFactory.createSocket(
                transport, transport.getInetAddress().getHostAddress(), transport.getPort(), false);
        try {
            socket.setUseClientMode(false);
            socket.setNeedClientAuth(true);
            socket.setSoTimeout(settings.admissionTimeoutMillis());
            socket.startHandshake();
            return socket;
        } catch (IOException | RuntimeException failure) {
            closeQuietly(transport);
            closeQuietly(socket);
            throw failure;
        }
    }

    private static String fingerprint(SSLSocket channel) throws IOException {
        Certificate leaf = channel.getSession().getPeerCertificates()[0];
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded());
            return HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException failure) {
            throw new IOException("Unable to read the CCC peer certificate fingerprint", failure);
        }
    }

    private boolean claimNode(String nodeId, SessionControl session) throws SocketException {
        synchronized (lock) {
            if (closed) {
                throw new SocketException("CCC is closing");
            }
            return sessions.putIfAbsent(nodeId, session) == null;
        }
    }

    private void sendRevocation(SessionControl session, String reasonCode, Integer retryAfterMs) {
        try {
            ScheduledFuture<?> deadline = expire(session.transport, settings.admissionTimeoutMillis());
            try {
                synchronized (session.writeLock) {
                    try {
                        CccProtocol.writeRevoked(session.output, reasonCode, retryAfterMs);
                    } finally {
                        closeQuietly(session.transport);
                    }
                }
            } finally {
                deadline.cancel(false);
            }
        } catch (IOException failure) {
            closeQuietly(session.transport);
        } finally {
            synchronized (lock) {
                lock.notifyAll();
            }
        }
    }

    private void reject(OutputStream output, JoinRequest join, String fingerprint,
            String reason, Integer retryMillis) throws IOException {
        appendAudit("JOIN_REJECTED", join, null, fingerprint, reason);
        CccProtocol.writeRejected(output, join.requestId(), reason, retryMillis);
    }

    private void maintainSession(SessionControl session, InputStream input)
            throws IOException, InterruptedException {
        Socket transport = session.transport;
        int interval = settings.heartbeatMillis();
        long intervalNanos = TimeUnit.MILLISECONDS.toNanos(interval);
        for (long sequence = 1; !isClosed() && !transport.isClosed(); sequence++) {
            long startedAt = System.nanoTime();
            ScheduledFuture<?> deadline = expire(transport, interval);
            try {
                synchronized (session.writeLock) {
                    CccProtocol.writePing(session.output, sequence);
                }
                CccProtocol.readPong(input, sequence);
                requireWithin(startedAt, interval);
            } catch (IOException failure) {
                requireWithin(startedAt, interval);
                throw failure;
            } finally {
                deadline.cancel(false);
            }
            waitForHeartbeat(transport, startedAt, intervalNanos);
        }
    }

    private void waitForHeartbeat(Socket transport, long startedAt, long intervalNanos)
            throws InterruptedException {
        synchronized (lock) {
            while (!closed && !transport.isClosed()) {
                long remaining = intervalNanos - (System.nanoTime() - startedAt);
                if (remaining <= 0) {
                    return;
                }
                TimeUnit.NANOSECONDS.timedWait(lock, remaining);
            }
        }
    }

    private ScheduledFuture<?> expire(Socket socket, int timeoutMillis) throws SocketException {
        try {
            return deadlines.schedule(() -> closeQuietly(socket), timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException failure) {
            throw new SocketException("CCC is closing");
        }
    }

    private static void requireWithin(long startedAt, int timeoutMillis) throws SocketTimeoutException {
        if (System.nanoTime() - startedAt >= TimeUnit.MILLISECONDS.toNanos(timeoutMillis)) {
            throw new SocketTimeoutException("CCC operation timed out");
        }
    }

    private void appendAudit(String event, JoinRequest join, UUID sessionId, String fingerprint,
            String reason) throws IOException {
        try {
            audit.append(event, join.nodeId(), join.requestId(), join.runId(), sessionId, fingerprint, reason);
        } catch (IOException failure) {
            LOGGER.log(System.Logger.Level.ERROR, "CCC audit write failed", failure);
            throw failure;
        }
    }

    private boolean isClosed() {
        synchronized (lock) {
            return closed;
        }
    }

    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException failure) {
                // Each transport is closed independently.
            }
        }
    }

    private static final class SessionControl {
        private final UUID id;
        private final Socket transport;
        private final OutputStream output;
        private final Object writeLock = new Object();
        private boolean admitted;
        private volatile String revocationReason;

        private SessionControl(UUID id, Socket transport, OutputStream output) {
            this.id = id;
            this.transport = transport;
            this.output = output;
        }

        private boolean allowsApplication() {
            return revocationReason == null;
        }
    }
}
