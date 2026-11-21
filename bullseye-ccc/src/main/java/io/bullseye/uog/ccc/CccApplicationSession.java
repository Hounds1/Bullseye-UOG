package io.bullseye.uog.ccc;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.bullseye.uog.ccc.CccProtocol.JoinRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/** Owns the concurrent work on one already admitted application connection. */
final class CccApplicationSession {
    private static final System.Logger LOGGER = System.getLogger(CccApplicationSession.class.getName());

    private final Socket transport;
    private final InputStream input;
    private final OutputStream output;
    private final JoinRequest join;
    private final CccServer.SessionHandler handler;
    private final Semaphore applicationSlots;
    private final ScheduledThreadPoolExecutor deadlines;
    private final long heartbeatNanos;
    private final Object state = new Object();
    private final Object writeLock;
    private final BooleanSupplier admitted;

    private volatile boolean active = true;
    private volatile boolean heartbeatExpired;
    private long heartbeatStartedAt;
    private long expectedPong;
    private boolean handling;
    private boolean responding;

    CccApplicationSession(Socket transport, InputStream input, OutputStream output, JoinRequest join,
            CccServer.SessionHandler handler, Semaphore applicationSlots,
            ScheduledThreadPoolExecutor deadlines, int heartbeatMillis, Object writeLock,
            BooleanSupplier admitted) {
        this.transport = transport;
        this.input = input;
        this.output = output;
        this.join = join;
        this.handler = handler;
        this.applicationSlots = applicationSlots;
        this.deadlines = deadlines;
        this.writeLock = writeLock;
        this.admitted = admitted;
        heartbeatNanos = TimeUnit.MILLISECONDS.toNanos(heartbeatMillis);
    }

    void run() throws IOException, InterruptedException {
        Thread.ofVirtual().name("bullseye-ccc-heartbeat").start(this::heartbeatLoop);
        try {
            while (sessionActive()) {
                ObjectNode frame = CccProtocol.readFrame(input);
                String type = CccProtocol.type(frame);
                if ("PONG".equals(type)) {
                    receivePong(frame);
                } else if (CccProtocol.controlType(type)) {
                    throw new IOException("Unexpected CCC control message after admission");
                } else {
                    dispatch(frame);
                }
            }
        } catch (IOException failure) {
            if (!heartbeatExpired) {
                throw failure;
            }
        } finally {
            stop();
        }
        if (heartbeatExpired) {
            throw new SocketTimeoutException("CCC heartbeat timed out");
        }
    }

    private void receivePong(ObjectNode frame) throws IOException {
        synchronized (state) {
            if (expectedPong == 0) {
                throw new IOException("Unexpected CCC heartbeat reply");
            }
            CccProtocol.requirePongSequence(frame, expectedPong);
            if (System.nanoTime() - heartbeatStartedAt >= heartbeatNanos) {
                throw new SocketTimeoutException("CCC heartbeat timed out");
            }
            expectedPong = 0;
            state.notifyAll();
        }
    }

    private void dispatch(ObjectNode frame) throws IOException, InterruptedException {
        synchronized (state) {
            // A well-behaved peer can read the ACK before the local TLS write returns.
            while (responding && sessionActive()) {
                state.wait();
            }
            if (!admitted.getAsBoolean()) {
                return;
            }
            if (!sessionActive() || handling || !applicationSlots.tryAcquire()) {
                throw new IOException("CCC application frame capacity exceeded");
            }
            handling = true;
        }
        try {
            Thread.ofVirtual().name("bullseye-ccc-application").start(() -> handle(frame));
        } catch (RuntimeException | Error failure) {
            endHandling();
            throw failure;
        }
    }

    private void handle(ObjectNode frame) {
        try {
            if (!handlerActive()) {
                return;
            }
            ObjectNode response = handler.handle(join.nodeId(), join.runId(), frame, this::handlerActive);
            synchronized (state) {
                if (!handlerActive()) {
                    return;
                }
                responding = true;
            }
            write(() -> {
                if (admitted.getAsBoolean()) {
                    CccProtocol.writeApplicationResponse(output, response);
                }
            });
        } catch (IOException failure) {
            stop();
        } catch (RuntimeException failure) {
            LOGGER.log(System.Logger.Level.ERROR, "CCC application handler failed", failure);
            stop();
        } finally {
            endHandling();
        }
    }

    private void endHandling() {
        synchronized (state) {
            applicationSlots.release();
            handling = false;
            responding = false;
            state.notifyAll();
        }
    }

    private void heartbeatLoop() {
        try {
            for (long sequence = 1; sessionActive(); sequence++) {
                sendHeartbeat(sequence);
            }
        } catch (InterruptedException stopping) {
            Thread.currentThread().interrupt();
        } catch (IOException failure) {
            // The reader observes the closed connection and records the session end.
        } finally {
            stop();
        }
    }

    private void sendHeartbeat(long sequence) throws IOException, InterruptedException {
        long startedAt = System.nanoTime();
        synchronized (state) {
            heartbeatStartedAt = startedAt;
            expectedPong = sequence;
        }
        ScheduledFuture<?> deadline = schedule(() -> expireHeartbeat(sequence));
        try {
            write(() -> CccProtocol.writePing(output, sequence));
            synchronized (state) {
                while (sessionActive() && expectedPong != 0) {
                    state.wait();
                }
            }
        } finally {
            deadline.cancel(false);
        }
        synchronized (state) {
            while (sessionActive()) {
                long remaining = heartbeatNanos - (System.nanoTime() - startedAt);
                if (remaining <= 0) {
                    return;
                }
                TimeUnit.NANOSECONDS.timedWait(state, remaining);
            }
        }
    }

    private void expireHeartbeat(long sequence) {
        synchronized (state) {
            if (!sessionActive() || expectedPong != sequence) {
                return;
            }
            heartbeatExpired = true;
            active = false;
            state.notifyAll();
        }
        closeTransport();
    }

    private void write(WriteOperation operation) throws IOException {
        synchronized (writeLock) {
            if (!sessionActive()) {
                throw new IOException("CCC application session closed");
            }
            ScheduledFuture<?> deadline = schedule(this::stop);
            try {
                operation.run();
            } finally {
                deadline.cancel(false);
            }
        }
    }

    private ScheduledFuture<?> schedule(Runnable expiration) throws IOException {
        try {
            return deadlines.schedule(expiration, heartbeatNanos, TimeUnit.NANOSECONDS);
        } catch (RejectedExecutionException failure) {
            throw new IOException("CCC is closing");
        }
    }

    private boolean sessionActive() {
        return active && !transport.isClosed();
    }

    private boolean handlerActive() {
        return sessionActive() && admitted.getAsBoolean();
    }

    private void stop() {
        synchronized (state) {
            active = false;
            state.notifyAll();
        }
        closeTransport();
    }

    private void closeTransport() {
        try {
            transport.close();
        } catch (IOException failure) {
            // The reader and writer independently leave the session on failure.
        }
    }

    @FunctionalInterface
    private interface WriteOperation {
        void run() throws IOException;
    }
}
