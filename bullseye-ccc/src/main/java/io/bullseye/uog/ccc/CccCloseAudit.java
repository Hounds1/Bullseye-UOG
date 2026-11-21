package io.bullseye.uog.ccc;

import java.io.IOException;
import java.util.ArrayDeque;

/** Retries frozen session-close records off the connection cleanup path. */
final class CccCloseAudit {
    private static final System.Logger LOGGER = System.getLogger(CccCloseAudit.class.getName());
    private static final long RETRY_MILLIS = 1_000;

    private final CccAuditHandoff.Sink append;
    private final ArrayDeque<String> pending = new ArrayDeque<>();
    private final Thread worker = Thread.ofPlatform().daemon().name("bullseye-ccc-close-audit")
            .unstarted(this::run);
    private boolean finishing;

    CccCloseAudit(CccAuditHandoff.Sink append) {
        this.append = append;
    }

    void start() {
        worker.start();
    }

    synchronized void offer(String record) {
        pending.addLast(record);
        notifyAll();
    }

    synchronized void finish() {
        finishing = true;
        notifyAll();
    }

    void awaitDrain() throws InterruptedException {
        worker.join(RETRY_MILLIS);
    }

    private void run() {
        try {
            String record;
            boolean failed = false;
            while ((record = awaitRecord()) != null) {
                try {
                    append.store(record);
                    synchronized (this) {
                        pending.removeFirst();
                    }
                    failed = false;
                } catch (IOException failure) {
                    if (!failed) {
                        LOGGER.log(System.Logger.Level.WARNING, "CCC session close audit delayed", failure);
                        failed = true;
                    }
                    synchronized (this) {
                        if (finishing) {
                            // The durable admission record permits recovery after restart.
                            return;
                        }
                        wait(RETRY_MILLIS);
                    }
                }
            }
        } catch (InterruptedException stopping) {
            Thread.currentThread().interrupt();
        }
    }

    private synchronized String awaitRecord() throws InterruptedException {
        while (pending.isEmpty() && !finishing) {
            wait();
        }
        return pending.peekFirst();
    }
}
