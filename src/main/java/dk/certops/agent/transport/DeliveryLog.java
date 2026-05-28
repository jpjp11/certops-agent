package dk.certops.agent.transport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * In-memory log of upload attempts (success/fail/retry).
 * Keeps the last 100 entries for diagnostics.
 */
@Component
public class DeliveryLog {

    private static final Logger log = LoggerFactory.getLogger(DeliveryLog.class);
    private static final int MAX_ENTRIES = 100;

    private final ConcurrentLinkedDeque<Entry> entries = new ConcurrentLinkedDeque<>();

    public void recordSuccess(int scanCount) {
        add(new Entry(Instant.now(), "SUCCESS", scanCount, null));
        log.info("Delivery success: {} scans uploaded", scanCount);
    }

    public void recordFailure(int scanCount, String error) {
        add(new Entry(Instant.now(), "FAILURE", scanCount, error));
        log.warn("Delivery failure: {} scans, error: {}", scanCount, error);
    }

    public void recordSpooled(int scanCount) {
        add(new Entry(Instant.now(), "SPOOLED", scanCount, null));
        log.info("Delivery spooled: {} scans queued for retry", scanCount);
    }

    public void recordRetrySuccess(String filename) {
        add(new Entry(Instant.now(), "RETRY_SUCCESS", 0, filename));
        log.info("Retry success: {}", filename);
    }

    public List<Entry> getRecentEntries() {
        return new ArrayList<>(entries);
    }

    private void add(Entry entry) {
        entries.addFirst(entry);
        while (entries.size() > MAX_ENTRIES) {
            entries.removeLast();
        }
    }

    public static class Entry {
        private final Instant timestamp;
        private final String status;
        private final int scanCount;
        private final String detail;

        public Entry(Instant timestamp, String status, int scanCount, String detail) {
            this.timestamp = timestamp;
            this.status = status;
            this.scanCount = scanCount;
            this.detail = detail;
        }

        public Instant getTimestamp() { return timestamp; }
        public String getStatus() { return status; }
        public int getScanCount() { return scanCount; }
        public String getDetail() { return detail; }
    }
}
