package dk.certops.agent.exposure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

public class PortScannerService {

    private static final Logger log = LoggerFactory.getLogger(PortScannerService.class);

    private final int maxHostsParallel;
    private final int maxPortsParallelPerHost;
    private final int connectTimeoutMs;
    private final int retries;

    public PortScannerService(int maxHostsParallel, int maxPortsParallelPerHost,
                              int connectTimeoutMs, int retries) {
        this.maxHostsParallel = Math.min(maxHostsParallel, 200);
        this.maxPortsParallelPerHost = Math.min(maxPortsParallelPerHost, 100);
        this.connectTimeoutMs = Math.min(connectTimeoutMs, 2000);
        this.retries = Math.max(0, Math.min(retries, 3));
    }

    public static class OpenPort {
        public final String host;
        public final int port;
        public final String proto = "tcp";
        public final long responseTimeMs;

        public OpenPort(String host, int port, long responseTimeMs) {
            this.host = host;
            this.port = port;
            this.responseTimeMs = responseTimeMs;
        }
    }

    public Map<String, List<OpenPort>> scan(List<String> hosts, List<Integer> ports,
                                            Consumer<Integer> progressCallback) {
        Map<String, List<OpenPort>> results = new ConcurrentHashMap<>();
        ExecutorService hostExecutor = Executors.newFixedThreadPool(
                Math.min(maxHostsParallel, hosts.size()));

        AtomicInteger completed = new AtomicInteger(0);
        AtomicInteger failures = new AtomicInteger(0);
        AtomicInteger attempts = new AtomicInteger(0);
        int totalHosts = hosts.size();

        // Randomize port order for jitter
        List<Integer> shuffledPorts = new ArrayList<>(ports);

        List<Future<?>> futures = new ArrayList<>();
        for (String host : hosts) {
            futures.add(hostExecutor.submit(() -> {
                List<Integer> localPorts = new ArrayList<>(shuffledPorts);
                Collections.shuffle(localPorts);

                List<OpenPort> openPorts = scanHost(host, localPorts, failures, attempts);
                if (!openPorts.isEmpty()) {
                    results.put(host, openPorts);
                }

                int done = completed.incrementAndGet();
                if (progressCallback != null && (done % Math.max(1, totalHosts / 10) == 0 || done == totalHosts)) {
                    progressCallback.accept((done * 100) / totalHosts);
                }
            }));
        }

        for (Future<?> f : futures) {
            try {
                f.get(5, TimeUnit.MINUTES);
            } catch (Exception e) {
                log.debug("Host scan timeout: {}", e.getMessage());
            }
        }

        hostExecutor.shutdown();
        try { hostExecutor.awaitTermination(30, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        log.info("Port scan completed: {} hosts, {} with open ports, {} total attempts, {} failures",
                totalHosts, results.size(), attempts.get(), failures.get());

        return results;
    }

    private List<OpenPort> scanHost(String host, List<Integer> ports,
                                    AtomicInteger globalFailures, AtomicInteger globalAttempts) {
        List<OpenPort> openPorts = new CopyOnWriteArrayList<>();
        ExecutorService portExecutor = Executors.newFixedThreadPool(
                Math.min(maxPortsParallelPerHost, ports.size()));

        List<Future<?>> futures = new ArrayList<>();
        for (int port : ports) {
            futures.add(portExecutor.submit(() -> {
                globalAttempts.incrementAndGet();
                long start = System.currentTimeMillis();
                boolean open = probePort(host, port);
                long elapsed = System.currentTimeMillis() - start;

                if (open) {
                    openPorts.add(new OpenPort(host, port, elapsed));
                } else {
                    globalFailures.incrementAndGet();
                }
            }));
        }

        for (Future<?> f : futures) {
            try {
                f.get(connectTimeoutMs * 3L, TimeUnit.MILLISECONDS);
            } catch (Exception e) {
                // Timeout
            }
        }

        portExecutor.shutdown();
        try { portExecutor.awaitTermination(10, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        return new ArrayList<>(openPorts);
    }

    private boolean probePort(String host, int port) {
        for (int attempt = 0; attempt <= retries; attempt++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
                return true;
            } catch (Exception e) {
                // Connection refused or timeout
            }
        }
        return false;
    }
}
