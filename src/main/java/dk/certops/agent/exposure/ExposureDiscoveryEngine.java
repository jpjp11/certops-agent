package dk.certops.agent.exposure;

import dk.certops.agent.security.FieldAllowlistFilter;
import dk.certops.agent.security.NetworkValidator;
import dk.certops.agent.security.RedactionService;
import dk.certops.agent.transport.CloudClientService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class ExposureDiscoveryEngine {

    private static final Logger log = LoggerFactory.getLogger(ExposureDiscoveryEngine.class);

    private final CloudClientService cloudClient;
    private final boolean allowPublicTargets;
    private final RedactionService redactionService;
    private final FieldAllowlistFilter fieldAllowlistFilter;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public ExposureDiscoveryEngine(CloudClientService cloudClient, boolean allowPublicTargets,
                                   RedactionService redactionService,
                                   FieldAllowlistFilter fieldAllowlistFilter) {
        this.cloudClient = cloudClient;
        this.allowPublicTargets = allowPublicTargets;
        this.redactionService = redactionService;
        this.fieldAllowlistFilter = fieldAllowlistFilter;
    }

    public boolean isRunning() {
        return running.get();
    }

    @SuppressWarnings("unchecked")
    public void execute(Map<String, Object> config, String runId) {
        if (!running.compareAndSet(false, true)) {
            log.warn("Exposure discovery already running, skipping");
            return;
        }

        try {
            log.info("Starting exposure discovery run {}", runId);

            // Check scan window
            Map<String, Object> scanWindow = (Map<String, Object>) config.get("scan_window");
            if (!ScanWindowChecker.isWithinWindow(scanWindow)) {
                log.info("Outside scan window, skipping run {}", runId);
                reportComplete(runId, List.of(), null);
                return;
            }

            // Resolve network scopes to IP list
            List<String> scopes = (List<String>) config.getOrDefault("network_scopes", List.of());
            if (scopes.isEmpty()) {
                log.warn("No network_scopes configured, aborting run {}", runId);
                reportComplete(runId, List.of(), "no network_scopes configured");
                return;
            }

            // Validate scopes are within private address space
            if (!allowPublicTargets) {
                List<String> originalScopes = new ArrayList<>(scopes);
                scopes = scopes.stream()
                        .filter(s -> {
                            boolean ok = NetworkValidator.isPrivateCidr(s.trim());
                            if (!ok) log.warn("SECURITY: Rejected public scope from exposure discovery: {}", s);
                            return ok;
                        })
                        .collect(Collectors.toList());
                if (scopes.isEmpty()) {
                    log.warn("SECURITY: All scopes rejected (all public) for run {}, original scopes: {}", runId, originalScopes);
                    reportComplete(runId, List.of(), "all network_scopes rejected — only private/internal ranges are allowed");
                    return;
                }
            }

            int maxHostsPerRun = toInt(config.get("max_hosts_per_run"), 10000);
            List<String> hosts = ScopeResolver.resolve(scopes, maxHostsPerRun, allowPublicTargets);
            log.info("Resolved {} hosts from {} scopes", hosts.size(), scopes.size());

            if (hosts.isEmpty()) {
                reportComplete(runId, List.of(), null);
                return;
            }

            // Parse port list
            List<Integer> ports = parsePorts(config);

            // Port scanning config
            int maxHostsParallel = toInt(config.get("max_hosts_parallel"), 50);
            int maxPortsParallel = toInt(config.get("max_ports_parallel_per_host"), 20);
            int connectTimeoutMs = toInt(config.get("connect_timeout_ms"), 500);
            int retries = toInt(config.get("retries"), 1);

            PortScannerService portScanner = new PortScannerService(
                    maxHostsParallel, maxPortsParallel, connectTimeoutMs, retries);

            // Port scan with progress reporting
            Map<String, List<PortScannerService.OpenPort>> openPorts = portScanner.scan(
                    hosts, ports, pct -> {
                        try {
                            Map<String, Object> progress = new LinkedHashMap<>();
                            progress.put("run_id", runId);
                            progress.put("phase", "port_scan");
                            progress.put("percent", pct);
                            progress.put("hosts_total", hosts.size());
                            cloudClient.post("/api/collector/exposure/progress", progress);
                        } catch (Exception e) {
                            log.debug("Failed to report progress: {}", e.getMessage());
                        }
                    });

            log.info("Port scan complete: {} hosts with open ports out of {}", openPorts.size(), hosts.size());

            // Report fingerprinting phase start
            try {
                Map<String, Object> progress = new LinkedHashMap<>();
                progress.put("run_id", runId);
                progress.put("phase", "fingerprinting");
                progress.put("percent", 0);
                progress.put("hosts_with_ports", openPorts.size());
                cloudClient.post("/api/collector/exposure/progress", progress);
            } catch (Exception e) {
                log.debug("Failed to report fingerprint progress: {}", e.getMessage());
            }

            // Fingerprint open ports
            int fingerprintConcurrency = toInt(config.get("fingerprint_concurrency"), 20);
            FingerprintService fingerprintService = new FingerprintService(fingerprintConcurrency);
            Map<String, List<Map<String, Object>>> fingerprintResults = fingerprintService.fingerprint(openPorts);

            // Build results payload
            List<Map<String, Object>> hostResults = buildResults(openPorts, fingerprintResults);

            log.info("Exposure discovery run {} complete: {} hosts scanned, {} with open ports",
                    runId, hosts.size(), hostResults.size());

            reportComplete(runId, hostResults, null);

        } catch (Exception e) {
            log.error("Exposure discovery run {} failed: {}", runId, e.getMessage(), e);
            try {
                reportComplete(runId, List.of(), e.getMessage());
            } catch (Exception ex) {
                log.error("Failed to report completion: {}", ex.getMessage());
            }
        } finally {
            running.set(false);
        }
    }

    private List<Map<String, Object>> buildResults(
            Map<String, List<PortScannerService.OpenPort>> openPorts,
            Map<String, List<Map<String, Object>>> fingerprintResults) {

        List<Map<String, Object>> hosts = new ArrayList<>();

        for (Map.Entry<String, List<PortScannerService.OpenPort>> entry : openPorts.entrySet()) {
            String ip = entry.getKey();
            Map<String, Object> host = new LinkedHashMap<>();
            host.put("ip", ip);

            // Reverse DNS lookup — resolves IP to hostname if available.
            // Keep the real hostname locally for device classification, but redact it
            // (per configured patterns) before it is stored/egressed.
            String hostname = reverseDns(ip);
            if (hostname != null) host.put("hostname", redactionService.redactHostname(hostname));

            List<Map<String, Object>> portResults = new ArrayList<>();
            List<Map<String, Object>> fpForHost = fingerprintResults.getOrDefault(ip, List.of());

            // Index fingerprints by port
            Map<Integer, Map<String, Object>> fpByPort = new HashMap<>();
            for (Map<String, Object> fp : fpForHost) {
                Integer port = (Integer) fp.get("port");
                if (port != null) fpByPort.put(port, fp);
            }

            List<Integer> openPortNumbers = new ArrayList<>();
            for (PortScannerService.OpenPort op : entry.getValue()) {
                Map<String, Object> portData = new LinkedHashMap<>();
                portData.put("port", op.port);
                portData.put("proto", op.proto);
                portData.put("state", "open");
                portData.put("response_time_ms", op.responseTimeMs);

                Map<String, Object> fp = fpByPort.get(op.port);
                if (fp != null && fp.containsKey("fingerprint")) {
                    portData.put("fingerprint", fp.get("fingerprint"));
                }

                portResults.add(portData);
                openPortNumbers.add(op.port);
            }

            DeviceClassifier.Result classification = DeviceClassifier.classify(openPortNumbers, hostname, fpByPort);
            host.put("device_type", classification.deviceType);
            host.put("device_confidence", classification.confidence);
            if (classification.vendor != null) host.put("vendor", classification.vendor);
            if (classification.model != null) host.put("model", classification.model);
            host.put("device_evidence", classification.evidence);
            host.put("ports", portResults);
            hosts.add(host);
        }

        return hosts;
    }

    private String reverseDns(String ip) {
        try {
            // Use a thread with timeout to avoid blocking the scan on slow DNS
            String[] result = new String[1];
            Thread t = new Thread(() -> {
                try {
                    String name = InetAddress.getByName(ip).getHostName();
                    if (!name.equals(ip)) result[0] = name;
                } catch (Exception ignored) {}
            });
            t.setDaemon(true);
            t.start();
            t.join(1000);
            return result[0];
        } catch (Exception e) {
            return null;
        }
    }

    private void reportComplete(String runId, List<Map<String, Object>> hosts, String error) {
        try {
            // Defense-in-depth: strip every host/port record to the allowlisted fields
            // before egress, so no unexpected captured data leaves the network.
            List<Map<String, Object>> safeHosts = new ArrayList<>();
            for (Map<String, Object> h : hosts) {
                safeHosts.add(fieldAllowlistFilter.filterExposureHost(h));
            }
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("run_id", runId);
            payload.put("hosts", safeHosts);
            if (error != null) payload.put("error", error);
            cloudClient.post("/api/collector/exposure/complete", payload);
        } catch (Exception e) {
            log.error("Failed to report exposure completion: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private List<Integer> parsePorts(Map<String, Object> config) {
        Object portsObj = config.get("ports");
        if (portsObj instanceof List) {
            List<Integer> ports = new ArrayList<>();
            for (Object p : (List<?>) portsObj) {
                if (p instanceof Number) ports.add(((Number) p).intValue());
            }
            if (!ports.isEmpty()) return ports;
        }

        String profile = (String) config.getOrDefault("port_profile", "top100");
        return "top50".equalsIgnoreCase(profile) ? Top100Ports.TOP_50 : Top100Ports.TOP_100;
    }

    private int toInt(Object o, int def) {
        if (o instanceof Number) return ((Number) o).intValue();
        if (o instanceof String) {
            try { return Integer.parseInt((String) o); } catch (Exception e) { return def; }
        }
        return def;
    }
}
