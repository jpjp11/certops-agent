package dk.certops.agent.scheduler;

import dk.certops.agent.config.AgentProperties;
import dk.certops.agent.discovery.CidrDiscoveryProvider;
import dk.certops.agent.discovery.StaticTargetProvider;
import dk.certops.agent.dto.ScanResultDto;
import dk.certops.agent.exposure.ExposureDiscoveryEngine;
import dk.certops.agent.scanner.HttpHeaderChecker;
import dk.certops.agent.scanner.DnsSecurityChecker;
import dk.certops.agent.scanner.OcspCrlChecker;
import dk.certops.agent.scanner.TlsScannerService;
import dk.certops.agent.security.RedactionService;
import dk.certops.agent.transport.CloudClientService;
import dk.certops.agent.transport.DeliveryLog;
import dk.certops.agent.transport.LocalSpoolService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class AgentSchedulerService {

    private static final Logger log = LoggerFactory.getLogger(AgentSchedulerService.class);

    /**
     * Agent version, read from the jar manifest (Implementation-Version, stamped by the
     * Spring Boot build plugin) — the same source Spring Boot uses for its "v1.4.0" startup
     * line, so it is always correct without a hardcoded constant to keep in sync.
     */
    static final String AGENT_VERSION = resolveAgentVersion();

    private static String resolveAgentVersion() {
        Package p = dk.certops.agent.CertopsAgentApplication.class.getPackage();
        String v = p != null ? p.getImplementationVersion() : null;
        return (v != null && !v.isBlank()) ? v : "unknown";
    }

    private final AgentProperties agentProperties;
    private final StaticTargetProvider staticTargetProvider;
    private final CidrDiscoveryProvider cidrDiscoveryProvider;
    private final TlsScannerService tlsScannerService;
    private final HttpHeaderChecker httpHeaderChecker;
    private final DnsSecurityChecker dnsSecurityChecker;
    private final OcspCrlChecker ocspCrlChecker;
    private final RedactionService redactionService;
    private final CloudClientService cloudClientService;
    private final LocalSpoolService localSpoolService;
    private final DeliveryLog deliveryLog;
    private final ObjectMapper objectMapper;

    private final AtomicReference<Instant> lastScanTime = new AtomicReference<>();
    private final AtomicReference<Instant> lastConfigPull = new AtomicReference<>();

    private final ExposureDiscoveryEngine exposureEngine;
    private volatile String lastExposureRunId = null;
    private volatile String lastKnownScopeHash = null;
    private static final String SCOPE_HASH_FILE = "/var/certops-agent/spool/.scope-hash";

    public AgentSchedulerService(AgentProperties agentProperties,
                                 StaticTargetProvider staticTargetProvider,
                                 CidrDiscoveryProvider cidrDiscoveryProvider,
                                 TlsScannerService tlsScannerService,
                                 HttpHeaderChecker httpHeaderChecker,
                                 DnsSecurityChecker dnsSecurityChecker,
                                 OcspCrlChecker ocspCrlChecker,
                                 RedactionService redactionService,
                                 dk.certops.agent.security.FieldAllowlistFilter fieldAllowlistFilter,
                                 CloudClientService cloudClientService,
                                 LocalSpoolService localSpoolService,
                                 DeliveryLog deliveryLog,
                                 ObjectMapper objectMapper) {
        this.agentProperties = agentProperties;
        this.staticTargetProvider = staticTargetProvider;
        this.cidrDiscoveryProvider = cidrDiscoveryProvider;
        this.tlsScannerService = tlsScannerService;
        this.httpHeaderChecker = httpHeaderChecker;
        this.dnsSecurityChecker = dnsSecurityChecker;
        this.ocspCrlChecker = ocspCrlChecker;
        this.redactionService = redactionService;
        this.cloudClientService = cloudClientService;
        this.localSpoolService = localSpoolService;
        this.deliveryLog = deliveryLog;
        this.objectMapper = objectMapper;
        this.exposureEngine = new ExposureDiscoveryEngine(cloudClientService, agentProperties.isAllowPublicTargets(),
                redactionService, fieldAllowlistFilter);

        // Security posture logging + cloud alert for non-default configuration
        if (agentProperties.isAllowPublicTargets()) {
            log.warn("SECURITY WARNING: allow-public-targets is ENABLED — agent will scan non-private IPs. This is a security risk.");
            Thread alertThread = new Thread(() -> {
                Map<String, Object> alert = new LinkedHashMap<>();
                alert.put("event", "ALLOW_PUBLIC_TARGETS_ENABLED");
                alert.put("severity", "HIGH");
                alert.put("message", "allow-public-targets is enabled on this agent — agent may scan non-private IP addresses");
                alert.put("timestamp", Instant.now().toString());
                for (int attempt = 1; attempt <= 3; attempt++) {
                    try {
                        cloudClientService.post("/api/collector/security-event", alert);
                        log.info("Sent allow-public-targets alert to cloud");
                        return;
                    } catch (Exception e) {
                        log.warn("allow-public-targets alert attempt {}/3 failed: {}", attempt, e.getMessage());
                        if (attempt < 3) {
                            try { Thread.sleep(10_000L * attempt); } catch (InterruptedException ie) { return; }
                        }
                    }
                }
                log.warn("Failed to send allow-public-targets alert after 3 attempts");
            }, "allow-public-alert");
            alertThread.setDaemon(true);
            alertThread.start();
        } else {
            log.info("Private network enforcement enabled — agent will only scan RFC1918/loopback/link-local/CGN addresses");
        }

        // Load persisted scope hash for integrity check across restarts
        try {
            Path hashFile = Paths.get(SCOPE_HASH_FILE);
            if (Files.exists(hashFile)) {
                lastKnownScopeHash = Files.readString(hashFile).trim();
                log.info("Loaded persisted scope hash: {}", lastKnownScopeHash);
            }
        } catch (Exception e) {
            log.debug("Could not load persisted scope hash: {}", e.getMessage());
        }
    }

    /**
     * Heartbeat — sends periodic status to cloud.
     */
    @Scheduled(fixedDelayString = "${certops.agent.heartbeat-interval-seconds:60}000")
    public void heartbeat() {
        if (agentProperties.getApiKey() == null || agentProperties.getApiKey().isBlank()) {
            log.warn("No API key configured — skipping heartbeat");
            return;
        }

        try {
            Map<String, Object> diagnostics = new LinkedHashMap<>();
            diagnostics.put("agent_version", AGENT_VERSION);
            try {
                diagnostics.put("hostname", InetAddress.getLocalHost().getHostName());
                diagnostics.put("ip_address", InetAddress.getLocalHost().getHostAddress());
            } catch (Exception e) {
                log.debug("Could not resolve local hostname: {}", e.getMessage());
            }
            diagnostics.put("endpoint_count", staticTargetProvider.getTargets().size());
            diagnostics.put("queue_size", localSpoolService.getQueueSize());
            diagnostics.put("last_scan", lastScanTime.get() != null ? lastScanTime.get().toString() : null);
            diagnostics.put("connectivity", cloudClientService.isReachable());
            diagnostics.put("allow_public_targets", agentProperties.isAllowPublicTargets());

            // Memory info
            Runtime rt = Runtime.getRuntime();
            diagnostics.put("memory_used_mb", (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024));
            diagnostics.put("memory_max_mb", rt.maxMemory() / (1024 * 1024));

            cloudClientService.post("/api/collector/heartbeat", diagnostics);
            log.debug("Heartbeat sent");
        } catch (Exception e) {
            log.warn("Heartbeat failed: {}", e.getMessage());
        }
    }

    /**
     * Scan cycle — scans all targets and uploads results.
     */
    @Scheduled(fixedDelayString = "${certops.agent.scan-interval-seconds:300}000",
               initialDelayString = "10000")
    public void scanCycle() {
        if (agentProperties.getApiKey() == null || agentProperties.getApiKey().isBlank()) {
            log.warn("No API key configured — skipping scan cycle");
            return;
        }

        List<AgentProperties.Target> targets = staticTargetProvider.getTargets();

        // CIDR discovery (default OFF)
        if (agentProperties.getCidrDiscovery().isEnabled()) {
            List<AgentProperties.Target> discovered = cidrDiscoveryProvider.discover();
            targets = new ArrayList<>(targets);
            targets.addAll(discovered);
        }

        if (targets.isEmpty()) {
            log.info("No targets configured — skipping scan");
            return;
        }

        log.info("Starting scan cycle: {} targets", targets.size());

        List<ScanResultDto> results = new ArrayList<>();
        for (AgentProperties.Target target : targets) {
            try {
                ScanResultDto result = tlsScannerService.scan(target);

                // HTTP header check (only for successful scans)
                if (agentProperties.isCheckHttpHeaders() && "OK".equals(result.getStatus())) {
                    try {
                        result.setHttpHeaders(httpHeaderChecker.check(target.getHost(), target.getPort()));
                    } catch (Exception e) {
                        log.debug("HTTP header check failed for {}: {}", target.toEndpoint(), e.getMessage());
                    }
                }

                // DNS security check (only for successful scans, opt-in)
                if (agentProperties.isCheckDnsSecurity() && "OK".equals(result.getStatus())) {
                    try {
                        var dnsResult = dnsSecurityChecker.check(target.getHost(), target.getPort());
                        if (dnsResult != null) {
                            result.setDnsSecurity(dnsResult);
                        }
                    } catch (Exception e) {
                        log.debug("DNS security check failed for {}: {}", target.toEndpoint(), e.getMessage());
                    }
                }

                // OCSP check (only if enabled and certs available)
                if (agentProperties.isCheckOcsp() && result.getRawCertificates() != null
                        && result.getRawCertificates().size() >= 2) {
                    try {
                        result.setOcspStatus(ocspCrlChecker.checkOcsp(result.getRawCertificates()));
                    } catch (Exception e) {
                        log.debug("OCSP check failed for {}: {}", target.toEndpoint(), e.getMessage());
                        result.setOcspStatus("ERROR: " + e.getMessage());
                    }
                }

                // Apply local redaction BEFORE anything else
                redactionService.redact(result);

                // Clear raw certificates before serialization (they're @JsonIgnore but clean up memory)
                result.setRawCertificates(null);

                results.add(result);
                log.debug("Scanned {} -> {}", target.toEndpoint(), result.getStatus());
            } catch (Exception e) {
                log.error("Scan error for {}: {}", target.toEndpoint(), e.getMessage());
            }
        }

        lastScanTime.set(Instant.now());

        if (results.isEmpty()) {
            log.info("No scan results to upload");
            return;
        }

        // Upload to cloud
        uploadResults(results);

        // Retry spooled files
        retrySpooled();
    }

    /**
     * Config pull — fetches cloud-pushed configuration.
     */
    @Scheduled(fixedDelayString = "${certops.agent.config-pull-interval-seconds:300}000",
               initialDelayString = "5000")
    @SuppressWarnings("unchecked")
    public void configPull() {
        if (agentProperties.getApiKey() == null || agentProperties.getApiKey().isBlank()) return;

        try {
            Map<String, Object> response = cloudClientService.get("/api/collector/config");
            Object configObj = response.get("config");
            if (configObj == null) return;

            String configStr = configObj instanceof String ? (String) configObj :
                    objectMapper.writeValueAsString(configObj);
            if (configStr == null || configStr.isBlank() || "null".equals(configStr)) return;

            Map<String, Object> config = objectMapper.readValue(configStr, Map.class);

            // Apply targets
            Object targetsObj = config.get("targets");
            if (targetsObj instanceof List) {
                List<Map<String, Object>> targetMaps = (List<Map<String, Object>>) targetsObj;
                List<AgentProperties.Target> cloudTargets = new ArrayList<>();
                for (Map<String, Object> tm : targetMaps) {
                    AgentProperties.Target t = new AgentProperties.Target();
                    t.setHost(String.valueOf(tm.get("host")));
                    t.setPort(tm.containsKey("port") ? ((Number) tm.get("port")).intValue() : 443);
                    if (tm.containsKey("env")) t.setEnv(String.valueOf(tm.get("env")));
                    cloudTargets.add(t);
                }
                staticTargetProvider.updateCloudTargets(cloudTargets);
            }

            // Apply redaction patterns
            Object patternsObj = config.get("redaction_patterns");
            if (patternsObj instanceof List) {
                redactionService.updateCloudPatterns((List<String>) patternsObj);
            }

            // Apply scan interval
            if (config.containsKey("scan_interval_seconds")) {
                try {
                    int interval = ((Number) config.get("scan_interval_seconds")).intValue();
                    agentProperties.setScanIntervalSeconds(interval);
                } catch (Exception e) {
                    log.warn("Invalid scan_interval_seconds in config: {}", e.getMessage());
                }
            }

            // Detect and audit network_scopes changes
            checkScopeIntegrity(config);

            // Check for exposure discovery trigger
            checkExposureDiscovery(config);

            lastConfigPull.set(Instant.now());
            log.info("Config pulled and applied");
        } catch (Exception e) {
            log.debug("Config pull failed: {}", e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private void checkExposureDiscovery(Map<String, Object> config) {
        if (!agentProperties.getExposureDiscovery().isEnabled()) return;

        Object edObj = config.get("exposure_discovery");
        if (!(edObj instanceof Map)) return;

        Map<String, Object> ed = (Map<String, Object>) edObj;
        Object rtObj = ed.get("runtime");
        if (!(rtObj instanceof Map)) return;

        Map<String, Object> runtime = (Map<String, Object>) rtObj;
        String status = (String) runtime.get("status");
        String runId = (String) runtime.get("run_id");

        if ("RUNNING".equals(status) && runId != null && !runId.equals(lastExposureRunId)) {
            if (exposureEngine.isRunning()) {
                log.debug("Exposure discovery already running locally, skipping new run {}", runId);
                return;
            }

            lastExposureRunId = runId;
            log.info("Detected exposure discovery run request: {}", runId);

            // Launch in separate thread
            Thread thread = new Thread(() -> exposureEngine.execute(ed, runId),
                    "exposure-discovery-" + runId);
            thread.setDaemon(true);
            thread.start();
        }
    }

    /**
     * Spool retry — attempts to deliver previously spooled scan batches.
     */
    @Scheduled(fixedDelayString = "${certops.agent.spool.retry-interval-seconds:60}000",
               initialDelayString = "30000")
    public void retrySpooled() {
        List<Path> spooled = localSpoolService.getSpooledFiles();
        if (spooled.isEmpty()) return;

        log.info("Retrying {} spooled batches", spooled.size());

        for (Path file : spooled) {
            try {
                Map<String, Object> batch = localSpoolService.read(file);
                cloudClientService.post("/api/collector/scans", batch);
                localSpoolService.remove(file);
                deliveryLog.recordRetrySuccess(file.getFileName().toString());
            } catch (Exception e) {
                log.debug("Retry failed for {}: {}", file.getFileName(), e.getMessage());
                break; // Stop retrying if cloud is still down
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void checkScopeIntegrity(Map<String, Object> config) {
        try {
            Object edObj = config.get("exposure_discovery");
            if (!(edObj instanceof Map)) return;
            Map<String, Object> ed = (Map<String, Object>) edObj;
            Object scopesObj = ed.get("network_scopes");
            if (!(scopesObj instanceof List)) return;

            List<String> scopes = new ArrayList<>();
            for (Object s : (List<?>) scopesObj) {
                scopes.add(String.valueOf(s));
            }
            Collections.sort(scopes);
            String currentHash = computeScopeHash(scopes);

            if (lastKnownScopeHash == null) {
                lastKnownScopeHash = currentHash;
                return;
            }

            if (!lastKnownScopeHash.equals(currentHash)) {
                String previousHash = lastKnownScopeHash;
                lastKnownScopeHash = currentHash;

                log.warn("SECURITY: network_scopes changed — previous hash={}, new hash={}, new scopes={}",
                        previousHash, currentHash, scopes);

                // Persist new hash so integrity survives restarts
                try {
                    Path hashFile = Paths.get(SCOPE_HASH_FILE);
                    Files.createDirectories(hashFile.getParent());
                    Files.writeString(hashFile, currentHash, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.SYNC);
                } catch (Exception e) {
                    log.warn("Failed to persist scope hash: {}", e.getMessage());
                }

                Map<String, Object> event = new LinkedHashMap<>();
                event.put("event", "SCOPE_CHANGE");
                event.put("previous_hash", previousHash);
                event.put("current_hash", currentHash);
                event.put("new_scopes", scopes);
                event.put("timestamp", Instant.now().toString());
                try {
                    cloudClientService.post("/api/collector/security-event", event);
                } catch (Exception e) {
                    log.warn("Failed to report scope change to cloud: {}", e.getMessage());
                }
            } else {
                // Persist on first successful check too (in case file was missing)
                try {
                    Path hashFile = Paths.get(SCOPE_HASH_FILE);
                    if (!Files.exists(hashFile)) {
                        Files.createDirectories(hashFile.getParent());
                        Files.writeString(hashFile, currentHash, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.SYNC);
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            log.debug("Scope integrity check failed: {}", e.getMessage());
        }
    }

    private String computeScopeHash(List<String> sortedScopes) {
        try {
            String joined = String.join("|", sortedScopes);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(joined.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return String.valueOf(sortedScopes.hashCode());
        }
    }

    private void uploadResults(List<ScanResultDto> results) {
        try {
            Map<String, Object> batch = new LinkedHashMap<>();
            batch.put("scans", results);

            cloudClientService.post("/api/collector/scans", batch);
            deliveryLog.recordSuccess(results.size());
        } catch (Exception e) {
            log.warn("Upload failed, spooling: {}", e.getMessage());

            // Spool for retry
            Map<String, Object> batch = new LinkedHashMap<>();
            batch.put("scans", results);
            localSpoolService.spool(batch);
            deliveryLog.recordSpooled(results.size());
        }
    }
}
