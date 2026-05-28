package dk.certops.agent.scanner;

import dk.certops.agent.config.AgentProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Performs DNS security checks: DANE/TLSA records, DNSSEC validation.
 * Uses dig command if available, with graceful degradation.
 */
@Component
public class DnsSecurityChecker {

    private static final Logger log = LoggerFactory.getLogger(DnsSecurityChecker.class);

    private final AgentProperties agentProperties;

    public DnsSecurityChecker(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;
    }

    /**
     * Run DNS security checks. Returns null if DNS checks are disabled.
     */
    public Map<String, Object> check(String host, int port) {
        if (!agentProperties.isCheckDnsSecurity()) {
            return null;
        }

        if (host == null || host.isEmpty() || isLikelyIp(host)) {
            return null;
        }

        Map<String, Object> result = new LinkedHashMap<>();

        // DANE/TLSA check
        result.put("dane_tlsa", checkDaneTlsa(host, port));

        // DNSSEC check
        result.put("dnssec", checkDnssec(host));

        return result;
    }

    private Map<String, Object> checkDaneTlsa(String host, int port) {
        Map<String, Object> dane = new LinkedHashMap<>();
        try {
            String tlsaName = "_" + port + "._tcp." + host;
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "TLSA", tlsaName);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith(";")) {
                        output.append(line).append("\n");
                    }
                }
            }

            boolean completed = process.waitFor(10, TimeUnit.SECONDS);
            if (!completed) process.destroyForcibly();

            boolean hasRecord = !output.toString().trim().isEmpty();
            dane.put("present", hasRecord);
            dane.put("query", tlsaName);
            if (hasRecord) {
                dane.put("record", output.toString().trim());
            }
        } catch (Exception e) {
            dane.put("present", false);
            dane.put("error", e.getMessage());
            log.debug("DANE/TLSA check failed for {}: {}", host, e.getMessage());
        }
        return dane;
    }

    private Map<String, Object> checkDnssec(String host) {
        Map<String, Object> dnssec = new LinkedHashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+dnssec", host);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            boolean completed = process.waitFor(10, TimeUnit.SECONDS);
            if (!completed) process.destroyForcibly();

            String fullOutput = output.toString();
            boolean hasAd = fullOutput.contains("flags:") && fullOutput.contains(" ad");
            boolean hasRrsig = fullOutput.contains("RRSIG");

            dnssec.put("validated", hasAd);
            dnssec.put("has_rrsig", hasRrsig);
        } catch (Exception e) {
            dnssec.put("validated", false);
            dnssec.put("error", e.getMessage());
            log.debug("DNSSEC check failed for {}: {}", host, e.getMessage());
        }
        return dnssec;
    }

    private boolean isLikelyIp(String host) {
        return host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || host.contains(":");
    }
}
