package dk.certops.agent.security;

import dk.certops.agent.config.AgentProperties;
import dk.certops.agent.dto.ChainCertDto;
import dk.certops.agent.dto.ScanResultDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Local redaction service — masks sensitive hostnames BEFORE data leaves the agent.
 */
@Service
public class RedactionService {

    private static final Logger log = LoggerFactory.getLogger(RedactionService.class);
    private static final String REDACTED = "[maskeret]";

    private final AgentProperties agentProperties;
    private final List<String> cloudPatterns = new CopyOnWriteArrayList<>();

    public RedactionService(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;
    }

    /**
     * Apply redaction to a scan result (mutates in place).
     */
    public void redact(ScanResultDto result) {
        if (!agentProperties.getRedaction().isEnabled()) return;

        boolean needsRedaction = false;

        // Check leaf CN
        if (matchesAnyPattern(result.getLeafSubjectCn())) {
            result.setLeafSubjectCn(REDACTED);
            needsRedaction = true;
        }

        // Check chain
        if (result.getChain() != null) {
            for (ChainCertDto cert : result.getChain()) {
                if (matchesAnyPattern(cert.getSubjectCn())) {
                    cert.setSubjectCn(REDACTED);
                    cert.setSubject(redactDn(cert.getSubject()));
                    needsRedaction = true;
                }
                if (cert.getSan() != null) {
                    List<String> redactedSans = new ArrayList<>();
                    for (String san : cert.getSan()) {
                        if (matchesAnyPattern(san)) {
                            redactedSans.add(REDACTED);
                            needsRedaction = true;
                        } else {
                            redactedSans.add(san);
                        }
                    }
                    cert.setSan(redactedSans);
                }
            }
        }

        if (needsRedaction) {
            log.debug("Redacted sensitive data from scan: {}", result.getEndpoint());
        }
    }

    /**
     * Redact a single hostname (e.g. from exposure-discovery reverse DNS) if it matches a
     * configured pattern. Returns {@code [maskeret]} on a match, otherwise the original value.
     */
    public String redactHostname(String hostname) {
        if (hostname == null) return null;
        if (!agentProperties.getRedaction().isEnabled()) return hostname;
        return matchesAnyPattern(hostname) ? REDACTED : hostname;
    }

    /**
     * Update cloud-pushed redaction patterns.
     */
    public void updateCloudPatterns(List<String> patterns) {
        cloudPatterns.clear();
        if (patterns != null) {
            cloudPatterns.addAll(patterns);
        }
        log.info("Cloud redaction patterns updated: {} patterns", cloudPatterns.size());
    }

    private boolean matchesAnyPattern(String hostname) {
        if (hostname == null || hostname.isBlank()) return false;
        String lower = hostname.toLowerCase();

        // Local patterns
        for (String pattern : agentProperties.getRedaction().getPatterns()) {
            if (matchesGlob(lower, pattern.toLowerCase())) return true;
        }

        // Cloud-pushed patterns
        for (String pattern : cloudPatterns) {
            if (matchesGlob(lower, pattern.toLowerCase())) return true;
        }

        return false;
    }

    private boolean matchesGlob(String hostname, String pattern) {
        if (!pattern.contains("*")) {
            return hostname.equals(pattern) || hostname.endsWith("." + pattern);
        }
        String regex = pattern.replace(".", "\\.").replace("*", ".*");
        try {
            return hostname.matches("(?i)" + regex);
        } catch (Exception e) {
            return false;
        }
    }

    private String redactDn(String dn) {
        if (dn == null) return null;
        return dn.replaceAll("CN=[^,]+", "CN=" + REDACTED);
    }
}
