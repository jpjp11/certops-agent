package dk.certops.agent.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Filters scan result maps to only include explicitly allowed fields.
 * Provides defense-in-depth: even if a scan captures extra data,
 * only allowlisted fields are sent to the cloud.
 */
@Component
public class FieldAllowlistFilter {

    private static final Logger log = LoggerFactory.getLogger(FieldAllowlistFilter.class);

    private static final Set<String> DEFAULT_ALLOWED = Set.of(
            "endpoint", "env", "tags", "status", "error",
            "negotiated_tls", "cipher_name", "cipher_version",
            "leaf_fp_sha256", "leaf_subject_cn", "leaf_issuer_cn",
            "leaf_valid_from", "leaf_valid_to",
            "chain", "tls_support",
            "http_headers", "dns_security", "ocsp_status"
    );

    /**
     * Filter a map to only contain allowed fields.
     */
    public Map<String, Object> filter(Map<String, Object> data) {
        Map<String, Object> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            if (DEFAULT_ALLOWED.contains(entry.getKey())) {
                filtered.put(entry.getKey(), entry.getValue());
            }
        }
        return filtered;
    }
}
