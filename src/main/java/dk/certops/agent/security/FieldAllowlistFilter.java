package dk.certops.agent.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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

    // Allowlist for exposure-discovery host/port records sent to the cloud.
    private static final Set<String> EXPOSURE_HOST_ALLOWED = Set.of(
            "ip", "hostname", "device_type", "device_confidence",
            "vendor", "model", "device_evidence", "ports");
    private static final Set<String> EXPOSURE_PORT_ALLOWED = Set.of(
            "port", "proto", "state", "response_time_ms", "fingerprint");

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

    /**
     * Filter an exposure-discovery host record (and its nested port records) to the
     * allowlisted fields only — defense-in-depth so no unexpected captured data egresses.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> filterExposureHost(Map<String, Object> host) {
        Map<String, Object> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : host.entrySet()) {
            String key = entry.getKey();
            if (!EXPOSURE_HOST_ALLOWED.contains(key)) continue;
            if ("ports".equals(key) && entry.getValue() instanceof List<?> ports) {
                List<Object> filteredPorts = new ArrayList<>();
                for (Object p : ports) {
                    if (p instanceof Map<?, ?> portMap) {
                        Map<String, Object> portOut = new LinkedHashMap<>();
                        for (Map.Entry<?, ?> pe : portMap.entrySet()) {
                            if (EXPOSURE_PORT_ALLOWED.contains(String.valueOf(pe.getKey()))) {
                                portOut.put(String.valueOf(pe.getKey()), pe.getValue());
                            }
                        }
                        filteredPorts.add(portOut);
                    } else {
                        filteredPorts.add(p);
                    }
                }
                filtered.put("ports", filteredPorts);
            } else {
                filtered.put(key, entry.getValue());
            }
        }
        return filtered;
    }
}
