package dk.certops.agent.exposure;

import dk.certops.agent.security.NetworkValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

public class ScopeResolver {

    private static final Logger log = LoggerFactory.getLogger(ScopeResolver.class);

    private static final int MAX_HOSTS_PER_RANGE = 10000;

    public static List<String> resolve(List<String> scopes, int maxHostsPerRun) {
        return resolve(scopes, maxHostsPerRun, false);
    }

    public static List<String> resolve(List<String> scopes, int maxHostsPerRun, boolean allowPublic) {
        List<String> allHosts = new ArrayList<>();
        int limit = Math.min(maxHostsPerRun, MAX_HOSTS_PER_RANGE);

        for (String scope : scopes) {
            if (allHosts.size() >= limit) break;

            String trimmed = scope.trim();

            // Validate CIDR is within private address space
            if (!allowPublic && !NetworkValidator.isPrivateCidr(trimmed)) {
                log.warn("SECURITY: Rejected public/external scope from exposure scan: {}", trimmed);
                continue;
            }

            try {
                List<String> expanded = expandCidr(trimmed);

                // Defense in depth: filter individual IPs even if CIDR passed validation
                if (!allowPublic) {
                    expanded = NetworkValidator.filterPrivateOnly(expanded);
                }

                for (String ip : expanded) {
                    if (allHosts.size() >= limit) break;
                    allHosts.add(ip);
                }
            } catch (Exception e) {
                log.warn("Failed to resolve scope {}: {}", trimmed, e.getMessage());
            }
        }
        return allHosts;
    }

    static List<String> expandCidr(String cidr) throws Exception {
        List<String> ips = new ArrayList<>();

        if (!cidr.contains("/")) {
            ips.add(cidr);
            return ips;
        }

        String[] parts = cidr.split("/");
        byte[] addr = InetAddress.getByName(parts[0]).getAddress();
        int prefixLen = Integer.parseInt(parts[1]);

        if (addr.length != 4) {
            log.warn("IPv6 not supported: {}", cidr);
            return ips;
        }

        int ip = ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16) |
                 ((addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
        int mask = prefixLen == 0 ? 0 : (-1 << (32 - prefixLen));
        int network = ip & mask;
        int broadcast = network | ~mask;

        int hostCount = broadcast - network - 1;
        if (hostCount > MAX_HOSTS_PER_RANGE) {
            log.warn("CIDR {} has {} hosts, limiting to {}", cidr, hostCount, MAX_HOSTS_PER_RANGE);
            broadcast = network + MAX_HOSTS_PER_RANGE + 1;
        }

        for (int i = network + 1; i < broadcast; i++) {
            ips.add(String.format("%d.%d.%d.%d",
                    (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF));
        }
        return ips;
    }
}
