package dk.certops.agent.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates that IP addresses and CIDR ranges are within private/internal networks.
 * Used to prevent the agent from being weaponized to scan public infrastructure.
 */
public final class NetworkValidator {

    private static final Logger log = LoggerFactory.getLogger(NetworkValidator.class);

    private NetworkValidator() {}

    /**
     * Check if an IPv4 address string is a private/internal address.
     * Covers: RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8),
     * link-local (169.254/16), CGN/RFC6598 (100.64/10), IPv6 ULA + loopback.
     */
    public static boolean isPrivateIp(String ip) {
        if (ip == null || ip.isBlank()) return false;
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return isPrivateAddress(addr);
        } catch (Exception e) {
            log.debug("Failed to parse IP {}: {}", ip, e.getMessage());
            return false;
        }
    }

    /**
     * Check if all resolved addresses for a hostname are private.
     * Returns false if any resolved IP is public, or if resolution fails.
     */
    public static boolean isPrivateHost(String hostname) {
        if (hostname == null || hostname.isBlank()) return false;
        try {
            InetAddress[] addresses = InetAddress.getAllByName(hostname);
            if (addresses.length == 0) return false;
            for (InetAddress addr : addresses) {
                if (!isPrivateAddress(addr)) {
                    log.warn("Host {} resolves to public IP {}", hostname, addr.getHostAddress());
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            log.debug("Failed to resolve hostname {}: {}", hostname, e.getMessage());
            return false;
        }
    }

    /**
     * Check if an entire CIDR block falls within private address space.
     * Validates both the network address and the broadcast (last) address.
     */
    public static boolean isPrivateCidr(String cidr) {
        if (cidr == null || cidr.isBlank()) return false;
        try {
            if (!cidr.contains("/")) {
                return isPrivateIp(cidr);
            }
            String[] parts = cidr.split("/");
            byte[] addr = InetAddress.getByName(parts[0]).getAddress();
            if (addr.length != 4) {
                // IPv6 — check if ULA (fc00::/7) or loopback
                InetAddress a = InetAddress.getByName(parts[0]);
                return a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress();
            }

            int prefixLen = Integer.parseInt(parts[1]);
            if (prefixLen < 8 || prefixLen > 32) return false;

            int ip = toInt(addr);
            int mask = prefixLen == 0 ? 0 : (-1 << (32 - prefixLen));
            int network = ip & mask;
            int broadcast = network | ~mask;

            // Both network start and end must be private
            return isPrivateIpv4(network) && isPrivateIpv4(broadcast);
        } catch (Exception e) {
            log.debug("Failed to parse CIDR {}: {}", cidr, e.getMessage());
            return false;
        }
    }

    /**
     * Filter a list of IPs, returning only private ones.
     * Logs rejected public IPs at WARN level.
     */
    public static List<String> filterPrivateOnly(List<String> ips) {
        List<String> filtered = new ArrayList<>();
        for (String ip : ips) {
            if (isPrivateIp(ip)) {
                filtered.add(ip);
            } else {
                log.warn("Rejected public IP from scan scope: {}", ip);
            }
        }
        if (filtered.size() < ips.size()) {
            log.warn("Filtered out {} public IPs from scan scope (kept {})",
                    ips.size() - filtered.size(), filtered.size());
        }
        return filtered;
    }

    private static boolean isPrivateAddress(InetAddress addr) {
        // Loopback, link-local and any-local are NOT valid scan targets — scanning them
        // reaches the agent host itself or the cloud metadata endpoint (169.254.169.254).
        // They are explicitly excluded so a cloud-pushed config cannot redirect the agent there.
        if (addr.isLoopbackAddress()) return false;    // 127.0.0.0/8, ::1
        if (addr.isLinkLocalAddress()) return false;   // 169.254.0.0/16 (incl. metadata), fe80::/10
        if (addr.isAnyLocalAddress()) return false;    // 0.0.0.0
        if (addr.isMulticastAddress()) return false;

        if (addr.isSiteLocalAddress()) return true;    // 10/8, 172.16/12, 192.168/16

        byte[] bytes = addr.getAddress();
        if (bytes.length == 4) {
            return isPrivateIpv4(toInt(bytes));
        }
        // IPv6: check ULA (fc00::/7)
        if (bytes.length == 16) {
            return (bytes[0] & 0xFE) == 0xFC;  // fc00::/7
        }
        return false;
    }

    private static boolean isPrivateIpv4(int ip) {
        // NOTE: loopback (127/8), link-local (169.254/16) and 0.0.0.0/8 are intentionally
        // NOT treated as scannable — they are rejected in isPrivateAddress above and must
        // also be excluded here so CIDRs covering them are rejected by isPrivateCidr.
        // 10.0.0.0/8
        if ((ip & 0xFF000000) == 0x0A000000) return true;
        // 172.16.0.0/12
        if ((ip & 0xFFF00000) == 0xAC100000) return true;
        // 192.168.0.0/16
        if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
        // 100.64.0.0/10 (CGN / RFC6598)
        if ((ip & 0xFFC00000) == 0x64400000) return true;
        return false;
    }

    private static int toInt(byte[] addr) {
        return ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16)
                | ((addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
    }
}
