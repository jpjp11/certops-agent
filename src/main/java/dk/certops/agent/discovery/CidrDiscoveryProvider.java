package dk.certops.agent.discovery;

import dk.certops.agent.config.AgentProperties;
import dk.certops.agent.security.NetworkValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

@Component
public class CidrDiscoveryProvider {

    private static final Logger log = LoggerFactory.getLogger(CidrDiscoveryProvider.class);

    private final AgentProperties agentProperties;

    public CidrDiscoveryProvider(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;
    }

    /**
     * Discover TLS endpoints in configured CIDR ranges. Default OFF.
     */
    public List<AgentProperties.Target> discover() {
        AgentProperties.CidrDiscovery config = agentProperties.getCidrDiscovery();
        if (!config.isEnabled() || config.getRanges() == null || config.getRanges().isEmpty()) {
            return List.of();
        }

        List<Integer> ports = parsePorts(config.getPorts());
        Semaphore rateLimiter = new Semaphore(config.getRateLimit());
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(config.getConcurrency(), 10));

        List<AgentProperties.Target> discovered = new CopyOnWriteArrayList<>();
        List<Future<?>> futures = new ArrayList<>();

        boolean allowPublic = agentProperties.isAllowPublicTargets();

        for (String cidr : config.getRanges()) {
            // Validate CIDR is within private address space
            if (!allowPublic && !NetworkValidator.isPrivateCidr(cidr)) {
                log.warn("SECURITY: Rejected public/external CIDR range from discovery: {}", cidr);
                continue;
            }

            try {
                List<String> ips = expandCidr(cidr);

                // Defense in depth: filter individual IPs
                if (!allowPublic) {
                    ips = NetworkValidator.filterPrivateOnly(ips);
                }

                for (String ip : ips) {
                    for (int port : ports) {
                        futures.add(executor.submit(() -> {
                            try {
                                rateLimiter.acquire();
                                try {
                                    if (probePort(ip, port, 3000)) {
                                        AgentProperties.Target t = new AgentProperties.Target();
                                        t.setHost(ip);
                                        t.setPort(port);
                                        t.setEnv("discovered");
                                        discovered.add(t);
                                        log.debug("Discovered: {}:{}", ip, port);
                                    }
                                } finally {
                                    rateLimiter.release();
                                }
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                            }
                        }));
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to expand CIDR {}: {}", cidr, e.getMessage());
            }
        }

        for (Future<?> f : futures) {
            try {
                f.get(60, TimeUnit.SECONDS);
            } catch (Exception e) {
                log.debug("CIDR probe timeout: {}", e.getMessage());
            }
        }

        executor.shutdown();
        log.info("CIDR discovery completed: {} endpoints found", discovered.size());
        return discovered;
    }

    private boolean probePort(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> expandCidr(String cidr) throws Exception {
        List<String> ips = new ArrayList<>();
        if (!cidr.contains("/")) {
            ips.add(cidr);
            return ips;
        }

        String[] parts = cidr.split("/");
        byte[] addr = InetAddress.getByName(parts[0]).getAddress();
        int prefixLen = Integer.parseInt(parts[1]);

        if (addr.length != 4) {
            log.warn("IPv6 CIDR not supported: {}", cidr);
            return ips;
        }

        int ip = ((addr[0] & 0xFF) << 24) | ((addr[1] & 0xFF) << 16) |
                 ((addr[2] & 0xFF) << 8) | (addr[3] & 0xFF);
        int mask = prefixLen == 0 ? 0 : (-1 << (32 - prefixLen));
        int network = ip & mask;
        int broadcast = network | ~mask;

        // Skip network and broadcast addresses, limit to /20 (4096 hosts)
        int hostCount = broadcast - network - 1;
        if (hostCount > 4096) {
            log.warn("CIDR {} too large ({} hosts), limiting to /20", cidr, hostCount);
            broadcast = network + 4097;
        }

        for (int i = network + 1; i < broadcast; i++) {
            ips.add(String.format("%d.%d.%d.%d",
                    (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF));
        }
        return ips;
    }

    private List<Integer> parsePorts(String portsStr) {
        List<Integer> ports = new ArrayList<>();
        if (portsStr == null || portsStr.isBlank()) {
            ports.add(443);
            return ports;
        }
        for (String p : portsStr.split(",")) {
            try {
                ports.add(Integer.parseInt(p.trim()));
            } catch (NumberFormatException e) {
                log.warn("Invalid port: {}", p);
            }
        }
        return ports;
    }
}
