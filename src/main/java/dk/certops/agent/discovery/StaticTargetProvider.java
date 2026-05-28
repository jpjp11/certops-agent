package dk.certops.agent.discovery;

import dk.certops.agent.config.AgentProperties;
import dk.certops.agent.security.NetworkValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class StaticTargetProvider {

    private static final Logger log = LoggerFactory.getLogger(StaticTargetProvider.class);

    private final AgentProperties agentProperties;
    private final List<AgentProperties.Target> cloudTargets = new CopyOnWriteArrayList<>();

    public StaticTargetProvider(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;
    }

    /**
     * Get all targets (local config + cloud-pushed).
     */
    public List<AgentProperties.Target> getTargets() {
        List<AgentProperties.Target> all = new ArrayList<>();

        // Local targets from application.yml
        if (agentProperties.getTargets() != null) {
            all.addAll(agentProperties.getTargets());
        }

        // Cloud-pushed targets
        all.addAll(cloudTargets);

        log.debug("Total targets: {} (local={}, cloud={})",
                all.size(), agentProperties.getTargets() != null ? agentProperties.getTargets().size() : 0,
                cloudTargets.size());
        return all;
    }

    /**
     * Update targets from cloud config push.
     * Validates that cloud-pushed targets only resolve to private/internal IPs.
     */
    public void updateCloudTargets(List<AgentProperties.Target> targets) {
        cloudTargets.clear();
        if (targets == null) return;

        boolean allowPublic = agentProperties.isAllowPublicTargets();
        int rejected = 0;

        for (AgentProperties.Target t : targets) {
            if (allowPublic || NetworkValidator.isPrivateHost(t.getHost())) {
                cloudTargets.add(t);
            } else {
                rejected++;
                log.warn("SECURITY: Rejected cloud-pushed target with public IP: {}:{}", t.getHost(), t.getPort());
            }
        }

        if (rejected > 0) {
            log.warn("SECURITY: Rejected {} cloud-pushed targets with public IPs (accepted {})",
                    rejected, cloudTargets.size());
        }
        log.info("Cloud targets updated: {} targets", cloudTargets.size());
    }
}
