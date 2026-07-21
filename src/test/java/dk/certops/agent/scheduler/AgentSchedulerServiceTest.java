package dk.certops.agent.scheduler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AgentSchedulerServiceTest {

    /**
     * The agent version is resolved from the jar manifest (Implementation-Version).
     * In the test classpath there is no manifest version, so the resolver must fall
     * back to a non-blank placeholder rather than null/empty — the heartbeat reports
     * this value to the cloud, and null/"" would corrupt the collector's version field.
     */
    @Test
    void agentVersion_isNeverNullOrBlank() {
        assertNotNull(AgentSchedulerService.AGENT_VERSION);
        assertFalse(AgentSchedulerService.AGENT_VERSION.isBlank());
    }
}
