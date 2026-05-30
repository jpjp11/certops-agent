package dk.certops.agent.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties("certops.agent")
public class AgentProperties {

    private String serverUrl = "https://certcontrol.pro";
    private String apiKey = "";
    // Per-collector HMAC signing secret (shown once at collector creation/regeneration).
    // When set, requests are signed (X-Timestamp/X-Nonce/X-Signature) and verified server-side.
    private String signingSecret = "";
    private String proxyUrl = "";

    private int scanIntervalSeconds = 300;
    private int heartbeatIntervalSeconds = 60;
    private int configPullIntervalSeconds = 300;

    private int timeoutMs = 10000;
    private boolean probeTlsVersions = true;
    private boolean checkOcsp = true;
    private boolean checkHttpHeaders = true;
    private boolean checkDnsSecurity = false;
    private boolean allowPublicTargets = false;

    private List<Target> targets = new ArrayList<>();

    private Redaction redaction = new Redaction();
    private Spool spool = new Spool();
    private CidrDiscovery cidrDiscovery = new CidrDiscovery();
    private Mtls mtls = new Mtls();
    private ExposureDiscovery exposureDiscovery = new ExposureDiscovery();

    // Getters and setters

    public String getServerUrl() { return serverUrl; }
    public void setServerUrl(String serverUrl) { this.serverUrl = serverUrl; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public String getSigningSecret() { return signingSecret; }
    public void setSigningSecret(String signingSecret) { this.signingSecret = signingSecret; }

    public String getProxyUrl() { return proxyUrl; }
    public void setProxyUrl(String proxyUrl) { this.proxyUrl = proxyUrl; }

    public int getScanIntervalSeconds() { return scanIntervalSeconds; }
    public void setScanIntervalSeconds(int scanIntervalSeconds) { this.scanIntervalSeconds = scanIntervalSeconds; }

    public int getHeartbeatIntervalSeconds() { return heartbeatIntervalSeconds; }
    public void setHeartbeatIntervalSeconds(int heartbeatIntervalSeconds) { this.heartbeatIntervalSeconds = heartbeatIntervalSeconds; }

    public int getConfigPullIntervalSeconds() { return configPullIntervalSeconds; }
    public void setConfigPullIntervalSeconds(int configPullIntervalSeconds) { this.configPullIntervalSeconds = configPullIntervalSeconds; }

    public int getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(int timeoutMs) { this.timeoutMs = timeoutMs; }

    public boolean isProbeTlsVersions() { return probeTlsVersions; }
    public void setProbeTlsVersions(boolean probeTlsVersions) { this.probeTlsVersions = probeTlsVersions; }

    public boolean isCheckOcsp() { return checkOcsp; }
    public void setCheckOcsp(boolean checkOcsp) { this.checkOcsp = checkOcsp; }

    public boolean isCheckHttpHeaders() { return checkHttpHeaders; }
    public void setCheckHttpHeaders(boolean checkHttpHeaders) { this.checkHttpHeaders = checkHttpHeaders; }

    public boolean isCheckDnsSecurity() { return checkDnsSecurity; }
    public void setCheckDnsSecurity(boolean checkDnsSecurity) { this.checkDnsSecurity = checkDnsSecurity; }

    public boolean isAllowPublicTargets() { return allowPublicTargets; }
    public void setAllowPublicTargets(boolean allowPublicTargets) { this.allowPublicTargets = allowPublicTargets; }

    public List<Target> getTargets() { return targets; }
    public void setTargets(List<Target> targets) { this.targets = targets; }

    public Redaction getRedaction() { return redaction; }
    public void setRedaction(Redaction redaction) { this.redaction = redaction; }

    public Spool getSpool() { return spool; }
    public void setSpool(Spool spool) { this.spool = spool; }

    public CidrDiscovery getCidrDiscovery() { return cidrDiscovery; }
    public void setCidrDiscovery(CidrDiscovery cidrDiscovery) { this.cidrDiscovery = cidrDiscovery; }

    public Mtls getMtls() { return mtls; }
    public void setMtls(Mtls mtls) { this.mtls = mtls; }

    public ExposureDiscovery getExposureDiscovery() { return exposureDiscovery; }
    public void setExposureDiscovery(ExposureDiscovery exposureDiscovery) { this.exposureDiscovery = exposureDiscovery; }

    public static class Target {
        private String host;
        private int port = 443;
        private String env = "prod";
        private List<String> tags = new ArrayList<>();

        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }
        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }
        public String getEnv() { return env; }
        public void setEnv(String env) { this.env = env; }
        public List<String> getTags() { return tags; }
        public void setTags(List<String> tags) { this.tags = tags; }

        public String toEndpoint() {
            return host + ":" + port;
        }
    }

    public static class Redaction {
        private boolean enabled = true;
        private List<String> patterns = new ArrayList<>();
        private boolean stripCertPem = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getPatterns() { return patterns; }
        public void setPatterns(List<String> patterns) { this.patterns = patterns; }
        public boolean isStripCertPem() { return stripCertPem; }
        public void setStripCertPem(boolean stripCertPem) { this.stripCertPem = stripCertPem; }
    }

    public static class Spool {
        private boolean enabled = true;
        private String directory = "/var/certops-agent/spool";
        private int maxSizeMb = 100;
        private int retryIntervalSeconds = 60;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getDirectory() { return directory; }
        public void setDirectory(String directory) { this.directory = directory; }
        public int getMaxSizeMb() { return maxSizeMb; }
        public void setMaxSizeMb(int maxSizeMb) { this.maxSizeMb = maxSizeMb; }
        public int getRetryIntervalSeconds() { return retryIntervalSeconds; }
        public void setRetryIntervalSeconds(int retryIntervalSeconds) { this.retryIntervalSeconds = retryIntervalSeconds; }
    }

    public static class CidrDiscovery {
        private boolean enabled = false;
        private List<String> ranges = new ArrayList<>();
        private String ports = "443,8443,9443,636";
        private int rateLimit = 10;
        private int concurrency = 5;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getRanges() { return ranges; }
        public void setRanges(List<String> ranges) { this.ranges = ranges; }
        public String getPorts() { return ports; }
        public void setPorts(String ports) { this.ports = ports; }
        public int getRateLimit() { return rateLimit; }
        public void setRateLimit(int rateLimit) { this.rateLimit = rateLimit; }
        public int getConcurrency() { return concurrency; }
        public void setConcurrency(int concurrency) { this.concurrency = concurrency; }
    }

    public static class Mtls {
        private boolean enabled = false;
        private String certPath = "";
        private String keyPath = "";
        private String caPath = "";

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getCertPath() { return certPath; }
        public void setCertPath(String certPath) { this.certPath = certPath; }
        public String getKeyPath() { return keyPath; }
        public void setKeyPath(String keyPath) { this.keyPath = keyPath; }
        public String getCaPath() { return caPath; }
        public void setCaPath(String caPath) { this.caPath = caPath; }
    }

    public static class ExposureDiscovery {
        private boolean enabled = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }
}
