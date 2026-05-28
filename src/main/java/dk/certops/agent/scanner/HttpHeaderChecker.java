package dk.certops.agent.scanner;

import dk.certops.agent.config.AgentProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Checks HTTP security headers (HSTS, X-Content-Type-Options, etc.)
 * for HTTPS endpoints. Only performs a HEAD/GET to read response headers.
 */
@Component
public class HttpHeaderChecker {

    private static final Logger log = LoggerFactory.getLogger(HttpHeaderChecker.class);

    private static final String[] SECURITY_HEADERS = {
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Server",
            "X-Powered-By",
            "Via",
            "X-AspNet-Version"
    };

    private final AgentProperties agentProperties;
    private final HttpClient httpClient;

    public HttpHeaderChecker(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;

        // Trust-all SSL context for header checking (we only care about headers, not cert validation)
        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }};

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, null);

            this.httpClient = HttpClient.newBuilder()
                    .sslContext(ctx)
                    .connectTimeout(Duration.ofMillis(agentProperties.getTimeoutMs()))
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create HttpClient for header checking", e);
        }
    }

    /**
     * Check security headers for an HTTPS endpoint.
     * Returns a map of header name -> value (or "MISSING" if not present).
     */
    public Map<String, String> check(String host, int port) {
        Map<String, String> result = new LinkedHashMap<>();

        try {
            String url = "https://" + host + (port == 443 ? "" : ":" + port) + "/";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofMillis(agentProperties.getTimeoutMs()))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());

            for (String header : SECURITY_HEADERS) {
                String value = response.headers().firstValue(header).orElse(null);
                result.put(header, value != null ? value : "MISSING");
            }

            result.put("_status_code", String.valueOf(response.statusCode()));

        } catch (Exception e) {
            log.debug("HTTP header check failed for {}:{} — {}", host, port, e.getMessage());
            result.put("_error", e.getMessage());
        }

        return result;
    }
}
