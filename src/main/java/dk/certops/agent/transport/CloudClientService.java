package dk.certops.agent.transport;

import dk.certops.agent.config.AgentProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

@Service
public class CloudClientService {

    private static final Logger log = LoggerFactory.getLogger(CloudClientService.class);

    private final AgentProperties agentProperties;
    private final ObjectMapper objectMapper;
    private final HmacSigner hmacSigner;
    private final HttpClient httpClient;

    public CloudClientService(AgentProperties agentProperties, ObjectMapper objectMapper, HmacSigner hmacSigner) {
        this.agentProperties = agentProperties;
        this.objectMapper = objectMapper;
        this.hmacSigner = hmacSigner;

        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30));

        // Proxy support
        if (agentProperties.getProxyUrl() != null && !agentProperties.getProxyUrl().isBlank()) {
            try {
                URI proxyUri = URI.create(agentProperties.getProxyUrl());
                builder.proxy(ProxySelector.of(new InetSocketAddress(
                        proxyUri.getHost(), proxyUri.getPort() > 0 ? proxyUri.getPort() : 8080)));
                log.info("Using proxy: {}", agentProperties.getProxyUrl());
            } catch (Exception e) {
                log.warn("Invalid proxy URL: {}", agentProperties.getProxyUrl());
            }
        }

        // mTLS support
        AgentProperties.Mtls mtls = agentProperties.getMtls();
        if (mtls.isEnabled()) {
            try {
                SSLContext sslContext = buildMtlsContext(mtls);
                builder.sslContext(sslContext);
                log.info("mTLS enabled: cert={}, ca={}", mtls.getCertPath(), mtls.getCaPath());
            } catch (Exception e) {
                log.error("Failed to configure mTLS — falling back to default TLS: {}", e.getMessage());
            }
        }

        this.httpClient = builder.build();
    }

    /**
     * Build SSLContext with client certificate and custom CA trust for mTLS.
     */
    private SSLContext buildMtlsContext(AgentProperties.Mtls mtls) throws Exception {
        // Load client certificate and private key
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        // If certPath is a PKCS12 file, load directly
        // If certPath is a PEM file, we need to convert
        String certPath = mtls.getCertPath();
        String keyPath = mtls.getKeyPath();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        if (certPath.endsWith(".p12") || certPath.endsWith(".pfx")) {
            // PKCS12 keystore
            try (FileInputStream fis = new FileInputStream(certPath)) {
                keyStore.load(fis, "".toCharArray());
            }
            kmf.init(keyStore, "".toCharArray());
        } else {
            // PEM files — load cert and key into a PKCS12 keystore
            // For PEM support, we use the cert file as a combined cert+key PEM
            // or separate cert and key files
            keyStore.load(null, null);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (FileInputStream certFis = new FileInputStream(certPath)) {
                X509Certificate clientCert = (X509Certificate) cf.generateCertificate(certFis);

                // Load private key
                java.security.PrivateKey privateKey = loadPrivateKey(keyPath);
                keyStore.setKeyEntry("client", privateKey, "".toCharArray(),
                        new java.security.cert.Certificate[]{clientCert});
            }
            kmf.init(keyStore, "".toCharArray());
        }

        // Load CA certificate for server verification
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        String caPath = mtls.getCaPath();

        if (caPath != null && !caPath.isBlank()) {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            try (FileInputStream caFis = new FileInputStream(caPath)) {
                int i = 0;
                for (java.security.cert.Certificate cert : cf.generateCertificates(caFis)) {
                    trustStore.setCertificateEntry("ca-" + i++, cert);
                }
            }
            tmf.init(trustStore);
        } else {
            tmf.init((KeyStore) null); // Use default trust store
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    /**
     * Load a PKCS8 PEM private key from file.
     */
    private java.security.PrivateKey loadPrivateKey(String keyPath) throws Exception {
        byte[] keyBytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(keyPath));
        String keyPem = new String(keyBytes, StandardCharsets.UTF_8);

        // Strip PEM headers
        keyPem = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = java.util.Base64.getDecoder().decode(keyPem);
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(decoded);

        // Try RSA first, then EC
        try {
            return java.security.KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception e) {
            return java.security.KeyFactory.getInstance("EC").generatePrivate(keySpec);
        }
    }

    /**
     * POST JSON to a cloud endpoint. Adds HMAC signature header.
     */
    public Map<String, Object> post(String path, Object body) throws IOException, InterruptedException {
        String url = agentProperties.getServerUrl() + path;
        String json = objectMapper.writeValueAsString(body);

        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + agentProperties.getApiKey())
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));

        // HMAC request signing (replay-protected): signs timestamp+nonce+method+path+body
        // with the per-collector signing secret. Verified server-side.
        addSignatureHeaders(reqBuilder, "POST", path, json);

        HttpRequest request = reqBuilder.build();

        log.debug("POST {} ({} bytes)", path, json.length());

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            @SuppressWarnings("unchecked")
            Map<String, Object> result = objectMapper.readValue(response.body(), Map.class);
            return result;
        } else {
            log.warn("POST {} -> HTTP {}: {}", path, response.statusCode(), response.body());
            throw new IOException("HTTP " + response.statusCode() + ": " + response.body());
        }
    }

    /**
     * GET from a cloud endpoint.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> get(String path) throws IOException, InterruptedException {
        String url = agentProperties.getServerUrl() + path;

        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", "Bearer " + agentProperties.getApiKey())
                .timeout(Duration.ofSeconds(30))
                .GET();
        addSignatureHeaders(reqBuilder, "GET", path, "");
        HttpRequest request = reqBuilder.build();

        log.debug("GET {}", path);

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            return objectMapper.readValue(response.body(), Map.class);
        } else {
            throw new IOException("HTTP " + response.statusCode() + ": " + response.body());
        }
    }

    /**
     * Adds replay-protected HMAC signature headers when a signing secret is configured.
     * Signs the canonical string {@code timestamp\nnonce\nMETHOD\npath\nbody}. When no
     * signing secret is set the request is sent unsigned (legacy mode); the server graces
     * such requests unless its require-signature flag is enabled.
     */
    private void addSignatureHeaders(HttpRequest.Builder builder, String method, String path, String body) {
        String secret = agentProperties.getSigningSecret();
        if (secret == null || secret.isBlank()) {
            return;
        }
        String timestamp = String.valueOf(System.currentTimeMillis() / 1000L);
        String nonce = java.util.UUID.randomUUID().toString();
        String canonical = timestamp + "\n" + nonce + "\n" + method.toUpperCase() + "\n"
                + path + "\n" + (body == null ? "" : body);
        String signature = hmacSigner.sign(canonical, secret);
        if (signature != null) {
            builder.header("X-Timestamp", timestamp)
                   .header("X-Nonce", nonce)
                   .header("X-Signature", signature);
        }
    }

    /**
     * Check connectivity to the cloud server.
     */
    public boolean isReachable() {
        try {
            get("/api/health");
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
