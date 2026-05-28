package dk.certops.agent.exposure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FingerprintService {

    private static final Logger log = LoggerFactory.getLogger(FingerprintService.class);

    private static final Pattern VERSION_PATTERN = Pattern.compile("[/\\s_-](\\d+(?:\\.\\d+)+)");
    private static final int BANNER_TIMEOUT_MS = 3000;

    public static class Fingerprint {
        public String product;
        public String version;
        public double confidence;
        public String method;
        public Map<String, Object> details = new LinkedHashMap<>();
    }

    private final int concurrency;

    public FingerprintService(int concurrency) {
        this.concurrency = Math.min(concurrency, 50);
    }

    public Map<String, List<Map<String, Object>>> fingerprint(
            Map<String, List<PortScannerService.OpenPort>> openPorts) {

        Map<String, List<Map<String, Object>>> results = new ConcurrentHashMap<>();
        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (Map.Entry<String, List<PortScannerService.OpenPort>> entry : openPorts.entrySet()) {
            String host = entry.getKey();
            for (PortScannerService.OpenPort op : entry.getValue()) {
                futures.add(executor.submit(() -> {
                    Map<String, Object> portResult = fingerprintPort(host, op.port);
                    results.computeIfAbsent(host, k -> new CopyOnWriteArrayList<>()).add(portResult);
                }));
            }
        }

        for (Future<?> f : futures) {
            try { f.get(30, TimeUnit.SECONDS); } catch (Exception e) { /* timeout */ }
        }

        executor.shutdown();
        try { executor.awaitTermination(30, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

        return results;
    }

    private Map<String, Object> fingerprintPort(String host, int port) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("port", port);
        result.put("proto", "tcp");

        Fingerprint best = null;

        // 1. TLS probe for likely TLS ports
        if (Top100Ports.TLS_PORTS.contains(port) || port == 443 || port == 8443) {
            try {
                Fingerprint tlsFp = probeTls(host, port);
                if (tlsFp != null && (best == null || tlsFp.confidence > best.confidence)) {
                    best = tlsFp;
                }
            } catch (Exception e) {
                log.debug("TLS probe failed for {}:{}: {}", host, port, e.getMessage());
            }
        }

        // 2. HTTP probe for likely HTTP ports
        if (Top100Ports.HTTP_PORTS.contains(port)) {
            try {
                Fingerprint httpFp = probeHttp(host, port, Top100Ports.TLS_PORTS.contains(port));
                if (httpFp != null) {
                    if (best != null && best.product != null && httpFp.product != null
                            && best.product.equalsIgnoreCase(httpFp.product)) {
                        httpFp.confidence = Math.min(1.0, httpFp.confidence + 0.1);
                    }
                    if (best == null || httpFp.confidence > best.confidence) {
                        best = httpFp;
                    }
                }
            } catch (Exception e) {
                log.debug("HTTP probe failed for {}:{}: {}", host, port, e.getMessage());
            }
        }

        // 3. Banner probe for known banner ports
        if (Top100Ports.BANNER_PORTS.contains(port)) {
            try {
                Fingerprint bannerFp = probeBanner(host, port);
                if (bannerFp != null && (best == null || bannerFp.confidence > best.confidence)) {
                    best = bannerFp;
                }
            } catch (Exception e) {
                log.debug("Banner probe failed for {}:{}: {}", host, port, e.getMessage());
            }
        }

        // 4. Fallback
        if (best == null) {
            best = new Fingerprint();
            best.product = "unknown";
            best.confidence = 0.3;
            best.method = "none";
        }

        Map<String, Object> fingerprint = new LinkedHashMap<>();
        fingerprint.put("product", best.product);
        if (best.version != null) fingerprint.put("version", best.version);
        fingerprint.put("confidence", Math.round(best.confidence * 100.0) / 100.0);
        fingerprint.put("method", best.method);
        fingerprint.putAll(best.details);

        result.put("fingerprint", fingerprint);
        return result;
    }

    // --- TLS Probe ---

    private Fingerprint probeTls(String host, int port) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new TrustAllX509()}, null);
        SSLSocketFactory factory = ctx.getSocketFactory();

        try (SSLSocket socket = (SSLSocket) factory.createSocket()) {
            socket.connect(new InetSocketAddress(host, port), 3000);
            socket.setSoTimeout(3000);

            // SNI
            SSLParameters params = socket.getSSLParameters();
            params.setServerNames(List.of(new SNIHostName(host)));
            socket.setSSLParameters(params);

            socket.startHandshake();

            Fingerprint fp = new Fingerprint();
            fp.method = "tls";
            fp.confidence = 0.5;
            fp.details.put("tls_protocol", socket.getSession().getProtocol());
            fp.details.put("cipher_suite", socket.getSession().getCipherSuite());

            java.security.cert.Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate leaf = (X509Certificate) certs[0];
                String cn = extractCN(leaf.getSubjectX500Principal().getName());
                String issuerCn = extractCN(leaf.getIssuerX500Principal().getName());

                fp.details.put("cert_subject_cn", cn);
                fp.details.put("cert_issuer_cn", issuerCn);

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] digest = md.digest(leaf.getEncoded());
                fp.details.put("cert_sha256", bytesToHex(digest));
            }

            return fp;
        }
    }

    // --- HTTP Probe ---

    private Fingerprint probeHttp(String host, int port, boolean useTls) {
        try {
            String scheme = useTls ? "https" : "http";
            String url = scheme + "://" + host + ":" + port + "/";

            HttpClient.Builder clientBuilder = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(3))
                    .followRedirects(HttpClient.Redirect.NEVER);

            if (useTls) {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, new TrustManager[]{new TrustAllX509()}, null);
                clientBuilder.sslContext(ctx);
            }

            HttpClient client = clientBuilder.build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("User-Agent", "CertOps-ExposureDiscovery/1.0")
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());

            Fingerprint fp = new Fingerprint();
            fp.method = "http";
            fp.confidence = 0.5;
            fp.details.put("status_code", response.statusCode());

            String server = response.headers().firstValue("Server").orElse(null);
            String poweredBy = response.headers().firstValue("X-Powered-By").orElse(null);

            if (server != null) {
                fp.details.put("server_header", truncate(server, 200));
                fp.product = server;
                Matcher m = VERSION_PATTERN.matcher(server);
                if (m.find()) {
                    fp.version = m.group(1);
                    fp.confidence = 0.7;
                }
            }
            if (poweredBy != null) {
                fp.details.put("x_powered_by", truncate(poweredBy, 200));
                if (fp.product == null) {
                    fp.product = poweredBy;
                    Matcher m = VERSION_PATTERN.matcher(poweredBy);
                    if (m.find()) fp.version = m.group(1);
                }
            }

            // Cookie count (no values)
            long cookieCount = response.headers().allValues("Set-Cookie").size();
            if (cookieCount > 0) fp.details.put("cookie_count", cookieCount);

            return fp;
        } catch (Exception e) {
            log.debug("HTTP probe failed for {}:{}: {}", host, port, e.getMessage());
            return null;
        }
    }

    // --- Banner Probe ---

    private Fingerprint probeBanner(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 3000);
            socket.setSoTimeout(BANNER_TIMEOUT_MS);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String banner = reader.readLine();

            if (banner == null || banner.isBlank()) return null;
            banner = truncate(banner.trim(), 500);

            Fingerprint fp = new Fingerprint();
            fp.method = "banner";
            fp.details.put("banner", banner);

            // SSH: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
            if (banner.startsWith("SSH-")) {
                fp.confidence = 0.9;
                String sshPart = banner.substring(banner.indexOf('-', 4) + 1);
                if (sshPart.toLowerCase().contains("openssh")) {
                    fp.product = "OpenSSH";
                    Matcher m = VERSION_PATTERN.matcher(sshPart);
                    if (m.find()) fp.version = m.group(1);
                } else {
                    fp.product = sshPart.split("\\s")[0];
                }
                return fp;
            }

            // SMTP: 220 mail.example.com ESMTP Postfix
            if (banner.startsWith("220 ")) {
                fp.confidence = 0.7;
                String lower = banner.toLowerCase();
                if (lower.contains("postfix")) {
                    fp.product = "Postfix";
                } else if (lower.contains("exim")) {
                    fp.product = "Exim";
                    Matcher m = VERSION_PATTERN.matcher(banner);
                    if (m.find()) fp.version = m.group(1);
                } else if (lower.contains("sendmail")) {
                    fp.product = "Sendmail";
                } else if (lower.contains("microsoft")) {
                    fp.product = "Microsoft SMTP";
                } else {
                    fp.product = "SMTP";
                    fp.confidence = 0.5;
                }

                // FTP: 220 (vsFTPd 3.0.5) or 220---------- Welcome to Pure-FTPd
                if (lower.contains("vsftpd")) {
                    fp.product = "vsftpd";
                    fp.confidence = 0.8;
                    Matcher m = VERSION_PATTERN.matcher(banner);
                    if (m.find()) fp.version = m.group(1);
                } else if (lower.contains("proftpd")) {
                    fp.product = "ProFTPD";
                    fp.confidence = 0.8;
                    Matcher m = VERSION_PATTERN.matcher(banner);
                    if (m.find()) fp.version = m.group(1);
                } else if (lower.contains("pure-ftpd")) {
                    fp.product = "Pure-FTPd";
                    fp.confidence = 0.8;
                }

                return fp;
            }

            // IMAP: * OK [CAPABILITY IMAP4rev1 ...] Dovecot ready.
            if (banner.startsWith("* OK") || banner.startsWith("* ok")) {
                fp.confidence = 0.7;
                String lower = banner.toLowerCase();
                if (lower.contains("dovecot")) {
                    fp.product = "Dovecot";
                } else if (lower.contains("courier")) {
                    fp.product = "Courier";
                } else {
                    fp.product = "IMAP";
                    fp.confidence = 0.5;
                }
                return fp;
            }

            // POP3: +OK POP3 server ready
            if (banner.startsWith("+OK")) {
                fp.confidence = 0.6;
                fp.product = "POP3";
                String lower = banner.toLowerCase();
                if (lower.contains("dovecot")) { fp.product = "Dovecot"; fp.confidence = 0.7; }
                return fp;
            }

            // Generic banner
            fp.product = "unknown";
            fp.confidence = 0.4;
            return fp;
        } catch (Exception e) {
            return null;
        }
    }

    // --- Helpers ---

    private String extractCN(String dn) {
        if (dn == null) return null;
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.toUpperCase().startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return dn;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String truncate(String s, int maxLen) {
        return s.length() <= maxLen ? s : s.substring(0, maxLen);
    }

    private static class TrustAllX509 implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
    }
}
