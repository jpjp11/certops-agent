package dk.certops.agent.scanner;

import dk.certops.agent.config.AgentProperties;
import dk.certops.agent.dto.ChainCertDto;
import dk.certops.agent.dto.ScanResultDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class TlsScannerService {

    private static final Logger log = LoggerFactory.getLogger(TlsScannerService.class);
    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_INSTANT;
    private static final String[] TLS_VERSIONS = {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"};

    private final AgentProperties agentProperties;

    public TlsScannerService(AgentProperties agentProperties) {
        this.agentProperties = agentProperties;
    }

    public ScanResultDto scan(AgentProperties.Target target) {
        String host = target.getHost();
        int port = target.getPort();
        String endpoint = target.toEndpoint();

        ScanResultDto result = new ScanResultDto();
        result.setEndpoint(endpoint);
        result.setEnv(target.getEnv());
        result.setTags(target.getTags());

        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }};

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, null);

            SSLSocketFactory factory = ctx.getSocketFactory();

            try (Socket rawSocket = new Socket()) {
                rawSocket.connect(new InetSocketAddress(host, port), agentProperties.getTimeoutMs());
                rawSocket.setSoTimeout(agentProperties.getTimeoutMs());

                SSLSocket sslSocket = (SSLSocket) factory.createSocket(rawSocket, host, port, true);
                // SNI support
                SSLParameters sslParams = sslSocket.getSSLParameters();
                sslParams.setServerNames(List.of(new SNIHostName(host)));
                sslSocket.setSSLParameters(sslParams);

                sslSocket.startHandshake();

                SSLSession session = sslSocket.getSession();
                result.setStatus("OK");
                result.setNegotiatedTls(session.getProtocol());
                result.setCipherName(session.getCipherSuite());

                java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
                if (peerCerts != null && peerCerts.length > 0) {
                    List<ChainCertDto> chain = new ArrayList<>();
                    List<X509Certificate> rawCerts = new ArrayList<>();
                    for (java.security.cert.Certificate cert : peerCerts) {
                        if (cert instanceof X509Certificate x509) {
                            chain.add(toChainCertDto(x509));
                            rawCerts.add(x509);
                        }
                    }
                    result.setChain(chain);
                    result.setRawCertificates(rawCerts);

                    // Leaf cert info
                    X509Certificate leaf = (X509Certificate) peerCerts[0];
                    result.setLeafFpSha256(sha256Fingerprint(leaf));
                    result.setLeafSubjectCn(extractCn(leaf.getSubjectX500Principal().getName()));
                    result.setLeafIssuerCn(extractCn(leaf.getIssuerX500Principal().getName()));
                    result.setLeafValidFrom(leaf.getNotBefore().toInstant().toString());
                    result.setLeafValidTo(leaf.getNotAfter().toInstant().toString());
                }

                sslSocket.close();
            }

            // Probe TLS versions if configured
            if (agentProperties.isProbeTlsVersions()) {
                Map<String, Boolean> tlsSupport = new LinkedHashMap<>();
                for (String ver : TLS_VERSIONS) {
                    tlsSupport.put(ver, probeVersion(host, port, ver));
                }
                result.setTlsSupport(tlsSupport);
            }

        } catch (Exception e) {
            result.setStatus("ERROR");
            result.setError(e.getMessage());
            log.debug("Scan error for {}: {}", endpoint, e.getMessage());
        }

        return result;
    }

    private Boolean probeVersion(String host, int port, String protocol) {
        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            }};

            SSLContext ctx = SSLContext.getInstance(protocol);
            ctx.init(null, trustAll, null);

            try (Socket rawSocket = new Socket()) {
                rawSocket.connect(new InetSocketAddress(host, port), 5000);
                rawSocket.setSoTimeout(5000);

                SSLSocket sslSocket = (SSLSocket) ctx.getSocketFactory()
                        .createSocket(rawSocket, host, port, true);
                sslSocket.setEnabledProtocols(new String[]{protocol});
                sslSocket.startHandshake();
                sslSocket.close();
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }

    private ChainCertDto toChainCertDto(X509Certificate cert) {
        ChainCertDto dto = new ChainCertDto();
        dto.setFpSha256(sha256Fingerprint(cert));
        dto.setSubject(cert.getSubjectX500Principal().getName());
        dto.setSubjectCn(extractCn(cert.getSubjectX500Principal().getName()));
        dto.setIssuer(cert.getIssuerX500Principal().getName());
        dto.setIssuerCn(extractCn(cert.getIssuerX500Principal().getName()));
        dto.setNotBefore(cert.getNotBefore().toInstant().toString());
        dto.setNotAfter(cert.getNotAfter().toInstant().toString());
        dto.setVersion(cert.getVersion());
        dto.setSerialNumber(cert.getSerialNumber().toString(16));
        dto.setKeyAlgorithm(cert.getPublicKey().getAlgorithm());
        dto.setSignatureAlgorithm(cert.getSigAlgName());
        dto.setIsCa(cert.getBasicConstraints() >= 0);

        // Key size
        try {
            if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey rsa) {
                dto.setKeySize(rsa.getModulus().bitLength());
            } else if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey ec) {
                dto.setKeySize(ec.getParams().getOrder().bitLength());
            }
        } catch (Exception e) {
            log.debug("Could not determine key size: {}", e.getMessage());
        }

        // SANs
        try {
            var sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                List<String> sanList = new ArrayList<>();
                for (var san : sans) {
                    if (san.size() >= 2 && (Integer) san.get(0) == 2) {
                        sanList.add(String.valueOf(san.get(1)));
                    }
                }
                dto.setSan(sanList);
            }
        } catch (CertificateParsingException e) {
            log.debug("Could not parse SANs: {}", e.getMessage());
        }

        // Cert type
        if (cert.getBasicConstraints() >= 0) {
            dto.setCertType("CA");
        } else {
            dto.setCertType(cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) ? "Self-Signed" : "Leaf");
        }

        return dto;
    }

    private String extractCn(String dn) {
        if (dn == null) return null;
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }

    private String sha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format("%02X", digest[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
