package dk.certops.agent.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

public class ScanResultDto {

    private String endpoint;
    private String env;
    private List<String> tags;
    private String status;
    private String error;

    @JsonProperty("negotiated_tls")
    private String negotiatedTls;

    @JsonProperty("cipher_name")
    private String cipherName;

    @JsonProperty("cipher_version")
    private String cipherVersion;

    @JsonProperty("leaf_fp_sha256")
    private String leafFpSha256;

    @JsonProperty("leaf_subject_cn")
    private String leafSubjectCn;

    @JsonProperty("leaf_issuer_cn")
    private String leafIssuerCn;

    @JsonProperty("leaf_valid_from")
    private String leafValidFrom;

    @JsonProperty("leaf_valid_to")
    private String leafValidTo;

    private List<ChainCertDto> chain;

    @JsonProperty("tls_support")
    private Map<String, Boolean> tlsSupport;

    @JsonProperty("http_headers")
    private Map<String, String> httpHeaders;

    @JsonProperty("dns_security")
    private Map<String, Object> dnsSecurity;

    @JsonProperty("ocsp_status")
    private String ocspStatus;

    @JsonIgnore
    private transient List<X509Certificate> rawCertificates;

    public ScanResultDto() {}

    public String getEndpoint() { return endpoint; }
    public void setEndpoint(String endpoint) { this.endpoint = endpoint; }

    public String getEnv() { return env; }
    public void setEnv(String env) { this.env = env; }

    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getError() { return error; }
    public void setError(String error) { this.error = error; }

    public String getNegotiatedTls() { return negotiatedTls; }
    public void setNegotiatedTls(String negotiatedTls) { this.negotiatedTls = negotiatedTls; }

    public String getCipherName() { return cipherName; }
    public void setCipherName(String cipherName) { this.cipherName = cipherName; }

    public String getCipherVersion() { return cipherVersion; }
    public void setCipherVersion(String cipherVersion) { this.cipherVersion = cipherVersion; }

    public String getLeafFpSha256() { return leafFpSha256; }
    public void setLeafFpSha256(String leafFpSha256) { this.leafFpSha256 = leafFpSha256; }

    public String getLeafSubjectCn() { return leafSubjectCn; }
    public void setLeafSubjectCn(String leafSubjectCn) { this.leafSubjectCn = leafSubjectCn; }

    public String getLeafIssuerCn() { return leafIssuerCn; }
    public void setLeafIssuerCn(String leafIssuerCn) { this.leafIssuerCn = leafIssuerCn; }

    public String getLeafValidFrom() { return leafValidFrom; }
    public void setLeafValidFrom(String leafValidFrom) { this.leafValidFrom = leafValidFrom; }

    public String getLeafValidTo() { return leafValidTo; }
    public void setLeafValidTo(String leafValidTo) { this.leafValidTo = leafValidTo; }

    public List<ChainCertDto> getChain() { return chain; }
    public void setChain(List<ChainCertDto> chain) { this.chain = chain; }

    public Map<String, Boolean> getTlsSupport() { return tlsSupport; }
    public void setTlsSupport(Map<String, Boolean> tlsSupport) { this.tlsSupport = tlsSupport; }

    public Map<String, String> getHttpHeaders() { return httpHeaders; }
    public void setHttpHeaders(Map<String, String> httpHeaders) { this.httpHeaders = httpHeaders; }

    public Map<String, Object> getDnsSecurity() { return dnsSecurity; }
    public void setDnsSecurity(Map<String, Object> dnsSecurity) { this.dnsSecurity = dnsSecurity; }

    public String getOcspStatus() { return ocspStatus; }
    public void setOcspStatus(String ocspStatus) { this.ocspStatus = ocspStatus; }

    public List<X509Certificate> getRawCertificates() { return rawCertificates; }
    public void setRawCertificates(List<X509Certificate> rawCertificates) { this.rawCertificates = rawCertificates; }
}
