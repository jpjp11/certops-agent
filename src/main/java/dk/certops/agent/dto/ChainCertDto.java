package dk.certops.agent.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ChainCertDto {

    @JsonProperty("fp_sha256")
    private String fpSha256;

    private String subject;

    @JsonProperty("subject_cn")
    private String subjectCn;

    private String issuer;

    @JsonProperty("issuer_cn")
    private String issuerCn;

    @JsonProperty("not_before")
    private String notBefore;

    @JsonProperty("not_after")
    private String notAfter;

    @JsonProperty("is_ca")
    private Boolean isCa;

    @JsonProperty("cert_type")
    private String certType;

    private List<String> san;

    @JsonProperty("key_algorithm")
    private String keyAlgorithm;

    @JsonProperty("key_size")
    private Integer keySize;

    @JsonProperty("signature_algorithm")
    private String signatureAlgorithm;

    @JsonProperty("serial_number")
    private String serialNumber;

    private Integer version;

    public ChainCertDto() {}

    public String getFpSha256() { return fpSha256; }
    public void setFpSha256(String fpSha256) { this.fpSha256 = fpSha256; }

    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }

    public String getSubjectCn() { return subjectCn; }
    public void setSubjectCn(String subjectCn) { this.subjectCn = subjectCn; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public String getIssuerCn() { return issuerCn; }
    public void setIssuerCn(String issuerCn) { this.issuerCn = issuerCn; }

    public String getNotBefore() { return notBefore; }
    public void setNotBefore(String notBefore) { this.notBefore = notBefore; }

    public String getNotAfter() { return notAfter; }
    public void setNotAfter(String notAfter) { this.notAfter = notAfter; }

    public Boolean getIsCa() { return isCa; }
    public void setIsCa(Boolean isCa) { this.isCa = isCa; }

    public String getCertType() { return certType; }
    public void setCertType(String certType) { this.certType = certType; }

    public List<String> getSan() { return san; }
    public void setSan(List<String> san) { this.san = san; }

    public String getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }

    public Integer getKeySize() { return keySize; }
    public void setKeySize(Integer keySize) { this.keySize = keySize; }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }
}
