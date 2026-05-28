package dk.certops.agent.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * OCSP and CRL revocation checker.
 * Checks leaf certificate revocation status via OCSP responder
 * using the Authority Information Access extension.
 */
@Component
public class OcspCrlChecker {

    private static final Logger log = LoggerFactory.getLogger(OcspCrlChecker.class);
    private static final int TIMEOUT_MS = 10000;
    private static final int MAX_RESPONSE_BYTES = 64 * 1024; // 64 KB max OCSP response

    /**
     * Check OCSP revocation status for a leaf certificate.
     * Requires the leaf cert and its issuer (index 0 and 1 in the chain).
     *
     * @param certs certificate chain (leaf at index 0, issuer at index 1+)
     * @return status string: "GOOD", "REVOKED", "UNKNOWN", "ERROR: ...", "NO_OCSP_URL"
     */
    public String checkOcsp(List<X509Certificate> certs) {
        if (certs == null || certs.size() < 2) {
            return "INSUFFICIENT_CHAIN";
        }

        X509Certificate leaf = certs.get(0);
        X509Certificate issuer = certs.get(1);

        try {
            // Extract OCSP URL from Authority Information Access extension
            String ocspUrl = extractOcspUrl(leaf);
            if (ocspUrl == null) {
                return "NO_OCSP_URL";
            }

            log.debug("OCSP URL for {}: {}", leaf.getSubjectX500Principal().getName(), ocspUrl);

            // Build OCSP request
            byte[] ocspRequest = buildOcspRequest(leaf, issuer);
            if (ocspRequest == null) {
                return "ERROR: failed to build OCSP request";
            }

            // Send OCSP request
            byte[] ocspResponse = sendOcspRequest(ocspUrl, ocspRequest);
            if (ocspResponse == null) {
                return "ERROR: no OCSP response";
            }

            // Parse OCSP response
            return parseOcspResponse(ocspResponse);

        } catch (Exception e) {
            log.debug("OCSP check failed: {}", e.getMessage());
            return "ERROR: " + e.getMessage();
        }
    }

    /**
     * Extract OCSP responder URL from the AIA extension (OID 1.3.6.1.5.5.7.1.1).
     */
    private String extractOcspUrl(X509Certificate cert) {
        try {
            byte[] aiaExtension = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
            if (aiaExtension == null) return null;

            // Parse ASN.1 manually to extract OCSP URL (no external deps)
            return parseAiaForOcsp(aiaExtension);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parse AIA extension value to extract OCSP responder URL.
     * Manual ASN.1 parsing without external dependencies.
     */
    private String parseAiaForOcsp(byte[] extensionValue) {
        try {
            // extensionValue is an OCTET STRING containing the actual extension
            // First, unwrap the outer OCTET STRING
            int idx = 0;
            if (extensionValue[idx] != 0x04) return null; // Not OCTET STRING
            idx++;
            int len = readAsn1Length(extensionValue, idx);
            idx += lengthBytes(extensionValue, idx);

            // Now we have the inner SEQUENCE (AuthorityInfoAccessSyntax)
            byte[] inner = new byte[len];
            System.arraycopy(extensionValue, idx, inner, 0, len);

            // Parse SEQUENCE of AccessDescription
            int pos = 0;
            if (inner[pos] != 0x30) return null; // Not SEQUENCE
            pos++;
            int seqLen = readAsn1Length(inner, pos);
            pos += lengthBytes(inner, pos);

            int seqEnd = pos + seqLen;

            while (pos < seqEnd) {
                // Each AccessDescription is a SEQUENCE
                if (inner[pos] != 0x30) break;
                pos++;
                int adLen = readAsn1Length(inner, pos);
                pos += lengthBytes(inner, pos);
                int adEnd = pos + adLen;

                // accessMethod is an OID
                if (inner[pos] == 0x06) { // OID
                    pos++;
                    int oidLen = readAsn1Length(inner, pos);
                    pos += lengthBytes(inner, pos);

                    byte[] oidBytes = new byte[oidLen];
                    System.arraycopy(inner, pos, oidBytes, 0, oidLen);
                    pos += oidLen;

                    // Check if this is OCSP (1.3.6.1.5.5.7.48.1)
                    // Encoded as: 2b 06 01 05 05 07 30 01
                    boolean isOcsp = oidLen == 8
                            && oidBytes[0] == 0x2b && oidBytes[1] == 0x06
                            && oidBytes[2] == 0x01 && oidBytes[3] == 0x05
                            && oidBytes[4] == 0x05 && oidBytes[5] == 0x07
                            && oidBytes[6] == 0x30 && oidBytes[7] == 0x01;

                    if (isOcsp) {
                        // accessLocation is a GeneralName (context tag [6] for URI)
                        if (pos < adEnd && (inner[pos] & 0xFF) == 0x86) { // context [6] implicit
                            pos++;
                            int urlLen = readAsn1Length(inner, pos);
                            pos += lengthBytes(inner, pos);
                            return new String(inner, pos, urlLen);
                        }
                    }
                }

                pos = adEnd;
            }

            return null;
        } catch (Exception e) {
            log.debug("Manual AIA parsing failed: {}", e.getMessage());
            return null;
        }
    }

    private int readAsn1Length(byte[] data, int offset) {
        int b = data[offset] & 0xFF;
        if (b < 0x80) return b;
        int numBytes = b & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (data[offset + 1 + i] & 0xFF);
        }
        return length;
    }

    private int lengthBytes(byte[] data, int offset) {
        int b = data[offset] & 0xFF;
        if (b < 0x80) return 1;
        return 1 + (b & 0x7F);
    }

    /**
     * Build a minimal OCSP request for the leaf certificate.
     * Uses SHA-1 hash of issuer name and key as per RFC 6960.
     */
    private byte[] buildOcspRequest(X509Certificate leaf, X509Certificate issuer) {
        try {
            java.security.MessageDigest sha1 = java.security.MessageDigest.getInstance("SHA-1");

            // Hash of issuer's distinguished name (DER encoded)
            byte[] issuerNameHash = sha1.digest(issuer.getSubjectX500Principal().getEncoded());

            // Hash of issuer's public key (the actual key bits, without the algorithm wrapper)
            sha1.reset();
            byte[] issuerKeyHash = sha1.digest(issuer.getPublicKey().getEncoded());
            // Note: we should hash just the BIT STRING contents, but for many OCSP responders
            // hashing the full SubjectPublicKeyInfo also works. Let's extract the actual key bits.
            byte[] pubKeyInfo = issuer.getPublicKey().getEncoded();
            // SubjectPublicKeyInfo is SEQUENCE { AlgorithmIdentifier, BIT STRING }
            // We need the BIT STRING value (without the unused bits byte)
            issuerKeyHash = sha1.digest(extractPublicKeyBits(pubKeyInfo));

            // Serial number
            byte[] serialNumber = leaf.getSerialNumber().toByteArray();

            // Build CertID: SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
            // hashAlgorithm = SEQUENCE { OID sha1 (1.3.14.3.2.26), NULL }
            byte[] sha1Oid = {0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a}; // OID 1.3.14.3.2.26
            byte[] hashAlg = wrapSequence(concat(sha1Oid, new byte[]{0x05, 0x00})); // SEQUENCE { OID, NULL }

            byte[] nameHashOctet = wrapOctetString(issuerNameHash);
            byte[] keyHashOctet = wrapOctetString(issuerKeyHash);
            byte[] serialInt = wrapInteger(serialNumber);

            byte[] certId = wrapSequence(concat(hashAlg, nameHashOctet, keyHashOctet, serialInt));

            // Request = SEQUENCE { certID }
            byte[] request = wrapSequence(certId);

            // TBSRequest = SEQUENCE { requestList: SEQUENCE OF Request }
            byte[] requestList = wrapSequence(request);
            byte[] tbsRequest = wrapSequence(requestList);

            // OCSPRequest = SEQUENCE { tbsRequest }
            return wrapSequence(tbsRequest);

        } catch (Exception e) {
            log.debug("Failed to build OCSP request: {}", e.getMessage());
            return null;
        }
    }

    private byte[] extractPublicKeyBits(byte[] subjectPublicKeyInfo) {
        // Parse SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        int pos = 0;
        if (subjectPublicKeyInfo[pos] != 0x30) return subjectPublicKeyInfo;
        pos++;
        readAsn1Length(subjectPublicKeyInfo, pos);
        pos += lengthBytes(subjectPublicKeyInfo, pos);

        // Skip AlgorithmIdentifier (SEQUENCE)
        if (subjectPublicKeyInfo[pos] != 0x30) return subjectPublicKeyInfo;
        pos++;
        int algLen = readAsn1Length(subjectPublicKeyInfo, pos);
        pos += lengthBytes(subjectPublicKeyInfo, pos);
        pos += algLen;

        // BIT STRING
        if (subjectPublicKeyInfo[pos] != 0x03) return subjectPublicKeyInfo;
        pos++;
        int bsLen = readAsn1Length(subjectPublicKeyInfo, pos);
        pos += lengthBytes(subjectPublicKeyInfo, pos);
        pos++; // skip unused bits byte

        byte[] bits = new byte[bsLen - 1];
        System.arraycopy(subjectPublicKeyInfo, pos, bits, 0, bsLen - 1);
        return bits;
    }

    /**
     * Send OCSP request to the responder URL.
     */
    private byte[] sendOcspRequest(String ocspUrl, byte[] requestData) {
        try {
            URL url = URI.create(ocspUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/ocsp-request");
            conn.setRequestProperty("Accept", "application/ocsp-response");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setDoOutput(true);

            try (OutputStream out = conn.getOutputStream()) {
                out.write(requestData);
            }

            if (conn.getResponseCode() != 200) {
                log.debug("OCSP responder returned HTTP {}", conn.getResponseCode());
                return null;
            }

            try (InputStream in = conn.getInputStream()) {
                byte[] data = in.readNBytes(MAX_RESPONSE_BYTES);
                if (in.read() != -1) {
                    log.warn("OCSP response exceeded {} bytes, truncated", MAX_RESPONSE_BYTES);
                }
                return data;
            }
        } catch (Exception e) {
            log.debug("OCSP request failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Parse OCSP response to extract certificate status.
     * OCSPResponse = SEQUENCE { responseStatus, responseBytes }
     */
    private String parseOcspResponse(byte[] responseData) {
        try {
            int pos = 0;
            // OCSPResponse: SEQUENCE
            if (responseData[pos] != 0x30) return "ERROR: invalid response";
            pos++;
            readAsn1Length(responseData, pos);
            pos += lengthBytes(responseData, pos);

            // responseStatus: ENUMERATED
            if (responseData[pos] != 0x0A) return "ERROR: missing status";
            pos++;
            int statusLen = readAsn1Length(responseData, pos);
            pos += lengthBytes(responseData, pos);

            int responseStatus = responseData[pos] & 0xFF;
            pos += statusLen;

            if (responseStatus != 0) {
                return switch (responseStatus) {
                    case 1 -> "ERROR: malformedRequest";
                    case 2 -> "ERROR: internalError";
                    case 3 -> "ERROR: tryLater";
                    case 5 -> "ERROR: sigRequired";
                    case 6 -> "ERROR: unauthorized";
                    default -> "ERROR: unknown status " + responseStatus;
                };
            }

            // responseStatus is successful(0), now find the certStatus in the response
            // Navigate: responseBytes -> BasicOCSPResponse -> tbsResponseData -> responses -> SingleResponse -> certStatus
            // This is deeply nested ASN.1. Search for the certStatus tag.
            // certStatus is a CHOICE: good[0], revoked[1], unknown[2]
            // We'll scan for the pattern after CertID in the response.

            return findCertStatus(responseData, pos);

        } catch (Exception e) {
            log.debug("Failed to parse OCSP response: {}", e.getMessage());
            return "ERROR: parse failed";
        }
    }

    /**
     * Scan OCSP response bytes for the certStatus field.
     * certStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT ..., unknown [2] IMPLICIT NULL }
     */
    private String findCertStatus(byte[] data, int startPos) {
        // Walk through the response looking for cert status after the certID
        // We need to go deep into: [0] -> SEQUENCE (BasicOCSPResponse) -> SEQUENCE (tbsResponseData)
        // -> SEQUENCE (responses) -> SEQUENCE (SingleResponse) -> certStatus

        // Simplified: scan for context tags [0], [1], [2] that appear after
        // a SHA-1 hash algorithm OID (which is part of CertID)
        // SHA-1 OID bytes: 2b 0e 03 02 1a

        for (int i = startPos; i < data.length - 5; i++) {
            // Look for SHA-1 OID in CertID
            if (data[i] == 0x2b && data[i + 1] == 0x0e && data[i + 2] == 0x03
                    && data[i + 3] == 0x02 && data[i + 4] == 0x1a) {
                // Found SHA-1 OID. Skip past CertID to find certStatus.
                // CertID has: hashAlg + issuerNameHash(22 bytes) + issuerKeyHash(22 bytes) + serialNumber
                // Jump ahead past the hashes to find the status
                int j = i + 5;

                // Skip NULL after OID
                if (j < data.length && data[j] == 0x05) j += 2;

                // Skip issuerNameHash (OCTET STRING, usually 22 bytes: tag + len + 20 bytes)
                if (j < data.length && data[j] == 0x04) {
                    j++;
                    int hashLen = readAsn1Length(data, j);
                    j += lengthBytes(data, j);
                    j += hashLen;
                }

                // Skip issuerKeyHash
                if (j < data.length && data[j] == 0x04) {
                    j++;
                    int hashLen = readAsn1Length(data, j);
                    j += lengthBytes(data, j);
                    j += hashLen;
                }

                // Skip serialNumber (INTEGER)
                if (j < data.length && data[j] == 0x02) {
                    j++;
                    int snLen = readAsn1Length(data, j);
                    j += lengthBytes(data, j);
                    j += snLen;
                }

                // Now we should be at certStatus
                if (j < data.length) {
                    int tag = data[j] & 0xFF;
                    if (tag == 0x80) return "GOOD";      // [0] IMPLICIT NULL
                    if (tag == 0xA1) return "REVOKED";    // [1] IMPLICIT SEQUENCE
                    if (tag == 0x82) return "UNKNOWN";    // [2] IMPLICIT NULL
                }
            }
        }

        return "UNKNOWN";
    }

    // ASN.1 helper methods

    private byte[] wrapSequence(byte[] content) {
        return wrapTag((byte) 0x30, content);
    }

    private byte[] wrapOctetString(byte[] content) {
        return wrapTag((byte) 0x04, content);
    }

    private byte[] wrapInteger(byte[] content) {
        return wrapTag((byte) 0x02, content);
    }

    private byte[] wrapTag(byte tag, byte[] content) {
        byte[] lenBytes = asn1Length(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private byte[] asn1Length(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        } else if (length < 0x100) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) (length & 0xFF)};
        }
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }
}
