package dk.certops.agent.transport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * HMAC-SHA256 request signing for additional transport security.
 */
@Component
public class HmacSigner {

    private static final Logger log = LoggerFactory.getLogger(HmacSigner.class);
    private static final String ALGORITHM = "HmacSHA256";

    /**
     * Sign a request body with the given secret.
     * Returns Base64-encoded HMAC-SHA256 signature.
     */
    public String sign(String body, String secret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
            mac.init(keySpec);
            byte[] hash = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            log.error("HMAC signing failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Verify a signature against a body and secret.
     */
    public boolean verify(String body, String secret, String signature) {
        String expected = sign(body, secret);
        if (expected == null || signature == null) return false;
        // Constant-time comparison to prevent timing attacks
        return java.security.MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                signature.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
