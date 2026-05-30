package dk.certops.agent.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that the agent only treats genuinely-internal RFC1918/ULA ranges as valid scan
 * targets, and refuses loopback + link-local (incl. cloud metadata 169.254.169.254) — the
 * fix for review finding HIGH #4 (scan-scope redirection / metadata SSRF).
 */
class NetworkValidatorTest {

    @Test
    void rfc1918_isScannable() {
        assertTrue(NetworkValidator.isPrivateIp("10.0.0.5"));
        assertTrue(NetworkValidator.isPrivateIp("172.16.4.9"));
        assertTrue(NetworkValidator.isPrivateIp("192.168.1.20"));
        assertTrue(NetworkValidator.isPrivateIp("100.64.0.1")); // CGN
    }

    @Test
    void loopback_isNotScannable() {
        assertFalse(NetworkValidator.isPrivateIp("127.0.0.1"));
        assertFalse(NetworkValidator.isPrivateIp("127.0.0.53"));
    }

    @Test
    void linkLocalAndMetadata_isNotScannable() {
        assertFalse(NetworkValidator.isPrivateIp("169.254.0.1"));
        assertFalse(NetworkValidator.isPrivateIp("169.254.169.254")); // cloud metadata
    }

    @Test
    void anyLocal_isNotScannable() {
        assertFalse(NetworkValidator.isPrivateIp("0.0.0.0"));
    }

    @Test
    void publicIp_isNotScannable() {
        assertFalse(NetworkValidator.isPrivateIp("8.8.8.8"));
        assertFalse(NetworkValidator.isPrivateIp("203.0.113.10"));
    }

    @Test
    void cidr_loopbackAndLinkLocal_rejected() {
        assertFalse(NetworkValidator.isPrivateCidr("127.0.0.0/8"));
        assertFalse(NetworkValidator.isPrivateCidr("169.254.0.0/16"));
    }

    @Test
    void cidr_rfc1918_accepted() {
        assertTrue(NetworkValidator.isPrivateCidr("10.0.0.0/8"));
        assertTrue(NetworkValidator.isPrivateCidr("192.168.0.0/16"));
    }

    @Test
    void filterPrivateOnly_dropsLoopbackLinkLocalAndPublic() {
        List<String> in = List.of("10.0.0.1", "127.0.0.1", "169.254.169.254", "8.8.8.8", "192.168.0.2");
        List<String> out = NetworkValidator.filterPrivateOnly(in);
        assertEquals(List.of("10.0.0.1", "192.168.0.2"), out);
    }
}
