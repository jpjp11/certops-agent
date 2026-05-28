package dk.certops.agent.exposure;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class DeviceClassifierTest {

    // ---- helpers ----

    private static DeviceClassifier.Result classify(List<Integer> ports, String hostname) {
        return DeviceClassifier.classify(ports, hostname, Map.of());
    }

    private static DeviceClassifier.Result classify(List<Integer> ports, String hostname,
                                                     Map<Integer, Map<String, Object>> fp) {
        return DeviceClassifier.classify(ports, hostname, fp);
    }

    private static Map<String, Object> fp(String serverHeader) {
        Map<String, Object> fingerprint = new LinkedHashMap<>();
        fingerprint.put("server_header", serverHeader);
        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("fingerprint", fingerprint);
        return wrapper;
    }

    private static Map<String, Object> fpProduct(String product) {
        Map<String, Object> fingerprint = new LinkedHashMap<>();
        fingerprint.put("product", product);
        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("fingerprint", fingerprint);
        return wrapper;
    }

    private static Map<String, Object> fpCert(String cn) {
        Map<String, Object> fingerprint = new LinkedHashMap<>();
        fingerprint.put("cert_subject_cn", cn);
        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("fingerprint", fingerprint);
        return wrapper;
    }

    private static Map<String, Object> fpBanner(String banner) {
        Map<String, Object> fingerprint = new LinkedHashMap<>();
        fingerprint.put("banner", banner);
        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("fingerprint", fingerprint);
        return wrapper;
    }

    // ---- printer tests ----

    @Test
    void printer_byPort9100() {
        DeviceClassifier.Result r = classify(List.of(9100, 80, 443), null);
        assertEquals("printer", r.deviceType);
        assertTrue(r.confidence > 0.5);
    }

    @Test
    void printer_byHpServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("HP HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(80, 9100), "hp-laserjet", fpByPort);
        assertEquals("printer", r.deviceType);
        assertEquals("HP", r.vendor);
        assertTrue(r.confidence > 0.7);
    }

    @Test
    void printer_byCanonHostname() {
        DeviceClassifier.Result r = classify(List.of(80, 443, 631), "canon-mf445dw.local");
        assertEquals("printer", r.deviceType);
    }

    @Test
    void printer_byEpsonServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("EPSON HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(80, 631), null, fpByPort);
        assertEquals("printer", r.deviceType);
        assertEquals("Epson", r.vendor);
    }

    // ---- camera tests ----

    @Test
    void camera_byPort554() {
        DeviceClassifier.Result r = classify(List.of(554, 80), null);
        assertEquals("camera", r.deviceType);
        assertTrue(r.confidence > 0.5);
    }

    @Test
    void camera_byHikvisionServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("Hikvision-Webs"));
        DeviceClassifier.Result r = classify(List.of(80, 554, 8000), null, fpByPort);
        assertEquals("camera", r.deviceType);
        assertEquals("Hikvision", r.vendor);
        assertTrue(r.confidence > 0.8);
    }

    @Test
    void camera_byDahuaHostname() {
        DeviceClassifier.Result r = classify(List.of(80, 554), "dahua-ipc-cam1.local");
        assertEquals("camera", r.deviceType);
    }

    // ---- router / access-point tests ----

    @Test
    void router_byMikrotikBanner() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(8291, fpBanner("MikroTik RouterOS"));
        DeviceClassifier.Result r = classify(List.of(22, 80, 8291), "mikrotik-rb.local", fpByPort);
        assertEquals("router", r.deviceType);
        assertEquals("MikroTik", r.vendor);
        assertTrue(r.confidence > 0.8);
    }

    @Test
    void router_byFritzBoxServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(49000, fp("FRITZ!Box HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(22, 80, 443, 49000), null, fpByPort);
        assertEquals("router", r.deviceType);
    }

    @Test
    void router_byDns53AndWeb() {
        DeviceClassifier.Result r = classify(List.of(53, 80, 443), "gateway.local");
        assertEquals("router", r.deviceType);
    }

    @Test
    void accessPoint_byUnifiHostname() {
        DeviceClassifier.Result r = classify(List.of(22, 80, 443, 8080), "unifi-ap-pro.local");
        // UniFi APs may classify as access-point or router depending on scores
        assertTrue(r.deviceType.equals("access-point") || r.deviceType.equals("router"),
                "Expected access-point or router, got: " + r.deviceType);
    }

    // ---- NAS tests ----

    @Test
    void nas_bySynologyHostname() {
        DeviceClassifier.Result r = classify(List.of(5000, 5001, 22, 80), "synology-ds920.local");
        assertEquals("nas", r.deviceType);
        assertTrue(r.confidence > 0.7);
    }

    @Test
    void nas_byQnapHostname() {
        DeviceClassifier.Result r = classify(List.of(8080, 443, 22), "qnap-ts451.local");
        assertEquals("nas", r.deviceType);
    }

    @Test
    void nas_bySynologyServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(5000, fp("Synology DiskStation"));
        DeviceClassifier.Result r = classify(List.of(5000, 5001, 22), null, fpByPort);
        assertEquals("nas", r.deviceType);
        assertEquals("Synology", r.vendor);
    }

    // ---- Windows tests ----

    @Test
    void windows_byRdpPort() {
        DeviceClassifier.Result r = classify(List.of(3389, 135, 445, 80), null);
        assertEquals("windows", r.deviceType);
        assertTrue(r.confidence > 0.6);
    }

    @Test
    void windows_bySmbPorts() {
        DeviceClassifier.Result r = classify(List.of(445, 135, 139), null);
        assertEquals("windows", r.deviceType);
    }

    @Test
    void windows_byIisServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("Microsoft-IIS/10.0"));
        DeviceClassifier.Result r = classify(List.of(80, 443, 135), null, fpByPort);
        assertEquals("windows", r.deviceType);
    }

    // ---- mobile tests ----

    @Test
    void mobile_byIosSyncPort() {
        DeviceClassifier.Result r = classify(List.of(62078), null);
        assertEquals("mobile", r.deviceType);
        assertTrue(r.confidence > 0.7);
    }

    @Test
    void mobile_byIphoneHostname() {
        DeviceClassifier.Result r = classify(List.of(62078), "iphone-of-lars.local");
        assertEquals("mobile", r.deviceType);
        assertTrue(r.confidence > 0.8);
    }

    @Test
    void mobile_byAndroidHostname() {
        DeviceClassifier.Result r = classify(List.of(5555, 8080), "android-abc123.local");
        assertEquals("mobile", r.deviceType);
    }

    // ---- Mac tests ----

    @Test
    void mac_byAfpPort() {
        DeviceClassifier.Result r = classify(List.of(548, 22, 80), null);
        assertEquals("mac", r.deviceType);
    }

    @Test
    void mac_byMacbookHostname() {
        DeviceClassifier.Result r = classify(List.of(22, 548), "MacBook-Pro-Lars.local");
        assertEquals("mac", r.deviceType);
        assertTrue(r.confidence > 0.7);
    }

    // ---- Linux tests ----

    @Test
    void linux_byOpenSshOnly() {
        DeviceClassifier.Result r = classify(List.of(22), null);
        assertEquals("linux", r.deviceType);
    }

    @Test
    void linux_bySshAndSmallPortSet() {
        DeviceClassifier.Result r = classify(List.of(22, 9090), null);
        assertEquals("linux", r.deviceType);
    }

    // ---- Raspberry Pi tests ----

    @Test
    void raspberryPi_byHostname() {
        DeviceClassifier.Result r = classify(List.of(22, 80), "raspberrypi.local");
        assertEquals("raspberry-pi", r.deviceType);
    }

    @Test
    void raspberryPi_byRpiHostname() {
        DeviceClassifier.Result r = classify(List.of(22), "rpi4-sensor.local");
        assertEquals("raspberry-pi", r.deviceType);
    }

    // ---- IoT tests ----

    @Test
    void iot_byMqttPort() {
        DeviceClassifier.Result r = classify(List.of(1883), null);
        assertEquals("iot", r.deviceType);
    }

    @Test
    void iot_byMqttTlsPort() {
        DeviceClassifier.Result r = classify(List.of(8883, 80), null);
        assertEquals("iot", r.deviceType);
    }

    // ---- UPS tests ----

    @Test
    void ups_byApcServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("APC HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(80, 443, 3052), null, fpByPort);
        assertEquals("ups", r.deviceType);
        assertEquals("APC", r.vendor);
    }

    // ---- Server tests ----

    @Test
    void server_byWebAndSsh() {
        DeviceClassifier.Result r = classify(List.of(22, 80, 443, 8080, 8443, 3306), null);
        assertEquals("server", r.deviceType);
    }

    // ---- Unknown tests ----

    @Test
    void unknown_noSignals() {
        DeviceClassifier.Result r = classify(List.of(), null);
        assertEquals("unknown", r.deviceType);
    }

    @Test
    void unknown_sparseSignals() {
        DeviceClassifier.Result r = classify(List.of(12345), null);
        assertEquals("unknown", r.deviceType);
    }

    // ---- Confidence tests ----

    @Test
    void confidence_highWhenMultipleSignalsAgree() {
        // Port 9100 + HP server header + hostname all point to printer
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("HP HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(9100, 80, 631), "hp-laserjet.local", fpByPort);
        assertEquals("printer", r.deviceType);
        assertTrue(r.confidence >= 0.9, "Expected high confidence, got: " + r.confidence);
    }

    @Test
    void confidence_lowWhenOnlySingleWeakSignal() {
        // Port 80 alone — server, but weak
        DeviceClassifier.Result r = classify(List.of(80), null);
        assertTrue(r.confidence < 0.7, "Expected lower confidence for single port signal, got: " + r.confidence);
    }

    // ---- Evidence tests ----

    @Test
    void evidence_isPopulated() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("Hikvision-Webs"));
        DeviceClassifier.Result r = classify(List.of(554, 80), null, fpByPort);
        assertFalse(r.evidence.isEmpty(), "Evidence list should not be empty");
    }

    // ---- Result.toMap() test ----

    @Test
    void toMap_includesAllFields() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fp("HP HTTP Server"));
        DeviceClassifier.Result r = classify(List.of(9100), "hp-laserjet.local", fpByPort);
        Map<String, Object> m = r.toMap();
        assertTrue(m.containsKey("device_type"));
        assertTrue(m.containsKey("device_confidence"));
        assertTrue(m.containsKey("device_evidence"));
        assertTrue(m.containsKey("vendor"));
    }

    // ---- Fingerprint signals without ports ----

    @Test
    void classify_byProductTextAlone() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(80, fpProduct("Synology DSM"));
        DeviceClassifier.Result r = classify(List.of(80), null, fpByPort);
        assertEquals("nas", r.deviceType);
    }

    @Test
    void classify_byCertCnAlone() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(443, fpCert("Synology DiskStation Manager"));
        DeviceClassifier.Result r = classify(List.of(443), null, fpByPort);
        assertEquals("nas", r.deviceType);
    }

    @Test
    void classify_byBannerMikroTik() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(21, fpBanner("MikroTik FTP server"));
        DeviceClassifier.Result r = classify(List.of(21, 22, 80), null, fpByPort);
        assertEquals("router", r.deviceType);
        assertEquals("MikroTik", r.vendor);
    }

    // ---- TV / Speaker ----

    @Test
    void tv_byRokuProduct() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(8060, fpProduct("Roku"));
        DeviceClassifier.Result r = classify(List.of(8060), null, fpByPort);
        assertEquals("tv", r.deviceType);
    }

    @Test
    void speaker_bySonosServerHeader() {
        Map<Integer, Map<String, Object>> fpByPort = Map.of(1400, fp("Sonos/56.0"));
        DeviceClassifier.Result r = classify(List.of(1400, 1443), null, fpByPort);
        assertEquals("speaker", r.deviceType);
        assertEquals("Sonos", r.vendor);
    }
}
