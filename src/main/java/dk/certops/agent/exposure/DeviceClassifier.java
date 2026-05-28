package dk.certops.agent.exposure;

import java.util.*;

/**
 * Scores device type from already-collected signals (ports, hostname, fingerprints).
 * No new network calls are made — all input comes from the port scan and fingerprint
 * probes that already ran.
 */
public final class DeviceClassifier {

    private DeviceClassifier() {}

    public static class Result {
        public final String deviceType;
        public final String vendor;
        public final String model;
        public final double confidence;
        public final List<String> evidence;

        Result(String deviceType, String vendor, String model, double confidence, List<String> evidence) {
            this.deviceType = deviceType;
            this.vendor = vendor;
            this.model = model;
            this.confidence = confidence;
            this.evidence = Collections.unmodifiableList(evidence);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("device_type", deviceType);
            if (vendor != null) m.put("vendor", vendor);
            if (model != null) m.put("model", model);
            m.put("device_confidence", confidence);
            m.put("device_evidence", evidence);
            return m;
        }
    }

    // Accumulates scores for each device type during classification
    private static class Scores {
        final Map<String, Integer> byType = new LinkedHashMap<>();
        String vendor;
        String model;
        final List<String> evidence = new ArrayList<>();

        void score(String type, int points, String why) {
            byType.merge(type, points, Integer::sum);
            evidence.add(type + " +" + points + ": " + why);
        }

        void score(String type, int points, String why, String vendorHint, String modelHint) {
            score(type, points, why);
            if (vendorHint != null && vendor == null) vendor = vendorHint;
            if (modelHint != null && model == null) model = modelHint;
        }
    }

    /**
     * Classify a host using only already-collected data.
     *
     * @param ports          open TCP port numbers
     * @param hostname       reverse-DNS hostname, may be null
     * @param fpByPort       fingerprint results keyed by port; each value is the
     *                       per-port result map from FingerprintService
     */
    @SuppressWarnings("unchecked")
    public static Result classify(List<Integer> ports, String hostname,
                                  Map<Integer, Map<String, Object>> fpByPort) {
        Scores s = new Scores();
        Set<Integer> p = new HashSet<>(ports);
        String h = hostname != null ? hostname.toLowerCase() : "";

        applyHostnameSignals(h, s);
        applyPortSignals(p, s);
        applyFingerprintSignals(fpByPort != null ? fpByPort : Collections.emptyMap(), s);

        return pickWinner(s);
    }

    // ── Hostname signals ──────────────────────────────────────────────────────

    private static void applyHostnameSignals(String h, Scores s) {
        if (h.isEmpty()) return;

        // Apple devices — iphone/ipad names are very distinctive
        if (any(h, "iphone", "ipad", "ipod-touch")) {
            s.score("mobile", 70, "hostname indicates Apple mobile device", "Apple", null);
        } else if (any(h, "macbook", "imac", "mac-mini", "macmini", "mac-pro", "macpro")) {
            s.score("mac", 65, "hostname indicates Apple Mac", "Apple", null);
        }

        // Android / Google
        if (h.startsWith("android-") || h.contains("_android_")) s.score("mobile", 60, "hostname suggests Android device");
        if (any(h, "pixel-", "pixel_") || h.matches(".*pixel-\\d+.*")) s.score("mobile", 60, "hostname suggests Google Pixel", "Google", null);
        if (any(h, "galaxy-", "galaxy_")) s.score("mobile", 55, "hostname suggests Samsung Galaxy", "Samsung", null);

        // Printers — vendor-specific keywords carry high weight
        if (any(h, "laserjet", "officejet", "deskjet", "pagewide", "hp-laserjet")) {
            s.score("printer", 65, "hostname contains HP printer model", "HP", extractFromString(h, "laserjet", "officejet", "deskjet"));
        } else if (any(h, "hp-", "hpprinter", "hplaserjet")) {
            s.score("printer", 50, "hostname suggests HP printer", "HP", null);
        } else if (any(h, "canon-", "canonmfp", "canon_")) {
            s.score("printer", 55, "hostname suggests Canon printer", "Canon", null);
        } else if (any(h, "epson")) {
            s.score("printer", 55, "hostname suggests Epson printer", "Epson", null);
        } else if (any(h, "brother")) {
            s.score("printer", 55, "hostname suggests Brother printer", "Brother", null);
        } else if (any(h, "kyocera")) {
            s.score("printer", 55, "hostname suggests Kyocera printer", "Kyocera", null);
        } else if (any(h, "ricoh")) {
            s.score("printer", 50, "hostname suggests Ricoh printer", "Ricoh", null);
        } else if (any(h, "xerox")) {
            s.score("printer", 55, "hostname suggests Xerox printer", "Xerox", null);
        } else if (any(h, "konica", "konicaminolta")) {
            s.score("printer", 50, "hostname suggests Konica Minolta printer", "Konica Minolta", null);
        } else if (any(h, "lexmark")) {
            s.score("printer", 55, "hostname suggests Lexmark printer", "Lexmark", null);
        } else if (any(h, "oki-", "okidata")) {
            s.score("printer", 50, "hostname suggests OKI printer", "OKI", null);
        }
        if (any(h, "printer", "-print.", "_print_")) s.score("printer", 40, "hostname contains 'printer'");

        // Cameras
        if (any(h, "hikvision", "hikv-", "hkvision", "hik-")) {
            s.score("camera", 70, "hostname indicates Hikvision camera", "Hikvision", null);
        } else if (any(h, "dahua", "dahuasec")) {
            s.score("camera", 70, "hostname indicates Dahua camera", "Dahua", null);
        } else if (any(h, "axis-", "axis2", "axiscam")) {
            s.score("camera", 60, "hostname indicates Axis camera", "Axis", null);
        } else if (any(h, "reolink")) {
            s.score("camera", 65, "hostname indicates Reolink camera", "Reolink", null);
        } else if (any(h, "amcrest")) {
            s.score("camera", 65, "hostname indicates Amcrest camera", "Amcrest", null);
        } else if (any(h, "hanwha", "wisenet")) {
            s.score("camera", 65, "hostname indicates Hanwha/Wisenet camera", "Hanwha", null);
        } else if (any(h, "vivotek")) {
            s.score("camera", 65, "hostname indicates Vivotek camera", "Vivotek", null);
        } else if (any(h, "foscam")) {
            s.score("camera", 60, "hostname indicates Foscam camera", "Foscam", null);
        }
        if (any(h, "ipcam", "ipcamera", "camera-", "cam-0", "cam-1", "nvr-", "dvr-")) {
            s.score("camera", 45, "hostname contains camera/NVR indicator");
        }

        // NAS
        if (any(h, "synology", "diskstation", "ds-")) {
            s.score("nas", 75, "hostname indicates Synology NAS", "Synology", null);
        } else if (any(h, "qnap", "turbonas")) {
            s.score("nas", 75, "hostname indicates QNAP NAS", "QNAP", null);
        } else if (any(h, "readynas")) {
            s.score("nas", 70, "hostname indicates Netgear ReadyNAS", "Netgear", null);
        } else if (any(h, "asustor")) {
            s.score("nas", 70, "hostname indicates ASUSTOR NAS", "ASUSTOR", null);
        } else if (any(h, "terramaster")) {
            s.score("nas", 65, "hostname indicates TerraMaster NAS", "TerraMaster", null);
        } else if (any(h, "drobo")) {
            s.score("nas", 65, "hostname indicates Drobo NAS", "Drobo", null);
        }
        if (h.endsWith("-nas") || h.endsWith(".nas") || h.contains("-nas-") || h.contains("_nas_")) {
            s.score("nas", 40, "hostname contains 'nas'");
        }

        // Routers / Gateways / Firewalls
        if (any(h, "mikrotik", "routeros")) {
            s.score("router", 70, "hostname indicates MikroTik router", "MikroTik", null);
        } else if (any(h, "draytek")) {
            s.score("router", 70, "hostname indicates DrayTek router", "DrayTek", null);
        } else if (any(h, "ubnt", "unifi", "ubiquiti")) {
            s.score("router", 60, "hostname indicates Ubiquiti device", "Ubiquiti", null);
        } else if (any(h, "eero")) {
            s.score("router", 65, "hostname indicates Amazon Eero", "Amazon", null);
        } else if (any(h, "orbi")) {
            s.score("router", 60, "hostname indicates Netgear Orbi", "Netgear", null);
        } else if (any(h, "covr")) {
            s.score("router", 55, "hostname indicates D-Link Covr", "D-Link", null);
        } else if (any(h, "archer", "tp-link", "tplink")) {
            s.score("router", 60, "hostname indicates TP-Link device", "TP-Link", null);
        } else if (any(h, "fritzbox", "fritz!box", "fritz-box", "fritz-")) {
            s.score("router", 70, "hostname indicates AVM FRITZ!Box", "AVM", "FRITZ!Box");
        } else if (any(h, "pfsense")) {
            s.score("router", 70, "hostname indicates pfSense firewall");
        } else if (any(h, "opnsense")) {
            s.score("router", 70, "hostname indicates OPNsense firewall");
        } else if (any(h, "edgerouter", "edgeswitch")) {
            s.score("router", 65, "hostname indicates Ubiquiti EdgeRouter/EdgeSwitch", "Ubiquiti", null);
        } else if (any(h, "asus") && !any(h, "asustor")) {
            s.score("router", 30, "hostname suggests ASUS (likely router/AP)");
        }
        if (any(h, "router", "gateway", "gw-", "-gw.", "firewall", "fw-", "-rtr.", "rtr-")) {
            s.score("router", 40, "hostname contains router/gateway indicator");
        }

        // Access points
        if (any(h, "-ap.", "ap-0", "ap-1", "wap-", "wifi-ap", "accesspoint", "access-point")) {
            s.score("access-point", 45, "hostname indicates wireless access point");
        }

        // Switches
        if (any(h, "sw-core", "sw-dist", "sw-access", "coreswitch", "netswitch")) {
            s.score("switch", 50, "hostname indicates network switch");
        } else if (h.matches(".*-sw-\\d+.*") || h.matches(".*sw\\d+\\..*")) {
            s.score("switch", 40, "hostname pattern indicates network switch");
        }

        // TV / Streaming
        if (any(h, "appletv", "apple-tv", "atv-")) {
            s.score("tv", 70, "hostname indicates Apple TV", "Apple", "Apple TV");
        } else if (any(h, "chromecast", "googletv", "google-cast")) {
            s.score("tv", 70, "hostname indicates Chromecast/Google TV", "Google", null);
        } else if (any(h, "firetv", "fire-tv", "firestick", "fire-stick")) {
            s.score("tv", 70, "hostname indicates Amazon Fire TV", "Amazon", null);
        } else if (any(h, "roku-", "rokubox", "roku_")) {
            s.score("tv", 65, "hostname indicates Roku device", "Roku", null);
        } else if (any(h, "nvidia-shield", "shield-tv", "shieldtv")) {
            s.score("tv", 65, "hostname indicates Nvidia SHIELD TV", "Nvidia", "SHIELD TV");
        } else if (any(h, "androidtv", "android-tv")) {
            s.score("tv", 60, "hostname indicates Android TV");
        } else if (any(h, "samsungtv", "samsung-tv", "smarttv")) {
            s.score("tv", 55, "hostname indicates smart TV");
        }

        // Speakers / Audio
        if (any(h, "sonos-", "sonos_", "sonosamp")) {
            s.score("speaker", 75, "hostname indicates Sonos speaker", "Sonos", null);
        } else if (any(h, "bose-", "bosesound")) {
            s.score("speaker", 70, "hostname indicates Bose device", "Bose", null);
        } else if (any(h, "homepod", "home-pod")) {
            s.score("speaker", 70, "hostname indicates Apple HomePod", "Apple", "HomePod");
        } else if (any(h, "echo-dot", "echo-show", "amazon-echo", "alexa-")) {
            s.score("speaker", 65, "hostname indicates Amazon Echo", "Amazon", null);
        }

        // UPS / PDU
        if (any(h, "apc-", "apcups")) {
            s.score("ups", 70, "hostname indicates APC UPS", "APC", null);
        } else if (any(h, "eaton-", "eatonups")) {
            s.score("ups", 70, "hostname indicates Eaton UPS", "Eaton", null);
        } else if (any(h, "cyberpower-", "cyberups")) {
            s.score("ups", 65, "hostname indicates CyberPower UPS", "CyberPower", null);
        } else if (h.endsWith("-ups") || h.startsWith("ups-") || h.contains("-ups-")) {
            s.score("ups", 55, "hostname contains 'ups'");
        } else if (any(h, "pdu-", "-pdu")) {
            s.score("ups", 40, "hostname indicates PDU");
        }

        // Raspberry Pi
        if (any(h, "raspberrypi", "raspberry-pi", "raspbian", "dietpi")) {
            s.score("raspberry-pi", 75, "hostname indicates Raspberry Pi");
        } else if (h.startsWith("rpi") || h.endsWith("-rpi") || (h.startsWith("pi-") && h.length() < 15)) {
            s.score("raspberry-pi", 55, "hostname pattern suggests Raspberry Pi");
        }

        // Smart appliances — require specific model keywords, not vendor alone
        if (any(h, "familyhub", "family-hub")) {
            s.score("appliance", 75, "hostname contains 'Family Hub' — Samsung refrigerator", "Samsung", "Family Hub");
        } else if (any(h, "refrigerator", "fridge", "freezer")) {
            s.score("appliance", 65, "hostname contains appliance keyword");
        }

        // Generic Windows PC names (often like DESKTOP-ABC1234 or LAPTOP-XXXXXX)
        if (h.startsWith("desktop-") || h.startsWith("laptop-") || h.startsWith("workstation-")) {
            s.score("windows", 45, "hostname pattern indicates Windows PC");
        }
    }

    // ── Port signals ──────────────────────────────────────────────────────────

    private static void applyPortSignals(Set<Integer> p, Scores s) {
        // Printers
        if (p.contains(9100)) s.score("printer", 70, "port 9100 (JetDirect raw printing)");
        if (p.contains(515)) s.score("printer", 45, "port 515 (LPD/LPR)");
        if (p.contains(631)) {
            if (p.contains(9100)) s.score("printer", 25, "ports 631+9100 (IPP + JetDirect combo)");
            else if (p.size() <= 5) s.score("printer", 50, "port 631 (IPP) with small port set");
            else s.score("printer", 25, "port 631 (IPP)");
        }

        // Cameras
        if (p.contains(554)) s.score("camera", 60, "port 554 (RTSP — streaming camera)");
        if (p.contains(8554)) s.score("camera", 55, "port 8554 (RTSP alt)");
        if (p.contains(37777)) s.score("camera", 60, "port 37777 (Dahua SDK)");
        if (p.contains(8000) && p.contains(554)) s.score("camera", 25, "ports 8000+554 (Hikvision SDK + RTSP)");

        // Mobile (Apple)
        if (p.contains(62078)) s.score("mobile", 75, "port 62078 (Apple iOS device sync)");

        // Mac / Apple
        if (p.contains(548)) s.score("mac", 65, "port 548 (AFP — Apple Filing Protocol)");
        if (p.contains(3283)) s.score("mac", 50, "port 3283 (Apple Remote Desktop)");

        // Windows
        if (p.contains(3389)) s.score("windows", 65, "port 3389 (RDP)");
        if (p.contains(445) && p.contains(135)) s.score("windows", 65, "ports 445+135 (SMB + MSRPC)");
        else if (p.contains(5985) || p.contains(5986)) s.score("windows", 55, "port 5985/5986 (WinRM)");

        // NAS
        if (p.contains(5000) && p.contains(5001)) {
            if (p.size() <= 8) s.score("nas", 65, "ports 5000+5001 (Synology DSM HTTP/HTTPS)");
            else s.score("nas", 40, "ports 5000+5001 present");
        }
        if (p.contains(8080) && p.contains(443) && p.contains(445)) s.score("nas", 35, "ports 8080+443+445 — possible NAS");
        if (p.contains(873)) s.score("nas", 25, "port 873 (rsync — common on NAS)");
        if (p.contains(6789)) s.score("nas", 30, "port 6789 (Synology Surveillance Station)");

        // Router / Network device
        if (p.contains(53) && p.contains(67)) {
            s.score("router", 60, "ports 53+67 (DNS + DHCP server)");
        } else if (p.contains(53) && p.size() <= 4) {
            s.score("router", 50, "port 53 (DNS) with very small port set");
        } else if (p.contains(53) && (p.contains(80) || p.contains(443)) && p.size() <= 7) {
            s.score("router", 45, "port 53 (DNS) with web interface");
        }
        if (p.contains(7547)) s.score("router", 55, "port 7547 (TR-069/CWMP — ISP CPE management)");
        if (p.contains(179)) s.score("router", 45, "port 179 (BGP — routing protocol)");
        if (p.contains(1723)) s.score("router", 40, "port 1723 (PPTP VPN)");
        if (p.contains(8291)) s.score("router", 55, "port 8291 (MikroTik Winbox)");
        if (p.contains(8728) || p.contains(8729)) s.score("router", 55, "port 8728/8729 (MikroTik API)");
        if (p.contains(22) && p.contains(80) && p.contains(443) && p.size() <= 5) {
            s.score("router", 40, "SSH + HTTP + HTTPS only — likely management device");
        }

        // IoT / MQTT
        if (p.contains(1883)) s.score("iot", 60, "port 1883 (MQTT)");
        if (p.contains(8883)) s.score("iot", 60, "port 8883 (MQTT over TLS)");
        if (p.contains(5683)) s.score("iot", 55, "port 5683 (CoAP — constrained IoT protocol)");

        // TV / Streaming
        if (p.contains(8009)) s.score("tv", 65, "port 8009 (Chromecast/Cast protocol)");

        // UPS
        if (p.contains(3052)) s.score("ups", 55, "port 3052 (APC PowerChute)");
        if (p.contains(9617)) s.score("ups", 50, "port 9617 (Eaton UPS daemon)");

        // SSH alone — generic Linux server hint
        if (p.contains(22) && !p.contains(53) && !p.contains(9100) && !p.contains(554) && !p.contains(1883)) {
            if (p.size() == 1) s.score("linux", 45, "SSH only");
            else if (p.size() <= 3) s.score("linux", 35, "SSH with small port set");
            else if (p.contains(80) || p.contains(443)) s.score("server", 30, "SSH + web server");
        }

        // Web server alone — very generic
        if ((p.contains(80) || p.contains(443)) && !p.contains(9100) && !p.contains(554)
                && !p.contains(5000) && !p.contains(53)) {
            s.score("server", 20, "web ports open");
        }

        // SMB without MSRPC — more likely NAS/Samba than Windows
        if (p.contains(445) && !p.contains(135)) s.score("nas", 25, "port 445 (SMB) without MSRPC — possibly NAS/Samba");

        // Telnet — older router or IoT
        if (p.contains(23)) s.score("router", 25, "port 23 (Telnet — common on older routers)");
        if (p.contains(2323)) s.score("iot", 35, "port 2323 (Telnet alt — often IoT/embedded)");
    }

    // ── Fingerprint signals ───────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static void applyFingerprintSignals(Map<Integer, Map<String, Object>> fpByPort, Scores s) {
        for (Map.Entry<Integer, Map<String, Object>> entry : fpByPort.entrySet()) {
            int port = entry.getKey();
            Map<String, Object> portResult = entry.getValue();
            if (portResult == null) continue;

            Object fpObj = portResult.get("fingerprint");
            if (!(fpObj instanceof Map)) continue;
            Map<String, Object> fp = (Map<String, Object>) fpObj;

            String product      = lower(fp.get("product"));
            String serverHeader = lower(fp.get("server_header"));
            String poweredBy    = lower(fp.get("x_powered_by"));
            String certCn       = lower(fp.get("cert_subject_cn"));
            String certIssuer   = lower(fp.get("cert_issuer_cn"));
            String banner       = lower(fp.get("banner"));

            if (!serverHeader.isEmpty()) applyServerHeaderSignals(serverHeader, port, s);
            if (!poweredBy.isEmpty())    applyProductTextSignals(poweredBy, "X-Powered-By", port, s);
            if (!product.isEmpty() && !product.equals("unknown")) applyProductTextSignals(product, "service product", port, s);
            if (!certCn.isEmpty())       applyCertTextSignals(certCn, false, port, s);
            if (!certIssuer.isEmpty())   applyCertTextSignals(certIssuer, true, port, s);
            if (!banner.isEmpty())       applyBannerTextSignals(banner, port, s);
        }
    }

    private static void applyServerHeaderSignals(String h, int port, Scores s) {
        // Printers
        if (any(h, "hp http server", "hp-ews", "hp embedded web server", "hp laserjet")) {
            s.score("printer", 70, "Server header indicates HP printer web server (port " + port + ")", "HP", null);
        } else if (any(h, "laserjet", "officejet", "deskjet", "pagewide")) {
            s.score("printer", 75, "Server header contains HP printer model (port " + port + ")", "HP", extractFromString(h, "laserjet", "officejet", "deskjet"));
        } else if (any(h, "canon http", "canon-http", "canon remote", "canon ews")) {
            s.score("printer", 70, "Server header indicates Canon web server (port " + port + ")", "Canon", null);
        } else if (any(h, "epson web", "epson http", "epsontm")) {
            s.score("printer", 70, "Server header indicates Epson device (port " + port + ")", "Epson", null);
        } else if (any(h, "brother http", "brother ews", "brother web")) {
            s.score("printer", 70, "Server header indicates Brother printer (port " + port + ")", "Brother", null);
        } else if (any(h, "kyocera")) {
            s.score("printer", 65, "Server header contains Kyocera (port " + port + ")", "Kyocera", null);
        } else if (any(h, "xerox")) {
            s.score("printer", 65, "Server header contains Xerox (port " + port + ")", "Xerox", null);
        } else if (any(h, "ricoh")) {
            s.score("printer", 65, "Server header contains Ricoh (port " + port + ")", "Ricoh", null);
        } else if (any(h, "oki data", "okidata")) {
            s.score("printer", 60, "Server header indicates OKI printer (port " + port + ")", "OKI", null);
        }

        // NAS
        if (any(h, "synology")) {
            s.score("nas", 75, "Server header contains Synology (port " + port + ")", "Synology", null);
        } else if (any(h, "qnap")) {
            s.score("nas", 75, "Server header contains QNAP (port " + port + ")", "QNAP", null);
        } else if (any(h, "asustor")) {
            s.score("nas", 70, "Server header contains ASUSTOR (port " + port + ")", "ASUSTOR", null);
        } else if (any(h, "terramaster")) {
            s.score("nas", 65, "Server header contains TerraMaster (port " + port + ")", "TerraMaster", null);
        }

        // Routers / Firewalls
        if (any(h, "routeros", "mikrotik")) {
            s.score("router", 80, "Server header indicates MikroTik RouterOS (port " + port + ")", "MikroTik", null);
        } else if (any(h, "fritz!box", "fritzbox", "fritz os", "fritz-box")) {
            s.score("router", 80, "Server header indicates AVM FRITZ!Box (port " + port + ")", "AVM", "FRITZ!Box");
        } else if (any(h, "dd-wrt")) {
            s.score("router", 75, "Server header indicates DD-WRT (port " + port + ")");
        } else if (any(h, "openwrt")) {
            s.score("router", 75, "Server header indicates OpenWrt (port " + port + ")");
        } else if (any(h, "draytek")) {
            s.score("router", 75, "Server header indicates DrayTek (port " + port + ")", "DrayTek", null);
        } else if (any(h, "pfsense")) {
            s.score("router", 75, "Server header indicates pfSense firewall (port " + port + ")");
        } else if (any(h, "opnsense")) {
            s.score("router", 75, "Server header indicates OPNsense firewall (port " + port + ")");
        } else if (any(h, "fortinet", "fortigate", "fortios")) {
            s.score("router", 70, "Server header indicates Fortinet (port " + port + ")", "Fortinet", null);
        } else if (any(h, "unifi", "ubiquiti", "ubnt")) {
            s.score("router", 70, "Server header indicates Ubiquiti device (port " + port + ")", "Ubiquiti", null);
        } else if (any(h, "cisco")) {
            s.score("router", 55, "Server header contains Cisco (port " + port + ")", "Cisco", null);
        } else if (any(h, "juniper", "junos")) {
            s.score("router", 60, "Server header indicates Juniper (port " + port + ")", "Juniper", null);
        }

        // Cameras
        if (any(h, "hikvision")) {
            s.score("camera", 80, "Server header indicates Hikvision camera (port " + port + ")", "Hikvision", null);
        } else if (any(h, "dahua")) {
            s.score("camera", 80, "Server header indicates Dahua camera (port " + port + ")", "Dahua", null);
        } else if (h.startsWith("axis/") || any(h, "axis camera", "axis network")) {
            s.score("camera", 75, "Server header indicates Axis camera (port " + port + ")", "Axis", null);
        } else if (any(h, "reolink")) {
            s.score("camera", 75, "Server header indicates Reolink camera (port " + port + ")", "Reolink", null);
        } else if (any(h, "vivotek")) {
            s.score("camera", 75, "Server header indicates Vivotek camera (port " + port + ")", "Vivotek", null);
        } else if (any(h, "hanwha", "wisenet")) {
            s.score("camera", 75, "Server header indicates Hanwha/Wisenet camera (port " + port + ")", "Hanwha", null);
        } else if (any(h, "amcrest")) {
            s.score("camera", 75, "Server header indicates Amcrest camera (port " + port + ")", "Amcrest", null);
        } else if (any(h, "foscam")) {
            s.score("camera", 70, "Server header indicates Foscam camera (port " + port + ")", "Foscam", null);
        }

        // Windows
        if (any(h, "microsoft-iis", "microsoft iis")) {
            s.score("windows", 60, "Server header indicates Microsoft IIS (port " + port + ")", "Microsoft", null);
        }

        // UPS
        if (any(h, "powerchute", "apc web", "apc ups", "apc http", "apc/")) {
            s.score("ups", 70, "Server header indicates APC UPS (port " + port + ")", "APC", null);
        } else if (any(h, "eaton ups", "eaton web")) {
            s.score("ups", 70, "Server header indicates Eaton UPS (port " + port + ")", "Eaton", null);
        } else if (any(h, "cyberpower")) {
            s.score("ups", 65, "Server header indicates CyberPower UPS (port " + port + ")", "CyberPower", null);
        }

        // Smart speakers
        if (any(h, "sonos")) {
            s.score("speaker", 80, "Server header indicates Sonos device (port " + port + ")", "Sonos", null);
        }

        // TV
        if (any(h, "roku")) {
            s.score("tv", 75, "Server header indicates Roku device (port " + port + ")", "Roku", null);
        }

        // IoT — embedded HTTP servers are a weak signal
        if (any(h, "lwip", "contiki")) {
            s.score("iot", 30, "Server header indicates embedded TCP/IP stack (port " + port + ")");
        }
    }

    private static void applyProductTextSignals(String text, String source, int port, Scores s) {
        if (any(text, "openssh")) s.score("linux", 35, source + ": OpenSSH on port " + port);
        if (any(text, "dropbear")) {
            s.score("router", 35, source + ": Dropbear SSH on port " + port + " (common on routers/embedded)");
            s.score("iot", 20, source + ": Dropbear SSH also used in IoT devices");
        }
        if (any(text, "routeros", "mikrotik")) s.score("router", 75, source + ": MikroTik RouterOS on port " + port, "MikroTik", null);
        if (any(text, "synology")) s.score("nas", 70, source + ": Synology on port " + port, "Synology", null);
        if (any(text, "qnap")) s.score("nas", 70, source + ": QNAP on port " + port, "QNAP", null);
        if (any(text, "hikvision")) s.score("camera", 75, source + ": Hikvision on port " + port, "Hikvision", null);
        if (any(text, "dahua")) s.score("camera", 75, source + ": Dahua on port " + port, "Dahua", null);
        if (any(text, "laserjet", "officejet")) s.score("printer", 70, source + ": HP printer product on port " + port, "HP", extractFromString(text, "laserjet", "officejet"));
        if (any(text, "fritz!box", "fritzbox")) s.score("router", 75, source + ": AVM FRITZ!Box on port " + port, "AVM", "FRITZ!Box");
        if (any(text, "dd-wrt")) s.score("router", 70, source + ": DD-WRT on port " + port);
        if (any(text, "openwrt")) s.score("router", 70, source + ": OpenWrt on port " + port);
        if (any(text, "microsoft-iis", "iis/")) s.score("windows", 55, source + ": Microsoft IIS on port " + port, "Microsoft", null);
        if (any(text, "apc", "powerchute")) s.score("ups", 65, source + ": APC/PowerChute on port " + port, "APC", null);
        if (any(text, "sonos")) s.score("speaker", 75, source + ": Sonos on port " + port, "Sonos", null);
        if (any(text, "roku")) s.score("tv", 70, source + ": Roku on port " + port, "Roku", null);
    }

    private static void applyCertTextSignals(String cn, boolean isIssuer, int port, Scores s) {
        String role = isIssuer ? "cert issuer" : "cert CN";
        if (any(cn, "synology")) s.score("nas", 55, role + " contains Synology (port " + port + ")", "Synology", null);
        else if (any(cn, "qnap")) s.score("nas", 55, role + " contains QNAP (port " + port + ")", "QNAP", null);
        else if (any(cn, "asustor")) s.score("nas", 50, role + " contains ASUSTOR (port " + port + ")", "ASUSTOR", null);
        else if (any(cn, "hikvision")) s.score("camera", 55, role + " contains Hikvision (port " + port + ")", "Hikvision", null);
        else if (any(cn, "dahua")) s.score("camera", 55, role + " contains Dahua (port " + port + ")", "Dahua", null);
        else if (any(cn, "axis")) s.score("camera", 50, role + " contains Axis (port " + port + ")", "Axis", null);
        else if (any(cn, "ubiquiti", "ubnt", "unifi")) s.score("router", 50, role + " contains Ubiquiti (port " + port + ")", "Ubiquiti", null);
        else if (any(cn, "mikrotik", "routeros")) s.score("router", 55, role + " contains MikroTik (port " + port + ")", "MikroTik", null);
        else if (any(cn, "fritz!box", "fritzbox")) s.score("router", 55, role + " contains FRITZ!Box (port " + port + ")", "AVM", "FRITZ!Box");
        else if (any(cn, "laserjet", "officejet")) s.score("printer", 45, role + " contains HP printer model (port " + port + ")", "HP", null);
        else if (any(cn, "sonos")) s.score("speaker", 55, role + " contains Sonos (port " + port + ")", "Sonos", null);
    }

    private static void applyBannerTextSignals(String banner, int port, Scores s) {
        if (any(banner, "routeros", "mikrotik")) s.score("router", 70, "banner contains MikroTik RouterOS on port " + port, "MikroTik", null);
        if (any(banner, "fritz!box", "fritzbox")) s.score("router", 70, "banner contains FRITZ!Box on port " + port, "AVM", "FRITZ!Box");
        if (any(banner, "synology")) s.score("nas", 65, "banner contains Synology on port " + port, "Synology", null);
        if (any(banner, "qnap")) s.score("nas", 65, "banner contains QNAP on port " + port, "QNAP", null);
        if (any(banner, "hikvision")) s.score("camera", 65, "banner contains Hikvision on port " + port, "Hikvision", null);
        if (any(banner, "dahua")) s.score("camera", 65, "banner contains Dahua on port " + port, "Dahua", null);
        if (any(banner, "laserjet", "hp laserjet", "hp officejet")) s.score("printer", 65, "banner contains HP printer model on port " + port, "HP", null);
        if (any(banner, "dropbear")) {
            s.score("router", 35, "banner indicates Dropbear SSH on port " + port + " (common on routers)");
            s.score("iot", 20, "banner indicates Dropbear SSH (also used in IoT)");
        }
        if (any(banner, "cisco ios", "cisco nexus")) s.score("router", 60, "banner contains Cisco IOS on port " + port, "Cisco", null);
        if (any(banner, "junos")) s.score("router", 55, "banner contains JunOS on port " + port, "Juniper", null);
        if (any(banner, "apc")) s.score("ups", 60, "banner contains APC on port " + port, "APC", null);
        if (any(banner, "sonos")) s.score("speaker", 70, "banner contains Sonos on port " + port, "Sonos", null);
    }

    // ── Pick winner ───────────────────────────────────────────────────────────

    private static Result pickWinner(Scores s) {
        if (s.byType.isEmpty()) {
            return new Result("unknown", null, null, 0.0, s.evidence);
        }

        String bestType = null;
        int bestScore = 0;
        int secondScore = 0;

        for (Map.Entry<String, Integer> e : s.byType.entrySet()) {
            if (e.getValue() > bestScore) {
                secondScore = bestScore;
                bestScore = e.getValue();
                bestType = e.getKey();
            } else if (e.getValue() > secondScore) {
                secondScore = e.getValue();
            }
        }

        if (bestType == null || bestScore < 25) {
            return new Result("unknown", s.vendor, s.model,
                    bestScore > 0 ? Math.round(bestScore / 100.0 * 100.0) / 100.0 : 0.0,
                    s.evidence);
        }

        // Base confidence: score / 100, capped at 0.99
        double confidence = Math.min(0.99, bestScore / 100.0);

        // Reduce confidence when a close second competitor exists
        if (secondScore > 0) {
            double dominance = (double) bestScore / (bestScore + secondScore);
            // Blend: weight dominance against raw score confidence
            confidence = Math.min(confidence, 0.6 * dominance + 0.4 * confidence + 0.05);
            confidence = Math.min(0.99, confidence);
        }

        confidence = Math.round(confidence * 100.0) / 100.0;

        return new Result(bestType, s.vendor, s.model, confidence, s.evidence);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static boolean any(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) return true;
        }
        return false;
    }

    private static String lower(Object o) {
        return o == null ? "" : String.valueOf(o).toLowerCase();
    }

    private static String extractFromString(String s, String... keywords) {
        for (String kw : keywords) {
            int idx = s.indexOf(kw);
            if (idx >= 0) {
                return s.substring(idx, Math.min(s.length(), idx + 30)).trim();
            }
        }
        return null;
    }
}
