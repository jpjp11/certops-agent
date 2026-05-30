# CertControl Pro Agent

The on-premise scanning agent for [CertControl Pro](https://certcontrol.pro) — a certificate lifecycle and TLS security management platform.

This source code is published so you can verify exactly what the agent does before deploying it in your network.

---

## What the agent does

The agent runs inside your network and scans your internal TLS endpoints. It connects to the hosts you configure, checks their certificates and TLS configuration, and reports the results back to your CertControl Pro account.

It does **not** proxy traffic, intercept connections, or act as a man-in-the-middle. It makes outbound TCP connections to the hosts you specify and reads their public TLS handshake — the same information any TLS client sees when connecting.

---

## What leaves your network

| Data sent to certcontrol.pro | Notes |
|---|---|
| Certificate metadata | Subject, issuer, expiry, SANs, chain |
| TLS protocol and cipher scan results | Which TLS versions and ciphers are accepted |
| HTTP security headers | HSTS, CSP, X-Frame-Options, etc. — only if `CHECK_HTTP_HEADERS=true` |
| Open port list | Only ports you configure or enable CIDR discovery on |
| Service fingerprints | Banner grab, protocol detection |
| Hostnames | Can be redacted via `CERTOPS_REDACTION_PATTERNS` |
| Heartbeat | Timestamp + agent version, every 60 seconds |

| Data never sent | |
|---|---|
| Private keys | Never read or accessed |
| Certificate PEM bodies | Stripped by default (`CERTOPS_STRIP_PEM=false` to include) |
| Passwords or credentials | Not read |
| Network traffic content | Agent only reads TLS handshake metadata |
| Files or filesystem data | Not accessed |

All outbound requests are authenticated with a Bearer token (your collector API key) and signed with HMAC-SHA256. The agent never opens inbound ports.

---

## Architecture

```
Your network
┌─────────────────────────────────────────────┐
│                                             │
│  certops-agent                              │
│  ├── AgentSchedulerService   (orchestrator) │
│  ├── scanner/                               │
│  │   ├── TlsScannerService   (TLS handshake)│
│  │   ├── HttpHeaderChecker   (HTTP headers) │
│  │   ├── OcspCrlChecker      (revocation)  │
│  │   └── DnsSecurityChecker  (DNSSEC/SPF)  │
│  ├── exposure/                              │
│  │   ├── PortScannerService  (TCP scan)     │
│  │   ├── FingerprintService  (banners)      │
│  │   └── ExposureDiscoveryEngine            │
│  ├── security/                              │
│  │   ├── NetworkValidator    (RFC 1918 guard)│
│  │   ├── RedactionService    (hostname mask)│
│  │   └── FieldAllowlistFilter              │
│  └── transport/                             │
│      ├── CloudClientService  (HTTPS + HMAC) │
│      └── LocalSpoolService   (offline queue)│
│                                             │
└──────────────────┬──────────────────────────┘
                   │ HTTPS (outbound only)
                   ▼
         certcontrol.pro
```

**Key security properties of the agent:**

- `NetworkValidator` blocks scanning of public internet addresses by default — the agent is designed for internal networks. Public targets require explicit opt-in (`CERTOPS_ALLOW_PUBLIC=true`).
- `RedactionService` masks hostnames matching your glob patterns before any data leaves the agent.
- `FieldAllowlistFilter` strips any fields from scan results that are not on the explicit allowlist — no unexpected data can leak through.
- `LocalSpoolService` queues results locally if the cloud is unreachable and retries — no data is lost, and no data is sent to any other destination.

---

## Verifying the JAR

Before running the agent, verify the JAR matches this release:

```bash
shasum -a 256 certops-agent-1.3.0.jar
# Expected: 6eece13877dd446739319a9bf064ce5f29c76a79a024f3289de7355d3ac28612
```

The SHA-256 checksum is also shown in the agent setup page in your CertControl account.
A `certops-agent-1.3.0.jar.sha256` file is included in this repository for scripted verification.

---

## Building from source

Requires Java 17 and Maven 3.8+.

```bash
git clone https://github.com/jpjp11/certops-agent.git
cd certops-agent
mvn clean package -DskipTests
# JAR is at target/certops-agent-*.jar
```

---

## Configuration

The agent is configured via environment variables. All settings have safe defaults.

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_SERVER_URL` | `https://certcontrol.pro` | CertControl Pro instance URL |
| `CERTOPS_API_KEY` | *(required)* | Collector API key from your account |
| `CERTOPS_SCAN_INTERVAL` | `300` | Seconds between scans |
| `CERTOPS_HEARTBEAT_INTERVAL` | `60` | Seconds between heartbeats |
| `CERTOPS_TIMEOUT_MS` | `10000` | TCP/TLS connection timeout |
| `CERTOPS_PROBE_TLS` | `true` | Test weak TLS versions and ciphers |
| `CERTOPS_CHECK_OCSP` | `true` | Check certificate revocation |
| `CERTOPS_CHECK_HTTP_HEADERS` | `true` | Check HTTP security headers |
| `CERTOPS_REDACTION_ENABLED` | `true` | Enable hostname redaction |
| `CERTOPS_REDACTION_PATTERNS` | *(empty)* | Comma-separated glob patterns, e.g. `*.internal,*.corp` |
| `CERTOPS_STRIP_PEM` | `false` | Strip certificate PEM from results |
| `CERTOPS_SPOOL_ENABLED` | `true` | Queue results locally if cloud unreachable |
| `CERTOPS_SPOOL_DIR` | `/var/certops-agent/spool` | Local spool directory |
| `CERTOPS_CIDR_ENABLED` | `false` | Enable automatic CIDR range discovery |
| `CERTOPS_ALLOW_PUBLIC` | `false` | Allow scanning public internet addresses |
| `CERTOPS_MTLS_ENABLED` | `false` | Enable mutual TLS for cloud connection |
| `HTTPS_PROXY` | *(empty)* | HTTP proxy URL |

---

## Installation

See `install.sh` (Linux/systemd) or `install.ps1` (Windows Service) for automated installation scripts.

For Docker, see `Dockerfile`.

---

## License

Source-available under the [Business Source License 1.1](LICENSE). You may read, audit, and build from this source. Commercial use requires a CertControl Pro subscription.

&copy; Certiva ApS
