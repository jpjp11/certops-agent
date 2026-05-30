# CertControl Pro Agent — Complete Setup Guide

> **Version:** 1.3.0 | **Java required:** 17+ | **Platforms:** Linux, Windows

This guide covers everything you need to install, configure, and operate the CertControl on-premise agent — from registering a collector through to running Exposure Discovery.

---

## Table of Contents

1. [What the agent does](#1-what-the-agent-does)
2. [Source code and integrity verification](#2-source-code-and-integrity-verification)
3. [Prerequisites](#3-prerequisites)
4. [Step 1 — Register a collector in CertControl](#4-step-1--register-a-collector-in-certcontrol)
5. [Step 2 — Download the agent](#5-step-2--download-the-agent)
6. [Step 3 — Install the agent](#6-step-3--install-the-agent)
   - [Option A: Docker (recommended)](#option-a-docker-recommended)
   - [Option B: Docker Compose](#option-b-docker-compose)
   - [Option C: Linux — systemd service](#option-c-linux--systemd-service)
   - [Option D: Windows — Windows Service](#option-d-windows--windows-service)
7. [Step 4 — Configure scan targets](#7-step-4--configure-scan-targets)
8. [Step 5 — Verify the agent is running](#8-step-5--verify-the-agent-is-running)
9. [Exposure Discovery](#9-exposure-discovery)
10. [Multi-agent setup](#10-multi-agent-setup)
11. [Hostname redaction](#11-hostname-redaction)
12. [Mutual TLS (mTLS)](#12-mutual-tls-mtls)
13. [HTTP proxy](#13-http-proxy)
14. [Upgrading the agent](#14-upgrading-the-agent)
15. [Complete configuration reference](#15-complete-configuration-reference)
16. [Troubleshooting](#16-troubleshooting)
17. [Security model](#17-security-model)

---

## 1. What the agent does

The CertControl agent is a lightweight Spring Boot application (~50 MB JAR) that runs inside your network and performs two types of scanning:

### TLS certificate scanning

Connects to the hosts you configure and collects:

- Certificate validity period, issuer, SAN list, and chain
- Supported TLS versions (1.0, 1.1, 1.2, 1.3)
- Weak cipher suites (RC4, DES, EXPORT, NULL, MD5, ANON, CBC in TLS 1.2)
- OCSP/CRL revocation status
- HTTP security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options, Referrer-Policy)

### Exposure Discovery

An optional network scanning mode that:

- Scans CIDR ranges for open TCP ports
- Fingerprints running services (product and version via TLS, HTTP, and banner probing)
- Correlates findings with known CVEs (via the NVD database synced in CertControl)
- Reports results to the Exposure dashboards in CertControl

**Network requirements:** The agent makes outbound HTTPS connections to CertControl only. No inbound ports are opened on the agent host.

---

## 2. Source code and integrity verification

The agent source code is publicly available so you can verify exactly what runs in your network before deploying it.

**Source code:** https://github.com/jpjp11/certops-agent

**SHA-256 checksum for v1.3.0:**
```
6eece13877dd446739319a9bf064ce5f29c76a79a024f3289de7355d3ac28612
```

After downloading the JAR, verify it before running:

```bash
# Linux / macOS
shasum -a 256 certops-agent-1.3.0.jar

# Windows (PowerShell)
Get-FileHash certops-agent-1.3.0.jar -Algorithm SHA256 | Select-Object Hash
```

The expected hash is also shown in CertControl under **Infrastructure → Collectors → Download Agent**.

**Building from source** (optional — skip if you trust the downloaded JAR):

```bash
git clone https://github.com/jpjp11/certops-agent.git
cd certops-agent
# Requires Java 17 and Maven 3.8+
mvn clean package -DskipTests
# JAR is at target/certops-agent-1.3.0.jar
```

---

## 3. Prerequisites

### System requirements

| Installation method | Minimum | Recommended |
|---|---|---|
| Docker | Docker Engine 20.10+ | Docker 24+ |
| Java (Linux/Windows) | Java 17 JRE | Java 17 or 21 LTS |
| RAM | 128 MB | 256 MB (512 MB with Exposure Discovery) |
| Disk | 200 MB | 500 MB (includes spool) |
| CPU | 1 core | 2 cores |

**Supported operating systems:**
- Linux: Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+, any systemd-based distro
- Windows: Windows Server 2019+ (2022 recommended), Windows 10/11

### Network requirements

| Direction | From | To | Port | Required |
|---|---|---|---|---|
| Outbound | Agent host | `certcontrol.pro` | 443/TCP | Yes |
| Outbound | Agent host | Internal scan targets | 443 or configured port | Yes |
| Outbound | Agent host | Internal subnets | Various | Only for Exposure Discovery |
| Inbound | — | Agent host | — | **Never required** |

The agent host must be able to reach your internal TLS endpoints and have outbound HTTPS to `certcontrol.pro`. No firewall rules need to be opened inbound to the agent.

---

## 4. Step 1 — Register a collector in CertControl

You must create a collector registration in CertControl before installing anything. This generates the API key the agent uses to authenticate.

1. Log in to CertControl as an **admin** user
2. Navigate to **Infrastructure → Collectors**
3. If prompted, read and accept the **Internal Scanner Agreement** — this is a one-time step recorded permanently for compliance
4. Click **+ New Collector**
5. Fill in:
   - **Name** — a unique, descriptive identifier, e.g. `dc1-prod-scanner` or `office-dmz`
   - **Network Zone** — the network segment this agent will cover, e.g. `DMZ`, `internal-dc1`
   - **Description** — optional free text
6. Click **Register**
7. **Copy the API key immediately** — it starts with `cwc_` and is shown **only once**. If you lose it, you can regenerate it from the collector management page (the old key is immediately invalidated).

The API key looks like:
```
cwc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 5. Step 2 — Download the agent

Go to **Infrastructure → Collectors → Download Agent** in CertControl.

You can download:
- `certops-agent-1.3.0.jar` — the agent JAR (for Docker or bare-metal installation)
- `Dockerfile` — to build a Docker image locally
- `docker-compose.yml` — pre-filled with your server URL and a placeholder for your API key

After downloading the JAR, [verify the SHA-256 checksum](#2-source-code-and-integrity-verification) before proceeding.

---

## 6. Step 3 — Install the agent

Choose the installation method that fits your environment. Docker is recommended for most setups because it provides isolation, easy upgrades, and a consistent runtime.

---

### Option A: Docker (recommended)

Build the Docker image from the downloaded JAR and Dockerfile, then run it.

**Step 1 — Place the JAR and Dockerfile in the same directory:**

```bash
mkdir -p /opt/certcontrol-agent
cd /opt/certcontrol-agent
# Copy certops-agent-1.3.0.jar and Dockerfile here
```

**Step 2 — Build the image:**

```bash
docker build -t certcontrol-agent:1.3.0 .
docker tag certcontrol-agent:1.3.0 certcontrol-agent:latest
```

**Step 3 — Run the agent:**

```bash
docker run -d \
  --name certcontrol-agent \
  --restart unless-stopped \
  -e CERTOPS_SERVER_URL=https://certcontrol.pro \
  -e CERTOPS_API_KEY=cwc_YOUR_TOKEN_HERE \
  -v certcontrol-agent-spool:/var/certops-agent/spool \
  certcontrol-agent:latest
```

Replace `cwc_YOUR_TOKEN_HERE` with the API key from Step 1.

The spool volume persists queued scan results across container restarts so no data is lost if the container is restarted.

**Step 4 — Verify it started:**

```bash
docker logs certcontrol-agent --tail 20
```

Expected output:
```
INFO  CertopsAgentApplication - Started CertopsAgentApplication in 2.6 seconds
INFO  AgentSchedulerService - Heartbeat sent OK
```

---

### Option B: Docker Compose

Create a `docker-compose.yml` in your working directory:

```yaml
services:
  certcontrol-agent:
    image: certcontrol-agent:latest
    build: .
    container_name: certcontrol-agent
    restart: unless-stopped
    environment:
      CERTOPS_SERVER_URL: https://certcontrol.pro
      CERTOPS_API_KEY: cwc_YOUR_TOKEN_HERE
      CERTOPS_SCAN_INTERVAL: "300"
      CERTOPS_HEARTBEAT_INTERVAL: "60"
      CERTOPS_CHECK_OCSP: "true"
      CERTOPS_CHECK_HTTP_HEADERS: "true"
      CERTOPS_REDACTION_ENABLED: "true"
      # CERTOPS_REDACTION_PATTERNS: "*.internal,*.corp,*.local"
    volumes:
      - spool:/var/certops-agent/spool

volumes:
  spool:
```

Start:

```bash
docker compose up -d
docker compose logs -f
```

**With a configuration file for scan targets** (recommended for more than a few targets):

Mount an `application.yml` file with your target list:

```yaml
services:
  certcontrol-agent:
    image: certcontrol-agent:latest
    build: .
    container_name: certcontrol-agent
    restart: unless-stopped
    environment:
      CERTOPS_SERVER_URL: https://certcontrol.pro
      CERTOPS_API_KEY: cwc_YOUR_TOKEN_HERE
      SPRING_CONFIG_ADDITIONAL_LOCATION: file:/app/config/
    volumes:
      - ./config/application.yml:/app/config/application.yml:ro
      - spool:/var/certops-agent/spool

volumes:
  spool:
```

---

### Option C: Linux — systemd service

For Linux servers without Docker. The included `install.sh` script handles everything.

**Requirements:** Java 17+ installed and accessible as `java` on the PATH. Check with `java -version`.

**Step 1 — Transfer files to the target server:**

```bash
scp certops-agent-1.3.0.jar install.sh user@server:/tmp/
```

**Step 2 — Run the installer as root:**

```bash
ssh user@server
cd /tmp
sudo bash install.sh
```

The script creates:

| Path | Purpose |
|---|---|
| `/opt/certops-agent/` | JAR file |
| `/etc/certops-agent/env` | Environment variables, secrets (mode 0600) |
| `/etc/certops-agent/application.yml` | Targets and feature configuration |
| `/var/certops-agent/spool/` | Offline disk queue |
| `/var/log/certops-agent/` | Log files |
| `/etc/systemd/system/certops-agent.service` | systemd unit |

**Step 3 — Set your API key:**

```bash
sudo nano /etc/certops-agent/env
```

Set at minimum:

```bash
CERTOPS_SERVER_URL=https://certcontrol.pro
CERTOPS_API_KEY=cwc_YOUR_TOKEN_HERE
```

Any environment variable from the [configuration reference](#15-complete-configuration-reference) can be set here.

**Step 4 — Configure scan targets:**

```bash
sudo nano /etc/certops-agent/application.yml
```

```yaml
certops:
  agent:
    targets:
      - host: intranet.corp.internal
        port: 443
        env: prod
      - host: ldap.corp.internal
        port: 636
        env: prod
      - host: api-gateway.internal
        port: 8443
        env: prod
```

**Step 5 — Start the service:**

```bash
sudo systemctl start certops-agent
sudo systemctl status certops-agent
```

**Monitor logs:**

```bash
sudo journalctl -u certops-agent -f
sudo tail -f /var/log/certops-agent/agent.log
```

**Uninstall:**

```bash
sudo bash install.sh --uninstall
```

**systemd security hardening** — the service runs with these restrictions by default:

| Directive | Effect |
|---|---|
| `NoNewPrivileges=true` | Process cannot escalate privileges |
| `ProtectSystem=strict` | Filesystem is read-only except for explicit write paths |
| `ProtectHome=true` | `/home`, `/root`, `/run/user` are inaccessible |
| `PrivateTmp=true` | Isolated `/tmp` namespace |
| `PrivateDevices=true` | No access to physical devices |
| `ReadWritePaths=` | Only spool and log directories are writable |

---

### Option D: Windows — Windows Service

For Windows Server environments. The included `install.ps1` script installs the agent as a native Windows Service using [WinSW](https://github.com/winsw/winsw).

**Requirements:** Java 17+ installed (Adoptium Temurin, Amazon Corretto, or Microsoft OpenJDK). Verify with `java -version` in PowerShell.

**Step 1 — Transfer files to the target server:**

Copy `certops-agent-1.3.0.jar` and `install.ps1` to the same directory on the server, e.g. `C:\install\`.

**Step 2 — Run the installer as Administrator:**

Open PowerShell as Administrator:

```powershell
cd C:\install
.\install.ps1
```

WinSW is downloaded automatically from GitHub. If the server has no internet access, download `WinSW-x64.exe` manually and place it as `C:\certops-agent\certops-agent.exe` before running the script.

The script creates:

| Path | Purpose |
|---|---|
| `C:\certops-agent\` | JAR file and WinSW executable |
| `C:\certops-agent\env.conf` | Environment variables (ACL: SYSTEM + Administrators only) |
| `C:\certops-agent\application.yml` | Targets and feature configuration |
| `C:\certops-agent\spool\` | Offline disk queue |
| `C:\certops-agent\logs\` | Log files |
| `C:\certops-agent\certops-agent.xml` | WinSW service definition |

**Step 3 — Set your API key:**

```powershell
notepad C:\certops-agent\env.conf
```

Set at minimum:

```
CERTOPS_SERVER_URL=https://certcontrol.pro
CERTOPS_API_KEY=cwc_YOUR_TOKEN_HERE
```

After editing, run the installer again to regenerate the WinSW XML with the new values:

```powershell
.\install.ps1
```

**Step 4 — Configure scan targets:**

```powershell
notepad C:\certops-agent\application.yml
```

```yaml
certops:
  agent:
    targets:
      - host: intranet.corp.internal
        port: 443
        env: prod
      - host: ldap.corp.internal
        port: 636
        env: prod
```

**Step 5 — Start the service:**

```powershell
Start-Service certops-agent
Get-Service certops-agent
```

**Monitor logs:**

```powershell
Get-Content C:\certops-agent\logs\agent.log -Tail 30 -Wait
```

**Uninstall:**

```powershell
.\install.ps1 -Uninstall
```

**Manual installation (without the script):**

If `install.ps1` cannot be used, install manually using the included `winsw.xml` as a template:

1. Create `C:\certops-agent\`
2. Copy `certops-agent-1.3.0.jar` there
3. Download WinSW and save as `C:\certops-agent\certops-agent.exe`
4. Copy `winsw.xml` to `C:\certops-agent\certops-agent.xml`, fill in paths and environment variables
5. Run: `certops-agent.exe install` then `certops-agent.exe start`

---

## 7. Step 4 — Configure scan targets

There are three ways to tell the agent which hosts to scan.

### Method A: CertControl UI (recommended)

Go to **Endpoints → + Add Endpoint**, select **On-premise (agent)**, choose your collector, and enter the hostname and port. The agent pulls this configuration automatically every `CERTOPS_CONFIG_PULL_INTERVAL` seconds (default: 5 minutes) — no agent restart needed.

This is the recommended approach. All target management is centralized in CertControl and changes take effect within 5 minutes without touching the agent.

### Method B: Local `application.yml`

For static environments, define targets directly in the agent configuration file:

```yaml
certops:
  agent:
    targets:
      - host: intranet.corp.internal
        port: 443
        env: prod
        tags: [web, critical]
      - host: ldap.corp.internal
        port: 636
        env: prod
        tags: [ldap]
      - host: api-gateway.internal
        port: 8443
        env: test
      - host: mail.corp.internal
        port: 993
        env: prod
        tags: [mail, imap]
      - host: db.corp.internal
        port: 5432
        env: prod
        tags: [database]
```

Valid `env` values: `prod`, `pilot`, `test`, `dev`.

**Supported port types:**

| Port | Protocol | Notes |
|---|---|---|
| 443, 8443, 9443 | HTTPS | Most common |
| 636 | LDAPS | Active Directory / LDAP over TLS |
| 993 | IMAPS | Mail over TLS |
| 995 | POP3S | Mail over TLS |
| 5432 | PostgreSQL TLS | |
| 3306 | MySQL TLS | |
| 6379 | Redis TLS | |
| Any port | TLS on non-standard port | Agent attempts TLS handshake on any configured port |

After editing the local config, restart the agent (or use Method A to push changes without restarting).

### Method C: CIDR auto-discovery

The agent can sweep IP ranges and automatically register hosts that respond on TLS ports:

```yaml
certops:
  agent:
    cidr-discovery:
      enabled: true
      ranges:
        - 10.0.1.0/24
        - 192.168.10.0/23
      ports: "443,8443,9443,636"
      rate-limit: 10      # parallel TCP probes per second
      concurrency: 5      # parallel TLS handshakes
```

> CIDR auto-discovery is disabled by default. Enable it only for RFC 1918 private ranges. The agent enforces this and logs a security warning for any public IP range; public IPs are blocked automatically unless `allowPublicTargets=true` is explicitly set in the local YAML file.

---

## 8. Step 5 — Verify the agent is running

### Check the CertControl dashboard

Go to **Infrastructure → Collectors**. Within 60–90 seconds after starting the agent, your collector should show a green **Active** badge and an updated **Last seen** timestamp.

### Check Docker logs

```bash
docker logs -f certcontrol-agent
```

Healthy output looks like:

```
13:00:01 INFO  AgentSchedulerService - Heartbeat sent OK
13:05:00 INFO  AgentSchedulerService - Starting scan cycle: 3 targets
13:05:03 INFO  AgentSchedulerService - Scan complete — uploaded 3 results
```

### Check Linux systemd logs

```bash
sudo journalctl -u certops-agent -f
```

### Check Windows logs

```powershell
Get-Content C:\certops-agent\logs\agent.log -Tail 30 -Wait
```

### Verify from the command line (test connectivity)

Before starting the agent, you can verify connectivity to CertControl and to a scan target:

```bash
# CertControl reachable?
curl -s https://certcontrol.pro/actuator/health

# Scan target reachable?
openssl s_client -connect intranet.corp.internal:443 -brief
```

---

## 9. Exposure Discovery

Exposure Discovery scans your internal network segments for open ports, fingerprints running services, and correlates findings with known CVEs. It maps your internal attack surface beyond just the endpoints you have explicitly configured.

### Enable Exposure Discovery on the agent

Add to `application.yml`:

```yaml
certops:
  agent:
    exposure-discovery:
      enabled: true
```

For Docker, add to your `docker run` command or `docker-compose.yml`:

```bash
-e CERTOPS_EXPOSURE_ENABLED=true
```

> **Note:** For Docker, Exposure Discovery often requires `--network=host` or a network that can reach the target IP ranges, since the agent must make TCP connections to the IPs in your configured CIDR scopes.

### Configure scan scopes in CertControl

1. Go to **Infrastructure → Collectors**
2. Click your collector → **Exposure Discovery**
3. Add CIDR ranges to scan, e.g. `10.0.0.0/24`, `192.168.1.0/24`
4. Accept the scanning agreement (required — scanning will not start without it)
5. Click **Save Configuration**

Only private RFC 1918 IP ranges are accepted. Public IP ranges are rejected both by the UI and by the agent itself.

### Trigger a scan

Click **Run Scan** in the Exposure Discovery panel. The agent picks up the instruction on its next config pull (up to 5 minutes) and runs the scan in two phases:

1. **Port scanning** — TCP connect probe on all ports in the configured profile for all IPs in scope
2. **Fingerprinting** — TLS handshake, HTTP response parsing, and banner reading on all open ports

Results are reported continuously as the scan progresses.

### View results

After the scan completes, findings appear in the **Exposure** section:

| Dashboard | Content |
|---|---|
| **Exposure Overview** | Aggregated scores and KPIs |
| **Internet Exposure Map** | Hosts, services, and open ports |
| **Attack Paths** | Risk-scored paths through your infrastructure |
| **Path Explorer** | Visual drill-down with filters and evidence |
| **Auto Discovery** | Newly discovered hosts awaiting onboarding |
| **Recommendations** | Prioritized remediation actions |

### Finding types

| Type | Severity | Trigger |
|---|---|---|
| `OPEN_PORT` | INFO | Any open TCP port found |
| `SERVICE_FINGERPRINT` | INFO | Service product identified (confidence ≥ 0.3) |
| `CVE_ON_SERVICE` | CRIT/HIGH/WARN | CVE matched to identified product and version |

### Port profiles

| Profile | Count | Typical ports |
|---|---|---|
| `top50` | 50 | 21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443, ... |
| `top100` | 100 | All of top50 plus: 8000, 8888, 9000, 9090, 9200, 9443, 11211, 27017, 27018, ... |

### Server-side Exposure Discovery settings

Configured via the CertControl UI and automatically pushed to the agent:

| Setting | Default | Description |
|---|---|---|
| `network_scopes` | *(required)* | CIDR ranges to scan |
| `port_profile` | `top100` | `top50` or `top100` |
| `max_hosts_parallel` | 10 | Concurrent hosts during port scanning |
| `max_ports_parallel_per_host` | 20 | Concurrent port probes per host |
| `connect_timeout_ms` | 500 | TCP connect timeout in milliseconds |
| `retries` | 1 | Retries per port |
| `scan_window` | *(none)* | Time window, e.g. `02:00-05:00` — scan only during this window |

---

## 10. Multi-agent setup

For larger environments, deploy separate agents to cover different network segments. Each agent registers as its own collector in CertControl.

### Example architecture

```
                     CertControl (Cloud)
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    Agent: dmz      Agent: internal   Agent: staging
    10.0.1.0/24     10.0.2.0/24      172.16.0.0/24
    TLS + Exposure  TLS + Exposure    TLS only
```

### Setup steps

For each network segment:

1. **Register a separate collector** in CertControl — give it a unique name and network zone, copy the API key
2. **Create a separate config file** per agent

Example `application.yml` for the DMZ agent:

```yaml
certops:
  agent:
    targets:
      - host: web01.dmz.corp
        port: 443
        env: prod
      - host: api.dmz.corp
        port: 443
        env: prod
    exposure-discovery:
      enabled: true
```

3. **Start each agent with its own key and config**

Docker example for two agents:

```bash
# DMZ agent
docker run -d \
  --name certcontrol-agent-dmz \
  --restart unless-stopped \
  --network dmz-bridge \
  -e CERTOPS_SERVER_URL=https://certcontrol.pro \
  -e CERTOPS_API_KEY=cwc_DMZ_TOKEN_HERE \
  -v certcontrol-dmz-spool:/var/certops-agent/spool \
  -v /etc/certops/dmz.yml:/app/config/application.yml:ro \
  -e SPRING_CONFIG_ADDITIONAL_LOCATION=file:/app/config/ \
  certcontrol-agent:latest

# Internal agent
docker run -d \
  --name certcontrol-agent-internal \
  --restart unless-stopped \
  --network internal-bridge \
  -e CERTOPS_SERVER_URL=https://certcontrol.pro \
  -e CERTOPS_API_KEY=cwc_INTERNAL_TOKEN_HERE \
  -v certcontrol-internal-spool:/var/certops-agent/spool \
  -v /etc/certops/internal.yml:/app/config/application.yml:ro \
  -e SPRING_CONFIG_ADDITIONAL_LOCATION=file:/app/config/ \
  certcontrol-agent:latest
```

4. **Configure Exposure Discovery scopes** per agent from the CertControl UI

### Monitoring the fleet

The **Collector Operations Dashboard** (Overview → Collectors) gives a unified view across all agents:

- **Fleet Health** — status for all collectors (Active / Inactive / Disabled)
- **Network Coverage** — which segments are covered by which agents
- **Attack Surface Map** — filterable per collector to see each segment in isolation
- **Exposure Discovery** — findings per network segment

---

## 11. Hostname redaction

Internal TLS certificates contain hostnames that reveal your internal network topology:

```
CN = db-master-01.prod.internal.corp
SAN = db-master-01.prod.internal.corp, db-slave-02.prod.internal.corp
```

Hostname redaction masks these values **before they leave the agent** — the original hostname never touches the network and is never stored in CertControl.

### Configure redaction

Via environment variable:

```bash
CERTOPS_REDACTION_ENABLED=true
CERTOPS_REDACTION_PATTERNS=*.internal,*.corp,*.local,10.*,192.168.*
```

Via `application.yml`:

```yaml
certops:
  agent:
    redaction:
      enabled: true
      patterns:
        - "*.internal.corp"
        - "*.prod.local"
        - "10.*"
        - "192.168.*"
```

### What gets redacted

With pattern `*.internal.corp`:

| Field | Before | After |
|---|---|---|
| `leaf_subject_cn` | `db-master-01.prod.internal.corp` | `[redacted]` |
| `chain[0].subject_cn` | `db-master-01.prod.internal.corp` | `[redacted]` |
| `chain[0].san[0]` | `db-master-01.prod.internal.corp` | `[redacted]` |
| `chain[0].san[1]` | `db-slave-02.prod.internal.corp` | `[redacted]` |
| `leaf_fp_sha256` | `AA:BB:CC:...` | `AA:BB:CC:...` (preserved) |
| `leaf_valid_to` | `2026-06-01` | `2026-06-01` (preserved) |

Certificate fingerprints, validity dates, issuer names, and TLS metadata are always preserved.

### Pattern syntax

| Pattern | Matches | Does not match |
|---|---|---|
| `*.internal.corp` | `api.internal.corp`, `db.prod.internal.corp` | `api.external.corp` |
| `*.local` | `server.local`, `db.prod.corp.local` | `server.com` |
| `10.*` | `10.0.1.50`, `10.255.255.255` | `192.168.1.1` |
| `db-master.corp` | `db-master.corp` (exact match) | `db-slave.corp` |

Matching is case-insensitive. Patterns are applied to both CN and all SAN entries.

### Stripping raw PEM

To also remove the raw PEM certificate body from results (which contains the original CN and SANs):

```bash
CERTOPS_STRIP_PEM=true
```

All parsed fields (fingerprint, validity, issuer, etc.) are preserved — only the raw PEM bytes are omitted.

---

## 12. Mutual TLS (mTLS)

For zero-trust environments requiring client certificate authentication in addition to the Bearer token:

```bash
CERTOPS_MTLS_ENABLED=true
CERTOPS_MTLS_CERT=/certs/client.pem       # Client certificate
CERTOPS_MTLS_KEY=/certs/client-key.pem    # Private key (PKCS8 PEM or RSA PEM)
CERTOPS_MTLS_CA=/certs/ca.pem             # CA certificate for server verification
```

Docker example:

```bash
docker run -d \
  --name certcontrol-agent \
  --restart unless-stopped \
  -e CERTOPS_SERVER_URL=https://certcontrol.pro \
  -e CERTOPS_API_KEY=cwc_YOUR_TOKEN \
  -e CERTOPS_MTLS_ENABLED=true \
  -e CERTOPS_MTLS_CERT=/certs/client.pem \
  -e CERTOPS_MTLS_KEY=/certs/client-key.pem \
  -e CERTOPS_MTLS_CA=/certs/ca.pem \
  -v /etc/certops/certs:/certs:ro \
  -v certcontrol-spool:/var/certops-agent/spool \
  certcontrol-agent:latest
```

Supported certificate formats:
- PEM — separate certificate and private key files (PKCS8 or RSA format)
- PKCS12 / PFX — combined certificate and key

---

## 13. HTTP proxy

If the agent must route outbound HTTPS through a corporate proxy:

```bash
HTTPS_PROXY=http://proxy.corp.internal:3128
```

Or in `application.yml`:

```yaml
certops:
  agent:
    proxy-url: http://proxy.corp.internal:3128
```

The proxy is used only for connections to CertControl. Connections to internal scan targets are not routed through the proxy.

---

## 14. Upgrading the agent

### Docker

```bash
# Rebuild the image with the new JAR
docker build -t certcontrol-agent:1.3.0 .
docker tag certcontrol-agent:1.3.0 certcontrol-agent:latest

# Stop and replace the container (spool volume is preserved)
docker stop certcontrol-agent
docker rm certcontrol-agent
docker run -d \
  --name certcontrol-agent \
  --restart unless-stopped \
  -e CERTOPS_SERVER_URL=https://certcontrol.pro \
  -e CERTOPS_API_KEY=cwc_YOUR_TOKEN \
  -v certcontrol-agent-spool:/var/certops-agent/spool \
  certcontrol-agent:latest
```

With Docker Compose:

```bash
docker compose down
docker compose build
docker compose up -d
```

### Linux systemd

```bash
# Copy the new JAR alongside install.sh and re-run:
sudo bash install.sh
sudo systemctl restart certops-agent
```

The installer is idempotent — it replaces the JAR and systemd unit but preserves `/etc/certops-agent/env` and `application.yml`.

### Windows

```powershell
# Copy the new JAR alongside install.ps1 and re-run:
.\install.ps1
Start-Service certops-agent
```

---

## 15. Complete configuration reference

All settings are configured via environment variables. All have safe defaults — you only need to set `CERTOPS_API_KEY` to get started.

### Connection

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_API_KEY` | *(required)* | Collector API key from Step 1 (`cwc_…`) |
| `CERTOPS_SERVER_URL` | `https://certcontrol.pro` | CertControl instance URL — change only for self-hosted |
| `HTTPS_PROXY` | *(empty)* | Forward proxy for outbound HTTPS, e.g. `http://proxy.corp:3128` |

### Timing

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_SCAN_INTERVAL` | `300` | Seconds between TLS scan cycles |
| `CERTOPS_HEARTBEAT_INTERVAL` | `60` | Seconds between heartbeats |
| `CERTOPS_CONFIG_PULL_INTERVAL` | `300` | Seconds between pulling updated config from CertControl |
| `CERTOPS_TIMEOUT_MS` | `10000` | TCP/TLS connection timeout per target (milliseconds) |

### TLS scan depth

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_PROBE_TLS` | `true` | Test which TLS versions and cipher suites are accepted |
| `CERTOPS_CHECK_OCSP` | `true` | Check OCSP/CRL certificate revocation status |
| `CERTOPS_CHECK_HTTP_HEADERS` | `true` | Check HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) |

> Setting `CERTOPS_PROBE_TLS=false` disables the extra TLS handshakes used to test weak protocol support. Useful if a target is sensitive to unexpected connections.

### Hostname redaction

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_REDACTION_ENABLED` | `true` | Enable hostname redaction |
| `CERTOPS_REDACTION_PATTERNS` | *(empty)* | Comma-separated glob patterns, e.g. `*.internal,*.corp,10.*` |
| `CERTOPS_STRIP_PEM` | `false` | Strip raw PEM certificate body from results |

### Offline spool

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_SPOOL_ENABLED` | `true` | Queue results locally when CertControl is unreachable |
| `CERTOPS_SPOOL_DIR` | `/var/certops-agent/spool` | Local spool directory |
| `CERTOPS_SPOOL_MAX_MB` | `100` | Maximum spool size in MB — oldest entries deleted when exceeded |
| `CERTOPS_SPOOL_RETRY` | `60` | Seconds between retry attempts while offline |

In Docker, always mount the spool directory as a named volume:
```bash
-v certcontrol-agent-spool:/var/certops-agent/spool
```

### Mutual TLS

| Variable | Default | Description |
|---|---|---|
| `CERTOPS_MTLS_ENABLED` | `false` | Enable mTLS for cloud connection |
| `CERTOPS_MTLS_CERT` | *(empty)* | Path to client certificate (PEM or PKCS12) |
| `CERTOPS_MTLS_KEY` | *(empty)* | Path to private key (PKCS8 PEM) |
| `CERTOPS_MTLS_CA` | *(empty)* | Path to CA certificate bundle for server verification |

### Complete example (all variables)

```bash
# ── Connection ─────────────────────────────────────────────────
CERTOPS_API_KEY=cwc_YOUR_TOKEN          # Required
CERTOPS_SERVER_URL=https://certcontrol.pro
HTTPS_PROXY=                            # e.g. http://proxy:3128

# ── Timing ─────────────────────────────────────────────────────
CERTOPS_SCAN_INTERVAL=300
CERTOPS_HEARTBEAT_INTERVAL=60
CERTOPS_CONFIG_PULL_INTERVAL=300
CERTOPS_TIMEOUT_MS=10000

# ── TLS scan depth ─────────────────────────────────────────────
CERTOPS_PROBE_TLS=true
CERTOPS_CHECK_OCSP=true
CERTOPS_CHECK_HTTP_HEADERS=true

# ── Hostname redaction ─────────────────────────────────────────
CERTOPS_REDACTION_ENABLED=true
CERTOPS_REDACTION_PATTERNS=*.internal,*.corp,*.local
CERTOPS_STRIP_PEM=false

# ── Offline spool ──────────────────────────────────────────────
CERTOPS_SPOOL_ENABLED=true
CERTOPS_SPOOL_DIR=/var/certops-agent/spool
CERTOPS_SPOOL_MAX_MB=100
CERTOPS_SPOOL_RETRY=60

# ── mTLS (optional) ────────────────────────────────────────────
CERTOPS_MTLS_ENABLED=false
CERTOPS_MTLS_CERT=
CERTOPS_MTLS_KEY=
CERTOPS_MTLS_CA=
```

### Memory tuning

For large target counts, increase the JVM heap. For Docker:

```bash
-e JAVA_OPTS="-Xmx512m"
```

For systemd, edit the `ExecStart` line in `/etc/systemd/system/certops-agent.service`:

```
ExecStart=/usr/bin/java -Xmx512m -jar /opt/certops-agent/certops-agent-1.3.0.jar ...
```

| Target count | Recommended heap |
|---|---|
| 1–50 | 256 MB (default) |
| 50–200 | 512 MB |
| 200–500 | 1 GB |
| 500+ | 2 GB |

---

## 16. Troubleshooting

### Collector shows Offline / Inactive

| Check | Command |
|---|---|
| Verify API key | Look for `HTTP 401` in agent logs |
| Test outbound HTTPS | `curl -v https://certcontrol.pro/actuator/health` |
| Check proxy config | `echo $HTTPS_PROXY` or grep env file |

**Common causes:**
- Wrong API key — regenerate from **Infrastructure → Collectors** in CertControl
- Firewall blocking outbound port 443 from the agent host
- Proxy required but not configured — add `HTTPS_PROXY`
- DNS resolution failure — try using the IP address in `CERTOPS_SERVER_URL` as a test

### No scan results after 10 minutes

| Check | Command |
|---|---|
| Targets configured? | Check `application.yml` targets section |
| Target reachable? | `openssl s_client -connect host:port -brief` |
| Scan errors in logs? | `docker logs certcontrol-agent \| grep -i "error\|timeout\|refused"` |

**Common causes:**
- No targets configured — add them via CertControl UI or `application.yml`
- Firewall between agent host and target — the agent host must reach the target on the configured port
- Target does not speak TLS — the agent only scans TLS-enabled services

### Hostnames show `[redacted]`

This is correct behaviour when redaction patterns match. Check `CERTOPS_REDACTION_PATTERNS` and ensure your patterns are not broader than intended.

### Spool growing on disk

The spool grows when results cannot be uploaded to CertControl. Check:
- Is `certcontrol.pro` reachable from the agent host?
- Is a proxy required?
- Is the API key valid?

The agent retries automatically when connectivity is restored.

### Exposure Discovery does not start

| Symptom | Cause | Fix |
|---|---|---|
| No log output for exposure | `exposure-discovery.enabled` is `false` | Set to `true` in `application.yml` and restart |
| Scan does not start after Run | Agent has not pulled new config | Wait up to 5 minutes or restart the agent |
| `No network_scopes configured` | Scopes not set in CertControl UI | Add CIDR ranges under Exposure Discovery config |
| `Outside scan window` | Scan window restricts execution | Adjust scan window in CertControl config |
| `Exposure discovery already running` | Previous scan still in progress | Wait for it to complete or click Stop |

### Agent fails to start

```bash
docker logs certcontrol-agent 2>&1 | head -40
```

| Error | Cause | Fix |
|---|---|---|
| `java.lang.OutOfMemoryError` | Insufficient RAM | Add `-e JAVA_OPTS="-Xmx256m"` |
| `Failed to bind properties` | Invalid YAML or env var | Check for typos in `application.yml` |
| `Failed to configure mTLS` | Wrong certificate path | Verify volume mounts and file permissions |

### Regenerate a lost API key

1. Go to **Infrastructure → Collectors** in CertControl
2. Click the collector → **Regenerate API Key**
3. Copy the new key and update `CERTOPS_API_KEY` in the agent configuration
4. Restart the agent
5. The old key is immediately invalidated

---

## 17. Security model

### What data leaves your network

The agent transmits only the following data via outbound HTTPS:

**Heartbeat (every 60 seconds)**

```json
{
  "agent_version": "1.3.0",
  "hostname": "prod-scanner-01",
  "ip_address": "10.0.1.50",
  "endpoint_count": 12,
  "queue_size": 0,
  "connectivity": true,
  "memory_used_mb": 87,
  "last_scan_at": "2026-01-01T10:00:00Z"
}
```

**TLS scan result (every scan cycle, per target)**

```json
{
  "endpoint": "api.corp.internal:443",
  "env": "prod",
  "status": "OK",
  "negotiated_tls": "TLSv1.3",
  "cipher_name": "TLS_AES_256_GCM_SHA384",
  "leaf_fp_sha256": "AA:BB:CC:...",
  "leaf_subject_cn": "[redacted]",
  "leaf_issuer_cn": "DigiCert SHA2 Extended Validation Server CA",
  "leaf_valid_from": "2025-06-01T00:00:00Z",
  "leaf_valid_to": "2026-06-01T00:00:00Z",
  "tls_support": { "TLSv1": false, "TLSv1.1": false, "TLSv1.2": true, "TLSv1.3": true },
  "http_headers": { "Strict-Transport-Security": "max-age=31536000", ... },
  "ocsp_status": "GOOD"
}
```

**What is never sent:**

| Data | Why |
|---|---|
| Private keys | Never read or accessed |
| Original internal hostnames (CN/SAN) | Replaced with `[redacted]` if patterns match |
| Raw PEM certificate bodies | Stripped when `CERTOPS_STRIP_PEM=true` |
| Network traffic content | Agent reads only TLS handshake metadata |
| Passwords or credentials | Not read |
| Filesystem contents | Not accessed |

### Transport and authentication

| Layer | Implementation |
|---|---|
| **Transport** | HTTPS (TLS 1.2+) — server certificate always validated |
| **Authentication** | Bearer token (`cwc_` prefix, BCrypt-hashed on server, shown once at registration) |
| **Request signing** | HMAC-SHA256 — `X-Signature` header on all POST requests |
| **Optional** | Mutual TLS — client certificate in addition to Bearer token |

### Private network enforcement

The agent enforces private IP scanning through three independent layers — compromising one does not bypass the others:

1. **Server-side config validation** — CertControl validates all target hostnames and CIDR scopes resolve to private IPs before pushing config to the agent
2. **Agent engine validation** — the agent independently rejects public CIDRs before starting any scan
3. **Agent scope resolver** — individual IPs are filtered during CIDR expansion, dropping any that are not private

The only way to scan public IPs is to set `allowPublicTargets: true` in the agent's local YAML file — this requires deliberate local action and is logged with a `SECURITY WARNING` at startup.

### Revocation and kill switch

- **Disable a collector** in the CertControl UI → the agent's next request is rejected with HTTP 401 — takes effect within seconds
- **Regenerate the API key** → old key immediately invalidated, agent stops uploading until reconfigured
- **Exposure Discovery stop** → admin can stop a running scan from the CertControl UI via **Stop Scan**

### Systemd security hardening (Linux)

The service runs with `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, and `PrivateDevices`. Only the spool and log directories are writable. The service runs as a dedicated non-root user (`certops-agent`).

### Container security (Docker)

The Docker image uses a non-root user (uid 1000) and an Alpine-based JRE image. No shell is needed for operation. The container runs with no inbound ports exposed.
