#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# CertControl Pro Agent — Linux systemd installer
#
# Usage:
#   sudo bash install.sh                      # Install / upgrade
#   sudo bash install.sh --uninstall          # Complete removal
#
# The script is idempotent — safe to run multiple times.
# On upgrade it replaces the JAR and systemd unit but preserves
# /etc/certops-agent/env and /etc/certops-agent/application.yml.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SERVICE_NAME="certops-agent"
SERVICE_USER="certops-agent"
INSTALL_DIR="/opt/certops-agent"
SPOOL_DIR="/var/certops-agent/spool"
LOG_DIR="/var/log/certops-agent"
CONF_DIR="/etc/certops-agent"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
JAR_NAME="certops-agent-1.3.1.jar"

# ── Colour helpers ────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── Root check ────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)."
    exit 1
fi

# ── Uninstall ─────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    info "Uninstalling ${SERVICE_NAME}..."

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        info "Service stopped."
    fi
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
        info "Service disabled."
    fi
    rm -f "${UNIT_FILE}" && systemctl daemon-reload
    info "Systemd unit removed."

    rm -rf "${INSTALL_DIR}"
    info "Removed ${INSTALL_DIR}"
    rm -rf "${SPOOL_DIR}"
    info "Removed ${SPOOL_DIR}"
    rm -rf "${LOG_DIR}"
    info "Removed ${LOG_DIR}"
    rm -rf "${CONF_DIR}"
    info "Removed ${CONF_DIR}"

    if id "${SERVICE_USER}" &>/dev/null; then
        userdel "${SERVICE_USER}" 2>/dev/null || true
        info "User ${SERVICE_USER} removed."
    fi

    info "Uninstall complete."
    exit 0
fi

# ── Locate JAR ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR_SOURCE=""

# Check common locations
for candidate in \
    "${SCRIPT_DIR}/${JAR_NAME}" \
    "${SCRIPT_DIR}/target/${JAR_NAME}" \
    "${SCRIPT_DIR}/../target/${JAR_NAME}"; do
    if [[ -f "${candidate}" ]]; then
        JAR_SOURCE="$(realpath "${candidate}")"
        break
    fi
done

if [[ -z "${JAR_SOURCE}" ]]; then
    error "Cannot find ${JAR_NAME}."
    error "Place it next to this script or build with: mvn package -DskipTests"
    exit 1
fi
info "Using JAR: ${JAR_SOURCE}"

# ── Check Java 17+ ───────────────────────────────────────────
find_java() {
    if [[ -n "${JAVA_HOME:-}" ]] && [[ -x "${JAVA_HOME}/bin/java" ]]; then
        echo "${JAVA_HOME}/bin/java"
        return
    fi
    if command -v java &>/dev/null; then
        command -v java
        return
    fi
    return 1
}

JAVA_BIN="$(find_java)" || {
    error "Java not found. Install Java 17+ and set JAVA_HOME or add java to PATH."
    exit 1
}

JAVA_VER=$("${JAVA_BIN}" -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')
if [[ "${JAVA_VER}" -lt 17 ]]; then
    error "Java 17+ required (found Java ${JAVA_VER})."
    exit 1
fi
JAVA_HOME_RESOLVED="$(dirname "$(dirname "$(readlink -f "${JAVA_BIN}")")")"
info "Java ${JAVA_VER} found: ${JAVA_BIN}"

# ── Create system user ───────────────────────────────────────
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    info "Created system user: ${SERVICE_USER}"
else
    info "User ${SERVICE_USER} already exists."
fi

# ── Create directories ───────────────────────────────────────
mkdir -p "${INSTALL_DIR}" "${SPOOL_DIR}" "${LOG_DIR}" "${CONF_DIR}"

chown "${SERVICE_USER}:${SERVICE_USER}" "${SPOOL_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
chmod 750 "${SPOOL_DIR}" "${LOG_DIR}"

info "Directories created."

# ── Copy JAR ──────────────────────────────────────────────────
cp -f "${JAR_SOURCE}" "${INSTALL_DIR}/${JAR_NAME}"
chown root:root "${INSTALL_DIR}/${JAR_NAME}"
chmod 644 "${INSTALL_DIR}/${JAR_NAME}"
info "JAR installed to ${INSTALL_DIR}/${JAR_NAME}"

# ── Generate env file (first install only) ────────────────────
ENV_FILE="${CONF_DIR}/env"
if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<'ENVEOF'
# CertControl Pro Agent — environment configuration
# This file contains secrets and is mode 0600.
# Edit values below, then restart: systemctl restart certops-agent

# REQUIRED — CertControl Pro cloud URL and API key
CERTOPS_SERVER_URL=https://certcontrol.pro
CERTOPS_API_KEY=

# Optional — HTTPS proxy for outbound connections
#HTTPS_PROXY=

# Scan intervals (seconds)
#CERTOPS_SCAN_INTERVAL=300
#CERTOPS_HEARTBEAT_INTERVAL=60
#CERTOPS_CONFIG_PULL_INTERVAL=300

# Scan options
#CERTOPS_TIMEOUT_MS=10000
#CERTOPS_PROBE_TLS=true
#CERTOPS_CHECK_OCSP=true
#CERTOPS_CHECK_HTTP_HEADERS=true

# Hostname redaction
#CERTOPS_REDACTION_ENABLED=true
#CERTOPS_REDACTION_PATTERNS=*.local,*.internal
#CERTOPS_STRIP_PEM=false

# Spool (offline queue)
#CERTOPS_SPOOL_ENABLED=true
#CERTOPS_SPOOL_DIR=/var/certops-agent/spool
#CERTOPS_SPOOL_MAX_MB=100
#CERTOPS_SPOOL_RETRY=60

# CIDR discovery
#CERTOPS_CIDR_ENABLED=false

# mTLS client certificate
#CERTOPS_MTLS_ENABLED=false
#CERTOPS_MTLS_CERT=
#CERTOPS_MTLS_KEY=
#CERTOPS_MTLS_CA=
ENVEOF
    chown root:root "${ENV_FILE}"
    chmod 0600 "${ENV_FILE}"
    info "Created ${ENV_FILE} (edit CERTOPS_API_KEY before starting)."
else
    info "${ENV_FILE} already exists — not overwritten."
fi

# ── Generate application.yml (first install only) ─────────────
APP_YML="${CONF_DIR}/application.yml"
if [[ ! -f "${APP_YML}" ]]; then
    cat > "${APP_YML}" <<'YMLEOF'
# CertControl Pro Agent — Spring Boot overrides
# This file is loaded via --spring.config.additional-location
# Environment variables in /etc/certops-agent/env take precedence.

server:
  port: 0

logging:
  file:
    name: /var/log/certops-agent/agent.log
  logback:
    rollingpolicy:
      max-file-size: 50MB
      max-history: 7
      total-size-cap: 200MB
  level:
    dk.certops.agent: INFO
YMLEOF
    chown root:root "${APP_YML}"
    chmod 644 "${APP_YML}"
    info "Created ${APP_YML}"
else
    info "${APP_YML} already exists — not overwritten."
fi

# ── Install systemd unit ─────────────────────────────────────
cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=CertControl Pro Agent
Documentation=https://certcontrol.pro/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}

Environment=JAVA_HOME=${JAVA_HOME_RESOLVED}
EnvironmentFile=${ENV_FILE}

ExecStart=${JAVA_HOME_RESOLVED}/bin/java \\
    -Xms64m -Xmx256m \\
    -jar ${INSTALL_DIR}/${JAR_NAME} \\
    --spring.config.additional-location=file:${APP_YML}

Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
ReadWritePaths=${SPOOL_DIR} ${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
info "Systemd unit installed and enabled."

# ── Done ──────────────────────────────────────────────────────
echo ""
info "Installation complete!"
echo ""
echo "  Next steps:"
echo "  1. Edit ${ENV_FILE}"
echo "     Set CERTOPS_SERVER_URL and CERTOPS_API_KEY"
echo ""
echo "  2. Start the service:"
echo "     systemctl start ${SERVICE_NAME}"
echo ""
echo "  3. Check status:"
echo "     systemctl status ${SERVICE_NAME}"
echo "     journalctl -u ${SERVICE_NAME} -f"
echo "     tail -f ${LOG_DIR}/agent.log"
echo ""
