#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CertControl Pro Agent - Windows Service installer (WinSW)

.DESCRIPTION
    Installs or upgrades the CertControl Pro Agent as a Windows service.
    Uses WinSW (Windows Service Wrapper) to run the JAR as a native service.
    Idempotent - safe to run multiple times.

.PARAMETER Uninstall
    Completely removes the service, files, and configuration.

.EXAMPLE
    .\install.ps1                  # Install or upgrade
    .\install.ps1 -Uninstall       # Complete removal
#>
param(
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────
$ServiceName    = "certops-agent"
$DisplayName    = "CertControl Pro Agent"
$InstallDir     = "C:\certops-agent"
$SpoolDir       = "C:\certops-agent\spool"
$LogDir         = "C:\certops-agent\logs"
$JarName        = "certops-agent-1.3.1.jar"
$WinSwExe       = "certops-agent.exe"
$WinSwXml       = "certops-agent.xml"
$EnvConf        = "env.conf"
$WinSwVersion   = "2.12.0"
$WinSwUrl       = "https://github.com/winsw/winsw/releases/download/v${WinSwVersion}/WinSW-x64.exe"

# ── Helpers ───────────────────────────────────────────────────
function Write-Info  { param($Msg) Write-Host "[INFO]  $Msg" -ForegroundColor Green }
function Write-Warn  { param($Msg) Write-Host "[WARN]  $Msg" -ForegroundColor Yellow }
function Write-Err   { param($Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red }

# ── Uninstall ─────────────────────────────────────────────────
if ($Uninstall) {
    Write-Info "Uninstalling ${ServiceName}..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            & "$InstallDir\$WinSwExe" stop 2>$null
            Start-Sleep -Seconds 3
            Write-Info "Service stopped."
        }
        & "$InstallDir\$WinSwExe" uninstall 2>$null
        Start-Sleep -Seconds 2
        Write-Info "Service uninstalled."
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Info "Removed ${InstallDir}"
    }

    Write-Info "Uninstall complete."
    exit 0
}

# ── Locate JAR ────────────────────────────────────────────────
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$JarSource = $null

foreach ($candidate in @(
    (Join-Path $ScriptDir $JarName),
    (Join-Path $ScriptDir "target\$JarName"),
    (Join-Path (Split-Path $ScriptDir) "target\$JarName")
)) {
    if (Test-Path $candidate) {
        $JarSource = (Resolve-Path $candidate).Path
        break
    }
}

if (-not $JarSource) {
    Write-Err "Cannot find ${JarName}."
    Write-Err "Place it next to this script or build with: mvn package -DskipTests"
    exit 1
}
Write-Info "Using JAR: ${JarSource}"

# ── Check Java 17+ ───────────────────────────────────────────
function Find-Java {
    # JAVA_HOME
    if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe")) {
        return "$env:JAVA_HOME\bin\java.exe"
    }
    # PATH
    $javaCmd = Get-Command java.exe -ErrorAction SilentlyContinue
    if ($javaCmd) { return $javaCmd.Source }
    # Known install locations
    foreach ($base in @(
        "C:\Program Files\Eclipse Adoptium",
        "C:\Program Files\Java",
        "C:\Program Files\Microsoft\jdk-17*",
        "C:\Program Files\Amazon Corretto"
    )) {
        $dirs = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending
        foreach ($d in $dirs) {
            $j = Join-Path $d.FullName "bin\java.exe"
            if (Test-Path $j) { return $j }
        }
    }
    return $null
}

$JavaExe = Find-Java
if (-not $JavaExe) {
    Write-Err "Java not found. Install Java 17+ and set JAVA_HOME."
    exit 1
}

$verOutput = & $JavaExe -version 2>&1 | Select-Object -First 1
if ($verOutput -match '"(\d+)') {
    $javaMajor = [int]$Matches[1]
} else {
    Write-Err "Cannot determine Java version."
    exit 1
}

if ($javaMajor -lt 17) {
    Write-Err "Java 17+ required (found Java ${javaMajor})."
    exit 1
}

$JavaHome = Split-Path (Split-Path $JavaExe)
Write-Info "Java ${javaMajor} found: ${JavaExe}"

# ── Create directories ───────────────────────────────────────
foreach ($dir in @($InstallDir, $SpoolDir, $LogDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Info "Directories created."

# ── Stop existing service if running ─────────────────────────
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc -and $existingSvc.Status -eq "Running") {
    Write-Info "Stopping existing service for upgrade..."
    & "$InstallDir\$WinSwExe" stop 2>$null
    Start-Sleep -Seconds 3
}

# ── Copy JAR ──────────────────────────────────────────────────
Copy-Item -Path $JarSource -Destination "$InstallDir\$JarName" -Force
Write-Info "JAR installed to $InstallDir\$JarName"

# ── Download WinSW ────────────────────────────────────────────
$winswPath = Join-Path $InstallDir $WinSwExe
if (-not (Test-Path $winswPath)) {
    Write-Info "Downloading WinSW v${WinSwVersion}..."
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $WinSwUrl -OutFile $winswPath -UseBasicParsing
        Write-Info "WinSW downloaded."
    } catch {
        Write-Err "Failed to download WinSW from ${WinSwUrl}"
        Write-Err "Download manually and place as ${winswPath}"
        exit 1
    }
} else {
    Write-Info "WinSW already present."
}

# ── Generate env.conf (first install only) ────────────────────
$envPath = Join-Path $InstallDir $EnvConf
if (-not (Test-Path $envPath)) {
    @"
# CertControl Pro Agent - environment configuration
# This file contains secrets. ACL restricted to SYSTEM + Administrators.
# Edit values below, then restart the service.

# REQUIRED - CertControl Pro cloud URL and API key
CERTOPS_SERVER_URL=https://certcontrol.pro
CERTOPS_API_KEY=

# Optional - HTTPS proxy for outbound connections
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
#CERTOPS_SPOOL_DIR=C:\certops-agent\spool
#CERTOPS_SPOOL_MAX_MB=100
#CERTOPS_SPOOL_RETRY=60

# CIDR discovery
#CERTOPS_CIDR_ENABLED=false

# mTLS client certificate
#CERTOPS_MTLS_ENABLED=false
#CERTOPS_MTLS_CERT=
#CERTOPS_MTLS_KEY=
#CERTOPS_MTLS_CA=
"@ | Set-Content -Path $envPath -Encoding UTF8

    # Restrict ACL: SYSTEM + Administrators only
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "SYSTEM", "FullControl", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators", "FullControl", "Allow")))
    Set-Acl -Path $envPath -AclObject $acl

    Write-Info "Created ${envPath} (edit CERTOPS_API_KEY before starting)."
} else {
    Write-Info "${envPath} already exists - not overwritten."
}

# ── Read env.conf and build <env> XML elements ────────────────
function Read-EnvConf {
    param($Path)
    $envEntries = @()
    if (Test-Path $Path) {
        foreach ($line in (Get-Content $Path)) {
            $trimmed = $line.Trim()
            if ($trimmed -and -not $trimmed.StartsWith("#")) {
                $eqIdx = $trimmed.IndexOf("=")
                if ($eqIdx -gt 0) {
                    $key = $trimmed.Substring(0, $eqIdx).Trim()
                    $val = $trimmed.Substring($eqIdx + 1).Trim()
                    $envEntries += "    <env name=`"$key`" value=`"$val`" />"
                }
            }
        }
    }
    return $envEntries
}

$envXmlLines = Read-EnvConf -Path $envPath
$envXmlBlock = ""
if ($envXmlLines.Count -gt 0) {
    $envXmlBlock = "`n" + ($envXmlLines -join "`n")
}

# ── Generate WinSW XML ────────────────────────────────────────
$xmlPath = Join-Path $InstallDir $WinSwXml
$xmlContent = @"
<service>
  <id>${ServiceName}</id>
  <name>${DisplayName}</name>
  <description>On-premise TLS scanner agent for CertControl Pro</description>

  <executable>${JavaHome}\bin\java.exe</executable>
  <arguments>-Xms64m -Xmx256m -jar "${InstallDir}\${JarName}" --spring.config.additional-location=file:${InstallDir}\application.yml</arguments>

  <logpath>${LogDir}</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>52428800</sizeThreshold>
    <keepFiles>7</keepFiles>
  </log>

  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>

  <onfailure action="restart" delay="10 sec" />
  <resetfailure>1 hour</resetfailure>
${envXmlBlock}
</service>
"@

$xmlContent | Set-Content -Path $xmlPath -Encoding UTF8
Write-Info "WinSW XML generated at ${xmlPath}"

# ── Generate application.yml (first install only) ─────────────
$appYmlPath = Join-Path $InstallDir "application.yml"
if (-not (Test-Path $appYmlPath)) {
    @"
# CertControl Pro Agent - Spring Boot overrides
# Environment variables in env.conf take precedence.

server:
  port: 0

logging:
  file:
    name: ${LogDir}\agent.log
  logback:
    rollingpolicy:
      max-file-size: 50MB
      max-history: 7
      total-size-cap: 200MB
  level:
    dk.certops.agent: INFO

certops:
  agent:
    spool:
      directory: ${SpoolDir}
"@ | Set-Content -Path $appYmlPath -Encoding UTF8
    Write-Info "Created ${appYmlPath}"
} else {
    Write-Info "${appYmlPath} already exists - not overwritten."
}

# ── Install / update service ─────────────────────────────────
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Info "Installing Windows service..."
    & $winswPath install
    Write-Info "Service installed."
} else {
    Write-Info "Service already registered — refreshing config."
    # WinSW reads the XML at start; just ensure it's up to date (already written above)
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Info "Installation complete!"
Write-Host ""
Write-Host "  Next steps:"
Write-Host "  1. Edit ${envPath}"
Write-Host "     Set CERTOPS_SERVER_URL and CERTOPS_API_KEY"
Write-Host ""
Write-Host "  2. Start the service:"
Write-Host "     & '${winswPath}' start"
Write-Host "     -or-  Start-Service ${ServiceName}"
Write-Host ""
Write-Host "  3. Check status:"
Write-Host "     Get-Service ${ServiceName}"
Write-Host "     Get-Content ${LogDir}\agent.log -Tail 30 -Wait"
Write-Host ""
