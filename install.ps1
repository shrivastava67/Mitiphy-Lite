# Mitiphy Lite installer (Windows PowerShell).
# Idempotent. No admin required. No Docker.

[CmdletBinding()]
param(
  [string]$Profile = "lite",
  [int]$ResumePhase = 0,
  [switch]$Reset,
  [switch]$Uninstall,
  [switch]$AcceptAup
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "[mitiphy] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "[ ok ] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "[warn] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[fail] $msg" -ForegroundColor Red }

$MitiphyHome = if ($env:MITIPHY_HOME) { $env:MITIPHY_HOME } else { Join-Path $HOME ".mitiphy" }
$StateFile = Join-Path $MitiphyHome "install.state.json"
New-Item -ItemType Directory -Force -Path $MitiphyHome | Out-Null

if ($Uninstall) {
  Write-Warn2 "Uninstall will remove $MitiphyHome."
  $ans = Read-Host "Type 'YES' to confirm"
  if ($ans -eq "YES") {
    Remove-Item -Recurse -Force $MitiphyHome
    Write-Ok "Removed $MitiphyHome"
  } else {
    Write-Fail "Aborted."; exit 1
  }
  exit 0
}

if ($Reset) {
  Write-Warn2 "Reset will wipe $MitiphyHome."
  $ans = Read-Host "Type 'YES' to confirm"
  if ($ans -eq "YES") {
    Remove-Item -Recurse -Force $MitiphyHome
    New-Item -ItemType Directory -Force -Path $MitiphyHome | Out-Null
    Write-Ok "State reset."
  } else {
    Write-Fail "Aborted."; exit 1
  }
}

function Write-State($phase) {
  $obj = @{ phase = $phase; ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
  $obj | ConvertTo-Json | Set-Content -Path $StateFile -Encoding utf8
}

function Get-Phase {
  if (Test-Path $StateFile) {
    try { (Get-Content $StateFile | ConvertFrom-Json).phase } catch { 0 }
  } else { 0 }
}

$StartPhase = if ($ResumePhase -gt 0) { $ResumePhase } else { Get-Phase }

# Phase 1: preflight
if ($StartPhase -lt 1) {
  Write-Step "Phase 1: Preflight"
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) {
    Write-Fail "python not found. Install Python 3.11+ and re-run."; exit 1
  }
  $pyver = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
  Write-Ok "Python $pyver detected"
  Write-State 1
}

# Phase 2: venv
$VenvDir = Join-Path $MitiphyHome "venv"
if ($StartPhase -lt 2) {
  Write-Step "Phase 2: Python environment"
  if (-not (Test-Path $VenvDir)) {
    & python -m venv $VenvDir
    Write-Ok "Created venv at $VenvDir"
  }
  & "$VenvDir\Scripts\python.exe" -m pip install --upgrade pip wheel | Out-Null
  Write-Ok "pip upgraded"
  Write-State 2
}

# Phase 3: install
if ($StartPhase -lt 3) {
  Write-Step "Phase 3: Install mitiphy"
  $RepoRoot = Split-Path -Parent $PSCommandPath
  & "$VenvDir\Scripts\pip.exe" install -e $RepoRoot
  Write-Ok "Installed mitiphy from $RepoRoot"
  Write-State 3
}

# Phase 4: state init
if ($StartPhase -lt 4) {
  Write-Step "Phase 4: Initialize state + audit chain"
  & "$VenvDir\Scripts\python.exe" -c "from mitiphy.core.config import get_settings; s=get_settings(); s.ensure_dirs(); print(s.state_dir)"
  & "$VenvDir\Scripts\python.exe" -c "from mitiphy.audit.chain import AuditChain; from mitiphy.core.config import get_settings; from mitiphy import __version__; s=get_settings(); c=AuditChain(s.audit_db); c.ensure_genesis(installer_version=__version__); print('rows=', c.count())"
  if ($AcceptAup) {
    & "$VenvDir\Scripts\mitiphy.exe" aup accept | Out-Host
  }
  Write-State 4
}

# Phase 5: verify
if ($StartPhase -lt 5) {
  Write-Step "Phase 5: Doctor + demo"
  & "$VenvDir\Scripts\mitiphy.exe" doctor
  & "$VenvDir\Scripts\mitiphy.exe" demo --dry-run
  Write-State 5
}

Write-Host ""
Write-Host "Mitiphy Lite is ready." -ForegroundColor Green
Write-Host "  Activate venv: . $VenvDir\Scripts\Activate.ps1"
Write-Host "  Chat TUI:      mitiphy chat"
Write-Host "  Web UI:        mitiphy web   then open http://127.0.0.1:7331"
Write-Host "  State:         $MitiphyHome"
