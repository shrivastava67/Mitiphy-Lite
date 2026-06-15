#!/usr/bin/env bash
# Mitiphy Lite installer (Linux/macOS).
# Idempotent. Resumable. Refuses root. Single-process native install (no Docker).

set -euo pipefail

PROFILE="lite"
RESUME_PHASE=""
DO_RESET=0
DO_UNINSTALL=0
ACCEPT_AUP=0
OFFLINE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --resume) RESUME_PHASE="$2"; shift 2 ;;
    --reset) DO_RESET=1; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    --accept-aup) ACCEPT_AUP=1; shift ;;
    --offline) OFFLINE=1; shift ;;
    -h|--help)
      cat <<EOF
Mitiphy installer (Lite profile)

Usage:
  ./install.sh                  Run the install
  ./install.sh --resume phase=N Resume from phase N (1-5)
  ./install.sh --reset          Wipe ~/.mitiphy/ and reinstall
  ./install.sh --uninstall      Remove install and state (asks confirmation)
  ./install.sh --accept-aup     Auto-accept AUP (non-interactive)
  ./install.sh --offline        Use bundled tarball if present
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; NC="\033[0m"
log()  { printf "${CYAN}[mitiphy]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ ok ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[warn]${NC} %s\n" "$*"; }
err()  { printf "${RED}[fail]${NC} %s\n" "$*" >&2; }

if [[ "$(id -u)" == "0" ]]; then
  err "Refusing to run as root. Run as your normal user."
  exit 2
fi

if [[ "$PROFILE" != "lite" ]]; then
  warn "This installer targets the Lite profile. Other profiles live in DESIGN-DEFAULT.md / DESIGN-FULL.md."
fi

MITIPHY_HOME="${MITIPHY_HOME:-$HOME/.mitiphy}"
STATE_FILE="$MITIPHY_HOME/install.state.json"
mkdir -p "$MITIPHY_HOME"

if [[ "$DO_UNINSTALL" == "1" ]]; then
  warn "Uninstall will remove $MITIPHY_HOME."
  read -rp "Type 'YES' to confirm: " ans
  if [[ "$ans" == "YES" ]]; then
    rm -rf "$MITIPHY_HOME"
    ok "Removed $MITIPHY_HOME"
  else
    err "Aborted."
    exit 1
  fi
  exit 0
fi

if [[ "$DO_RESET" == "1" ]]; then
  warn "Reset will wipe $MITIPHY_HOME."
  read -rp "Type 'YES' to confirm: " ans
  if [[ "$ans" == "YES" ]]; then
    rm -rf "$MITIPHY_HOME"
    mkdir -p "$MITIPHY_HOME"
    ok "State reset."
  else
    err "Aborted."
    exit 1
  fi
fi

write_state() {
  printf '{"phase": %s, "ts": "%s"}\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE_FILE"
}

current_phase() {
  if [[ -f "$STATE_FILE" ]]; then
    python3 -c "import json,sys; print(json.load(open('$STATE_FILE')).get('phase', 0))" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

START_PHASE=0
if [[ -n "$RESUME_PHASE" ]]; then
  START_PHASE="${RESUME_PHASE#phase=}"
else
  START_PHASE="$(current_phase)"
fi

# ---- Phase 1: Preflight ------------------------------------------------------
if (( START_PHASE < 1 )); then
  log "Phase 1: Preflight"
  if ! command -v python3 >/dev/null 2>&1; then
    err "python3 not found. Install Python 3.11+ and re-run."
    exit 1
  fi
  PYV=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  ok "Python $PYV detected"
  if ! command -v git >/dev/null 2>&1; then
    warn "git not found — upgrades will require manual pulls."
  else
    ok "git detected"
  fi
  # Free RAM check (best effort).
  if command -v free >/dev/null 2>&1; then
    RAM_MB=$(free -m | awk 'NR==2 {print $2}')
    if (( RAM_MB < 4096 )); then
      warn "RAM ${RAM_MB}MB < 4 GB recommended. Lite still works for collectors but LLM modes will be limited."
    else
      ok "RAM ${RAM_MB}MB"
    fi
  fi
  write_state 1
fi

# ---- Phase 2: uv or venv -----------------------------------------------------
if (( START_PHASE < 2 )); then
  log "Phase 2: Python environment"
  VENV_DIR="$MITIPHY_HOME/venv"
  if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    ok "Created venv at $VENV_DIR"
  fi
  # shellcheck source=/dev/null
  source "$VENV_DIR/bin/activate"
  python -m pip install --upgrade pip wheel >/dev/null
  ok "pip upgraded"
  write_state 2
fi

# ---- Phase 3: Install mitiphy ------------------------------------------------
if (( START_PHASE < 3 )); then
  log "Phase 3: Install mitiphy"
  # shellcheck source=/dev/null
  source "$MITIPHY_HOME/venv/bin/activate"
  REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
  pip install -e "$REPO_ROOT"
  ok "Installed mitiphy from $REPO_ROOT"
  write_state 3
fi

# ---- Phase 4: Initialize state -----------------------------------------------
if (( START_PHASE < 4 )); then
  log "Phase 4: Initialize state directories + audit chain"
  # shellcheck source=/dev/null
  source "$MITIPHY_HOME/venv/bin/activate"
  python -c "from mitiphy.core.config import get_settings; s=get_settings(); s.ensure_dirs(); print(s.state_dir)"
  python -c "
from mitiphy.audit.chain import AuditChain
from mitiphy.core.config import get_settings
from mitiphy import __version__
s = get_settings()
chain = AuditChain(s.audit_db)
chain.ensure_genesis(installer_version=__version__)
print('genesis ok, rows=', chain.count())
"
  ok "Audit chain anchored"
  if [[ "$ACCEPT_AUP" == "1" ]]; then
    "$MITIPHY_HOME/venv/bin/mitiphy" aup accept || true
  fi
  write_state 4
fi

# ---- Phase 5: Verify ---------------------------------------------------------
if (( START_PHASE < 5 )); then
  log "Phase 5: Doctor + demo"
  # shellcheck source=/dev/null
  source "$MITIPHY_HOME/venv/bin/activate"
  if ! mitiphy doctor; then
    warn "Doctor reported issues — see output above."
  fi
  mitiphy demo --dry-run || warn "Demo failed; continuing."
  write_state 5
fi

cat <<EOF

${GREEN}Mitiphy Lite is ready.${NC}

  Try:    ${CYAN}source $MITIPHY_HOME/venv/bin/activate && mitiphy chat${NC}
  Web UI: ${CYAN}mitiphy web${NC}  then open http://127.0.0.1:7331
  State:  $MITIPHY_HOME

Active recon is disabled in Lite. Upgrade to Default profile for full OSINT muscle.
EOF
