#!/usr/bin/env bash
#
# CottenDns Client Linux Installer
#
# Run this script from the directory where the release archive was extracted.
# It installs the CottenDns client as a systemd service so it starts on boot.
# No internet access is required; all files are taken from the current directory.
#
# Usage:
#   sudo bash client_linux_install.sh

set -euo pipefail
IFS=$'\n\t'

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

log_header() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[DONE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || log_error "Missing command: $1"; }
extract_config_version() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  grep '^CONFIG_VERSION' "$f" | awk -F'=' '{print $2}' | tr -d ' "' | head -n1 || true
}
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}

# Apply the same preservation contract as the server installer. New config
# options have defaults in the binary; an upgrade must retain the existing
# domain, shared credential and selected normal/Max mode.
restore_client_config() {
  local install_dir="$1"
  [[ -f "$install_dir/client_config.toml.backup" ]] || return 0
  mv -f "$install_dir/client_config.toml" "$install_dir/client_config.toml.dist"
  mv -f "$install_dir/client_config.toml.backup" "$install_dir/client_config.toml"
}

set_client_tunnel_mode() {
  local config="$1" mode="$2"
  [[ "$mode" == legacy || "$mode" == cottenmax ]] || return 2
  if grep -q '^[[:space:]]*TUNNEL_MODE[[:space:]]*=' "$config"; then
    sed -i "s/^[[:space:]]*TUNNEL_MODE[[:space:]]*=.*$/TUNNEL_MODE = \"$mode\"/" "$config"
  else
    printf '\nTUNNEL_MODE = "%s"\n' "$mode" >> "$config"
  fi
}

print_client_usage() {
  cat <<'USAGE'
CottenDNS Client Linux Installer
Run from the extracted client bundle after setting DOMAINS, ENCRYPTION_KEY and
client_resolvers.txt. Existing profile values are preserved on upgrade.

Usage: sudo bash client_linux_install.sh [--mode legacy|cottenmax]
  --mode legacy     Normal CottenDNS; also the fallback from Max.
  --mode cottenmax  CottenMax beta; requires a compatible beta server.
  --help            Show this help without installing.

Omit --mode to keep the profile's existing selection (Normal if not configured).
Both modes share the same domain/key/profile. Max has its own Soar cipher;
DATA_ENCRYPTION_METHOD applies to Normal mode. Reconnect after switching.
USAGE
}

run_client_upgrade_contract_self_test() {
  local fixture
  fixture="$(mktemp -d)"
  [[ -n "$fixture" && -d "$fixture" ]] || log_error "Could not create client upgrade fixture."
  printf '%s\n' 'CONFIG_VERSION = "old"' 'DOMAINS = ["existing.example"]' 'ENCRYPTION_KEY = "unchanged-key"' 'TUNNEL_MODE = "cottenmax"' > "$fixture/client_config.toml.backup"
  printf '%s\n' 'CONFIG_VERSION = "new"' 'DOMAINS = ["template.example"]' > "$fixture/client_config.toml"
  restore_client_config "$fixture"
  grep -qx 'DOMAINS = \["existing.example"\]' "$fixture/client_config.toml" || log_error "Client upgrade replaced the domain."
  grep -qx 'ENCRYPTION_KEY = "unchanged-key"' "$fixture/client_config.toml" || log_error "Client upgrade changed the shared credential."
  grep -qx 'TUNNEL_MODE = "cottenmax"' "$fixture/client_config.toml" || log_error "Client upgrade changed the selected mode."
  grep -qx 'CONFIG_VERSION = "new"' "$fixture/client_config.toml.dist" || log_error "Client upgrade lost the new template."
  set_client_tunnel_mode "$fixture/client_config.toml" legacy
  grep -qx 'TUNNEL_MODE = "legacy"' "$fixture/client_config.toml" || log_error "Could not select Normal mode."
  set_client_tunnel_mode "$fixture/client_config.toml" cottenmax
  grep -qx 'TUNNEL_MODE = "cottenmax"' "$fixture/client_config.toml" || log_error "Could not select Max mode."
  grep -qx 'ENCRYPTION_KEY = "unchanged-key"' "$fixture/client_config.toml" || log_error "Mode selection changed the key."
  if set_client_tunnel_mode "$fixture/client_config.toml" invalid; then log_error "Invalid mode accepted."; fi
  printf '%s\n' '  TUNNEL_MODE = "legacy"' 'ENCRYPTION_KEY = "keep-this-key"' > "$fixture/indented.toml"
  set_client_tunnel_mode "$fixture/indented.toml" cottenmax
  [[ $(grep -c 'TUNNEL_MODE' "$fixture/indented.toml") == 1 ]] || log_error "Mode update duplicated an indented TOML key."
  grep -qx 'TUNNEL_MODE = "cottenmax"' "$fixture/indented.toml" || log_error "Indented mode update failed."
  printf '%s\n' 'ENCRYPTION_KEY = "keep-this-key"' > "$fixture/missing.toml"
  set_client_tunnel_mode "$fixture/missing.toml" cottenmax
  grep -qx 'TUNNEL_MODE = "cottenmax"' "$fixture/missing.toml" || log_error "Missing mode insertion failed."
  rm -rf -- "$fixture"
  log_success "Client upgrade contract passed."
}

if [[ "${COTTENDNS_INSTALLER_SELF_TEST:-0}" == "1" ]]; then
  run_client_upgrade_contract_self_test
  exit 0
fi

REQUESTED_MODE=""
MODE_REQUESTED=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || { print_client_usage; exit 2; }
      REQUESTED_MODE="$2"; MODE_REQUESTED=true; shift 2 ;;
    --mode=*) REQUESTED_MODE="${1#*=}"; MODE_REQUESTED=true; shift ;;
    -h|--help) print_client_usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; print_client_usage; exit 2 ;;
  esac
done
if [[ "$MODE_REQUESTED" == true && "$REQUESTED_MODE" != legacy && "$REQUESTED_MODE" != cottenmax ]]; then
  echo "Invalid mode: $REQUESTED_MODE (choose legacy or cottenmax)." >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  log_error "Run this script as root (sudo)."
fi

INSTALL_DIR="$(pwd -P)"
[[ -n "${PWD:-}" ]] && INSTALL_DIR="$PWD"
if [[ "$INSTALL_DIR" == /dev/fd* || "$INSTALL_DIR" == /proc/*/fd* ]]; then
  INSTALL_DIR="$(pwd -P)"
fi
log_info "Installation directory: $INSTALL_DIR"
cd "$INSTALL_DIR" || log_error "Cannot access install directory: $INSTALL_DIR"

echo -e "${MAGENTA}${BOLD}"
echo -e "          CottenDns Client Auto-Installer${NC}"
echo -e "${CYAN}------------------------------------------------------${NC}"

require_cmd systemctl

stop_existing_CottenDns_client_service() {
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^cottendns-client\.service'; then
    log_info "Stopping existing CottenDns client service..."
    systemctl stop cottendns-client 2>/dev/null || true

    for _ in 1 2 3 4 5; do
      if ! systemctl is-active --quiet cottendns-client; then
        break
      fi
      sleep 1
    done

    local main_pid
    main_pid="$(systemctl show cottendns-client --property MainPID --value 2>/dev/null || true)"
    if [[ -n "${main_pid:-}" && "$main_pid" != "0" ]] && kill -0 "$main_pid" 2>/dev/null; then
      log_warn "cottendns-client service is still active. Sending SIGTERM to MainPID: $main_pid"
      kill "$main_pid" 2>/dev/null || true
      sleep 2
      kill -0 "$main_pid" 2>/dev/null && kill -9 "$main_pid" 2>/dev/null || true
    fi

    systemctl reset-failed cottendns-client 2>/dev/null || true
  fi
}

# Remove the pre-rename "cottenpickdns-client" unit so an upgrade does not leave
# a stale service running or re-enabled at boot.
cleanup_legacy_cottenpickdns_client() {
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^cottenpickdns-client\.service'; then
    log_info "Removing legacy cottenpickdns-client service..."
    systemctl stop cottenpickdns-client 2>/dev/null || true
    systemctl disable cottenpickdns-client >/dev/null 2>&1 || true
    systemctl reset-failed cottenpickdns-client 2>/dev/null || true
  fi
  rm -f /etc/systemd/system/cottenpickdns-client.service 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

log_header "Locating Client Binary"
# The installer is bundled inside the release archive alongside the binary.
# Find the most recently modified CottenDns_Client_* file in the current directory.
shopt -s nullglob
client_bins=(CottenDns_Client_* CottenDNS_Client_*)
shopt -u nullglob
[[ ${#client_bins[@]} -eq 0 ]] && log_error "No CottenDns_Client_* binary found in $INSTALL_DIR. Run this script from the extracted release directory."
EXECUTABLE="${client_bins[0]}"
log_info "Found binary: $EXECUTABLE"
chmod +x "$EXECUTABLE"
./"$EXECUTABLE" --version >/dev/null 2>&1 || log_error "Client binary failed its version check; existing service was not stopped."
CLIENT_HELP="$(./"$EXECUTABLE" --help 2>&1 || true)"
if [[ "$REQUESTED_MODE" == cottenmax ]] && ! grep -q 'CottenMax' <<< "$CLIENT_HELP"; then
  log_error "This client binary does not advertise CottenMax support. Use a matching beta client bundle."
fi
log_success "Binary is ready."

log_header "Configuration"
[[ -f "client_config.toml" ]] || log_error "client_config.toml not found in $INSTALL_DIR."
CURRENT_VERSION="$(extract_config_version client_config.toml)"
if [[ -z "${CURRENT_VERSION:-}" ]]; then
  log_error "client_config.toml is invalid (CONFIG_VERSION missing)."
fi
if [[ -f "client_config.toml.backup" ]]; then
  BACKUP_VERSION="$(extract_config_version client_config.toml.backup)"
  if [[ -z "${BACKUP_VERSION:-}" ]]; then
    log_error "Backup config is too old (CONFIG_VERSION missing). Merge manually."
  fi

  if [[ "$BACKUP_VERSION" == "$CURRENT_VERSION" ]]; then
    restore_client_config "$INSTALL_DIR"
    log_info "Existing config restored; new defaults are in client_config.toml.dist."
  elif version_lt "$BACKUP_VERSION" "$CURRENT_VERSION"; then
    restore_client_config "$INSTALL_DIR"
    log_info "Existing config, domain and credential preserved (backup=$BACKUP_VERSION < new=$CURRENT_VERSION)."
    log_info "New optional defaults are available in client_config.toml.dist."
  else
    log_error "Backup config version is newer than the bundled config (backup=$BACKUP_VERSION, new=$CURRENT_VERSION). Merge manually."
  fi
fi

if [[ -n "$REQUESTED_MODE" ]]; then
  set_client_tunnel_mode client_config.toml "$REQUESTED_MODE"
fi
log_header "Tunnel Mode"
SELECTED_MODE="$(sed -nE 's/^[[:space:]]*TUNNEL_MODE[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' client_config.toml | head -n 1)"
if [[ "$SELECTED_MODE" == cottenmax ]]; then
  grep -q 'CottenMax' <<< "$CLIENT_HELP" || log_error "The selected Max profile requires a compatible beta client binary; existing service was not stopped."
  log_info "Selected: CottenMax beta. The server must support Max; keep the same domain and shared key."
else
  log_info "Selected: Normal CottenDNS. Max remains optional in this same profile."
fi
log_info "Configure DOMAINS, ENCRYPTION_KEY and client_resolvers.txt before connecting."
log_info 'Switch with --mode legacy|cottenmax, or edit TUNNEL_MODE and restart cottendns-client.'
log_info "Keep optional Max transport/tuning defaults for the first connection."

# When running as a systemd service the process is non-interactive,
# so switch the startup mode from the default "ask" to "logs" to avoid
# waiting indefinitely for user input on every restart.
if grep -q '^STARTUP_MODE[[:space:]]*=[[:space:]]*"ask"' client_config.toml; then
  sed -i 's/^STARTUP_MODE[[:space:]]*=.*$/STARTUP_MODE = "logs"/' client_config.toml
  log_info "STARTUP_MODE set to \"logs\" for non-interactive service operation."
fi

log_header "Stopping Existing CottenDns Client"
cleanup_legacy_cottenpickdns_client
stop_existing_CottenDns_client_service

log_header "Installing System Service"
SVC="/etc/systemd/system/cottendns-client.service"
cat > "$SVC" <<EOF
[Unit]
Description=CottenDns Client
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$EXECUTABLE --config $INSTALL_DIR/client_config.toml
Restart=always
RestartSec=5
User=root

LimitNOFILE=1048576
LimitNPROC=65535
TasksMax=infinity
TimeoutStopSec=15
KillMode=control-group

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cottendns-client >/dev/null 2>&1 || log_warn "Could not enable cottendns-client service at boot."
systemctl restart cottendns-client

sleep 2
if ! systemctl is-active --quiet cottendns-client; then
  journalctl -u cottendns-client -n 50 --no-pager || true
  log_error "Service failed to start. See logs above."
fi

log_success "CottenDns client service is running."

echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${YELLOW}>${NC} Start:   systemctl start cottendns-client"
echo -e "  ${YELLOW}>${NC} Stop:    systemctl stop cottendns-client"
echo -e "  ${YELLOW}>${NC} Restart: systemctl restart cottendns-client"
echo -e "  ${YELLOW}>${NC} Logs:    journalctl -u cottendns-client -f"
echo -e "\n${BOLD}Files:${NC}"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/client_config.toml"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/client_resolvers.txt"
echo -e "${YELLOW}Note:${NC} Edit client_config.toml (set DOMAINS, ENCRYPTION_KEY, etc.) then run:"
echo -e "  ${YELLOW}>${NC} systemctl restart cottendns-client"
