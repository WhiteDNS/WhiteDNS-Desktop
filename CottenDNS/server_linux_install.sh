#!/usr/bin/env bash

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

restore_existing_config() {
  local install_dir="$1"
  local config="$install_dir/server_config.toml"
  local backup="$install_dir/server_config.toml.backup"
  local template="$install_dir/server_config.toml.dist"

  if [[ -f "$backup" ]]; then
    mv -f "$config" "$template"
    mv -f "$backup" "$config"
    log_success "Existing config preserved; new defaults are available in $template."
  fi
}

# CI exercises the same config-swap helper used by a real --upgrade without
# requiring root or systemd. This protects the promise that old deployments keep
# both their config and encryption key when the latest defaults are installed.
run_upgrade_contract_self_test() {
  local fixture
  fixture="$(mktemp -d)"
  [[ -n "$fixture" && -d "$fixture" ]] || log_error "Could not create upgrade test fixture."

  printf '%s\n' 'CONFIG_VERSION = "legacy"' > "$fixture/server_config.toml.backup"
  printf '%s\n' 'CONFIG_VERSION = "current"' > "$fixture/server_config.toml"
  printf '%s\n' 'unchanged-key' > "$fixture/encrypt_key.txt"
  restore_existing_config "$fixture"

  grep -q 'legacy' "$fixture/server_config.toml" || log_error "Upgrade test replaced the legacy config."
  grep -q 'current' "$fixture/server_config.toml.dist" || log_error "Upgrade test did not retain the new defaults."
  grep -qx 'unchanged-key' "$fixture/encrypt_key.txt" || log_error "Upgrade test changed the encryption key."
  rm -rf -- "$fixture"
  log_success "Legacy upgrade contract passed."
}

if [[ "${COTTENDNS_INSTALLER_SELF_TEST:-0}" == "1" ]]; then
  run_upgrade_contract_self_test
  exit 0
fi
require_cmd() { command -v "$1" >/dev/null 2>&1 || log_error "Missing command: $1"; }
backup_file_once() {
  local f="$1"
  [[ -f "$f" && ! -f "${f}.bak" ]] && cp -a "$f" "${f}.bak"
}
extract_config_version() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  grep '^CONFIG_VERSION' "$f" | awk -F'=' '{print $2}' | tr -d ' "' | head -n1
}
version_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
detect_legacy_linux() {
  local id="${ID:-}"
  local version_major="${VERSION_ID%%.*}"

  case "$id" in
    ubuntu)
      [[ "${version_major:-0}" -le 20 ]]
      ;;
    debian)
      [[ "${version_major:-0}" -le 11 ]]
      ;;
    almalinux|rocky|rhel|centos)
      [[ "${version_major:-0}" -le 8 ]]
      ;;
    *)
      return 1
      ;;
  esac
}
select_release_artifact() {
  local arch="$1"
  local version="${2:-}"
  local legacy=0
  if detect_legacy_linux; then
    legacy=1
    log_info "Legacy system detected (broader Linux compatibility mode)."
  fi

  local base_url
  if [[ -n "$version" ]]; then
    base_url="https://github.com/TaJirax/CottenDns/releases/download/${version}"
    log_info "Targeting CottenDns release: ${version}"
  else
    base_url="https://github.com/TaJirax/CottenDns/releases/latest/download"
  fi

  case "$arch" in
    aarch64|arm64)
      if [[ $legacy -eq 1 ]]; then
        PREFIX="CottenDns_Server_Linux-Legacy_ARM64"
      else
        PREFIX="CottenDns_Server_Linux_ARM64"
      fi
      ;;
    armv7l|armv7|armhf)
      PREFIX="CottenDns_Server_Linux_ARMV7"
      ;;
    x86_64|amd64)
      if [[ $legacy -eq 1 ]]; then
        PREFIX="CottenDns_Server_Linux-Legacy_AMD64"
      else
        PREFIX="CottenDns_Server_Linux_AMD64"
      fi
      ;;
    i386|i486|i586|i686|x86)
      PREFIX="CottenDns_Server_Linux_X86"
      ;;
    *)
      log_error "Unsupported architecture: $arch"
      ;;
  esac

  URL="${base_url}/${PREFIX}.zip"
}

find_local_server_binary() {
  local arch="$1"
  local search_dirs=("$INSTALL_DIR" "$INSTALL_DIR/dist")
  local pat

  case "$arch" in
    x86_64|amd64) pat="_(A|a)(M|m)(D|d)64" ;;
    aarch64|arm64) pat="_(A|a)(R|r)(M|m)64" ;;
    armv7l|armv7|armhf) pat="_(A|a)(R|r)(M|m)(V|v)7" ;;
    i386|i486|i586|i686|x86) pat="_(X|x)86" ;;
    *) log_error "Unsupported architecture: $arch" ;;
  esac

  for sd in "${search_dirs[@]}"; do
    [[ -d "$sd" ]] || continue
    local found
    found="$(find "$sd" -maxdepth 1 \( -name "CottenDns_Server_Linux*" -o -name "CottenDNS_Server_Linux*" \) -type f 2>/dev/null | grep -E "$pat" | xargs ls -t 2>/dev/null | head -n1)"
    if [[ -n "$found" ]]; then
      echo "$found"
      return 0
    fi
  done
  return 1
}

find_local_config() {
  local search_dirs=("$INSTALL_DIR" "$INSTALL_DIR/dist")

  for sd in "${search_dirs[@]}"; do
    if [[ -f "$sd/server_config.toml" ]]; then
      echo "$sd/server_config.toml"
      return 0
    fi
  done

  if [[ -f "$INSTALL_DIR/server_config.toml.simple" ]]; then
    cp "$INSTALL_DIR/server_config.toml.simple" "$INSTALL_DIR/server_config.toml"
    echo "$INSTALL_DIR/server_config.toml"
    return 0
  fi

  return 1
}

print_usage() {
  cat <<'USAGE'
CottenDns Server Linux Installer

Usage:
  bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh) [OPTIONS]

Options:
  -v, --version <VERSION>   Install a specific CottenDns release (tag), e.g. v1.2.3.
                            If omitted, the latest release is installed.
  -l, --local               Local/offline install: use the server binary and
                            config found in the current directory (or dist/).
                            No download from GitHub is performed.
  -u, --uninstall           Uninstall CottenDns: stop and remove the systemd
                            service, drop kernel/limit tunings, and clean up
                            binaries and config files in the install directory.
      --upgrade             Upgrade an existing systemd installation in place.
                            Preserves config/key and rolls the unit back if the
                            new process does not become healthy.
  -h, --help                Show this help message and exit.

Examples:
  # Install the latest release (default behavior):
  bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh)

  # Install a specific release version:
  bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh) --version v1.2.3

  # Upgrade an existing server in one command:
  bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh) --upgrade

  # Local/offline install for testing:
  python build.py
  sudo bash server_linux_install.sh --local

  # Uninstall CottenDns:
  bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh) --uninstall
USAGE
}

ACTION="install"
TARGET_VERSION=""
LOCAL_MODE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      [[ $# -ge 2 ]] || { echo "Error: $1 requires a value" >&2; print_usage; exit 2; }
      TARGET_VERSION="$2"
      shift 2
      ;;
    --version=*)
      TARGET_VERSION="${1#*=}"
      shift
      ;;
    -u|--uninstall)
      ACTION="uninstall"
      shift
      ;;
    --upgrade)
      ACTION="upgrade"
      shift
      ;;
    -l|--local)
      LOCAL_MODE=1
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      print_usage
      exit 2
      ;;
  esac
done

if [[ "$LOCAL_MODE" -eq 1 && -n "$TARGET_VERSION" ]]; then
  echo "Error: --local cannot be combined with --version" >&2
  exit 2
fi

if [[ "$ACTION" == "uninstall" && -n "$TARGET_VERSION" ]]; then
  echo "Error: --version cannot be combined with --uninstall" >&2
  exit 2
fi

if [[ "$ACTION" == "upgrade" && "$LOCAL_MODE" -eq 1 ]]; then
  echo "Error: --upgrade cannot be combined with --local" >&2
  exit 2
fi

if [[ -n "$TARGET_VERSION" && ! "$TARGET_VERSION" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "Error: invalid version tag: $TARGET_VERSION" >&2
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
if [[ "$ACTION" == "upgrade" ]]; then
  EXISTING_SERVICE_FILE="$(systemctl show cottendns.service --property FragmentPath --value 2>/dev/null || true)"
  [[ -f "$EXISTING_SERVICE_FILE" ]] || log_error "No existing cottendns systemd installation was found."
  EXISTING_EXECUTABLE="$(sed -n 's|^ExecStart=\([^[:space:]]*\).*|\1|p' "$EXISTING_SERVICE_FILE" | head -n1)"
  [[ -n "$EXISTING_EXECUTABLE" ]] || log_error "Could not determine the existing server path from cottendns.service."
  INSTALL_DIR="$(dirname "$EXISTING_EXECUTABLE")"
  [[ -f "$INSTALL_DIR/server_config.toml" ]] || log_error "Existing server config not found at $INSTALL_DIR/server_config.toml."
  [[ -f "$EXISTING_EXECUTABLE" ]] || log_error "Existing executable not found at $EXISTING_EXECUTABLE."
fi
log_info "Installation directory: $INSTALL_DIR"
cd "$INSTALL_DIR" || log_error "Cannot access install directory: $INSTALL_DIR"

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  log_error "OS detection failed (/etc/os-release missing)."
fi

echo -e "${MAGENTA}${BOLD}"
if [[ "$ACTION" == "uninstall" ]]; then
  echo -e "          CottenDns Server Auto-Uninstaller${NC}"
elif [[ "$ACTION" == "upgrade" ]]; then
  echo -e "          CottenDns Server Safe Upgrader${NC}"
elif [[ "$LOCAL_MODE" -eq 1 ]]; then
  echo -e "          CottenDns Server Local-Installer${NC}"
else
  echo -e "           CottenDns Server Auto-Installer${NC}"
fi
echo -e "${CYAN}------------------------------------------------------${NC}"

# Remove units/files from the pre-rename "cottenpickdns" naming so an upgrade
# does not leave a stale service holding port 53 or restarting in the background.
cleanup_legacy_cottenpickdns() {
  for unit in cottenpickdns cottenpickdns-egress-filter; do
    if systemctl list-unit-files --all 2>/dev/null | grep -q "^${unit}\.service"; then
      log_info "Removing legacy ${unit} service..."
      systemctl stop "${unit}" 2>/dev/null || true
      systemctl disable "${unit}" >/dev/null 2>&1 || true
      systemctl reset-failed "${unit}" 2>/dev/null || true
    fi
  done
  rm -f /etc/systemd/system/cottenpickdns.service 2>/dev/null || true
  rm -f /etc/systemd/system/cottenpickdns-egress-filter.service 2>/dev/null || true
  rm -rf /etc/systemd/system/cottenpickdns.service.d 2>/dev/null || true
  rm -f /usr/local/sbin/cottenpickdns-egress-filter.sh 2>/dev/null || true
  rm -f /etc/sysctl.d/99-cottenpickdns.conf /etc/sysctl.d/99-cottenpickdns-tuning.conf 2>/dev/null || true
  rm -f /etc/security/limits.d/99-cottenpickdns.conf 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
}

do_uninstall() {
  log_header "Uninstalling CottenDns"

  cleanup_legacy_cottenpickdns

  if systemctl list-unit-files --all 2>/dev/null | grep -q '^cottendns\.service'; then
    log_info "Stopping and disabling cottendns service..."
    systemctl stop cottendns 2>/dev/null || true
    systemctl disable cottendns >/dev/null 2>&1 || true
    systemctl reset-failed cottendns 2>/dev/null || true
  else
    log_info "No cottendns systemd unit found."
  fi

  if [[ -f /etc/systemd/system/cottendns.service ]]; then
    rm -f /etc/systemd/system/cottendns.service
    log_success "Removed /etc/systemd/system/cottendns.service"
  fi
  if [[ -f /etc/systemd/system/cottendns-egress-filter.service ]]; then
    systemctl stop cottendns-egress-filter.service 2>/dev/null || true
    systemctl disable cottendns-egress-filter.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/cottendns-egress-filter.service
    log_success "Removed /etc/systemd/system/cottendns-egress-filter.service"
  fi
  if [[ -d /etc/systemd/system/cottendns.service.d ]]; then
    rm -rf /etc/systemd/system/cottendns.service.d
    log_success "Removed /etc/systemd/system/cottendns.service.d/"
  fi
  if [[ -f /usr/local/sbin/cottendns-egress-filter.sh ]]; then
    rm -f /usr/local/sbin/cottendns-egress-filter.sh
    log_success "Removed /usr/local/sbin/cottendns-egress-filter.sh"
  fi
  systemctl daemon-reload 2>/dev/null || true

  local pid cmdline
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
    if echo "$cmdline" | grep -qiE 'cottendns'; then
      log_warn "Terminating stray CottenDns process (PID: $pid)..."
      kill "$pid" 2>/dev/null || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
      fi
    fi
  done < <(pgrep -fi 'cottendns' 2>/dev/null || true)

  if [[ -f /etc/sysctl.d/99-cottendns.conf ]]; then
    rm -f /etc/sysctl.d/99-cottendns.conf
    sysctl --system >/dev/null 2>&1 || true
    log_success "Removed kernel tuning (/etc/sysctl.d/99-cottendns.conf)."
  fi
  if [[ -f /etc/sysctl.d/99-cottendns-tuning.conf ]]; then
    rm -f /etc/sysctl.d/99-cottendns-tuning.conf
    sysctl --system >/dev/null 2>&1 || true
    log_success "Removed supplementary kernel tuning (/etc/sysctl.d/99-cottendns-tuning.conf)."
  fi
  if [[ -f /etc/security/limits.d/99-cottendns.conf ]]; then
    rm -f /etc/security/limits.d/99-cottendns.conf
    log_success "Removed file descriptor limits (/etc/security/limits.d/99-cottendns.conf)."
  fi

  if [[ -f /etc/systemd/resolved.conf.bak && -f /etc/systemd/resolved.conf ]]; then
    log_info "Restoring original /etc/systemd/resolved.conf from backup..."
    mv -f /etc/systemd/resolved.conf.bak /etc/systemd/resolved.conf
    systemctl restart systemd-resolved 2>/dev/null || true
  fi

  log_header "Cleaning Install Directory"
  log_info "Install directory: $INSTALL_DIR"
  shopt -s nullglob
  local removed=0
  for f in \
    "$INSTALL_DIR"/CottenDns_Server_Linux* \
    "$INSTALL_DIR"/CottenDNS_Server_Linux* \
    "$INSTALL_DIR"/server_config.toml \
    "$INSTALL_DIR"/server_config.toml.backup \
    "$INSTALL_DIR"/server_config.toml.bak \
    "$INSTALL_DIR"/server_config_*.toml \
    "$INSTALL_DIR"/encrypt_key.txt \
    "$INSTALL_DIR"/init_logs.tmp \
    "$INSTALL_DIR"/*.spec; do
    if [[ -e "$f" ]]; then
      rm -f -- "$f"
      log_info "Removed: $f"
      removed=1
    fi
  done
  shopt -u nullglob
  if [[ $removed -eq 0 ]]; then
    log_warn "No CottenDns files found in $INSTALL_DIR. If you installed elsewhere, run the uninstaller from that directory."
  fi

  echo -e "\n${CYAN}======================================================${NC}"
  echo -e " ${GREEN}${BOLD}        COTTENDNS UNINSTALL COMPLETED${NC}"
  echo -e "${CYAN}======================================================${NC}"
  echo -e "${YELLOW}Note:${NC} Firewall rules for port 53 (UDP/TCP) were left in place."
  echo -e "      Remove them manually if no longer needed."
}

if [[ "$ACTION" == "uninstall" ]]; then
  do_uninstall
  exit 0
fi

if [[ -f "server_config.toml.backup" ]]; then
  mv -f server_config.toml.backup "server_config.toml.backup.$(date +%Y%m%d_%H%M%S)"
  log_warn "Moved a stale config backup aside before continuing."
fi

TMP_LOG="init_logs.tmp"
DOWNLOAD_DIR=""
cleanup() {
  rm -f "$TMP_LOG" 2>/dev/null || true
  if [[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]]; then
    rm -rf "$DOWNLOAD_DIR" 2>/dev/null || true
  fi
  if [[ "$ACTION" == "upgrade" && "${UPGRADE_COMPLETED:-false}" != true ]]; then
    if [[ -f "$INSTALL_DIR/server_config.toml.backup" ]]; then
      [[ -f "$INSTALL_DIR/server_config.toml" ]] && mv -f "$INSTALL_DIR/server_config.toml" "$INSTALL_DIR/server_config.toml.failed-upgrade"
      mv -f "$INSTALL_DIR/server_config.toml.backup" "$INSTALL_DIR/server_config.toml"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart cottendns >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
UPGRADE_COMPLETED=false

PM=""
if command -v apt-get >/dev/null 2>&1; then PM="apt";
elif command -v dnf >/dev/null 2>&1; then PM="dnf";
elif command -v yum >/dev/null 2>&1; then PM="yum";
else log_error "No supported package manager found (apt/dnf/yum)."; fi

log_header "Preparing Environment"
if [[ "$LOCAL_MODE" -eq 0 ]]; then
  log_info "Installing dependencies..."
  if [[ "$PM" == "apt" ]]; then
    apt-get update -y >/dev/null 2>&1
    apt-get install -y lsof net-tools wget unzip curl ca-certificates iproute2 procps irqbalance >/dev/null 2>&1
  elif [[ "$PM" == "dnf" ]]; then
    dnf -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng irqbalance >/dev/null 2>&1
  else
    yum -y install lsof net-tools wget unzip curl ca-certificates iproute procps-ng irqbalance >/dev/null 2>&1
  fi
else
  log_info "Local mode: skipping package installation."
fi
require_cmd ss
require_cmd systemctl
require_cmd sysctl
log_success "System tools are ready."

if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -qx 'irqbalance.service'; then
  log_info "Enabling irqbalance for better multi-core packet distribution..."
  systemctl enable --now irqbalance >/dev/null 2>&1 || log_warn "Could not enable/start irqbalance."
fi

check_port53() {
  ss -H -lun "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  ss -H -ltn "sport = :53" 2>/dev/null | grep -q ':53' && return 0
  return 1
}

show_port53_usage() {
  log_warn "Current listeners on port 53:"
  ss -lupn "sport = :53" 2>/dev/null || true
  ss -ltpn "sport = :53" 2>/dev/null || true
  lsof -nP -iUDP:53 -iTCP:53 2>/dev/null || true
}

get_port53_pids() {
  local pids_udp pids_tcp pids
  pids_udp="$(ss -H -lupn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids_tcp="$(ss -H -ltpn "sport = :53" 2>/dev/null | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | sort -u)"
  pids="$(printf '%s\n%s\n' "$pids_udp" "$pids_tcp" | sed '/^$/d' | sort -u)"
  if [[ -n "$pids" ]]; then
    echo "$pids"
    return 0
  fi
  lsof -ti :53 2>/dev/null || true
}

stop_service_if_present() {
  local unit="$1"
  if systemctl list-unit-files --type=service --all 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
    if systemctl is-active --quiet "$unit"; then
      log_info "Stopping conflicting service: $unit"
      systemctl stop "$unit" || true
    fi
    systemctl disable "$unit" >/dev/null 2>&1 || true
  fi
}

stop_socket_if_present() {
  local unit="$1"
  if systemctl list-unit-files --type=socket --all 2>/dev/null | awk '{print $1}' | grep -qx "$unit"; then
    if systemctl is-active --quiet "$unit"; then
      log_info "Stopping conflicting socket: $unit"
      systemctl stop "$unit" || true
    fi
    systemctl disable "$unit" >/dev/null 2>&1 || true
  fi
}

terminate_port53_pid() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  local cmdline
  cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
  log_warn "Trying to terminate PID on port 53: $pid (${cmdline:-unknown})"

  kill "$pid" 2>/dev/null || true
  for _ in 1 2 3; do
    sleep 1
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  done

  kill -9 "$pid" 2>/dev/null || true
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    log_warn "PID $pid is still alive after SIGKILL."
    return 1
  fi
  return 0
}

force_release_port53() {
  local stubborn=0
  local pid

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    terminate_port53_pid "$pid" || stubborn=1
  done <<< "$(get_port53_pids)"

  if command -v fuser >/dev/null 2>&1 && check_port53; then
    log_warn "Trying fuser fallback for port 53..."
    fuser -k 53/udp 2>/dev/null || true
    fuser -k 53/tcp 2>/dev/null || true
    sleep 1
  fi

  return "$stubborn"
}

remove_iptables_port53_redirects() {
  local tool="$1"
  command -v "$tool" >/dev/null 2>&1 || return 0

  local rule delete_rule
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    delete_rule="${rule/-A /-D }"
    log_warn "Removing ${tool} NAT redirect rule for port 53: $rule"
    # shellcheck disable=SC2086
    $tool -t nat $delete_rule >/dev/null 2>&1 || true
  done < <("$tool" -t nat -S 2>/dev/null | grep -E '(^-A )' | grep -E -- '(-p (tcp|udp)|-p (udp|tcp)).*--dport 53([^0-9]|$)' | grep -E 'REDIRECT|DNAT' || true)
}

remove_nft_port53_redirects() {
  command -v nft >/dev/null 2>&1 || return 0

  local rule
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    log_warn "Removing nftables redirect rule for port 53: $rule"
    nft delete rule $rule >/dev/null 2>&1 || true
  done < <(nft -a list ruleset 2>/dev/null | awk '
    / dport 53 / && ($0 ~ /redirect/ || $0 ~ /dnat/) {
      for (i = 1; i <= NF; i++) {
        if ($i == "table") table = $(i+1)
        if ($i == "chain") chain = $(i+1)
        if ($i == "handle") handle = $(i+1)
      }
      if (table != "" && chain != "" && handle != "") {
        print "ip " table " " chain " handle " handle
      }
      table = ""; chain = ""; handle = ""
    }
  ' || true)
}

remove_port53_forward_rules() {
  log_info "Checking for port 53 redirect/forward rules..."
  remove_iptables_port53_redirects iptables
  remove_iptables_port53_redirects ip6tables
  remove_nft_port53_redirects
}

stop_existing_CottenDns_service() {
  local unit_present=0
  if systemctl list-unit-files --all 2>/dev/null | grep -q '^cottendns\.service'; then
    unit_present=1
    log_info "Stopping existing CottenDns service..."
    systemctl stop cottendns 2>/dev/null || true

    for _ in 1 2 3 4 5; do
      if ! systemctl is-active --quiet cottendns; then
        break
      fi
      sleep 1
    done

    local main_pid
    main_pid="$(systemctl show cottendns --property MainPID --value 2>/dev/null || true)"
    if [[ -n "${main_pid:-}" && "$main_pid" != "0" ]] && kill -0 "$main_pid" 2>/dev/null; then
      log_warn "cottendns service is still active. Trying to terminate MainPID: $main_pid"
      terminate_port53_pid "$main_pid" || true
    fi

    systemctl stop cottendns 2>/dev/null || true
    systemctl reset-failed cottendns 2>/dev/null || true
  fi

  local pid cmdline killed=0
  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    cmdline="$(ps -p "$pid" -o cmd= 2>/dev/null || true)"
    if echo "$cmdline" | grep -qiE 'cottendns|CottenDns[_-]?[Ss]erver|CottenDNS[_-]?[Ss]erver'; then
      if [[ $killed -eq 0 && $unit_present -eq 0 ]]; then
        log_info "Stopping existing CottenDns process that was started outside systemd..."
      fi
      terminate_port53_pid "$pid" || true
      killed=1
    fi
  done <<< "$(get_port53_pids)"
}

log_header "Stopping Existing CottenDns"
cleanup_legacy_cottenpickdns
stop_existing_CottenDns_service

log_header "Managing Network Ports (Port 53)"
remove_port53_forward_rules

if check_port53; then
  log_warn "Port 53 is occupied. Trying auto-cleanup..."
  show_port53_usage

  if systemctl is-active --quiet systemd-resolved; then
    log_info "Configuring systemd-resolved DNSStubListener=no ..."
    backup_file_once /etc/systemd/resolved.conf
    if grep -q '^#\?DNSStubListener=' /etc/systemd/resolved.conf; then
      sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf || true
    else
      echo 'DNSStubListener=no' >> /etc/systemd/resolved.conf
    fi
    if ! grep -q '^DNS=' /etc/systemd/resolved.conf; then
      echo 'DNS=8.8.8.8' >> /etc/systemd/resolved.conf
    fi
    systemctl restart systemd-resolved || true
  fi

  stop_socket_if_present systemd-resolved.socket
  stop_socket_if_present dnsmasq.socket

  for srv in \
    bind9 bind9.service named named.service named-pkcs11 named-pkcs11.service \
    dnsmasq dnsmasq.service unbound unbound.service pdns pdns.service \
    knot-resolver kresd kresd@1.service dnscrypt-proxy dnscrypt-proxy.service \
    smartdns smartdns.service coredns coredns.service pihole-FTL pihole-FTL.service; do
    stop_service_if_present "$srv"
  done

  if check_port53; then
    log_warn "Port 53 is still busy after stopping known services. Trying direct process termination..."
    force_release_port53 || true
  fi

  if check_port53 && systemctl is-active --quiet systemd-resolved; then
    log_warn "Port 53 is still in use. Stopping systemd-resolved completely..."
    systemctl stop systemd-resolved || true
    systemctl disable systemd-resolved >/dev/null 2>&1 || true
    stop_socket_if_present systemd-resolved.socket
  fi

  if check_port53; then
    log_warn "Port 53 still occupied. Trying one more forced cleanup pass..."
    force_release_port53 || true
  fi

  if check_port53; then
    OCC_INFO="$(ss -H -lupn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
    [[ -z "${OCC_INFO:-}" ]] && OCC_INFO="$(ss -H -ltn 'sport = :53' 2>/dev/null | head -n1 | awk '{print $NF}' || true)"
    show_port53_usage
    log_error "Port 53 is still occupied: ${OCC_INFO:-unknown}. Stop it manually and retry."
  fi
fi
log_success "Port 53 is available."

log_header "Configuring Firewall (Port 53 UDP/TCP)"
ACTIVE_FIREWALL="none"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw active; then
  ACTIVE_FIREWALL="ufw"
  ufw allow 53/udp >/dev/null 2>&1 || true
  ufw allow 53/tcp >/dev/null 2>&1 || true
  log_success "Port 53 (UDP/TCP) opened via UFW."
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
  ACTIVE_FIREWALL="firewalld"
  firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port=53/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  log_success "Port 53 (UDP/TCP) opened via firewalld."
elif command -v iptables >/dev/null 2>&1; then
  ACTIVE_FIREWALL="iptables"
  iptables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j ACCEPT
  iptables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j ACCEPT
  if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -C INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport 53 -j ACCEPT
    ip6tables -C INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 53 -j ACCEPT
  fi
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6
  fi
  log_success "Port 53 (UDP/TCP) rule is ready via iptables."
elif command -v nft >/dev/null 2>&1; then
  ACTIVE_FIREWALL="nftables"
  if nft list table inet filter >/dev/null 2>&1; then
    nft add rule inet filter input udp dport 53 accept >/dev/null 2>&1 || true
    nft add rule inet filter input tcp dport 53 accept >/dev/null 2>&1 || true
    log_success "Port 53 (UDP/TCP) rule is ready via nftables."
  else
    log_warn "nftables is present but no 'inet filter' table was found. Open port 53 manually if needed."
  fi
else
  log_warn "No supported firewall tool detected. Skipping firewall setup."
fi
log_info "Detected firewall handling: ${ACTIVE_FIREWALL}"

log_header "Tuning Kernel & Limits"
cat > /etc/sysctl.d/99-cottendns.conf <<'EOF'
# CottenDns high-load tuning
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 25165824
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.udp_mem = 65536 131072 262144
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_udp_timeout = 15
net.netfilter.nf_conntrack_udp_timeout_stream = 60
net.ipv4.ip_local_port_range = 10240 65535
EOF
sysctl --system >/dev/null 2>&1 || log_warn "Could not fully apply sysctl settings."

cat > /etc/sysctl.d/99-cottendns-tuning.conf <<'EOF'
# CottenDns performance tuning (supplementary)
fs.file-max = 2097152
fs.nr_open = 2097152
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 65535
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.ip_local_port_range = 10240 65535
EOF
sysctl --system >/dev/null 2>&1 || log_warn "Some supplementary sysctl values may not have applied."

cat > /etc/security/limits.d/99-cottendns.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
log_success "Kernel and file descriptor limits configured."

if [[ "$LOCAL_MODE" -eq 1 ]]; then
  log_header "Locating Local Server Binary"
  ARCH="$(uname -m)"

  LOCAL_BIN="$(find_local_server_binary "$ARCH")"
  [[ -z "$LOCAL_BIN" ]] && log_error "No CottenDns server binary found. Run 'python build.py' first."
  log_info "Found binary: $LOCAL_BIN"

  LOCAL_BIN_DIR="$(dirname "$LOCAL_BIN")"
  if [[ "$LOCAL_BIN_DIR" != "$INSTALL_DIR" ]]; then
    cp "$LOCAL_BIN" "$INSTALL_DIR/"
    log_info "Copied binary to install directory."
  fi
  EXECUTABLE="$(basename "$LOCAL_BIN")"
  chmod +x "$INSTALL_DIR/$EXECUTABLE"
  log_success "Binary ready: $EXECUTABLE"

  if [[ -f "$INSTALL_DIR/server_config.toml" ]]; then
    mv -f "$INSTALL_DIR/server_config.toml" "$INSTALL_DIR/server_config.toml.backup"
    log_info "Existing config backed up."
  fi

  LOCAL_CONFIG="$(find_local_config)"
  if [[ -n "$LOCAL_CONFIG" && "$LOCAL_CONFIG" != "$INSTALL_DIR/server_config.toml" ]]; then
    cp "$LOCAL_CONFIG" "$INSTALL_DIR/server_config.toml"
    log_info "Config copied from: $LOCAL_CONFIG"
  elif [[ ! -f "$INSTALL_DIR/server_config.toml" ]]; then
    log_error "No server_config.toml or server_config.toml.simple found. Cannot install."
  fi
else
  if [[ -n "$TARGET_VERSION" ]]; then
    log_header "Fetching Release ${TARGET_VERSION}"
  else
    log_header "Fetching Latest Release"
  fi
  ARCH="$(uname -m)"
  select_release_artifact "$ARCH" "$TARGET_VERSION"

  if [[ -f "server_config.toml" ]]; then
    mv -f server_config.toml server_config.toml.backup
    log_info "Existing config backed up."
  fi

  log_info "Downloading server binaries..."
  require_cmd curl
  require_cmd unzip
  if ! DOWNLOAD_DIR="$(mktemp -d /tmp/CottenDns_download.XXXXXX 2>/dev/null)"; then
    DOWNLOAD_DIR="$(mktemp -d "$INSTALL_DIR/CottenDns_download.XXXXXX" 2>/dev/null || true)"
  fi
  [[ -n "${DOWNLOAD_DIR:-}" && -d "${DOWNLOAD_DIR:-}" ]] || log_error "Failed to create temporary download directory. Check free space and /tmp permissions."
  ZIP_PATH="${DOWNLOAD_DIR}/server.zip"

  if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$ZIP_PATH" "$URL"; then
    log_warn "curl download failed, trying wget..."
    wget -qO "$ZIP_PATH" "$URL" || {
      log_warn "Disk usage snapshot:"
      df -h "$INSTALL_DIR" /tmp 2>/dev/null || true
      log_error "Download failed."
    }
  fi

  [[ -s "$ZIP_PATH" ]] || log_error "Downloaded archive is missing or empty: $ZIP_PATH"
  unzip -q -o "$ZIP_PATH" -d "$INSTALL_DIR" || log_error "Failed to extract archive."
  log_success "Files extracted."

  EXECUTABLE="$(ls -t ${PREFIX}_v* 2>/dev/null | head -n1 || true)"
  [[ -z "$EXECUTABLE" ]] && log_error "Binary not found in package."
  chmod +x "$EXECUTABLE"
fi

[[ -x "$EXECUTABLE" ]] || log_error "Downloaded server binary is not executable: $EXECUTABLE"
./"$EXECUTABLE" --version >/dev/null 2>&1 || log_error "Downloaded server binary failed its version check. Existing service was not changed."

log_header "Configuration"
[[ -f "server_config.toml" ]] || log_error "server_config.toml not found."
restore_existing_config "$INSTALL_DIR"

if [[ -f "server_config.toml" ]] && grep -q '"v.domain.com"' server_config.toml; then
  echo -e "${YELLOW}${BOLD}Attention:${NC} Set your NS domain."
  read -r -p ">>> Enter your Domain (e.g. vpn.example.com): " USER_DOMAIN </dev/tty || true
  if [[ -n "${USER_DOMAIN:-}" ]]; then
    sed -i -E "s|^DOMAIN[[:space:]]*=.*$|DOMAIN = [\"${USER_DOMAIN}\"]|" server_config.toml
  fi
fi

log_header "Security Initialization"
log_info "Starting server once to generate encryption key..."
./"$EXECUTABLE" > "$TMP_LOG" 2>&1 &
APP_PID=$!
READY=false
for _ in {1..10}; do
  if grep -q "Active Encryption Key" "$TMP_LOG" 2>/dev/null; then
    READY=true
    break
  fi
  sleep 1
done
kill "$APP_PID" 2>/dev/null || true
wait "$APP_PID" 2>/dev/null || true

if [[ "$READY" != true ]]; then
  log_warn "Initialization log tail:"
  tail -n 20 "$TMP_LOG" || true
  log_error "Could not verify key generation. Ensure Port 53 is free."
fi

echo -e "${GREEN}${BOLD}------------------------------------------------------"
echo -e "  YOUR ENCRYPTION KEY: ${NC}${CYAN}$(cat encrypt_key.txt 2>/dev/null)${NC}"
echo -e "${GREEN}${BOLD}------------------------------------------------------${NC}"

log_header "Removing Legacy TCP/53 Egress Block"
# Older installers blocked every outbound TCP DNS request. That also blocked
# standards-compliant TCP fallback when an upstream UDP response was truncated.
systemctl disable --now cottendns-egress-filter.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/cottendns-egress-filter.service /usr/local/sbin/cottendns-egress-filter.sh
for firewall_tool in iptables ip6tables; do
  if command -v "$firewall_tool" >/dev/null 2>&1; then
    while "$firewall_tool" -C OUTPUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null; do
      "$firewall_tool" -D OUTPUT -p tcp --dport 53 -j REJECT --reject-with tcp-reset || break
    done
  fi
done
log_success "Outbound TCP DNS is available for upstream fallback."

log_header "Installing System Service"
SVC="/etc/systemd/system/cottendns.service"
SVC_BACKUP=""
SVC_WAS_CREATED=false
if [[ "$ACTION" == "upgrade" && -f "$SVC" ]]; then
  SVC_BACKUP="${SVC}.upgrade-backup"
  cp -a "$SVC" "$SVC_BACKUP"
elif [[ "$ACTION" == "upgrade" ]]; then
  SVC_WAS_CREATED=true
fi
cat > "$SVC" <<EOF
[Unit]
Description=CottenDns Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$EXECUTABLE -config $INSTALL_DIR/server_config.toml -metrics-address 127.0.0.1:9090
Restart=always
RestartSec=3
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

rm -rf /etc/systemd/system/cottendns.service.d
systemctl daemon-reload

systemctl enable cottendns >/dev/null 2>&1
systemctl restart cottendns

HEALTHY=false
for _ in {1..30}; do
  if systemctl is-active --quiet cottendns && curl -fsS --max-time 2 http://127.0.0.1:9090/healthz >/dev/null 2>&1; then
    HEALTHY=true
    break
  fi
  sleep 1
done

if [[ "$HEALTHY" != true ]]; then
  journalctl -u cottendns -n 50 --no-pager || true
  if [[ -n "$SVC_BACKUP" && -f "$SVC_BACKUP" ]]; then
    log_warn "New service failed its health check; restoring the previous service unit."
    mv -f "$SVC_BACKUP" "$SVC"
    systemctl daemon-reload
    systemctl restart cottendns || true
  elif [[ "$SVC_WAS_CREATED" == true ]]; then
    log_warn "Removing the failed override unit and returning to the previous packaged unit."
    rm -f "$SVC"
    systemctl daemon-reload
    systemctl restart cottendns || true
  fi
  log_error "Service failed to become healthy. The previous unit was restored when available."
fi
rm -f "$SVC_BACKUP" 2>/dev/null || true

log_success "CottenDns service is running and healthy."
UPGRADE_COMPLETED=true

log_info "Cleaning up old server binaries..."
shopt -s nullglob
for old_bin in "$INSTALL_DIR"/CottenDns_Server_Linux* "$INSTALL_DIR"/CottenDNS_Server_Linux*; do
  [[ "$(basename "$old_bin")" == "$EXECUTABLE" ]] && continue
  rm -f -- "$old_bin"
  log_info "Removed old binary: $(basename "$old_bin")"
done
shopt -u nullglob

echo -e "\n${CYAN}======================================================${NC}"
echo -e " ${GREEN}${BOLD}       INSTALLATION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "${BOLD}Commands:${NC}"
echo -e "  ${YELLOW}>${NC} Start:   systemctl start cottendns"
echo -e "  ${YELLOW}>${NC} Stop:    systemctl stop cottendns"
echo -e "  ${YELLOW}>${NC} Restart: systemctl restart cottendns"
echo -e "  ${YELLOW}>${NC} Logs:    journalctl -u cottendns -f"
echo -e "  ${YELLOW}>${NC} Health:  curl http://127.0.0.1:9090/healthz"
echo -e "  ${YELLOW}>${NC} Upgrade: bash <(curl -Ls https://raw.githubusercontent.com/TaJirax/CottenDns/main/server_linux_install.sh) --upgrade"
echo -e "\n${BOLD}Files:${NC}"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/server_config.toml"
echo -e "  ${YELLOW}>${NC} ${INSTALL_DIR}/encrypt_key.txt"
echo -e "${YELLOW}Final Note:${NC} If config changes, run: systemctl restart cottendns"

rm -f *.spec >/dev/null 2>&1 || true
