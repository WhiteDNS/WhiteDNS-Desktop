#!/usr/bin/env bash
# Capture once while healthy and again WHILE SLOW, before restarting anything.
# Reads host/process counters; creates one private evidence directory. Requires
# Bash 4.4+. Root improves /proc, socket and service visibility; it is optional.
# Does not read configs, argv, environment variables, credentials or journals.
set -u
umask 077
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4))); then
  printf 'This collector requires Bash 4.4 or newer.\n' >&2
  exit 2
fi

usage() {
  printf '%s\n' 'Usage: bash collect-slowdown.sh [options] [output-dir] [Cotten HTTP base] [Router HTTP base]
  --samples N        Samples, 1..120 (default 3)
  --interval N       Seconds between samples, 0..3600 (default 30)
  --service NAME     Additional systemd service (repeatable)
  --pid PID          Additional host process, including a manual client (repeatable)
  --container NAME   Docker container on the local socket (repeatable; read-only)
  --help             Show usage

The output directory must not exist; its parent must exist. Default is /tmp.
HTTP bases must be http://127.0.0.1:PORT, http://localhost:PORT or
http://[::1]:PORT, optionally with a path prefix. localhost is pinned to IPv4.
No cookies, tokens, redirects, proxy settings or curl configuration are used.
Panel /api/diagnostics requires authentication: save its JSON separately in
your signed-in browser while healthy and slow. This helper never acquires credentials.
Default sampling includes 60 seconds of waiting, plus collection/HTTP time.
Missing tools and inaccessible processes are recorded; no services are changed.'
}

audit_samples=3
audit_interval=30
audit_positions=()
audit_extra_services=()
audit_pids=()
audit_containers=()
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --samples|--interval|--service|--pid|--container)
      audit_option=$1
      (($# >= 2)) || { printf 'Missing value for %s\n' "$1" >&2; exit 2; }
      case "$audit_option" in
        --samples) audit_samples=$2 ;;
        --interval) audit_interval=$2 ;;
        --service) audit_extra_services+=("$2") ;;
        --pid) audit_pids+=("$2") ;;
        --container) audit_containers+=("$2") ;;
      esac
      shift 2 ;;
    --) shift; audit_positions+=("$@"); break ;;
    -*) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    *) audit_positions+=("$1"); shift ;;
  esac
done
if ((${#audit_positions[@]} > 3)) || [[ ! "$audit_samples" =~ ^[1-9][0-9]{0,2}$ ]] || ((audit_samples > 120)) || [[ ! "$audit_interval" =~ ^(0|[1-9][0-9]{0,3})$ ]] || ((audit_interval > 3600)); then
  printf 'Invalid argument count, sample count or interval. Use --help.\n' >&2
  exit 2
fi
for audit_pid in "${audit_pids[@]}"; do
  [[ "$audit_pid" =~ ^[1-9][0-9]{0,9}$ ]] || { printf 'Invalid PID.\n' >&2; exit 2; }
done
for audit_service in "${audit_extra_services[@]}"; do
  [[ "$audit_service" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$ ]] || { printf 'Invalid service name.\n' >&2; exit 2; }
done
for audit_container in "${audit_containers[@]}"; do
  [[ "$audit_container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { printf 'Invalid container name/ID.\n' >&2; exit 2; }
done
audit_cotten_url=${audit_positions[1]:-}
audit_router_url=${audit_positions[2]:-}
audit_url_pattern='^http://(127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?$'
for audit_url in "$audit_cotten_url" "$audit_router_url"; do
  [[ -z "$audit_url" ]] && continue
  if [[ ! "$audit_url" =~ $audit_url_pattern ]] || ((10#${BASH_REMATCH[2]:-0} < 1 || 10#${BASH_REMATCH[2]:-0} > 65535)); then
    printf 'HTTP bases require a loopback host and numeric port, without credentials/query/fragment.\n' >&2
    exit 2
  fi
done

timestamp() { TZ=UTC printf '%(%Y-%m-%dT%H:%M:%SZ)T' -1; }
audit_output=${audit_positions[0]:-"/tmp/cottendns-slowdown-$(TZ=UTC printf '%(%Y%m%dT%H%M%SZ)T' -1)-$$"}
if [[ -e "$audit_output" || -L "$audit_output" ]]; then
  printf 'Output already exists: %s\n' "$audit_output" >&2
  exit 2
fi
# Atomic creation also refuses a directory/symlink created after the check.
mkdir -m 700 -- "$audit_output" || exit 1
audit_started=$SECONDS
audit_completed=0
finish() {
  local audit_status=$?
  { printf 'finished_utc='; timestamp; printf '\nactual_duration_seconds=%s\nsamples_completed=%s\nexit_code=%s\n' "$((SECONDS-audit_started))" "$audit_completed" "$audit_status"; } >> "$audit_output/metadata.txt"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run() {
  local audit_tool=$1
  if ! command -v "$audit_tool" >/dev/null 2>&1; then printf 'UNAVAILABLE tool=%s\n' "$audit_tool"; return 127; fi
  if command -v timeout >/dev/null 2>&1; then timeout 5s "$@"; else "$@"; fi
}
{
  printf 'collector_format=1\nstarted_utc='; timestamp
  printf '\neuid=%s\nsamples_requested=%s\ninterval_seconds=%s\nminimum_wait_seconds=%s\n' "$EUID" "$audit_samples" "$audit_interval" "$(((audit_samples-1)*audit_interval))"
  printf 'scope=host counters; service/process resource counters; optional local Docker and loopback HTTP\n'
  printf 'root_visibility=non-root runs may miss other users socket owners, /proc files and Docker access\n'
  printf 'panel_diagnostics=save /api/diagnostics JSON separately in a signed-in browser; no credentials collected\n'
  printf 'sampling=collection time is additional; process/service snapshots are not atomic\n'
  for audit_tool in timeout systemctl ps ss free df uptime uname cat awk sha256sum curl docker sleep; do
    if command -v "$audit_tool" >/dev/null 2>&1; then printf 'tool_%s=available\n' "$audit_tool"; else printf 'tool_%s=missing\n' "$audit_tool"; fi
  done
  command -v timeout >/dev/null 2>&1 || printf 'command_timeout=unavailable; HTTP remains bounded but other available tools may take longer\n'
} > "$audit_output/metadata.txt"
{
  timestamp; printf '\n'
  run uname -srm
  run uptime
  run free -m
  run df -h / /var /tmp
} > "$audit_output/host.txt" 2>&1

declare -A audit_services=()
for audit_service in cottendns cottendns-client cottenrouter soar-panel whitedns-panel "${audit_extra_services[@]}"; do
  [[ "$audit_service" == *.service ]] || audit_service+=.service
  audit_services["$audit_service"]=1
done
audit_discovery=$(run systemctl list-units --all --type=service --no-legend --plain --no-pager 2>&1)
while read -r audit_service _; do
  case "$audit_service" in
    cottendns*.service|cottenrouter*.service|soar-panel*.service|whitedns-panel*.service)
      [[ "$audit_service" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$ ]] && audit_services["$audit_service"]=1 ;;
  esac
done <<< "$audit_discovery"
printf '%s\n' "${!audit_services[@]}" > "$audit_output/services.txt"

process_sample() {
  local audit_pid=$1
  [[ "$audit_pid" =~ ^[1-9][0-9]{0,9}$ ]] || return 0
  [[ -z "${audit_seen_pids[$audit_pid]:-}" ]] || return 0
  audit_seen_pids["$audit_pid"]=1
  printf '\nPROCESS pid=%s\n' "$audit_pid"
  if [[ ! -d "/proc/$audit_pid" ]]; then printf 'UNAVAILABLE process exited or /proc inaccessible\n'; return 0; fi
  run ps -p "$audit_pid" -o pid,ppid,etime,time,pcpu,pmem,rss,vsz,nlwp,comm
  run awk '/^(VmPeak|VmSize|VmRSS|RssAnon|RssFile|VmSwap|Threads|FDSize|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):/' "/proc/$audit_pid/status"
  run cat "/proc/$audit_pid/io" "/proc/$audit_pid/limits" "/proc/$audit_pid/schedstat"
  if [[ -r "/proc/$audit_pid/fd" && -x "/proc/$audit_pid/fd" ]]; then
    local audit_fds=(/proc/"$audit_pid"/fd/*)
    printf 'open_fds=%s\n' "${#audit_fds[@]}"
  else printf 'open_fds=unavailable\n'; fi
  local audit_line audit_state audit_udp=0
  local -A audit_states=()
  if ((audit_tcp_ok)); then
    while IFS= read -r audit_line; do
      [[ "$audit_line" == *"pid=$audit_pid,"* ]] || continue
      read -r audit_state _ <<< "$audit_line"
      audit_states["$audit_state"]=$(( ${audit_states[$audit_state]:-0} + 1 ))
    done <<< "$audit_tcp_snapshot"
    for audit_state in "${!audit_states[@]}"; do printf 'tcp_state_%s=%s\n' "$audit_state" "${audit_states[$audit_state]}"; done
  else printf 'tcp_states=unavailable\n'; fi
  if ((audit_udp_ok)); then
    while IFS= read -r audit_line; do [[ "$audit_line" == *"pid=$audit_pid,"* ]] && ((audit_udp+=1)); done <<< "$audit_udp_snapshot"
    printf 'udp_sockets=%s\n' "$audit_udp"
  else printf 'udp_sockets=unavailable\n'; fi
  if ((audit_sample == 1)); then run sha256sum "/proc/$audit_pid/exe"; fi
}

http_sample() {
  local audit_base=$1 audit_suffix=$2 audit_name=$3
  [[ -n "$audit_base" ]] || return 0
  local audit_resolve=()
  if [[ "$audit_base" =~ ^http://localhost:([0-9]+) ]]; then audit_resolve=(--resolve "localhost:${BASH_REMATCH[1]}:127.0.0.1"); fi
  # --disable must be first: never load a user's curlrc/auth/redirect options.
  run curl --disable --noproxy '*' --proto '=http' --max-time 3 --connect-timeout 2 --max-filesize 4194304 --max-redirs 0 --fail --silent --show-error "${audit_resolve[@]}" "${audit_base%/}$audit_suffix" > "$audit_output/$audit_name-$audit_sample.txt" 2> "$audit_output/$audit_name-$audit_sample.err"
}

shopt -s nullglob
for ((audit_sample=1; audit_sample<=audit_samples; audit_sample++)); do
  audit_tcp_ok=0; audit_udp_ok=0
  audit_tcp_snapshot=$(run ss -Htanp 2>&1) && audit_tcp_ok=1
  audit_udp_snapshot=$(run ss -Huanp 2>&1) && audit_udp_ok=1
  declare -A audit_seen_pids=()
  {
    printf 'sample=%s started_utc=' "$audit_sample"; timestamp; printf '\n'
    run cat /proc/uptime /proc/loadavg
    run awk '/^(cpu|ctxt|processes|procs_running|procs_blocked)/' /proc/stat
    run free -m
    run ss -s
    run cat /proc/net/snmp /proc/net/netstat /proc/net/sockstat /proc/net/sockstat6 /proc/net/dev /proc/net/softnet_stat
    run cat /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io
    run awk '/^(pswpin|pswpout|pgmajfault|oom_kill|allocstall|pgscan|pgsteal)/' /proc/vmstat
    for audit_sysctl in nf_conntrack_count nf_conntrack_max; do
      audit_path="/proc/sys/net/netfilter/$audit_sysctl"
      if [[ -r "$audit_path" ]]; then printf '%s=' "$audit_sysctl"; run cat "$audit_path"; fi
    done
    for audit_service in "${!audit_services[@]}"; do
      printf '\nSERVICE %s\n' "$audit_service"
      run systemctl show "$audit_service" --property=LoadState,ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,MemoryCurrent,TasksCurrent,CPUUsageNSec,LimitNOFILE
      audit_pid=$(run systemctl show "$audit_service" --property=MainPID --value 2>/dev/null)
      process_sample "$audit_pid"
    done
    for audit_pid in "${audit_pids[@]}"; do process_sample "$audit_pid"; done
    for audit_container in "${audit_containers[@]}"; do
      printf '\nDOCKER container=%s (local Unix socket only)\n' "$audit_container"
      if ! command -v timeout >/dev/null 2>&1; then printf 'UNAVAILABLE Docker collection requires timeout\n'; continue; fi
      run docker --host unix:///var/run/docker.sock inspect --type container --format '{{.Id}} {{.State.Pid}} {{.State.Status}} {{.RestartCount}} {{.State.StartedAt}} {{.Image}} {{.HostConfig.Memory}} {{.HostConfig.NanoCpus}} {{.HostConfig.PidsLimit}}' "$audit_container"
      run docker --host unix:///var/run/docker.sock stats --no-stream --no-trunc --format '{{.ID}} {{.CPUPerc}} {{.MemUsage}} {{.MemPerc}} {{.NetIO}} {{.BlockIO}} {{.PIDs}}' "$audit_container"
      audit_container_pids=$(run docker --host unix:///var/run/docker.sock top "$audit_container" -eo pid 2>&1)
      audit_container_count=0
      while read -r audit_pid _; do
        [[ "$audit_pid" =~ ^[1-9][0-9]{0,9}$ ]] || continue
        ((audit_container_count+=1))
        if ((audit_container_count > 64)); then printf 'container_process_limit=64; use --pid for additional processes\n'; break; fi
        process_sample "$audit_pid"
      done <<< "$audit_container_pids"
    done
    printf '\nsample_finished_utc='; timestamp; printf '\n'
  } > "$audit_output/sample-$audit_sample.txt" 2>&1
  http_sample "$audit_cotten_url" /metrics cotten-metrics
  http_sample "$audit_cotten_url" /healthz cotten-health
  http_sample "$audit_router_url" /v1/status router-status
  audit_completed=$audit_sample
  if ((audit_sample < audit_samples && audit_interval > 0)); then
    if command -v sleep >/dev/null 2>&1; then sleep "$audit_interval"; else printf 'UNAVAILABLE tool=sleep; samples are consecutive\n' >> "$audit_output/metadata.txt"; fi
  fi
done
printf 'Diagnostics saved to %s\n' "$audit_output"
