#!/usr/bin/env sh
set -eu

repo="TaJirax/cottenDNS"
install_dir="${COTTENDNS_DOCKER_DIR:-/opt/cottendns-docker}"
domain="${COTTENDNS_DOMAIN:-}"
upgrade=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --upgrade) upgrade=true ;;
        --domain) shift; domain="${1:-}" ;;
        --install-dir) shift; install_dir="${1:-}" ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (for example with sudo)." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "Docker Engine with the Compose plugin is required." >&2
    exit 1
fi

mkdir -p "$install_dir/data"
compose_url="https://raw.githubusercontent.com/${repo}/main/compose.yaml"
tmp_file="${install_dir}/compose.yaml.new"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$compose_url" -o "$tmp_file"
else
    wget -qO "$tmp_file" "$compose_url"
fi
mv "$tmp_file" "$install_dir/compose.yaml"

env_file="${install_dir}/.env"
if [ ! -f "$env_file" ]; then
    if [ -z "$domain" ]; then
        echo "First install requires --domain vpn.example.com" >&2
        exit 2
    fi
    printf 'COTTENDNS_DOMAIN=%s\nCOTTENDNS_IMAGE_TAG=latest\n' "$domain" > "$env_file"
elif [ -n "$domain" ]; then
    if grep -q '^COTTENDNS_DOMAIN=' "$env_file"; then
        sed -i "s|^COTTENDNS_DOMAIN=.*|COTTENDNS_DOMAIN=${domain}|" "$env_file"
    else
        printf 'COTTENDNS_DOMAIN=%s\n' "$domain" >> "$env_file"
    fi
fi

cd "$install_dir"
docker compose pull
docker compose up -d --remove-orphans

attempt=0
while [ "$attempt" -lt 30 ]; do
    if docker inspect --format '{{.State.Health.Status}}' cottendns-server 2>/dev/null | grep -q '^healthy$'; then
        echo "CottenDNS is healthy. Upgrade command:"
        echo "curl -fsSL https://raw.githubusercontent.com/${repo}/main/server_docker_install.sh | sudo sh -s -- --upgrade"
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done

echo "CottenDNS did not become healthy; showing recent logs." >&2
docker compose logs --tail=100 server >&2
exit 1
