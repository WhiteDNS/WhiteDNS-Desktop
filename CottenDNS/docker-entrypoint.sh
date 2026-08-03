#!/bin/sh
set -eu

config_path="${COTTENDNS_CONFIG:-/data/server_config.toml}"
chown -R cottendns:cottendns /data
if [ ! -f "$config_path" ]; then
    cp /opt/cottendns/server_config.toml.simple "$config_path"
	chown cottendns:cottendns "$config_path"
fi

if [ -n "${COTTENDNS_DOMAIN:-}" ]; then
    escaped_domain=$(printf '%s' "$COTTENDNS_DOMAIN" | sed 's/[\\&|]/\\&/g')
    sed -i "s|^DOMAIN = .*|DOMAIN = [\"${escaped_domain}\"]|" "$config_path"
fi

if grep -q 'DOMAIN = \["v.domain.com"\]' "$config_path"; then
    echo "COTTENDNS_DOMAIN must be set for the first start, or edit $config_path" >&2
    exit 2
fi

exec su-exec cottendns:cottendns /usr/local/bin/cottendns-server \
    -config "$config_path" \
    -metrics-address "${COTTENDNS_METRICS_ADDRESS:-0.0.0.0:9090}" \
    "$@"
