#!/usr/bin/env bash
# Install the same build dependencies on both CI architectures. If the hosted
# x64 runner's Azure mirror stalls, retry using Ubuntu's official archive.
set -euo pipefail

arch="${1:?Expected the Linux architecture}"
apt_root="${2:-/etc/apt}"
if [[ "$arch" != amd64 && "$arch" != arm64 ]]; then
  echo "Unsupported Linux CI architecture: $arch" >&2
  exit 1
fi

packages=(build-essential curl file libarchive-tools pkg-config rpm zstd libgtk-3-dev libwebkit2gtk-4.1-dev)

phase() {
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2
}

apt_update() {
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 update
}

apt_install() {
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install --no-install-recommends -y "${packages[@]}"
}

if [[ "$arch" == amd64 ]]; then
  phase 'Trying the default Ubuntu mirror (three minutes per apt phase).'
  if sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 update && \
     sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install --no-install-recommends -y "${packages[@]}"; then
    exit 0
  fi

  phase 'Initial package setup failed or timed out; switching Azure mirror entries to archive.ubuntu.com.'
  # Ubuntu hosted runners may select mirrors through this separate mirror list.
  for sources in "$apt_root/apt-mirrors.txt" "$apt_root/sources.list" "$apt_root"/sources.list.d/*.sources "$apt_root"/sources.list.d/*.list; do
    [[ -f "$sources" ]] || continue
    sudo sed -i -E 's@(https?://)azure\.archive\.ubuntu\.com/ubuntu@\1archive.ubuntu.com/ubuntu@g' "$sources"
  done
  # An interrupted installation may have left packages awaiting configuration.
  phase 'Repairing any interrupted package configuration.'
  sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
  fallback_opts=(-o Acquire::Retries=2 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30)
  phase 'Updating package indexes from the fallback mirror.'
  sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive apt-get "${fallback_opts[@]}" update
  phase 'Installing build dependencies from the fallback mirror.'
  sudo timeout --kill-after=15s 600s env DEBIAN_FRONTEND=noninteractive apt-get "${fallback_opts[@]}" install --no-install-recommends -y "${packages[@]}"
  exit 0
fi

phase 'Installing ARM build dependencies using the existing mirror settings.'
apt_update
apt_install
