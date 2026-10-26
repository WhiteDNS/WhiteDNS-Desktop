#!/usr/bin/env bash
# Install the same build dependencies on both CI architectures. If the hosted
# x64 runner's Azure mirror stalls, retry using Ubuntu's official archive.
set -euo pipefail

arch="${1:?Expected the Linux architecture}"
if [[ "$arch" != amd64 && "$arch" != arm64 ]]; then
  echo "Unsupported Linux CI architecture: $arch" >&2
  exit 1
fi

packages=(build-essential curl file libarchive-tools pkg-config rpm zstd libgtk-3-dev libwebkit2gtk-4.1-dev)

apt_update() {
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 update
}

apt_install() {
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install --no-install-recommends -y "${packages[@]}"
}

if [[ "$arch" == amd64 ]]; then
  if sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 update && \
     sudo timeout --kill-after=15s 180s env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install --no-install-recommends -y "${packages[@]}"; then
    exit 0
  fi

  echo 'Initial Ubuntu package setup failed or timed out; retrying with archive.ubuntu.com.' >&2
  for sources in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
    [[ -f "$sources" ]] || continue
    sudo sed -i 's|http://azure.archive.ubuntu.com/ubuntu|http://archive.ubuntu.com/ubuntu|g' "$sources"
  done
  # An interrupted installation may have left packages awaiting configuration.
  sudo env DEBIAN_FRONTEND=noninteractive dpkg --configure -a
fi

apt_update
apt_install
