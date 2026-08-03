#!/usr/bin/env bash
set -euo pipefail

# Build from the engine module root regardless of the caller's working
# directory. CI invokes this script by path from the Android workspace root, so
# `go build ./cmd/client` must not depend on the caller having cd'd here first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${MODULE_ROOT}"

: "${NDK_ROOT:?Set NDK_ROOT to the installed Android NDK directory}"

ANDROID_API="${ANDROID_API:-26}"
NDK_HOST="${NDK_HOST:-linux-x86_64}"
OUTPUT_DIR="${OUTPUT_DIR:-dist/android}"
GO_BIN="${GO_BIN:-go}"
TOOLCHAIN="${NDK_ROOT}/toolchains/llvm/prebuilt/${NDK_HOST}/bin"
LDFLAGS='-s -w -linkmode external -extldflags "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"'

build_abi() {
  local abi="$1"
  local goarch="$2"
  local compiler="$3"
  local goarm="${4:-}"
  local output="${OUTPUT_DIR}/${abi}/libcottendns_client.so"

  mkdir -p "$(dirname "${output}")"
  if [[ ! -x "${TOOLCHAIN}/${compiler}" ]]; then
    echo "Android compiler not found: ${TOOLCHAIN}/${compiler}" >&2
    exit 1
  fi
  if [[ -n "${goarm}" ]]; then
    CGO_ENABLED=1 GOOS=android GOARCH="${goarch}" GOARM="${goarm}" \
      CC="${TOOLCHAIN}/${compiler}" \
      "${GO_BIN}" build -trimpath -ldflags="${LDFLAGS}" -o "${output}" ./cmd/client
  else
    CGO_ENABLED=1 GOOS=android GOARCH="${goarch}" \
      CC="${TOOLCHAIN}/${compiler}" \
      "${GO_BIN}" build -trimpath -ldflags="${LDFLAGS}" -o "${output}" ./cmd/client
  fi
  chmod 755 "${output}"
  echo "Built ${output}"
}

requested="${1:-all}"
case "${requested}" in
  arm64-v8a) build_abi arm64-v8a arm64 "aarch64-linux-android${ANDROID_API}-clang" ;;
  armeabi-v7a) build_abi armeabi-v7a arm "armv7a-linux-androideabi${ANDROID_API}-clang" 7 ;;
  x86_64) build_abi x86_64 amd64 "x86_64-linux-android${ANDROID_API}-clang" ;;
  x86) build_abi x86 386 "i686-linux-android${ANDROID_API}-clang" ;;
  all)
    build_abi arm64-v8a arm64 "aarch64-linux-android${ANDROID_API}-clang"
    build_abi armeabi-v7a arm "armv7a-linux-androideabi${ANDROID_API}-clang" 7
    build_abi x86_64 amd64 "x86_64-linux-android${ANDROID_API}-clang"
    build_abi x86 386 "i686-linux-android${ANDROID_API}-clang"
    ;;
  *)
    echo "Usage: $0 [all|arm64-v8a|armeabi-v7a|x86_64|x86]" >&2
    exit 2
    ;;
esac
