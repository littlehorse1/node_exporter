#!/usr/bin/env bash
set -euo pipefail

# One-click: update repo and build binaries.
#
# Outputs:
# - out/node_exporter_linux_amd64  (NVML enabled, requires CGO/gcc, build tag: nvml)
# - out/node_exporter_linux_arm64  (NVML disabled, pure Go, CGO off)
#
# Usage:
#   ./pull_and_build.sh
#   OUT_DIR=/path/to/out ./pull_and_build.sh
#
# Notes:
# - Run this on a Linux amd64 build machine (recommended).
# - The amd64 NVML build requires a working C toolchain (gcc).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"

cd "${ROOT_DIR}"

if ! command -v git >/dev/null 2>&1; then
  echo "[ERROR] git not found"
  exit 1
fi
if ! command -v go >/dev/null 2>&1; then
  echo "[ERROR] go not found"
  exit 1
fi

echo "==> repo update (git pull --rebase)"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  echo "[ERROR] not a git repository: ${ROOT_DIR}"
  exit 1
}
git fetch --all --prune
git pull --rebase

mkdir -p "${OUT_DIR}"

echo "==> build linux/amd64 (NVML enabled: -tags nvml, CGO on)"
if ! command -v gcc >/dev/null 2>&1; then
  echo "[ERROR] gcc not found; required for NVML build (CGO_ENABLED=1)"
  echo "        Install gcc and retry (e.g. Ubuntu: apt-get install -y gcc)."
  exit 1
fi
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  go build -tags nvml -o "${OUT_DIR}/node_exporter_linux_amd64" .

echo "==> build linux/arm64 (NVML disabled, CGO off)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o "${OUT_DIR}/node_exporter_linux_arm64" .

echo "==> outputs"
ls -lh "${OUT_DIR}/node_exporter_linux_amd64" "${OUT_DIR}/node_exporter_linux_arm64" 2>/dev/null || true

