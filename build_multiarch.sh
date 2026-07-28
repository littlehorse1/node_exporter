#!/usr/bin/env bash
set -euo pipefail

# Build linux/amd64 and linux/arm64 binaries.
#
# Default:
# - amd64: without NVML (pure Go, CGO off)
# - arm64: without NVML (pure Go, CGO off)
#
# Optional:
# - set WITH_NVML_AMD64=1 to build amd64 with NVML (requires CGO and a native Linux amd64 build host)
#
# Outputs are written to ./out

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/out}"
WITH_NVML_AMD64="${WITH_NVML_AMD64:-0}"

mkdir -p "${OUT_DIR}"

echo "==> building linux/arm64 (NVML disabled)"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -o "${OUT_DIR}/node_exporter_linux_arm64" .

if [[ "${WITH_NVML_AMD64}" == "1" ]]; then
  echo "==> building linux/amd64 (NVML enabled: -tags nvml, CGO on)"
  CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -tags nvml -o "${OUT_DIR}/node_exporter_linux_amd64" .
else
  echo "==> building linux/amd64 (NVML disabled)"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o "${OUT_DIR}/node_exporter_linux_amd64" .
fi

echo "==> done"
ls -lh "${OUT_DIR}"/node_exporter_linux_* 2>/dev/null || true

