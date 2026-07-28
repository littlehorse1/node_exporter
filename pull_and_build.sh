#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec /usr/bin/env bash "$0" "$@"
fi
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

stash_if_dirty() {
  # Returns 0 if stashed, 1 if nothing to stash.
  if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    return 1
  fi

  local msg="auto-stash: pull_and_build.sh"
  local before after
  before="$(git stash list 2>/dev/null | wc -l | tr -d '[:space:]' || echo 0)"

  # Newer git:
  if git stash push -u -m "${msg}" >/dev/null 2>&1; then
    :
  # Older git (no 'push' / no '-m'):
  elif git stash save -u "${msg}" >/dev/null 2>&1; then
    :
  elif git stash save --include-untracked "${msg}" >/dev/null 2>&1; then
    :
  else
    # Worst-case fallback (may not include untracked files)
    git stash save "${msg}" >/dev/null
  fi

  after="$(git stash list 2>/dev/null | wc -l | tr -d '[:space:]' || echo 0)"
  if [ "${after}" -le "${before}" ]; then
    echo "[WARN] stash did not create a new entry; continuing without stash pop"
    return 0
  fi
  return 0
}

pop_stash_if_any() {
  # Pop latest stash entry (best effort).
  git stash pop >/dev/null 2>&1 || {
    echo "[WARN] stash pop had conflicts; resolve manually: git status"
  }
}

# If working tree is dirty, auto-stash to allow rebase pull.
# This avoids: "Cannot pull with rebase: You have unstaged changes."
if ! git diff --quiet || ! git diff --cached --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  echo "[WARN] working tree has local changes; using autostash for pull --rebase"
  if git pull --rebase --autostash; then
    :
  else
    echo "[WARN] git pull --autostash failed; falling back to manual stash"
    stash_if_dirty || true
    git pull --rebase
    pop_stash_if_any
  fi
else
  git pull --rebase
fi

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

