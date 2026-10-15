#!/usr/bin/env bash
# Fetch exact WhiteVPN fork commits; preserve existing developer checkouts.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/mihomo-pins.sh"
THIRD_PARTY_DIR="${MIHOMO_THIRD_PARTY_DIR:-${ROOT_DIR}/third_party}"
FLCLASH_DIR="${THIRD_PARTY_DIR}/flclash-whitevpn"
CORE_DIR="${FLCLASH_DIR}/core"
MIHOMO_DIR="${CORE_DIR}/Clash.Meta"

die() { printf '%s\n' "$*" >&2; exit 1; }
command -v git >/dev/null 2>&1 || die "git is required."
command -v go >/dev/null 2>&1 || die "Go is required."

fetch_pinned() {
  local path="$1" repo="$2" commit="$3"
  if [[ ! -d "${path}/.git" && ! -f "${path}/.git" ]]; then
    if [[ -d "${path}" && -n "$(find "${path}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      die "Source directory is not empty: ${path}"
    fi
    mkdir -p "${path}"
    git init --quiet "${path}"
    git -C "${path}" remote add origin "${repo}"
    git -C "${path}" fetch --quiet --depth 1 origin "${commit}"
    git -C "${path}" checkout --quiet --detach FETCH_HEAD
  fi
  [[ "$(git -C "${path}" rev-parse HEAD)" == "${commit}" ]] ||
    die "${path} must be at ${commit}; use a fresh MIHOMO_THIRD_PARTY_DIR to preserve local changes."
}

fetch_pinned "${FLCLASH_DIR}" "${FLCLASH_REPO}" "${FLCLASH_COMMIT}"
fetch_pinned "${MIHOMO_DIR}" "${MIHOMO_REPO}" "${MIHOMO_COMMIT}"
[[ -f "${CORE_DIR}/server.go" && -f "${CORE_DIR}/main.go" ]] || die "Desktop engine entry point is missing."
grep -Fq 'newFragmentDialerChain' "${MIHOMO_DIR}/adapter/outbound/base.go" || die "Core lacks fragmentation."
grep -Fq 'func (c *fragmentConn) writeTLSHello' "${MIHOMO_DIR}/adapter/outbound/fragment.go" || die "Core lacks TLS fragmentation."
printf 'Engine source ready: FlClash %s, mihomo %s (%s)\n' "${FLCLASH_COMMIT}" "${MIHOMO_TAG}" "${MIHOMO_COMMIT}"
