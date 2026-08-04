#!/usr/bin/env bash
# Build the mihomo engine for a desktop target.
#
# Android builds this same source as a c-shared library, because there it is
# loaded in-process and handed a TUN file descriptor by VpnService. Desktop
# builds it as a plain executable with CGO off, which is the variant whose entry
# point is core/main.go + core/server.go: it dials back on a pipe or socket and
# speaks the action protocol. That variant has no startTUN at all — the tunnel
# comes from mihomo's own tun.enable + auto-route instead.
#
# -tags=with_gvisor is not optional. Without it the build still succeeds and the
# tunnel then fails at runtime, which is a far more expensive way to find out.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${MIHOMO_THIRD_PARTY_DIR:-${ROOT_DIR}/third_party}"
CORE_DIR="${THIRD_PARTY_DIR}/flclash/core"
MIHOMO_TAG="v1.19.29"

TARGET_GOOS="${TARGET_GOOS:-$(go env GOOS)}"
TARGET_GOARCH="${TARGET_GOARCH:-$(go env GOARCH)}"
DEST_DIR="${MIHOMO_DEST_DIR:-${ROOT_DIR}/cores}"

die() { printf '%s\n' "$*" >&2; exit 1; }

[[ -f "${CORE_DIR}/go.mod" ]] ||
  die "Engine source is missing. Run scripts/setup-mihomo-core.sh first."

binary="mihomo-${TARGET_GOOS}-${TARGET_GOARCH}"
[[ "${TARGET_GOOS}" == "windows" ]] && binary="${binary}.exe"

mkdir -p "${DEST_DIR}"
printf 'Building mihomo %s for %s/%s...\n' "${MIHOMO_TAG}" "${TARGET_GOOS}" "${TARGET_GOARCH}"

(
  cd "${CORE_DIR}"
  # FlClash's go.mod is written against its own mihomo fork, so pointing the
  # replace directive at the pinned upstream tree leaves it slightly out of
  # date. Android's build script tidies for the same reason.
  go mod tidy
  CGO_ENABLED=0 GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" \
    go build \
    -tags=with_gvisor \
    -trimpath \
    -ldflags "-X github.com/metacubex/mihomo/constant.Version=${MIHOMO_TAG} -w -s" \
    -o "${DEST_DIR}/${binary}" \
    .
)

chmod 755 "${DEST_DIR}/${binary}" 2>/dev/null || true
printf 'Built %s\n' "${DEST_DIR}/${binary}"

# mihomo creates the Windows adapter through wintun, which it loads from beside
# the executable. Xray needs the same DLL, so the repo already ships one.
if [[ "${TARGET_GOOS}" == "windows" ]]; then
  if [[ -f "${DEST_DIR}/wintun.dll" ]]; then
    printf 'wintun.dll already staged in %s\n' "${DEST_DIR}"
  else
    printf 'WARNING: wintun.dll is not in %s — TUN mode will fail at runtime.\n' "${DEST_DIR}" >&2
  fi
fi
