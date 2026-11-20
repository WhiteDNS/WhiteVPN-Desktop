#!/usr/bin/env bash
# Fetch the pinned psiphon-tunnel-core commit and build its console client as
# the desktop's Psiphon worker, cores/psiphon-<goos>-<goarch>[.exe].
#
# Android links the same commit in-process through gomobile. The desktop has no
# such host, so it runs the upstream ConsoleClient as a separate process and
# reads the JSON notices it prints; internal/engines/psiphon is that host.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Same pin as Android's native/engines/sources.json and native/engines/windows-sources.json.
PSIPHON_REPO="https://github.com/CluvexStudio/psiphon-tunnel-core.git"
PSIPHON_COMMIT="83aa73b9b982e7421e00117f5b0c5aceb5dda452"
PSIPHON_BUILD_ID="psiphon-${PSIPHON_COMMIT}-consoleclient-1"

THIRD_PARTY_DIR="${PSIPHON_THIRD_PARTY_DIR:-${ROOT_DIR}/third_party}"
SOURCE_DIR="${THIRD_PARTY_DIR}/psiphon-tunnel-core"
TARGET_GOOS="${TARGET_GOOS:-$(go env GOOS)}"
TARGET_GOARCH="${TARGET_GOARCH:-$(go env GOARCH)}"
DEST_DIR="${PSIPHON_DEST_DIR:-${ROOT_DIR}/cores}"

die() { printf '%s\n' "$*" >&2; exit 1; }
command -v git >/dev/null 2>&1 || die "git is required."
command -v go >/dev/null 2>&1 || die "Go is required."

binary="psiphon-${TARGET_GOOS}-${TARGET_GOARCH}"
[[ "${TARGET_GOOS}" == "windows" ]] && binary="${binary}.exe"

if [[ "${FORCE_PSIPHON_BUILD:-0}" != "1" && -f "${DEST_DIR}/${binary}" && -f "${DEST_DIR}/${binary}.build-id" && "$(<"${DEST_DIR}/${binary}.build-id")" == "${PSIPHON_BUILD_ID}" ]]; then
  printf 'Pinned Psiphon engine already built: %s\n' "${DEST_DIR}/${binary}"
  exit 0
fi

# Fetch by SHA rather than a branch, so a later push to the fork cannot change
# what an old release builds.
if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
  if [[ -d "${SOURCE_DIR}" && -n "$(find "${SOURCE_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    die "Source directory is not empty: ${SOURCE_DIR}"
  fi
  mkdir -p "${SOURCE_DIR}"
  git init --quiet "${SOURCE_DIR}"
  git -C "${SOURCE_DIR}" remote add origin "${PSIPHON_REPO}"
  git -C "${SOURCE_DIR}" fetch --quiet --depth 1 origin "${PSIPHON_COMMIT}"
  git -C "${SOURCE_DIR}" checkout --quiet --detach FETCH_HEAD
fi
[[ "$(git -C "${SOURCE_DIR}" rev-parse HEAD)" == "${PSIPHON_COMMIT}" ]] ||
  die "${SOURCE_DIR} must be at ${PSIPHON_COMMIT}; use a fresh PSIPHON_THIRD_PARTY_DIR to preserve local changes."
[[ -f "${SOURCE_DIR}/ConsoleClient/main.go" ]] || die "The pinned source has no ConsoleClient."

printf 'Building Psiphon %s for %s/%s...\n' "${PSIPHON_COMMIT:0:12}" "${TARGET_GOOS}" "${TARGET_GOARCH}"
mkdir -p "${DEST_DIR}"
(
  cd "${SOURCE_DIR}"
  CGO_ENABLED=0 GOOS="${TARGET_GOOS}" GOARCH="${TARGET_GOARCH}" \
    go build -mod=vendor -trimpath -ldflags "-w -s" -o "${DEST_DIR}/${binary}" ./ConsoleClient
)
chmod 755 "${DEST_DIR}/${binary}" 2>/dev/null || true
printf '%s\n' "${PSIPHON_BUILD_ID}" > "${DEST_DIR}/${binary}.build-id"
printf 'Built %s\n' "${DEST_DIR}/${binary}"
