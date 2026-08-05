#!/usr/bin/env bash
# Fetch the engine source WhiteVPN for Android runs, pinned to the same refs.
#
# The Android build (scripts/build-flclash-core.sh in WhiteDNS/WhiteVPN) expects
# FlClash to be sitting on disk already and only fetches mihomo. Nothing here can
# assume that, so this fetches both — but pins them to exactly what Android
# builds, because the whole point of this port is that the two apps run the same
# engine. Bump these three together or not at all.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
THIRD_PARTY_DIR="${MIHOMO_THIRD_PARTY_DIR:-${ROOT_DIR}/third_party}"
FLCLASH_DIR="${THIRD_PARTY_DIR}/flclash"
CORE_DIR="${FLCLASH_DIR}/core"
MIHOMO_DIR="${CORE_DIR}/Clash.Meta"

FLCLASH_REPO="https://github.com/chen08209/FlClash.git"
FLCLASH_COMMIT="7c831855efedceb1a72bd0b4c18da026593d0853"
MIHOMO_REPO="https://github.com/MetaCubeX/mihomo.git"
MIHOMO_TAG="v1.19.29"
FLCLASH_PATCH_REPO="https://github.com/chen08209/Clash.Meta.git"
FLCLASH_PATCH_COMMIT="80362fc1895dcf60b79b562896653046e0687413"

log() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required."
command -v go >/dev/null 2>&1 || die "Go is required to build the mihomo core."

# --- FlClash: the Go glue that wraps mihomo ---------------------------------
if [[ ! -f "${CORE_DIR}/go.mod" ]]; then
  log "Fetching FlClash ${FLCLASH_COMMIT:0:12}..."
  rm -rf "${FLCLASH_DIR}"
  mkdir -p "$(dirname "${FLCLASH_DIR}")"
  git init --quiet "${FLCLASH_DIR}"
  git -C "${FLCLASH_DIR}" remote add origin "${FLCLASH_REPO}"
  git -C "${FLCLASH_DIR}" fetch --quiet --depth 1 origin "${FLCLASH_COMMIT}"
  git -C "${FLCLASH_DIR}" checkout --quiet FETCH_HEAD
fi

# Verify by content. A directory that merely exists proves nothing: an
# interrupted clone leaves one behind, and so does a stale checkout at the wrong
# ref, and both fail later in ways that look like build problems.
[[ -f "${CORE_DIR}/go.mod" ]] || die "FlClash core is missing go.mod: ${CORE_DIR}"
[[ -f "${CORE_DIR}/server.go" ]] || die "FlClash core has no server.go — the Windows entry point is absent: ${CORE_DIR}"
actual_flclash="$(git -C "${FLCLASH_DIR}" rev-parse HEAD)"
[[ "${actual_flclash}" == "${FLCLASH_COMMIT}" ]] ||
  die "FlClash is at ${actual_flclash}, expected ${FLCLASH_COMMIT}"

# --- mihomo: the engine itself ----------------------------------------------
if [[ ! -f "${MIHOMO_DIR}/go.mod" ]]; then
  if [[ -e "${MIHOMO_DIR}" && -n "$(find "${MIHOMO_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]]; then
    die "mihomo checkout is present but incomplete: ${MIHOMO_DIR}"
  fi
  log "Fetching mihomo ${MIHOMO_TAG} and applying the FlClash commit..."
  rm -rf "${MIHOMO_DIR}"
  git clone --quiet --depth 1 --branch "${MIHOMO_TAG}" "${MIHOMO_REPO}" "${MIHOMO_DIR}"
  git -C "${MIHOMO_DIR}" fetch --quiet --depth 2 "${FLCLASH_PATCH_REPO}" "${FLCLASH_PATCH_COMMIT}"
  # The identity is supplied rather than assumed. A cherry-pick writes a
  # commit, and git refuses to write one without a committer — which is every
  # CI runner that has not been told who it is, and every developer who has
  # just installed git. It goes on the command line so nothing outside this
  # tree is configured on the way past.
  git -c commit.gpgsign=false \
    -c user.name="WhiteVPN Desktop build" \
    -c user.email="build@localhost" \
    -C "${MIHOMO_DIR}" cherry-pick "${FLCLASH_PATCH_COMMIT}"
fi

# Same checks Android's script makes, for the same reason.
git -C "${MIHOMO_DIR}" rev-parse --verify "${MIHOMO_TAG}^{commit}" >/dev/null 2>&1 ||
  die "mihomo checkout does not know tag ${MIHOMO_TAG}: ${MIHOMO_DIR}"
git -C "${MIHOMO_DIR}" merge-base --is-ancestor "${MIHOMO_TAG}" HEAD ||
  die "mihomo source is not based on ${MIHOMO_TAG}: ${MIHOMO_DIR}"

# And one Android does not: prove the FlClash commit actually landed. Android
# gets away without this because it re-clones; here the tree persists between
# runs, so "cherry-pick already applied" has to be distinguishable from
# "cherry-pick silently skipped".
if ! git -C "${MIHOMO_DIR}" log --format=%s -20 | grep -q "support FlClash"; then
  die "mihomo tree is missing the FlClash commit ${FLCLASH_PATCH_COMMIT}: ${MIHOMO_DIR}"
fi

log "Engine source ready:"
log "  FlClash ${FLCLASH_COMMIT:0:12} at ${CORE_DIR}"
log "  mihomo  ${MIHOMO_TAG} + FlClash commit at ${MIHOMO_DIR}"
