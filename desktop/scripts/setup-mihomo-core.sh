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
# FlClash and its mihomo patch are pinned separately and deliberately do not
# move together.
#
# The patch had to advance for v1.19.30: the v0.8.94 one calls dns.ReCreateServer
# with the signature it had before, and the build fails to compile. The v0.8.95
# patch fixes that.
#
# The tree must not. FlClash rewrote its action protocol in v0.8.95 — action.go
# gone, message.go and method.go in its place — and internal/engine speaks the
# older one. What that combination looks like is worse than a build failure:
# every call returns success, so validateConfig accepts unparseable YAML and
# reports nothing wrong. The positive tests all still pass, because they assert
# that a good config is accepted and it is. Only the negative control caught it.
#
# Moving the tree therefore means porting internal/engine to the new protocol
# first, in its own change, with those negative tests as the evidence.
FLCLASH_COMMIT="7c831855efedceb1a72bd0b4c18da026593d0853"
MIHOMO_REPO="https://github.com/MetaCubeX/mihomo.git"
MIHOMO_TAG="v1.19.30"
FLCLASH_PATCH_REPO="https://github.com/chen08209/Clash.Meta.git"
FLCLASH_PATCH_COMMIT="0f7f05adff5e2c49775a112dcfe05a6aa36fda0c"

# The one hunk the FlClash commit and mihomo v1.19.30 both touch, and the
# recorded answer to it. Kept beside the pins so that moving one without the
# other is visible.
KNOWN_CONFLICT="hub/executor/executor.go"
NTP_PATCH="${ROOT_DIR}/scripts/patches/flclash-ntp-after-dns.patch"

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
# A tree fetched for an older pin does not know the new tag, and the checks below
# would stop with an accurate complaint and no way forward. This is a build input
# rather than anything anybody edits — it is produced entirely by the clone just
# below — so the answer to "wrong version on disk" is to fetch the right one.
if [[ -f "${MIHOMO_DIR}/go.mod" ]] &&
  ! git -C "${MIHOMO_DIR}" rev-parse --verify "${MIHOMO_TAG}^{commit}" >/dev/null 2>&1; then
  log "Engine source on disk predates ${MIHOMO_TAG}; fetching it again."
  rm -rf "${MIHOMO_DIR}"
fi

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
  if ! git -c commit.gpgsign=false \
    -c user.name="WhiteVPN Desktop build" \
    -c user.email="build@localhost" \
    -C "${MIHOMO_DIR}" cherry-pick "${FLCLASH_PATCH_COMMIT}"; then
    # One hunk is known to collide and has a known answer. Anything else is a
    # change upstream made that nobody has looked at, and guessing at it would
    # produce an engine whose behaviour no one chose.
    conflicted="$(git -C "${MIHOMO_DIR}" diff --diff-filter=U --name-only)"
    [[ "${conflicted}" == "${KNOWN_CONFLICT}" ]] ||
      die "cherry-picking the FlClash commit onto ${MIHOMO_TAG} conflicts where this script has no recorded answer:
${conflicted}
Resolve it by hand, then record the resolution the way ${NTP_PATCH##*/} records the known one."

    log "Resolving the known ${KNOWN_CONFLICT} conflict..."
    # FlClash's side first, so its edits to the surrounding lines survive; the
    # patch then puts mihomo's newer NTP ordering back on top of them.
    git -C "${MIHOMO_DIR}" checkout --theirs "${KNOWN_CONFLICT}"
    git -C "${MIHOMO_DIR}" apply "${NTP_PATCH}" ||
      die "the recorded resolution no longer applies: ${NTP_PATCH}"
    git -C "${MIHOMO_DIR}" add "${KNOWN_CONFLICT}"
    git -c commit.gpgsign=false \
      -c user.name="WhiteVPN Desktop build" \
      -c user.email="build@localhost" \
      -C "${MIHOMO_DIR}" cherry-pick --continue --no-edit
  fi
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
