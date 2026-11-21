#!/usr/bin/env bash
# Stage the Tor engine for windows/amd64 from the official Tor Expert Bundle.
#
# The bundle pinned in native/engines/windows-sources.json (torExpertBundle) was
# checked once against its signed sha256sums; this script refuses any archive
# whose sha256 differs from that pin, before extracting it.
#
#   scripts/build-tor-engine.sh                        use the archive already in
#                                                      third_party/ (or $TOR_EXPERT_BUNDLE)
#   scripts/build-tor-engine.sh --fetch-expert-bundle  download it there first
#
# Output is cores/tor-windows-amd64/, laid out as the runtime expects it:
# tor.exe, and lyrebird.exe (obfs4 and snowflake) plus conjure-client.exe as the
# plugin dir, with Tor's geoip databases.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINS="${ROOT_DIR}/native/engines/windows-sources.json"
DEST="${TOR_DEST_DIR:-${ROOT_DIR}/cores}/tor-windows-amd64"

die() { printf '%s\n' "$*" >&2; exit 1; }

fetch=0
for arg in "$@"; do
  case "${arg}" in
    --fetch-expert-bundle) fetch=1 ;;
    *) die "unknown argument: ${arg}" ;;
  esac
done

# The manifest is hand-formatted; this reads one key inside one named block.
pin() { sed -n "/\"$1\": *{/,/}/s/.*\"$2\": *\"\([^\"]*\)\".*/\1/p" "${PINS}" | head -n1; }
version="$(pin torExpertBundle version)"
url="$(pin torExpertBundle url)"
want="$(pin torExpertBundle sha256)"
[[ -n "${version}" && "${url}" == https://dist.torproject.org/* && "${want}" =~ ^[0-9a-f]{64}$ ]] ||
  die "torExpertBundle in ${PINS} has no pinned version, https URL and sha256"

archive="${TOR_EXPERT_BUNDLE:-${ROOT_DIR}/third_party/tor-expert-bundle-${version}/$(basename "${url}")}"
if [[ ! -f "${archive}" ]]; then
  [[ "${fetch}" == "1" ]] || die "${archive} is missing; pass --fetch-expert-bundle or set TOR_EXPERT_BUNDLE"
  mkdir -p "$(dirname "${archive}")"
  curl -fL --proto '=https' -o "${archive}.part" "${url}"
  mv "${archive}.part" "${archive}"
fi
# shasum on the macOS runners that cross-build the Windows package.
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
[[ "$(sha256 "${archive}")" == "${want}" ]] || die "${archive}: sha256 does not match the pinned expert bundle"

build_id="tor-expert-bundle-${version} ${want}"
if [[ "${FORCE_TOR_ENGINE_BUILD:-0}" != "1" && -f "${DEST}/build-id" && "$(<"${DEST}/build-id")" == "${build_id}" ]]; then
  printf 'Pinned Tor engine already staged: %s\n' "${DEST}"
  exit 0
fi

unpacked="$(mktemp -d)"
trap 'rm -rf "${unpacked}"' EXIT
tar -xzf "${archive}" -C "${unpacked}" tor/tor.exe tor/pluggable_transports/lyrebird.exe \
  tor/pluggable_transports/conjure-client.exe data/geoip data/geoip6

# The pinned sha256 already proves which tor.exe this is; running it is an
# extra check only a Windows host can make.
reported="Tor from expert bundle ${version}"
if [[ "${OS:-}" == "Windows_NT" ]]; then
  reported="$("${unpacked}/tor/tor.exe" --version | head -n1 | tr -d '\r')" || die "tor.exe from the bundle does not run"
  [[ "${reported}" =~ ^Tor\ version\ 0\.4\.9\.[0-9]+ ]] || die "bundle tor.exe reports '${reported}', expected Tor 0.4.9.x"
fi

rm -rf "${DEST}"
mkdir -p "${DEST}"
cp "${unpacked}/tor/tor.exe" "${unpacked}/tor/pluggable_transports/lyrebird.exe" \
  "${unpacked}/tor/pluggable_transports/conjure-client.exe" "${unpacked}/data/geoip" "${unpacked}/data/geoip6" "${DEST}/"
printf '%s\n' "${build_id}" > "${DEST}/build-id"
printf 'Staged %s into %s\n' "${reported}" "${DEST}"
