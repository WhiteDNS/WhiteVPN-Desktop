#!/usr/bin/env bash
# Package inspection for the privileged components.
#
# The capability gate in the app trusts one thing about a Linux install: files
# at fixed root-owned paths that only a package could have put there. These
# checks unpack each release artifact and assert exactly that — paths,
# owners, modes, the polkit action id, and that the core inside is byte-for-
# byte the core that was built. A package that fails here must not ship,
# because its tunnel mode would either not appear or appear without its
# guarantees.
#
# Usage: test-packages.sh <artifact.deb|artifact.rpm> [source-core]
set -euo pipefail

artifact="${1:?usage: test-packages.sh <artifact> [source-core]}"
source_core="${2:-}"

HELPER_PATH="./usr/libexec/whitevpn-desktop/whitevpn-helper"
CORE_PATH="./usr/libexec/whitevpn-desktop/mihomo"
POLICY_PATH="./usr/share/polkit-1/actions/org.whitevpn.desktop.policy"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'ok: %s\n' "$*"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

extract() {
  case "$artifact" in
    *.deb)
      command -v dpkg-deb >/dev/null || fail "dpkg-deb required to inspect .deb"
      dpkg-deb -x "$artifact" "$work/pkg"
      dpkg-deb -e "$artifact" "$work/control"
      ;;
    *.rpm)
      command -v rpm2cpio >/dev/null || fail "rpm2cpio required to inspect .rpm"
      mkdir -p "$work/pkg"
      rpm2cpio "$artifact" | (cd "$work/pkg" && cpio -idm --quiet)
      ;;
    *) fail "unknown artifact type: $artifact" ;;
  esac
}

assert_regular_root_755() {
  local path="$1" label="$2"
  [ -e "$path" ] || fail "$label is missing from the package"
  [ ! -L "$path" ] || fail "$label is a symlink; privileged files must be plain"
  [ -f "$path" ] || fail "$label is not a regular file"
  # Ownership comes out of the archive listing rather than the extracted copy,
  # which takes on the extracting user's identity.
  case "$artifact" in
    *.deb)
      dpkg-deb --contents "$artifact" | grep -E '[^[:space:]]+ root/root' >/dev/null \
        || true  # full per-file assertion happens below via tar listing
      local owner
      owner="$(dpkg-deb --contents "$artifact" | awk -v p="${path#./}" '$NF ~ p {print $2 "/" $3}')"
      [ "$owner" = "root/root" ] || fail "$label owned by '$owner', want root/root"
      ;;
    *.rpm)
      local listing
      listing="$(rpm -qlpv "$artifact" | awk -v p="${path#./}" '$0 ~ p {print}')"
      printf '%s' "$listing" | grep -q 'root root' || fail "$label not owned by root in rpm listing ($listing)"
      ;;
  esac
  local mode
  mode="$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")"
  [ "$mode" = "755" ] || fail "$label mode is $mode, want 755"
  pass "$label present, root-owned plain file, mode 755"
}

extract

assert_regular_root_755 "$work/$HELPER_PATH" "helper"
assert_regular_root_755 "$work/$CORE_PATH" "core"

# The polkit action: installed read-only, naming our helper by path, with the
# action id the code looks for.
[ -f "$work/$POLICY_PATH" ] || fail "polkit policy missing"
policy_mode="$(stat -c '%a' "$work/$POLICY_PATH" 2>/dev/null || stat -f '%Lp' "$work/$POLICY_PATH")"
[ "$policy_mode" = "644" ] || fail "polkit policy mode $policy_mode, want 644"
grep -q 'action id="com.whitevpn.desktop.tunnel"' "$work/$POLICY_PATH" \
  || fail "polkit action id does not match what the helper's pkexec caller requests"
grep -q '/usr/libexec/whitevpn-desktop/whitevpn-helper' "$work/$POLICY_PATH" \
  || fail "polkit policy does not name the installed helper path"
pass "polkit policy installed with correct action id and exec path"

# The packaged core must be the built core, byte for byte.
if [ -n "$source_core" ]; then
  want="$(sha256sum "$source_core" | awk '{print $1}')"
  got="$(sha256sum "$work/$CORE_PATH" | awk '{print $1}')"
  [ "$want" = "$got" ] || fail "packaged core hash $got != built core hash $want"
  pass "packaged core matches the build output by sha256"
fi

# Development overrides must never ride along in a privileged path.
if grep -q "WHITEVPN_MIHOMO_BIN" "$work/$HELPER_PATH"; then
  fail "helper binary references WHITEVPN_MIHOMO_BIN"
fi
pass "no development override strings in the privileged helper"

printf 'All package inspections passed for %s\n' "$artifact"
