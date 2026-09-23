#!/bin/sh
set -eu

# Builds the Windows MSI from an already-built executable.
#
# Separate from the Wails build because it needs a Windows toolchain that the
# rest of the packaging does not: WiX is a .NET tool and only produces MSIs on
# Windows, so this runs in its own job while every other Windows artifact is
# cross-compiled from macOS.

app_name="${APP_NAME:-WhiteVPN Desktop}"
version="${VERSION:-${APP_VERSION:-0.0.0}}"
source_dir="${PACKAGE_SOURCE_DIR:-build/bin}"
output_dir="${PACKAGE_OUTPUT_DIR:-build/releases}"
asset_suffix="${WINDOWS_ASSET_SUFFIX:-windows-x64}"
arch="${MSI_ARCH:-x64}"
wxs="${MSI_WXS:-build/windows/installer/whitevpn.wxs}"

cd "$(dirname "$0")/.."

if [ ! -f "$source_dir/$app_name.exe" ]; then
  printf 'No built executable at %s\n' "$source_dir/$app_name.exe" >&2
  exit 1
fi
if ! command -v wix >/dev/null 2>&1; then
  printf 'wix is required: dotnet tool install --global wix\n' >&2
  exit 1
fi

# An MSI ProductVersion is three numbers and nothing else — Windows compares
# them to decide what is an upgrade, and it has no idea what "-rc1" means. A
# pre-release therefore installs under its release number while the file keeps
# the full one, so `1.0.23-rc1.msi` carries ProductVersion 1.0.23.
#
# Said out loud rather than done quietly: two pre-releases of the same version
# are the same version to Windows, and the second will repair over the first
# rather than upgrade it. That is the right trade for a test build and the wrong
# one to discover by surprise.
product_version="${version%%-*}"
case "$product_version" in
  *[!0-9.]*|'')
    printf 'Version %s does not reduce to a numeric MSI version\n' "$version" >&2
    exit 1
    ;;
esac
if [ "$product_version" != "$version" ]; then
  printf 'MSI ProductVersion is %s; the file keeps %s\n' "$product_version" "$version"
fi

mkdir -p "$output_dir"
msi_path="$output_dir/WhiteVPN-Desktop-$version-$asset_suffix.msi"

wix build \
  -arch "$arch" \
  -ext WixToolset.UI.wixext \
  -ext WixToolset.Util.wixext \
  -d "ProductVersion=$product_version" \
  -d "SourceDir=$source_dir" \
  -o "$msi_path" \
  "$wxs"

printf 'Created %s\n' "$msi_path"
