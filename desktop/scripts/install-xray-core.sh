#!/bin/sh
set -eu

version="${XRAY_CORE_VERSION:-v26.3.27}"
os_name="${TARGET_GOOS:-$(go env GOOS)}"
arch_name="${TARGET_GOARCH:-$(go env GOARCH)}"
dest_dir="${XRAY_DEST_DIR:-cores}"

case "$os_name/$arch_name" in
  darwin/amd64) asset_name="Xray-macos-64.zip" ;;
  darwin/arm64) asset_name="Xray-macos-arm64-v8a.zip" ;;
  windows/amd64) asset_name="Xray-windows-64.zip" ;;
  windows/arm64) asset_name="Xray-windows-arm64-v8a.zip" ;;
  linux/amd64) asset_name="Xray-linux-64.zip" ;;
  linux/arm64) asset_name="Xray-linux-arm64-v8a.zip" ;;
  *)
    printf 'Unsupported Xray target: %s/%s\n' "$os_name" "$arch_name" >&2
    exit 1
    ;;
esac

core_name="xray-${os_name}-${arch_name}"
binary_name="xray"
if [ "$os_name" = "windows" ]; then
  core_name="${core_name}.exe"
  binary_name="xray.exe"
fi

cd "$(dirname "$0")/.."
mkdir -p "$dest_dir"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

archive="$tmp_dir/$asset_name"
url="https://github.com/XTLS/Xray-core/releases/download/${version}/${asset_name}"
curl -fL "$url" -o "$archive"

extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"
unzip -q "$archive" -d "$extract_dir"

binary_path="$(find "$extract_dir" -type f -name "$binary_name" | head -n 1)"
if [ -z "$binary_path" ]; then
  printf 'Downloaded archive did not contain %s\n' "$binary_name" >&2
  exit 1
fi

cp "$binary_path" "$dest_dir/$core_name"
chmod 755 "$dest_dir/$core_name"

for asset in geoip.dat geosite.dat; do
  asset_path="$(find "$extract_dir" -type f -name "$asset" | head -n 1)"
  if [ -z "$asset_path" ]; then
    printf 'Downloaded archive did not contain %s\n' "$asset" >&2
    exit 1
  fi
  cp "$asset_path" "$dest_dir/$asset"
done

if [ "$os_name" = "windows" ]; then
  wintun_path="$(find "$extract_dir" -type f -name "wintun.dll" | head -n 1)"
  if [ -z "$wintun_path" ]; then
    printf 'Downloaded archive did not contain wintun.dll\n' >&2
    exit 1
  fi
  cp "$wintun_path" "$dest_dir/wintun.dll"
  chmod 644 "$dest_dir/wintun.dll"
fi

printf 'Installed Xray core %s to %s\n' "$version" "$dest_dir/$core_name"
