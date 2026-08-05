#!/bin/sh
set -eu

app_name="${APP_NAME:-WhiteVPN Desktop}"
package_name="${LINUX_PACKAGE_NAME:-whitevpn-desktop}"
version="${VERSION:-${APP_VERSION:-1.0.0-beta6}}"
source_dir="${PACKAGE_SOURCE_DIR:-build/bin}"
output_dir="${PACKAGE_OUTPUT_DIR:-build/releases}"
arch="${LINUX_ARCH:-$(go env GOARCH)}"
webkit="${LINUX_WEBKIT:-4.0}"
formats="${LINUX_PACKAGE_FORMATS-deb,rpm}"
asset_suffix="${LINUX_ASSET_SUFFIX:-linux-$arch}"
description="${LINUX_PACKAGE_DESCRIPTION:-WhiteDNS desktop client}"
maintainer="${LINUX_PACKAGE_MAINTAINER:-WhiteDNS <noreply@whitedns.local>}"
license="${LINUX_PACKAGE_LICENSE:-MIT}"
linuxdeploy_url="${LINUXDEPLOY_URL:-https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage}"
linuxdeploy_bin="${LINUXDEPLOY_BIN:-}"

case "$arch" in
  amd64)
    deb_arch="amd64"
    rpm_arch="x86_64"
    ;;
  arm64)
    deb_arch="arm64"
    rpm_arch="aarch64"
    ;;
  *)
    printf 'Unsupported Linux package architecture: %s\n' "$arch" >&2
    exit 1
    ;;
esac

case "$webkit" in
  4.1)
    deb_webkit_dep="libwebkit2gtk-4.1-0"
    ;;
  *)
    deb_webkit_dep="libwebkit2gtk-4.0-37"
    ;;
esac

cd "$(dirname "$0")/.."

if [ ! -d "$source_dir" ]; then
  printf 'Package source directory does not exist: %s\n' "$source_dir" >&2
  exit 1
fi

if [ ! -f "$source_dir/$app_name" ]; then
  printf 'Package source is missing executable: %s/%s\n' "$source_dir" "$app_name" >&2
  exit 1
fi

mkdir -p "$output_dir"
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

payload_root="$tmp_dir/payload"
install_dir="$payload_root/opt/$package_name"
bin_dir="$payload_root/usr/bin"
apps_dir="$payload_root/usr/share/applications"
icons_dir="$payload_root/usr/share/icons/hicolor/512x512/apps"

mkdir -p "$install_dir" "$bin_dir" "$apps_dir" "$icons_dir"
cp -R "$source_dir"/. "$install_dir"/
chmod 755 "$install_dir/$app_name"

cat > "$bin_dir/$package_name" <<EOF
#!/bin/sh
exec "/opt/$package_name/$app_name" "\$@"
EOF
chmod 755 "$bin_dir/$package_name"

cat > "$apps_dir/$package_name.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$app_name
Comment=$description
Exec=/usr/bin/$package_name
Icon=$package_name
Terminal=false
Categories=Network;Utility;
StartupNotify=true
EOF

if [ -f build/appicon.png ]; then
  icon_source="build/appicon.png"
elif [ -f frontend/public/icon-512.png ]; then
  icon_source="frontend/public/icon-512.png"
else
  icon_source=""
fi

if [ -n "$icon_source" ]; then
  cp "$icon_source" "$icons_dir/$package_name.png"
fi

installed_size="$(du -sk "$payload_root" | awk '{print $1}')"
asset_base="WhiteDNS-Desktop-$version-$asset_suffix"

format_enabled() {
  case ",$formats," in
    *",$1,"*) return 0 ;;
    *) return 1 ;;
  esac
}

download_linuxdeploy() {
  if [ -n "$linuxdeploy_bin" ]; then
    if [ ! -x "$linuxdeploy_bin" ]; then
      printf 'LINUXDEPLOY_BIN is not executable: %s\n' "$linuxdeploy_bin" >&2
      exit 1
    fi
    printf '%s\n' "$linuxdeploy_bin"
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is required to download linuxdeploy for AppImage packaging\n' >&2
    exit 1
  fi

  linuxdeploy_tmp="$tmp_dir/linuxdeploy-x86_64.AppImage"
  curl -fsSL "$linuxdeploy_url" -o "$linuxdeploy_tmp"
  chmod 755 "$linuxdeploy_tmp"
  printf '%s\n' "$linuxdeploy_tmp"
}

if format_enabled deb; then
  if ! command -v dpkg-deb >/dev/null 2>&1; then
    printf 'dpkg-deb is required to build Debian packages\n' >&2
    exit 1
  fi

  deb_root="$tmp_dir/deb"
  mkdir -p "$deb_root/DEBIAN"
  cp -R "$payload_root"/. "$deb_root"/

  cat > "$deb_root/DEBIAN/control" <<EOF
Package: $package_name
Version: $version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: $maintainer
Installed-Size: $installed_size
Depends: ca-certificates, libgtk-3-0, $deb_webkit_dep
Description: $description
 Managed desktop client for WhiteDNS and StormDNS.
EOF

  deb_path="$output_dir/$asset_base.deb"
  dpkg-deb --root-owner-group --build "$deb_root" "$deb_path" >/dev/null
  printf 'Created Debian package %s\n' "$deb_path"
fi

if format_enabled rpm; then
  if ! command -v rpmbuild >/dev/null 2>&1; then
    printf 'rpmbuild is required to build RPM packages\n' >&2
    exit 1
  fi

  rpm_top="$tmp_dir/rpmbuild"
  rpm_version="$version"
  rpm_release="1"
  case "$version" in
    *-*)
      rpm_version="${version%%-*}"
      rpm_release="0.${version#*-}"
      ;;
  esac
  rpm_version="$(printf '%s' "$rpm_version" | sed 's/[^A-Za-z0-9._+~^]/_/g')"
  rpm_release="$(printf '%s' "$rpm_release" | sed 's/[^A-Za-z0-9._+~^]/_/g')"

  mkdir -p "$rpm_top/BUILD" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"
  spec_path="$rpm_top/SPECS/$package_name.spec"
  cat > "$spec_path" <<EOF
Name: $package_name
Version: $rpm_version
Release: $rpm_release%{?dist}
Summary: $description
License: $license
Requires: ca-certificates

%description
Managed desktop client for WhiteDNS and StormDNS.

%prep

%build

%install
mkdir -p %{buildroot}
cp -a %{_payload_dir}/. %{buildroot}/

%files
/opt/$package_name
/usr/bin/$package_name
/usr/share/applications/$package_name.desktop
/usr/share/icons/hicolor/512x512/apps/$package_name.png
EOF

  rpmbuild \
    --target "$rpm_arch" \
    --define "_topdir $rpm_top" \
    --define "_payload_dir $payload_root" \
    -bb "$spec_path" >/dev/null
  rpm_path="$(find "$rpm_top/RPMS" -type f -name '*.rpm' | head -n 1)"
  if [ -z "$rpm_path" ]; then
    printf 'rpmbuild completed without creating an RPM\n' >&2
    exit 1
  fi
  cp "$rpm_path" "$output_dir/$asset_base.rpm"
  printf 'Created RPM package %s\n' "$output_dir/$asset_base.rpm"
fi

if format_enabled appimage; then
  if [ "$arch" != "amd64" ]; then
    printf 'Skipping AppImage package for unsupported architecture %s; amd64 is supported first.\n' "$arch" >&2
    exit 0
  fi

  if [ -z "$icon_source" ]; then
    printf 'AppImage packaging requires an icon at build/appicon.png or frontend/public/icon-512.png\n' >&2
    exit 1
  fi

  linuxdeploy="$(download_linuxdeploy)"
  appimage_root="$tmp_dir/AppDir"
  appimage_bin_dir="$appimage_root/usr/bin"
  appimage_desktop="$tmp_dir/$package_name.desktop"
  appimage_icon="$tmp_dir/$package_name.png"
  appimage_output_dir="$tmp_dir/appimage-output"

  mkdir -p "$appimage_bin_dir" "$appimage_output_dir"
  cp "$source_dir/$app_name" "$appimage_bin_dir/$package_name"
  chmod 755 "$appimage_bin_dir/$package_name"
  cp "$icon_source" "$appimage_icon"

  cat > "$appimage_root/AppRun" <<EOF
#!/bin/sh
appdir="\${APPDIR:-\$(dirname "\$(readlink -f "\$0")")}"
exec "\$appdir/usr/bin/$package_name" "\$@"
EOF
  chmod 755 "$appimage_root/AppRun"

  cat > "$appimage_desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$app_name
Comment=$description
Exec=$package_name
Icon=$package_name
Terminal=false
Categories=Network;Utility;
StartupNotify=true
X-AppImage-Version=$version
EOF

  (
    cd "$appimage_output_dir"
    ARCH=x86_64 \
      APPIMAGE_EXTRACT_AND_RUN=1 \
      VERSION="$version" \
      "$linuxdeploy" \
        --appdir "$appimage_root" \
        --executable "$appimage_bin_dir/$package_name" \
        --desktop-file "$appimage_desktop" \
        --icon-file "$appimage_icon" \
        --output appimage >/dev/null
  )

  appimage_path="$(find "$appimage_output_dir" -maxdepth 1 -type f -name '*.AppImage' | head -n 1)"
  if [ -z "$appimage_path" ]; then
    printf 'linuxdeploy completed without creating an AppImage\n' >&2
    exit 1
  fi

  cp "$appimage_path" "$output_dir/$asset_base.AppImage"
  chmod 755 "$output_dir/$asset_base.AppImage"
  printf 'Created AppImage package %s\n' "$output_dir/$asset_base.AppImage"
fi
