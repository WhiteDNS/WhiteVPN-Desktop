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
linuxdeploy_url="${LINUXDEPLOY_URL:-https://github.com/linuxdeploy/linuxdeploy/releases/download/1-alpha-20251107-1/linuxdeploy-x86_64.AppImage}"
linuxdeploy_sha256="${LINUXDEPLOY_SHA256:-c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d}"
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

# The 512 icon first, and build/appicon.png only as a fallback. Two reasons,
# both about it being 1024x1024: it lands in a directory named 512x512, and
# linuxdeploy refuses it outright —
#
#   ERROR: Icon whitevpn-desktop.png has invalid x resolution: 1024
#
# which is what killed every AppImage build, silently, until the linuxdeploy
# output stopped being redirected to /dev/null.
if [ -f frontend/public/icon-512.png ]; then
  icon_source="frontend/public/icon-512.png"
elif [ -f build/appicon.png ]; then
  icon_source="build/appicon.png"
else
  icon_source=""
fi

if [ -n "$icon_source" ]; then
  cp "$icon_source" "$icons_dir/$package_name.png"
fi

installed_size="$(du -sk "$payload_root" | awk '{print $1}')"
# WhiteVPN, not WhiteDNS: the app was renamed and this line was missed, so the
# .deb and .rpm came out under the old name while the .tar.gz beside them used
# the new one. Everything built; only the names disagreed, and the workflow went
# looking for files that were never going to be there.
asset_base="WhiteVPN-Desktop-$version-$asset_suffix"

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
    if [ "${LINUXDEPLOY_SHA256+x}" = x ]; then
      verify_linuxdeploy "$linuxdeploy_bin"
    fi
    printf '%s\n' "$linuxdeploy_bin"
    return 0
  fi

  if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is required to download linuxdeploy for AppImage packaging\n' >&2
    exit 1
  fi

  linuxdeploy_tmp="$tmp_dir/linuxdeploy-x86_64.AppImage"
  curl --proto '=https' --tlsv1.2 -fsSL "$linuxdeploy_url" -o "$linuxdeploy_tmp"
  verify_linuxdeploy "$linuxdeploy_tmp"
  chmod 755 "$linuxdeploy_tmp"
  printf '%s\n' "$linuxdeploy_tmp"
}

verify_linuxdeploy() {
  actual_sha256="$(sha256sum "$1" | awk '{print $1}')"
  if [ "$actual_sha256" != "$linuxdeploy_sha256" ]; then
    printf 'linuxdeploy checksum mismatch: expected %s, got %s\n' "$linuxdeploy_sha256" "$actual_sha256" >&2
    exit 1
  fi
}

# linuxdeploy copies libwebkit2gtk into the AppDir but leaves WebKitWebProcess on the
# host. On newer distros the system helpers speak a different IPC dialect than the
# bundled library, which produces a blank window and:
#   Received invalid message: 'WebPage_SetActivityStateReply'
# Ship the matching helpers next to the bundled library and point WEBKIT_EXEC_PATH at them.
bundle_webkit_helpers() {
  appdir="$1"
  helper_src=""
  for candidate in \
    "/usr/lib/x86_64-linux-gnu/webkit2gtk-$webkit" \
    "/usr/lib/aarch64-linux-gnu/webkit2gtk-$webkit" \
    "/usr/lib64/webkit2gtk-$webkit" \
    "/usr/lib/webkit2gtk-$webkit"
  do
    if [ -x "$candidate/WebKitWebProcess" ]; then
      helper_src="$candidate"
      break
    fi
  done

  if [ -z "$helper_src" ]; then
    printf 'Warning: WebKitGTK %s helpers not found on the build host; AppImage may show a blank window on newer distros.\n' "$webkit" >&2
    return 0
  fi

  helper_dest="$appdir/usr/lib/webkit2gtk-$webkit"
  mkdir -p "$helper_dest"
  for helper in WebKitWebProcess WebKitNetworkProcess WebKitGPUProcess; do
    if [ -e "$helper_src/$helper" ]; then
      cp -a "$helper_src/$helper" "$helper_dest/"
    fi
  done
  if [ -d "$helper_src/injected-bundle" ]; then
    rm -rf "$helper_dest/injected-bundle"
    cp -a "$helper_src/injected-bundle" "$helper_dest/"
  fi
  printf 'Bundled WebKitGTK %s helpers from %s\n' "$webkit" "$helper_src"
}

write_appimage_apprun() {
  appdir="$1"
  cat > "$appdir/AppRun" <<EOF
#!/bin/sh
appdir="\${APPDIR:-\$(dirname "\$(readlink -f "\$0")")}"

# Prefer the WebKit helpers that match the libraries linuxdeploy bundled.
for webkit_dir in "\$appdir/usr/lib/webkit2gtk-4.1" "\$appdir/usr/lib/webkit2gtk-4.0"; do
  if [ -x "\$webkit_dir/WebKitWebProcess" ]; then
    export WEBKIT_EXEC_PATH="\$webkit_dir"
    break
  fi
done

# Keep bundled libraries ahead of the host so the UI process and helpers match.
for libdir in "\$appdir/usr/lib" "\$appdir/usr/lib/x86_64-linux-gnu" "\$appdir/usr/lib64"; do
  if [ -d "\$libdir" ]; then
    LD_LIBRARY_PATH="\$libdir\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
  fi
done
export LD_LIBRARY_PATH

# Avoid loading host GVFS modules against the bundled GLib (undefined symbols).
if [ -z "\${GIO_MODULE_DIR+x}" ]; then
  export GIO_MODULE_DIR=/dev/null
fi

exec "\$appdir/usr/bin/$package_name" "\$@"
EOF
  chmod 755 "$appdir/AppRun"
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
Depends: ca-certificates, libgtk-3-0 | libgtk-3-0t64, $deb_webkit_dep
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

  write_appimage_apprun "$appimage_root"

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

  # Deploy shared libraries first, then attach matching WebKit helpers and AppRun
  # before packaging. linuxdeploy copies libwebkit2gtk but not WebKitWebProcess.
  (
    cd "$appimage_output_dir"
    ARCH=x86_64 \
      APPIMAGE_EXTRACT_AND_RUN=1 \
      "$linuxdeploy" \
        --appdir "$appimage_root" \
        --executable "$appimage_bin_dir/$package_name" \
        --desktop-file "$appimage_desktop" \
        --icon-file "$appimage_icon"
  )

  bundle_webkit_helpers "$appimage_root"
  write_appimage_apprun "$appimage_root"

  (
    cd "$appimage_output_dir"
    ARCH=x86_64 \
      APPIMAGE_EXTRACT_AND_RUN=1 \
      VERSION="$version" \
      "$linuxdeploy" \
        --appdir "$appimage_root" \
        --output appimage
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
