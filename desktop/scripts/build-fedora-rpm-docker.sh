#!/bin/sh
set -eu

docker_bin="${LINUX_DOCKER:-docker}"
image="${FEDORA_DOCKER_IMAGE:-fedora:44}"
target_arch="${LINUX_CLIENT_ARCH:-amd64}"
version="${VERSION:-1.0.0-beta6}"
release_ldflags="${RELEASE_LDFLAGS:--s -w}"
helper_ldflags="${HELPER_GO_LDFLAGS:-$release_ldflags}"
upx="${UPX:-0}"
upx_flags="${UPX_FLAGS:---best --lzma}"

case "$target_arch" in
  amd64)
    docker_platform="linux/amd64"
    target_name="linux-amd64-fedora44-webkit41"
    ;;
  arm64)
    docker_platform="linux/arm64"
    target_name="linux-arm64-fedora44-webkit41"
    ;;
  *)
    printf 'Unsupported Fedora RPM target architecture: %s\n' "$target_arch" >&2
    exit 1
    ;;
esac

cd "$(dirname "$0")/../.."
repo_dir="$(pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

if ! command -v "$docker_bin" >/dev/null 2>&1; then
  printf 'Docker is required to build Fedora RPM packages.\n' >&2
  exit 1
fi
if ! "$docker_bin" info >/dev/null 2>&1; then
  printf 'Docker is installed but the daemon is not running.\n' >&2
  exit 1
fi

printf 'Building Fedora 44 WebKitGTK 4.1 RPM for %s\n' "$target_arch"
"$docker_bin" run --rm \
  --platform "$docker_platform" \
  -v "$repo_dir:/workspace" \
  -v "whitevpn-desktop-fedora-npm-$target_arch:/root/.npm" \
  -v "whitevpn-desktop-fedora-go-mod-$target_arch:/go/pkg/mod" \
  --mount type=volume,target=/workspace/desktop/frontend/node_modules \
  -e VERSION="$version" \
  -e TARGET_ARCH="$target_arch" \
  -e TARGET_NAME="$target_name" \
  -e RELEASE_LDFLAGS="$release_ldflags" \
  -e HELPER_GO_LDFLAGS="$helper_ldflags" \
  -e UPX="$upx" \
  -e UPX_FLAGS="$upx_flags" \
  -e HOST_UID="$host_uid" \
  -e HOST_GID="$host_gid" \
  -w /workspace/desktop \
  "$image" \
  sh -c '
    set -eu
    dnf -y install \
      ca-certificates \
      curl \
      file \
      gcc \
      gcc-c++ \
      git \
      golang \
      gtk3-devel \
      make \
      nodejs \
      npm \
      pkgconf-pkg-config \
      rpm-build \
      unzip \
      webkit2gtk4.1-devel \
      zip
    export PATH="/root/go/bin:/usr/local/go/bin:/go/bin:$PATH"
    npm ci --include=optional --prefix frontend
    rm -rf frontend/dist
    npm run build --prefix frontend
    wails_version="$(go list -m -f "{{.Version}}" github.com/wailsapp/wails/v2)"
    go install "github.com/wailsapp/wails/v2/cmd/wails@$wails_version"
    make package-linux-distros \
      VERSION="$VERSION" \
      LINUX_PLATFORMS="linux/$TARGET_ARCH" \
      LINUX_CLIENT_ARCH="$TARGET_ARCH" \
      LINUX_GO_TAGS="webkit2_41" \
      LINUX_WEBKIT="4.1" \
      LINUX_ASSET_SUFFIX="$TARGET_NAME" \
      LINUX_PACKAGE_OUTPUT_DIR=build/releases/all \
      LINUX_PACKAGE_FORMATS="rpm" \
      GO_BUILD_CACHE="/workspace/desktop/.cache/go-build-fedora-$TARGET_ARCH" \
      XRAY_CACHE_DIR=/workspace/desktop/.cache/xray \
      XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-v26.3.27}" \
      RELEASE_LDFLAGS="$RELEASE_LDFLAGS" \
      HELPER_GO_LDFLAGS="$HELPER_GO_LDFLAGS" \
      UPX="$UPX" \
      UPX_FLAGS="$UPX_FLAGS"
    rpm -qpR "build/releases/all/WhiteDNS-Desktop-$VERSION-$TARGET_NAME.rpm" | grep -E "lib(webkit2gtk|javascriptcoregtk)-4.1"
    chown -R "$HOST_UID:$HOST_GID" build clients cores .cache frontend/dist frontend/wailsjs 2>/dev/null || true
  '
