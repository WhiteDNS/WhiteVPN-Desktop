#!/bin/sh
set -eu

docker_bin="${LINUX_DOCKER:-docker}"
image="${LINUX_DOCKER_IMAGE:-golang:1.25-bookworm}"
node_major="${LINUX_NODE_MAJOR:-24}"
platforms="${ALL_LINUX_PLATFORMS:-linux/amd64,linux/arm64}"
version="${VERSION:-1.0.0-beta6}"
package_formats="${LINUX_PACKAGE_FORMATS:-deb,rpm}"
release_ldflags="${RELEASE_LDFLAGS:--s -w}"
helper_ldflags="${HELPER_GO_LDFLAGS:-$release_ldflags}"
upx="${UPX:-0}"
upx_flags="${UPX_FLAGS:---best --lzma}"

cd "$(dirname "$0")/../.."
repo_dir="$(pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

if ! command -v "$docker_bin" >/dev/null 2>&1; then
  printf 'Docker is required to build Linux packages from this host. Install Docker, or run make all on Linux.\n' >&2
  exit 1
fi

if ! "$docker_bin" info >/dev/null 2>&1; then
  printf 'Docker is installed but the daemon is not running. Start Docker, or run make all on Linux.\n' >&2
  exit 1
fi

for platform in $(printf '%s' "$platforms" | tr ',' ' '); do
  target_goos="${platform%/*}"
  target_arch="${platform#*/}"
  if [ "$target_goos" = "$target_arch" ]; then
    target_arch="amd64"
  fi
  if [ "$target_goos" != "linux" ]; then
    printf 'Skipping non-Linux platform in Linux Docker builder: %s\n' "$platform" >&2
    continue
  fi

  case "$target_arch" in
    amd64|arm64) ;;
    *)
      printf 'Unsupported Linux Docker target architecture: %s\n' "$target_arch" >&2
      exit 1
      ;;
  esac

  target_name="linux-$target_arch"
  docker_platform="linux/$target_arch"
  npm_cache_volume="whitedns-desktop-npm-$target_arch"
  gomod_volume="whitedns-desktop-go-mod"

  printf 'Building %s in Docker (%s)\n' "$target_name" "$docker_platform"
  "$docker_bin" run --rm \
    --platform "$docker_platform" \
    -v "$repo_dir:/workspace" \
    -v "$npm_cache_volume:/root/.npm" \
    -v "$gomod_volume:/go/pkg/mod" \
    --mount type=volume,target=/workspace/desktop/frontend/node_modules \
    -e DEBIAN_FRONTEND=noninteractive \
    -e VERSION="$version" \
    -e TARGET_PLATFORM="linux/$target_arch" \
    -e TARGET_ARCH="$target_arch" \
    -e TARGET_NAME="$target_name" \
    -e LINUX_NODE_MAJOR="$node_major" \
    -e LINUX_PACKAGE_FORMATS="$package_formats" \
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
      export PATH="/usr/local/go/bin:/go/bin:$PATH"
      apt-get update
      apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        gnupg \
        libgtk-3-dev \
        libwebkit2gtk-4.0-dev \
        pkg-config \
        rpm \
        unzip \
        zip
      install -d -m 0755 /etc/apt/keyrings
      curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o /tmp/nodesource.gpg.key
      gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg /tmp/nodesource.gpg.key
      printf "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\n" "$LINUX_NODE_MAJOR" > /etc/apt/sources.list.d/nodesource.list
      apt-get update
      apt-get install -y --no-install-recommends nodejs
      node --version
      npm --version
      npm ci --include=optional --prefix frontend
      wails_version="$(go list -m -f "{{.Version}}" github.com/wailsapp/wails/v2)"
      go install "github.com/wailsapp/wails/v2/cmd/wails@$wails_version"
      make package-linux-distros \
        VERSION="$VERSION" \
        LINUX_PLATFORMS="$TARGET_PLATFORM" \
        LINUX_CLIENT_ARCH="$TARGET_ARCH" \
        LINUX_ASSET_SUFFIX="$TARGET_NAME" \
        LINUX_PACKAGE_OUTPUT_DIR=build/releases/all \
        LINUX_PACKAGE_FORMATS="$LINUX_PACKAGE_FORMATS" \
        GO_BUILD_CACHE="/workspace/desktop/.cache/go-build-linux-$TARGET_ARCH" \
        XRAY_CACHE_DIR=/workspace/desktop/.cache/xray \
        XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-v26.3.27}" \
        RELEASE_LDFLAGS="$RELEASE_LDFLAGS" \
        HELPER_GO_LDFLAGS="$HELPER_GO_LDFLAGS" \
        UPX="$UPX" \
        UPX_FLAGS="$UPX_FLAGS"
      make stage-artifacts VERSION="$VERSION" PLATFORM="all/$TARGET_NAME"
      chown -R "$HOST_UID:$HOST_GID" build clients cores .cache frontend/dist frontend/wailsjs 2>/dev/null || true
    '
done
