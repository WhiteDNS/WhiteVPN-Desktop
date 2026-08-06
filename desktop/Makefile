SHELL := /bin/sh

APP_NAME := WhiteVPN Desktop
DEFAULT_VERSION := 1.0.0
VERSION_FROM_ARGS := $(shell set -- $(MAKECMDGOALS); while [ "$$1" != "" ]; do if [ "$$1" = "--version" ]; then shift; if [ "$$1" != "" ]; then printf '%s' "$$1"; fi; exit; fi; shift; done)
VERSION ?= $(if $(VERSION_FROM_ARGS),$(VERSION_FROM_ARGS),$(DEFAULT_VERSION))
APP_VERSION := $(strip $(VERSION))
export VERSION := $(APP_VERSION)
RELEASE_ASSET_PREFIX ?= WhiteVPN-Desktop
ROOT_DIR := ..
WAILS ?= wails
GO_BUILD_CACHE ?= $(CURDIR)/.cache/go-build
GO_ENV_FILE ?= $(CURDIR)/.cache/go-env
XRAY_CORE_VERSION ?= v26.3.27
XRAY_CACHE_DIR ?= $(CURDIR)/.cache/xray
RELEASE_LDFLAGS ?= -s -w
WAILS_RELEASE_FLAGS := -trimpath -ldflags "$(RELEASE_LDFLAGS)"
HELPER_GO_LDFLAGS ?= $(RELEASE_LDFLAGS)
UPX ?= 0
UPX_FLAGS ?= --best --lzma
MACOS_CGO_LDFLAGS ?= -framework UniformTypeIdentifiers
MACOS_GO_TAGS ?= desktop,wv2runtime.download,production
MACOS_GO_LDFLAGS ?= $(RELEASE_LDFLAGS)
MACOS_DEPLOYMENT_TARGET_AMD64 ?= 10.13
MACOS_DEPLOYMENT_TARGET_ARM64 ?= 11.0
MACOS_BUNDLE_MIN_VERSION ?= $(if $(filter arm64,$(MACOS_CLIENT_ARCH)),$(MACOS_DEPLOYMENT_TARGET_ARM64),$(MACOS_DEPLOYMENT_TARGET_AMD64))
LINUX_GO_TAGS ?=
ifneq ($(strip $(LINUX_GO_TAGS)),)
LINUX_WAILS_TAG_FLAGS := -tags "$(LINUX_GO_TAGS)"
else
LINUX_WAILS_TAG_FLAGS :=
endif
LINUX_WEBKIT ?= $(if $(findstring webkit2_41,$(LINUX_GO_TAGS)),4.1,4.0)
LINUX_PACKAGE_FORMATS ?= deb,rpm
LINUX_ASSET_SUFFIX ?= linux-$(LINUX_CLIENT_ARCH)$(if $(filter 4.1,$(LINUX_WEBKIT)),-webkit41,)
LINUX_PACKAGE_OUTPUT_DIR ?= build/releases
LINUX_DOCKER ?= docker
LINUX_DOCKER_IMAGE ?= golang:1.25-bookworm
LINUX_NODE_MAJOR ?= 24
ifeq ($(UPX),1)
WAILS_OPTIONAL_UPX_FLAGS := -upx -upxflags "$(UPX_FLAGS)"
else
WAILS_OPTIONAL_UPX_FLAGS :=
endif
GOOS_VALUE := $(shell go env GOOS)
GOARCH_VALUE := $(shell go env GOARCH)
MACOS_PLATFORMS ?= darwin/$(GOARCH_VALUE)
MACOS_CLIENT_ARCH ?= $(GOARCH_VALUE)
WINDOWS_PLATFORMS ?= windows/amd64
WINDOWS_CLIENT_ARCH ?= amd64
LINUX_PLATFORMS ?= linux/amd64
LINUX_CLIENT_ARCH ?= amd64
ALL_MACOS_PLATFORMS ?= darwin/amd64,darwin/arm64
ALL_WINDOWS_PLATFORMS ?= windows/amd64,windows/arm64
ALL_LINUX_PLATFORMS ?= linux/amd64,linux/arm64
ALL_PLATFORMS ?= $(ALL_MACOS_PLATFORMS),$(ALL_WINDOWS_PLATFORMS),$(ALL_LINUX_PLATFORMS)
MACOS_APP_BIN_DIR := build/bin/$(APP_NAME).app/Contents/MacOS
MACOS_APP_RESOURCES_DIR := build/bin/$(APP_NAME).app/Contents/Resources
MACOS_APP_EXECUTABLE := $(MACOS_APP_BIN_DIR)/$(APP_NAME)
MACOS_APP_INFO_PLIST := build/bin/$(APP_NAME).app/Contents/Info.plist

ifeq ($(filter --version,$(MAKECMDGOALS)),--version)
ifeq ($(VERSION_FROM_ARGS),)
$(error --version requires a value; use `make all -- --version 1.0.0`)
endif
endif

.PHONY: help deps frontend-deps tidy dev build build-mac build-windows build-linux build-all all check-linux-builder frontend-build backend-build prepare-package prepare-macos-go-env prepare-embedded-core prepare-embedded-platform prepare-embedded-platforms prepare-embedded-macos-cores macos-app-bundle validate-version package package-mac package-windows package-linux package-linux-distros package-linux-all-docker package-linux-fedora-rpm-docker package-all stage-artifacts archive-artifacts package-helper package-assets test test-backend test-frontend xray-core xray-core-all xray-core-target mihomo-core mihomo-core-setup clean --version
ifneq ($(VERSION_FROM_ARGS),)
.PHONY: $(VERSION_FROM_ARGS)
endif

help:
	@printf '%s\n' \
		'WhiteVPN Desktop targets:' \
		'' \
		'  make deps             Install npm deps and tidy Go modules' \
		'  make dev              Fetch the Xray core and run wails dev' \
		'  make build            Build frontend and Go desktop binary' \
		'  make build-mac        Build/package macOS app ($(MACOS_PLATFORMS))' \
		'  make build-windows    Build/package Windows app (windows/amd64)' \
		'  make build-linux      Build/package Linux app (linux/amd64)' \
		'  make build-all        Build release packages for the desktop matrix' \
		'  make all              Build minified packages for the desktop release matrix' \
		'  make package          Build package with the matching embedded Xray core' \
		'  make package-linux-distros  Build Linux .deb/.rpm packages from the Linux app build' \
		'  make package-linux-all-docker  Build Linux release packages through Docker' \
		'  make package-linux-fedora-rpm-docker  Build Fedora 42+ compatible WebKitGTK 4.1 RPM' \
		'  make package-all      Alias for build-all' \
		'  make all VERSION=1.0.0         Build release assets with this version' \
		'  make all -- --version 1.0.0    Alternate flag form' \
		'  make package-windows UPX=1  Build Windows package with UPX compression' \
		'  make package-linux UPX=1    Build Linux package with UPX compression' \
		'  make test             Run desktop Go tests and frontend TypeScript build' \
		'  make mihomo-core      Fetch and build the mihomo engine into cores/' \
		'  make mihomo-core-setup  Fetch the pinned engine source only' \
		'  make xray-core        Install matching Xray core into cores/' \
		'  make xray-core-all    Cache macOS, Windows, and Linux Xray cores' \
		'  make clean            Remove build output and cached cores'

deps: frontend-deps tidy

frontend-deps:
	npm install --prefix frontend

tidy:
	go mod tidy

dev: xray-core
	wails dev

build: xray-core frontend-build backend-build

build-mac: package-mac

build-windows: package-windows

build-linux: package-linux

build-all: all

all: validate-version check-linux-builder prepare-package
	rm -rf build/releases/all
	@if [ -n "$(ALL_MACOS_PLATFORMS)" ]; then \
		if [ "$(GOOS_VALUE)" = "darwin" ]; then \
			set -e; \
			for platform in $$(printf '%s' "$(ALL_MACOS_PLATFORMS)" | tr ',' ' '); do \
				arch="$${platform#*/}"; \
				if [ "$$arch" = "$$platform" ]; then arch="$(MACOS_CLIENT_ARCH)"; fi; \
				name="macos-$$arch"; \
				$(MAKE) package-mac MACOS_PLATFORMS="$$platform" MACOS_CLIENT_ARCH="$$arch"; \
				$(MAKE) stage-artifacts PLATFORM="all/$$name"; \
			done; \
		else \
			printf 'Skipping macOS packages: Wails macOS packaging must run on a macOS host; current host is %s.\n' "$(GOOS_VALUE)" >&2; \
		fi; \
	fi
	@set -e; \
	for platform in $$(printf '%s' "$(ALL_WINDOWS_PLATFORMS)" | tr ',' ' '); do \
		arch="$${platform#*/}"; \
		if [ "$$arch" = "$$platform" ]; then arch="$(WINDOWS_CLIENT_ARCH)"; fi; \
		case "$$arch" in \
			amd64) name="windows-x64";; \
			arm64) name="windows-arm64-windows-on-arm";; \
			*) name="windows-$$arch";; \
		esac; \
		$(MAKE) package-windows WINDOWS_PLATFORMS="$$platform" WINDOWS_CLIENT_ARCH="$$arch"; \
		$(MAKE) stage-artifacts PLATFORM="all/$$name"; \
	done
	@if [ "$(GOOS_VALUE)" = "linux" ]; then \
		set -e; \
		for platform in $$(printf '%s' "$(ALL_LINUX_PLATFORMS)" | tr ',' ' '); do \
			arch="$${platform#*/}"; \
			if [ "$$arch" = "$$platform" ]; then arch="$(LINUX_CLIENT_ARCH)"; fi; \
			$(MAKE) package-linux-distros LINUX_PLATFORMS="$$platform" LINUX_CLIENT_ARCH="$$arch" LINUX_ASSET_SUFFIX="linux-$$arch" LINUX_PACKAGE_OUTPUT_DIR="build/releases/all"; \
			$(MAKE) stage-artifacts PLATFORM="all/linux-$$arch"; \
		done; \
	elif [ -n "$(ALL_LINUX_PLATFORMS)" ]; then \
		$(MAKE) package-linux-all-docker; \
	fi

check-linux-builder:
	@if [ "$(GOOS_VALUE)" != "linux" ] && [ -n "$(ALL_LINUX_PLATFORMS)" ]; then \
		if ! command -v "$(LINUX_DOCKER)" >/dev/null 2>&1; then \
			printf 'Docker is required to build Linux packages from this host. Install Docker, run make all on Linux, or set ALL_LINUX_PLATFORMS= to skip Linux.\n' >&2; \
			exit 1; \
		fi; \
		if ! "$(LINUX_DOCKER)" info >/dev/null 2>&1; then \
			printf 'Docker is installed but the daemon is not running. Start Docker, run make all on Linux, or set ALL_LINUX_PLATFORMS= to skip Linux.\n' >&2; \
			exit 1; \
		fi; \
	fi

frontend-build:
	npm run build --prefix frontend

backend-build: frontend-build
	go build -o build/bin/whitevpn-desktop .

prepare-package:
	mkdir -p "$(GO_BUILD_CACHE)"
	rm -rf build/bin

prepare-macos-go-env: prepare-package
	@printf '%s\n' \
		'GOCACHE=$(GO_BUILD_CACHE)' \
		'CGO_LDFLAGS=-O2 $(MACOS_CGO_LDFLAGS)' \
		> "$(GO_ENV_FILE)"

validate-version:
	@if [ -z "$(APP_VERSION)" ]; then \
		printf 'VERSION is required\n' >&2; \
		exit 1; \
	fi; \
	case "$(APP_VERSION)" in \
		*[!A-Za-z0-9._+-]* ) \
			printf 'Invalid VERSION "%s"; use only letters, numbers, dot, underscore, plus, and hyphen\n' "$(APP_VERSION)" >&2; \
			exit 1; \
			;; \
	esac

package: validate-version
	@if [ "$(GOOS_VALUE)" = "darwin" ]; then \
		$(MAKE) package-mac; \
	else \
		$(MAKE) prepare-package; \
		$(MAKE) prepare-embedded-core TARGET_GOOS="$(GOOS_VALUE)" TARGET_GOARCH="$(GOARCH_VALUE)"; \
		GOCACHE="$(GO_BUILD_CACHE)" $(WAILS) build $(WAILS_RELEASE_FLAGS) $(WAILS_OPTIONAL_UPX_FLAGS); \
		$(MAKE) package-assets; \
	fi

# The engine that travels inside the app. mihomo is the only one now, so this
# makes sure it is built for the target rather than fetching a second core.
prepare-embedded-core:
	@if [ -z "$(TARGET_GOOS)" ] || [ -z "$(TARGET_GOARCH)" ]; then \
		printf 'TARGET_GOOS and TARGET_GOARCH are required\n' >&2; \
		exit 1; \
	fi
	@set -e; \
	core="mihomo-$(TARGET_GOOS)-$(TARGET_GOARCH)"; \
	if [ "$(TARGET_GOOS)" = "windows" ]; then core="$$core.exe"; fi; \
	if [ ! -f "cores/$$core" ]; then \
		$(MAKE) mihomo-core TARGET_GOOS="$(TARGET_GOOS)" TARGET_GOARCH="$(TARGET_GOARCH)"; \
	fi; \
	chmod 755 "cores/$$core"; \
	printf 'Embedding engine %s\n' "cores/$$core"

prepare-embedded-platform:
	@if [ -z "$(TARGET_GOOS)" ] || [ -z "$(TARGET_GOARCH)" ]; then \
		printf 'TARGET_GOOS and TARGET_GOARCH are required\n' >&2; \
		exit 1; \
	fi
	$(MAKE) xray-core-target TARGET_GOOS="$(TARGET_GOOS)" TARGET_GOARCH="$(TARGET_GOARCH)"
	@set -e; \
	core="xray-$(TARGET_GOOS)-$(TARGET_GOARCH)"; \
	if [ "$(TARGET_GOOS)" = "windows" ]; then core="$$core.exe"; fi; \
	cp "$(XRAY_CACHE_DIR)/$$core" "cores/$$core"; \
	chmod 755 "cores/$$core"; \
	cp "$(XRAY_CACHE_DIR)/geoip.dat" "cores/geoip.dat"; \
	cp "$(XRAY_CACHE_DIR)/geosite.dat" "cores/geosite.dat"; \
	if [ "$(TARGET_GOOS)" = "windows" ]; then \
		if [ ! -f "$(XRAY_CACHE_DIR)/wintun.dll" ]; then \
			printf 'Windows Xray TUN support requires %s\n' "$(XRAY_CACHE_DIR)/wintun.dll" >&2; \
			exit 1; \
		fi; \
		cp "$(XRAY_CACHE_DIR)/wintun.dll" "cores/wintun.dll"; \
		chmod 644 "cores/wintun.dll"; \
	fi; \
	printf 'Prepared embedded Xray core %s\n' "cores/$$core"

prepare-embedded-platforms:
	@if [ -z "$(TARGET_PLATFORMS)" ]; then \
		printf 'TARGET_PLATFORMS is required\n' >&2; \
		exit 1; \
	fi
	rm -rf cores
	mkdir -p cores
	@: > cores/.keep
	@set -e; \
	for platform in $$(printf '%s' "$(TARGET_PLATFORMS)" | tr ',' ' '); do \
		target_goos="$${platform%/*}"; \
		target_goarch="$${platform#*/}"; \
		if [ "$$target_goos" = "$$target_goarch" ]; then \
			target_goarch="$(GOARCH_VALUE)"; \
		fi; \
		case "$$target_goarch" in \
			universal) \
				$(MAKE) prepare-embedded-platform TARGET_GOOS="$$target_goos" TARGET_GOARCH=arm64; \
				$(MAKE) prepare-embedded-platform TARGET_GOOS="$$target_goos" TARGET_GOARCH=amd64; \
				;; \
			*) \
				$(MAKE) prepare-embedded-platform TARGET_GOOS="$$target_goos" TARGET_GOARCH="$$target_goarch"; \
				;; \
		esac; \
	done

prepare-embedded-macos-cores:
	$(MAKE) prepare-embedded-core TARGET_GOOS=darwin TARGET_GOARCH="$(MACOS_CLIENT_ARCH)"

package-mac: validate-version prepare-macos-go-env frontend-build
	@case "$(MACOS_PLATFORMS)" in \
		*universal*) \
			$(MAKE) prepare-embedded-core TARGET_GOOS=darwin TARGET_GOARCH=amd64; \
			MACOSX_DEPLOYMENT_TARGET="$(MACOS_DEPLOYMENT_TARGET_AMD64)" GOENV="$(GO_ENV_FILE)" GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags "$(MACOS_GO_TAGS)" -ldflags "$(MACOS_GO_LDFLAGS)" -o "build/bin/$(APP_NAME)-amd64" .; \
			$(MAKE) prepare-embedded-core TARGET_GOOS=darwin TARGET_GOARCH=arm64; \
			MACOSX_DEPLOYMENT_TARGET="$(MACOS_DEPLOYMENT_TARGET_ARM64)" GOENV="$(GO_ENV_FILE)" GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags "$(MACOS_GO_TAGS)" -ldflags "$(MACOS_GO_LDFLAGS)" -o "build/bin/$(APP_NAME)-arm64" .; \
			lipo -create -output "build/bin/$(APP_NAME)" "build/bin/$(APP_NAME)-amd64" "build/bin/$(APP_NAME)-arm64"; \
			rm -f "build/bin/$(APP_NAME)-amd64" "build/bin/$(APP_NAME)-arm64"; \
			;; \
		*) \
			target_arch="$(MACOS_CLIENT_ARCH)"; \
			platform="$(MACOS_PLATFORMS)"; \
			case "$$platform" in darwin/*) target_arch="$${platform#*/}";; esac; \
			if [ -z "$$target_arch" ] || [ "$$target_arch" = "universal" ]; then \
				printf 'Invalid macOS target architecture: %s\n' "$$target_arch" >&2; \
				exit 1; \
			fi; \
			deployment_target="$(MACOS_DEPLOYMENT_TARGET_AMD64)"; \
			if [ "$$target_arch" = "arm64" ]; then deployment_target="$(MACOS_DEPLOYMENT_TARGET_ARM64)"; fi; \
			$(MAKE) prepare-embedded-core TARGET_GOOS=darwin TARGET_GOARCH="$$target_arch"; \
			MACOSX_DEPLOYMENT_TARGET="$$deployment_target" GOENV="$(GO_ENV_FILE)" GOOS=darwin GOARCH="$$target_arch" CGO_ENABLED=1 go build -buildvcs=false -trimpath -tags "$(MACOS_GO_TAGS)" -ldflags "$(MACOS_GO_LDFLAGS)" -o "build/bin/$(APP_NAME)" .; \
			;; \
	esac
	$(MAKE) macos-app-bundle
	$(MAKE) package-assets

macos-app-bundle:
	mkdir -p "$(MACOS_APP_BIN_DIR)" "$(MACOS_APP_RESOURCES_DIR)"
	cp "build/bin/$(APP_NAME)" "$(MACOS_APP_EXECUTABLE)"
	chmod 755 "$(MACOS_APP_EXECUTABLE)"
	@{ \
		printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'; \
		printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'; \
		printf '%s\n' '<plist version="1.0">'; \
		printf '%s\n' '<dict>'; \
		printf '%s\n' '  <key>CFBundlePackageType</key><string>APPL</string>'; \
		printf '%s\n' '  <key>CFBundleName</key><string>$(APP_NAME)</string>'; \
		printf '%s\n' '  <key>CFBundleExecutable</key><string>$(APP_NAME)</string>'; \
		printf '%s\n' '  <key>CFBundleIdentifier</key><string>com.whitedns.vpn</string>'; \
		printf '%s\n' '  <key>CFBundleIconFile</key><string>appicon.icns</string>'; \
		printf '%s\n' '  <key>CFBundleVersion</key><string>$(APP_VERSION)</string>'; \
		printf '%s\n' '  <key>CFBundleShortVersionString</key><string>$(APP_VERSION)</string>'; \
		printf '%s\n' '  <key>LSMinimumSystemVersion</key><string>$(MACOS_BUNDLE_MIN_VERSION)</string>'; \
		printf '%s\n' '  <key>NSHighResolutionCapable</key><true/>'; \
		printf '%s\n' '</dict>'; \
		printf '%s\n' '</plist>'; \
	} > "$(MACOS_APP_INFO_PLIST)"
	cp "build/appicon.icns" "$(MACOS_APP_RESOURCES_DIR)/appicon.icns"
	rm -f "build/bin/$(APP_NAME)"

package-windows: validate-version prepare-package
	$(MAKE) prepare-embedded-core TARGET_GOOS=windows TARGET_GOARCH="$(WINDOWS_CLIENT_ARCH)"
	GOCACHE="$(GO_BUILD_CACHE)" $(WAILS) build -clean $(WAILS_RELEASE_FLAGS) $(WAILS_OPTIONAL_UPX_FLAGS) -platform $(WINDOWS_PLATFORMS)
	$(MAKE) package-assets

package-linux: validate-version prepare-package
	@if [ "$(GOOS_VALUE)" != "linux" ]; then \
		printf 'Wails Linux packaging must run on a Linux host; current host is %s. Use this target in a Linux CI/job.\n' "$(GOOS_VALUE)" >&2; \
		exit 1; \
	fi
	$(MAKE) prepare-embedded-core TARGET_GOOS=linux TARGET_GOARCH="$(LINUX_CLIENT_ARCH)"
	GOCACHE="$(GO_BUILD_CACHE)" $(WAILS) build -clean $(WAILS_RELEASE_FLAGS) $(LINUX_WAILS_TAG_FLAGS) $(WAILS_OPTIONAL_UPX_FLAGS) -platform $(LINUX_PLATFORMS)
	$(MAKE) package-assets

package-linux-distros: package-linux
	APP_NAME="$(APP_NAME)" VERSION="$(APP_VERSION)" PACKAGE_SOURCE_DIR="build/bin" PACKAGE_OUTPUT_DIR="$(LINUX_PACKAGE_OUTPUT_DIR)" LINUX_ARCH="$(LINUX_CLIENT_ARCH)" LINUX_WEBKIT="$(LINUX_WEBKIT)" LINUX_ASSET_SUFFIX="$(LINUX_ASSET_SUFFIX)" LINUX_PACKAGE_FORMATS="$(LINUX_PACKAGE_FORMATS)" ./scripts/package-linux-dist.sh

package-linux-all-docker: validate-version
	VERSION="$(APP_VERSION)" ALL_LINUX_PLATFORMS="$(ALL_LINUX_PLATFORMS)" LINUX_DOCKER="$(LINUX_DOCKER)" LINUX_DOCKER_IMAGE="$(LINUX_DOCKER_IMAGE)" LINUX_NODE_MAJOR="$(LINUX_NODE_MAJOR)" LINUX_PACKAGE_FORMATS="$(LINUX_PACKAGE_FORMATS)" RELEASE_LDFLAGS="$(RELEASE_LDFLAGS)" HELPER_GO_LDFLAGS="$(HELPER_GO_LDFLAGS)" UPX="$(UPX)" UPX_FLAGS="$(UPX_FLAGS)" ./scripts/build-linux-releases-docker.sh

package-linux-fedora-rpm-docker: validate-version
	VERSION="$(APP_VERSION)" LINUX_DOCKER="$(LINUX_DOCKER)" LINUX_CLIENT_ARCH="$(LINUX_CLIENT_ARCH)" RELEASE_LDFLAGS="$(RELEASE_LDFLAGS)" HELPER_GO_LDFLAGS="$(HELPER_GO_LDFLAGS)" UPX="$(UPX)" UPX_FLAGS="$(UPX_FLAGS)" ./scripts/build-fedora-rpm-docker.sh

package-all: all

stage-artifacts:
	@if [ -z "$(PLATFORM)" ]; then \
		printf 'PLATFORM is required\n' >&2; \
		exit 1; \
	fi; \
	if [ ! -d "build/bin" ]; then \
		printf 'build/bin does not exist; run a package target first\n' >&2; \
		exit 1; \
	fi; \
	rm -rf "build/releases/$(PLATFORM)"; \
	mkdir -p "build/releases/$(PLATFORM)"; \
	cp -R build/bin/. "build/releases/$(PLATFORM)/"; \
	case "$(PLATFORM)" in \
		*windows-x64*|*windows-amd64*) \
			printf '%s\n' \
				'WhiteDNS Desktop for Windows x64' \
				'' \
				'Use this build for normal 64-bit Windows 10/11 PCs with Intel or AMD processors.' \
				'If your Windows Settings page says 64-bit but your processor is Intel or AMD, this is the correct package.' \
				'' \
				'Do not use the ARM64 package unless this PC is specifically Windows on ARM, such as Snapdragon/Surface Pro X.' \
				> "build/releases/$(PLATFORM)/README-Windows.txt"; \
			;; \
		*windows-arm64*) \
			printf '%s\n' \
				'WhiteDNS Desktop for Windows on ARM' \
				'' \
				'Use this build only for Windows on ARM devices, such as Snapdragon-based PCs or Surface Pro X.' \
				'This ARM64 executable will show "This app cannot run on your PC" on normal Intel/AMD 64-bit Windows.' \
				'' \
				'For most 64-bit Windows 10/11 PCs, download the Windows x64 package instead.' \
				> "build/releases/$(PLATFORM)/README-Windows.txt"; \
			;; \
		*linux*) \
			printf '%s\n' \
				'WhiteDNS Desktop for Linux' \
				'' \
				'Use the AppImage on Linux x64 when you want a single-file download without installing a distro package.' \
				'Use the .deb package on Debian or Ubuntu and the .rpm package on RPM-based distributions when available.' \
				'For newer RPM distributions, prefer the webkit41 RPM asset.' \
				'The tar.gz archive is a portable fallback and requires GTK 3 plus the matching WebKitGTK runtime package from your distribution.' \
				'' \
				'Launch the AppImage after making it executable, run "./WhiteDNS Desktop" from this directory, or install a distro package to add a desktop entry.' \
				> "build/releases/$(PLATFORM)/README-Linux.txt"; \
			;; \
	esac; \
	find "build/releases/$(PLATFORM)" -name .DS_Store -delete; \
	printf 'Staged %s artifacts in build/releases/%s\n' "$(PLATFORM)" "$(PLATFORM)"
	$(MAKE) archive-artifacts PLATFORM="$(PLATFORM)"

archive-artifacts: validate-version
	@if [ -z "$(PLATFORM)" ]; then \
		printf 'PLATFORM is required\n' >&2; \
		exit 1; \
	fi; \
	if [ ! -d "build/releases/$(PLATFORM)" ]; then \
		printf 'build/releases/%s does not exist; run stage-artifacts first\n' "$(PLATFORM)" >&2; \
		exit 1; \
	fi; \
	if ! command -v zip >/dev/null 2>&1; then \
		printf 'zip is required to create compressed release assets\n' >&2; \
		exit 1; \
	fi; \
	set -e; \
	stage_dir="build/releases/$(PLATFORM)"; \
	stage_parent=$$(dirname "$$stage_dir"); \
	stage_name=$$(basename "$$stage_dir"); \
	archive_platform="$(PLATFORM)"; \
	archive_platform="$${archive_platform#all/}"; \
	archive_name="$(RELEASE_ASSET_PREFIX)-$(APP_VERSION)-$$archive_platform.zip"; \
	rm -f "$$stage_parent/$$archive_name"; \
	( cd "$$stage_parent" && zip -qry "$$archive_name" "$$stage_name" ); \
	printf 'Created compressed artifact %s\n' "$$stage_parent/$$archive_name"

package-helper: xray-core package-assets

package-assets:
	@printf 'Runtime helpers and proxy cores are embedded in the app binary\n'

test: test-backend test-frontend

test-backend:
	go test ./...

test-frontend:
	npm run build --prefix frontend

# The mihomo engine, pinned to the same refs WhiteVPN for Android builds.
mihomo-core-setup:
	./scripts/setup-mihomo-core.sh

mihomo-core: mihomo-core-setup
	TARGET_GOOS="$(TARGET_GOOS)" TARGET_GOARCH="$(TARGET_GOARCH)" ./scripts/build-mihomo-core.sh

xray-core:
	$(MAKE) prepare-embedded-core TARGET_GOOS=$(GOOS_VALUE) TARGET_GOARCH=$(GOARCH_VALUE)

xray-core-all:
	$(MAKE) xray-core-target TARGET_GOOS=darwin TARGET_GOARCH=arm64
	$(MAKE) xray-core-target TARGET_GOOS=darwin TARGET_GOARCH=amd64
	$(MAKE) xray-core-target TARGET_GOOS=windows TARGET_GOARCH="$(WINDOWS_CLIENT_ARCH)"
	$(MAKE) xray-core-target TARGET_GOOS=linux TARGET_GOARCH="$(LINUX_CLIENT_ARCH)"

xray-core-target:
	@if [ -z "$(TARGET_GOOS)" ] || [ -z "$(TARGET_GOARCH)" ]; then \
		printf 'TARGET_GOOS and TARGET_GOARCH are required\n' >&2; \
		exit 1; \
	fi
	@set -e; \
	core="xray-$(TARGET_GOOS)-$(TARGET_GOARCH)"; \
	if [ "$(TARGET_GOOS)" = "windows" ]; then core="$$core.exe"; fi; \
	mkdir -p "$(XRAY_CACHE_DIR)"; \
	cache_ready=1; \
	for asset in "$$core" geoip.dat geosite.dat; do \
		if [ ! -f "$(XRAY_CACHE_DIR)/$$asset" ]; then cache_ready=0; fi; \
	done; \
	if [ "$(TARGET_GOOS)" = "windows" ] && [ ! -f "$(XRAY_CACHE_DIR)/wintun.dll" ]; then cache_ready=0; fi; \
	if [ "$$cache_ready" = "1" ]; then \
		printf 'Using cached Xray core %s\n' "$(XRAY_CACHE_DIR)/$$core"; \
	elif [ -f "cores/$$core" ]; then \
		cp "cores/$$core" "$(XRAY_CACHE_DIR)/$$core"; \
		if [ -f "cores/geoip.dat" ]; then cp "cores/geoip.dat" "$(XRAY_CACHE_DIR)/geoip.dat"; fi; \
		if [ -f "cores/geosite.dat" ]; then cp "cores/geosite.dat" "$(XRAY_CACHE_DIR)/geosite.dat"; fi; \
		if [ "$(TARGET_GOOS)" = "windows" ] && [ -f "cores/wintun.dll" ]; then cp "cores/wintun.dll" "$(XRAY_CACHE_DIR)/wintun.dll"; fi; \
		chmod 755 "$(XRAY_CACHE_DIR)/$$core"; \
		if [ ! -f "$(XRAY_CACHE_DIR)/geoip.dat" ] || [ ! -f "$(XRAY_CACHE_DIR)/geosite.dat" ] || { [ "$(TARGET_GOOS)" = "windows" ] && [ ! -f "$(XRAY_CACHE_DIR)/wintun.dll" ]; }; then \
			TARGET_GOOS="$(TARGET_GOOS)" TARGET_GOARCH="$(TARGET_GOARCH)" XRAY_DEST_DIR="$(XRAY_CACHE_DIR)" XRAY_CORE_VERSION="$(XRAY_CORE_VERSION)" ./scripts/install-xray-core.sh; \
		fi; \
		printf 'Cached existing Xray core %s\n' "$(XRAY_CACHE_DIR)/$$core"; \
	else \
		TARGET_GOOS="$(TARGET_GOOS)" TARGET_GOARCH="$(TARGET_GOARCH)" XRAY_DEST_DIR="$(XRAY_CACHE_DIR)" XRAY_CORE_VERSION="$(XRAY_CORE_VERSION)" ./scripts/install-xray-core.sh; \
	fi

clean:
	rm -rf build cores .cache
	mkdir -p cores
	@: > cores/.keep

--version:
	@:

ifneq ($(VERSION_FROM_ARGS),)
$(VERSION_FROM_ARGS):
	@:
endif
