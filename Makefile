SHELL := /bin/sh

DEFAULT_VERSION := 1.0.0-beta6
VERSION_FROM_ARGS := $(shell set -- $(MAKECMDGOALS); while [ "$$1" != "" ]; do if [ "$$1" = "--version" ]; then shift; if [ "$$1" != "" ]; then printf '%s' "$$1"; fi; exit; fi; shift; done)
VERSION ?= $(if $(VERSION_FROM_ARGS),$(VERSION_FROM_ARGS),$(DEFAULT_VERSION))
APP_VERSION := $(strip $(VERSION))
DESKTOP_MAKE := $(MAKE) -C desktop VERSION="$(APP_VERSION)"

ifeq ($(filter --version,$(MAKECMDGOALS)),--version)
ifeq ($(VERSION_FROM_ARGS),)
$(error --version requires a value; use `make all -- --version 1.0.0-beta6`)
endif
endif

.PHONY: help deps dev build build-mac build-windows build-linux build-all all package package-mac package-windows package-linux package-linux-distros package-linux-all-docker package-linux-fedora-rpm-docker package-all test test-desktop clean --version
ifneq ($(VERSION_FROM_ARGS),)
.PHONY: $(VERSION_FROM_ARGS)
endif

help:
	@printf '%s\n' \
		'WhiteVPN Desktop development targets:' \
		'' \
		'  make deps             Install desktop frontend dependencies and tidy Go modules' \
		'  make dev              Run the Wails desktop app in dev mode' \
		'  make build            Build frontend and compile the desktop app' \
		'  make build-mac        Build/package the macOS desktop app' \
		'  make build-windows    Build/package the Windows desktop app' \
		'  make build-linux      Build/package the Linux desktop app' \
		'  make build-all        Build release packages for the desktop matrix' \
		'  make all              Build minified packages for the desktop release matrix' \
		'  make package          Build package with the matching embedded Xray core' \
		'  make package-linux-distros  Build Linux .deb/.rpm packages on a Linux host' \
		'  make package-linux-all-docker  Build Linux release packages through Docker' \
		'  make package-linux-fedora-rpm-docker  Build Fedora 42+ compatible WebKitGTK 4.1 RPM' \
		'  make package-all      Alias for build-all' \
		'  make all VERSION=1.0.0-beta6         Build release assets with this version' \
		'  make all -- --version 1.0.0-beta6    Alternate flag form' \
		'  make test             Run desktop Go tests' \
		'  make test-desktop     Run desktop backend tests' \
		'  make clean            Remove generated desktop build output'

deps:
	$(DESKTOP_MAKE) deps

dev:
	$(DESKTOP_MAKE) dev

build:
	$(DESKTOP_MAKE) build

build-mac:
	$(DESKTOP_MAKE) package-mac

build-windows:
	$(DESKTOP_MAKE) package-windows

build-linux:
	$(DESKTOP_MAKE) package-linux

build-all:
	$(DESKTOP_MAKE) all

all:
	$(DESKTOP_MAKE) all

package:
	$(DESKTOP_MAKE) package

package-mac: build-mac

package-windows: build-windows

package-linux: build-linux

package-linux-distros:
	$(DESKTOP_MAKE) package-linux-distros

package-linux-all-docker:
	$(DESKTOP_MAKE) package-linux-all-docker

package-linux-fedora-rpm-docker:
	$(DESKTOP_MAKE) package-linux-fedora-rpm-docker

package-all: all

test: test-desktop

test-desktop:
	$(DESKTOP_MAKE) test

clean:
	$(DESKTOP_MAKE) clean

--version:
	@:

ifneq ($(VERSION_FROM_ARGS),)
$(VERSION_FROM_ARGS):
	@:
endif
