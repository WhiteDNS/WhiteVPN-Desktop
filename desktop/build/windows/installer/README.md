# The Windows installer

`whitevpn.wxs` is the whole of it. There is one payload — the engine, wintun and
the frontend are embedded in the executable — so the install is that file plus
the shortcuts that make it findable, and the uninstall entry that makes it
removable.

## Building one

    dotnet tool install --global wix --version 5.0.2
    wix extension add -g WixToolset.UI.wixext/5.0.2
    wix extension add -g WixToolset.Util.wixext/5.0.2
    make -C desktop VERSION=1.0.23 package-windows-msi

It needs an executable in `desktop/build/bin` already, and it only runs on
Windows: WiX is a .NET tool and produces MSIs nowhere else. That is why the
release workflow builds this in its own job while every other Windows artifact
is cross-compiled from macOS.

## Two things worth knowing

**WiX is pinned to v5.** From v7 it refuses to run without accepting the Open
Source Maintenance Fee EULA, which is a licensing decision rather than one a
build script should make on anybody's behalf. v5 is MS-RL and has no such gate.

**A pre-release installs under its release number.** An MSI ProductVersion is
three numbers — Windows compares them to decide what is an upgrade and has no
idea what `-rc1` means — so `1.0.23-rc1.msi` carries ProductVersion `1.0.23`.
Two pre-releases of one version are therefore the same version to Windows, and
the second repairs over the first rather than upgrading it. Right for a test
build; wrong to discover by surprise.
