# TUN and Linux proxy support plan

Status: proposed  
Source audit: 2026-08-22

## Outcome

WhiteVPN can remove the current platform limitations, but they are three
different jobs:

1. Linux desktop proxy configuration already exists. It needs accurate status,
   per-backend restore semantics and real desktop-session tests.
2. Linux has a `pkexec` launcher, but TUN is still hidden and its elevated path
   is not ready to expose safely. It needs a trusted core/helper, reliable
   lifecycle control and Linux route verification.
3. macOS has no TUN launcher. The minimum-change design is a signed launch
   daemon registered with `SMAppService`; `SMJobBless` is deprecated. This work
   depends on a stable code-signing identity. Notarisation improves release
   installation and Gatekeeper behaviour, but is not an implementation blocker.

Proxy-only mode remains the fallback everywhere. A bare Linux window manager
cannot be made to honour a desktop proxy preference that it does not have, and
programs that ignore GNOME or KDE preferences cannot be transparently captured
without TUN.

## What the source does today

| Area | Current source | Gap |
|---|---|---|
| TUN capability | `desktop/tunnel_support.go` returns true only on Windows and `settingsForThisMachine` drops TUN elsewhere. | Linux's launcher cannot be reached; macOS has no launcher. |
| Linux elevation | `internal/engine/elevate_linux.go` starts the core with `pkexec`. | The path can come from `WHITEVPN_MIHOMO_BIN` or a user-writable extracted core; shutdown fallback only kills `pkexec`; no live TUN test exists. |
| macOS elevation | `internal/engine/elevate_other.go` refuses elevated startup on macOS. | No registered helper/service, authenticated IPC, packaging, signing or approval flow. |
| Tunnel verification | `internal/session/tun_other.go` marks every non-Windows tunnel unverifiable. | Linux and macOS can report connected without proving the adapter and IPv4/IPv6 routes exist. |
| Linux proxy | `internal/sysproxy/sysproxy_linux.go` writes GNOME and KDE backends and verifies a readback. | Unit tests cover argument construction only; capability reporting, mixed-backend restore and live-session coverage are missing. |
| Proxy recovery | `desktop/system_proxy.go` persists one `sysproxy.State` before applying a change. | Linux can have distinct GNOME/KDE states, and macOS distinct states per network service; restoring one state to all of them can overwrite a user's earlier configuration. |
| Packaging | Arch names polkit as optional; `.deb`, `.rpm`, AppImage and tar packages do not install a privileged helper or policy. | Package type must determine whether secure TUN is available. |

This also explains the contradictory repository text: Linux proxy support was
added after the top-level limitation was written, and the Linux TUN launcher was
added after the Windows-only capability gate without changing that gate.

## Design rules

- Never run the Wails UI as root.
- Enforce signing only where the operating system or a privileged trust boundary
  requires it. Do not make Windows or Linux TUN wait for macOS signing or
  notarisation. Linux uses root ownership, non-writable modes and package
  integrity; Windows keeps its existing explicit UAC approval model.
- Never elevate an executable chosen through an environment variable or stored
  in a user-writable directory.
- Treat the UI-to-privileged-component channel as a security boundary. Authenticate
  its peer and expose a narrow request schema; do not offer an arbitrary command,
  executable path, working directory or shell string.
- Do not label a tunnel connected until the proxy health check succeeds and the
  expected IPv4 routes exist. If the host has routable IPv6 and IPv6 TUN is
  enabled, require IPv6 coverage too.
- Record the exact proxy state of every backend before changing any of them and
  restore each backend independently after disconnect or crash.
- Report capabilities with a reason. “Unsupported,” “helper not installed,”
  “approval required,” and “available” lead to different user actions.
- Portable Linux artifacts may remain proxy-only if they cannot install a
  root-owned component safely. Do not weaken the privilege boundary to make a
  checkbox appear.

## Workstream A — capabilities and proxy state

This is the first implementation milestone because later work needs more than
the current `TunnelSupported() bool`.

1. Add a backend capability result, for example:

       RoutingCapabilities {
         Tunnel: { Status, Reason, RequiresApproval }
         SystemProxy: { Status, Scope, Backends, Reason }
       }

   Keep `TunnelSupported()` temporarily as a compatibility wrapper for the
   frontend, then remove it after the UI moves to the structured result.
2. Show the available routing modes and an actionable explanation in Settings.
   On a bare window manager, keep system-proxy mode selectable only if the UI
   clearly says that applications must be configured manually; alternatively
   collapse it into the existing proxy-only mode.
3. Version the on-disk proxy backup and replace the single `State` with a
   platform snapshot:

   - Windows: the existing WinINET state.
   - Linux: one state per successfully probed GNOME/KDE backend.
   - macOS: one state per enabled network service.

4. Make apply transactional: capture all states, persist the snapshot, apply
   every target, verify each target that was successfully changed, and roll
   those targets back if the operation fails. Retain the snapshot until every
   changed target is restored.
5. On Linux, probe the backend itself rather than only checking whether its
   executable is on `PATH`. A machine can have `gsettings` installed without a
   usable schema/session, or KDE writers without the matching reader.
6. Add live integration tests for GNOME, KDE Plasma 5/6, both toolsets installed,
   and a minimal window-manager session. Test connect, disconnect, crash/restart
   recovery, a pre-existing disabled proxy, and distinct pre-existing backend
   values.

Acceptance:

- GNOME and KDE applications that honour desktop proxy settings use the mixed
  proxy and return to their exact prior configuration after a clean disconnect
  and after simulated app termination.
- A partially working backend does not cause another successfully configured
  backend to fail verification.
- A bare window manager gets a truthful manual endpoint and no success badge
  claiming that a system setting changed.

## Workstream B — Linux TUN

Do not enable Linux by changing `runtime.GOOS == "windows"` to include
`"linux"`. Complete the privilege and verification work first.

1. Define the supported distribution model:

   - `.deb`, `.rpm` and Arch packages install a fixed, root-owned helper and/or
     core under `/usr/libexec/whitevpn-desktop` (distribution-appropriate paths
     may differ) plus a polkit action.
   - AppImage and tar builds remain proxy-only until a separate, checksummed
     helper installer is designed. Their capability reason should say this.

2. Make the privileged entry point accept only `start-tunnel` with validated
   values. It must resolve a fixed root-owned core, reject symlinks and
   group/world-writable files, constrain the socket to the invoking user's
   runtime directory, verify socket ownership, and clear the environment.
3. Do not honour `WHITEVPN_MIHOMO_BIN` for elevated sessions. Keep it for
   unelevated development and proxy-mode tests only.
4. Have the helper supervise the core. If the UI socket closes, the UI exits, or
   a startup deadline expires, request a clean engine shutdown and then terminate
   the root child. The UI must not depend on killing the intermediate `pkexec`
   process.
5. Implement Linux adapter and route verification without parsing localised
   desktop command output. Verify interface-up state plus IPv4 and conditional
   IPv6 coverage using netlink or kernel route files behind a small testable
   interface.
6. Add startup recovery for an orphaned helper/core and stale routes. Recovery
   must identify only WhiteVPN-owned processes and interfaces; it must never
   delete an arbitrary similarly named interface.
7. Package polkit metadata and helper files with root ownership and non-writable
   modes. Add package tests that unpack each artifact and assert paths, owners,
   modes, action IDs and executable hashes.
8. Only then return Linux TUN as available and stop dropping the saved setting.
   Roll it out behind an experimental flag for one release.

Live acceptance matrix:

- Ubuntu/Debian, Fedora and Arch; amd64 and arm64 where runners or hardware are
  available.
- Polkit agent present, `pkexec` absent, approval declined, non-admin user, and
  stale helper version.
- IPv4-only, dual-stack, network change while connected, sleep/wake, clean
  disconnect, forced UI exit and forced core hang.
- Confirm public IPv4/IPv6 through the selected node, DNS through the configured
  resolver, local-network bypass where requested, and no remaining TUN routes or
  root process after disconnect.

## Workstream C — macOS TUN

### Recommended architecture

Use a launch daemon registered with `SMAppService` on macOS 13 and newer. Apple
documents `SMJobBless` as deprecated in favour of `SMAppService`. Keep proxy mode
available on older supported macOS versions, but report TUN as requiring macOS
13+ unless the project deliberately accepts the cost of an `SMJobBless` legacy
fallback.

The minimum-change path keeps the existing mihomo TUN configuration and engine
protocol:

1. Add a small native service-management bridge and a signed privileged daemon
   to the app bundle. The daemon launches only the bundled, signed mihomo core.
2. Register the daemon, surface `not registered`, `awaiting approval`, `enabled`
   and `version mismatch` states, and guide the user to the macOS approval UI.
3. Use authenticated XPC for UI-to-daemon control. Validate the caller's audit
   token and designated code requirement, use a versioned message protocol, and
   expose start/status/stop only. Subscription content and arbitrary filesystem
   paths should not cross this administrative API.
4. Make the daemon own and supervise the privileged core so it can guarantee
   shutdown after an app crash or IPC loss.
5. Implement macOS TUN discovery and route verification. Do not assume the
   configured `utun20` name is the interface the kernel ultimately assigns;
   obtain or discover the actual interface and verify IPv4 plus conditional IPv6
   routes.
6. Update the app bundle to include the daemon, launchd plist and helper/core in
   their required locations. Sign nested code in dependency order, enable the
   hardened runtime and sign the containing app. Notarise and staple public
   release artifacts when release policy and credentials allow it; do not block
   local development or the Linux/Windows work on notarisation.
7. Add upgrade handling: register a new helper version safely, refuse incompatible
   UI/helper protocols, and preserve a working old helper until replacement is
   approved.

Code signing is a prerequisite for the macOS privileged-service identity, not a
project-wide TUN prerequisite. `SMAppService` protects helpers by keeping service
metadata inside the signed application bundle, and the UI/helper authentication
design needs stable identities on both sides. Notarisation is a separate macOS
distribution control: strongly recommended for releases, but not required to
develop the helper and never a gate for Linux or Windows.

### Alternative: Network Extension

Apple's native VPN architecture is a `NEPacketTunnelProvider`. It gives macOS
ownership of the virtual interface, routing and lifecycle, and is the better
long-term design if WhiteVPN later wants system-integrated VPN status or an App
Store path. It is not the first milestone here: the current desktop engine asks
mihomo to create TUN itself and does not expose a packet-flow/file-descriptor
entry point, so adopting Network Extension requires a native extension and a
new packet bridge or library integration rather than just another launcher.

Decision gate: prototype both approaches only far enough to prove that the
bundled mihomo core can be supervised reliably by the launch daemon. Choose
Network Extension instead if helper-based routing is unstable on the minimum
supported macOS release or if App Store distribution becomes a requirement.

Apple references:

- [SMAppService registration](https://developer.apple.com/documentation/servicemanagement/smappservice/register())
- [Apple's migration guidance for the current Service Management API](https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api)
- [SMJobBless deprecation](https://developer.apple.com/documentation/servicemanagement/smjobbless(_:_:_:_:))
- [Packet tunnel providers](https://developer.apple.com/documentation/networkextension/packet-tunnel-provider)
- [Network Extension entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)

## Delivery order

| Milestone | Deliverable | May be released when |
|---|---|---|
| 0 | Accurate README and this plan | Immediately. |
| 1 | Structured capabilities and transactional per-backend proxy snapshots | Unit tests and GNOME/KDE live tests pass. |
| 2 | Root-owned Linux helper/core, supervision and route verification | Security-negative tests and the Linux live matrix pass; expose as experimental. |
| 3 | macOS service identity, nested code signing and hardened runtime | macOS builds have stable identities and nested signatures verify; notarisation may be added independently for public distribution. |
| 4 | `SMAppService` daemon, authenticated control, supervision and route verification | macOS 13+ Intel and Apple Silicon live tests pass; expose as experimental. |
| 5 | Stable rollout and documentation cleanup | One release of telemetry-free field reports/crash diagnostics shows no orphaned helpers, routes or unrecovered proxy state. |

Milestones 1 and 3 can proceed independently. Milestone 4 depends on 3.
Milestone 2 does not depend on macOS work.

## Verification required for every privileged change

- Unit tests for capability decisions, request validation, state migration,
  route interpretation and rollback.
- Integration tests with fake helper/core peers for authentication failure,
  protocol mismatch, timeout, disconnect and crash.
- Package inspection tests for ownership, modes, platform-required signatures,
  plists/policies and absence of development overrides in privileged paths.
- Live end-to-end traffic and leak tests on the target operating systems.
- A manual abuse review: replace the core, substitute a socket, inject arguments,
  connect as another local user, replay a request, kill the UI, and downgrade the
  helper. Every case must fail closed or clean itself up.
- Documentation and UI must distinguish transparent TUN, desktop-preference
  proxying and manual per-application proxying.

## Definition of done

The limitations can be removed from the README only when:

- Linux TUN is available from supported native packages, verified after start,
  and leaves no privileged process, adapter or route after all tested shutdowns.
- macOS TUN installs through the supported approval flow, runs only signed
  bundled code, verifies its routes, survives upgrades and cleans up after UI
  failure.
- Linux GNOME/KDE proxy settings are applied and restored per backend, while a
  bare window manager receives an explicit manual endpoint without a misleading
  system-proxy claim.
- Release artifacts—not development checkouts—pass the complete platform matrix.
