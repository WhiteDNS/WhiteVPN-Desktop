# Android parity checklist

WhiteVPN for Android is the specification for this app. Someone who has used the
phone app should find the same options here, under recognisable names, producing
the same behaviour — so every setting it has is listed below with where it lives
on the phone and where it lands on the desktop.

Source of truth: `WhiteDNS/WhiteVPN` at `main`. Verified against commit `760973b`
on 2026-08-04. Re-check this file whenever that repo's settings change.

Status: `[ ]` not started · `[~]` partial · `[x]` done · `[—]` deliberately dropped

---

## Where things live

| Android | Desktop |
|---|---|
| VPN tab (dashboard) | **VPN** page |
| Subscriptions tab | **Subscriptions** page |
| Settings tab ("Advanced"), 5 sections | **Settings** page, same 5 sections in the same order |
| Kebab menu (Theme, Language) | **Settings**, appearance section |

The phone's three-tab bar becomes three entries in the existing sidebar. Nothing
about the visual language changes; only the content is ported.

---

## 1. Dashboard rows

| # | Setting | Store / key | Default | Desktop | Status |
|---|---|---|---|---|---|
| 1.1 | Location filter | `white_dns_connection_location` / `country_code` | unset = Automatic | VPN page row → country dialog. Reuse `country.go` | `[ ]` |
| 1.2 | Connection (node pick) | `white_dns_connection_selection` / `profile:<subId>` | unset = Automatic | VPN page row → connection dialog | `[ ]` |
| 1.3 | Connection type filter | `white_dns_connection_selection` / `types:<subId>` | empty = all types | Inside the connection dialog | `[ ]` |
| 1.4 | Sort by delay | `white_dns_connection_selection` / `delay-sort:<subId>` | `false` | Toggle in the connection dialog | `[ ]` |
| 1.5 | Split tunnel mode | `white_dns_split_tunnel` / `mode` | `off` | VPN page row → split-tunnel dialog | `[x]` |
| 1.6 | Split tunnel selection | `white_dns_split_tunnel` / `packages` | empty | **Adapted**: Windows processes/`.exe` instead of Android packages | `[x]` |

Split tunnel keeps all three Android modes: `off`, `bypass_selected`
(selected apps skip the VPN), `vpn_only_selected` (only selected apps use it).
Android refuses to save `vpn_only_selected` with nothing selected; so does this.

> Matching on Windows is by executable **basename**, so two programs with the
> same `.exe` name cannot be told apart. Say so in the dialog rather than
> letting a user discover it.

## 2. Settings — section order matches Android exactly

### 2.1 TLS integrity (`tls_integrity_section`)

| Setting | Store / key | Default | Status |
|---|---|---|---|
| TLS integrity | `white_dns_tls_integrity` / `enabled` | `false` | `[x]` |

Probes certificate validity and quarantines a failing endpoint for 24 h
(`white_dns_scan_state` → `tls_quarantine:*`).

### 2.2 WARP / Amnezia noise (`settings_warp_section`)

| Setting | Store / key | Default | Range | Status |
|---|---|---|---|---|
| Noise enabled | `white_dns_connection_options` / `amnezia_noise_enabled` | `false` | — | `[x]` |
| Noise count | `…` / `noise_count` | `5` | 1–20 | `[x]` |
| Noise min size | `…` / `noise_min_size` | `50` | 1–1280 | `[x]` |
| Noise max size | `…` / `noise_max_size` | `100` | 1–1280 | `[x]` |

Three numeric fields plus an Apply button, exactly as on the phone. Validation
must reject out-of-range values rather than clamping them silently.

### 2.3 IP fronting (`fronting_section`)

| Setting | Store / key | Default | Status |
|---|---|---|---|
| Fronting IPs | `white_dns_fronting_ip` / `fronting_ip` | unset | `[x]` |

Comma-separated, **at most 5** entries of `IP` or `IP:port`. Port preference
order when connecting: 443, 8443, then 2053, 2083, 2087, 2096.

### 2.4 DNS privacy (`dns_privacy_section`)

| Setting | Store / key | Default | Status |
|---|---|---|---|
| Mode | `white_dns_privacy` / `mode` | `automatic` (`automatic` \| `doh` \| `dot`) | `[x]` |
| DoH URL | `…` / `doh_url` | `https://1.1.1.1/dns-query` | `[x]` |
| DoT endpoint | `…` / `dot_endpoint` | `tls://1.1.1.1:853` | `[x]` |

Server order per mode, as Android builds it:
- **Automatic** — `https://1.1.1.1/dns-query`, `https://8.8.8.8/dns-query`, `tls://1.1.1.1:853`, `tls://8.8.8.8:853`
- **DoH** — the user's URL first, then the two DoH defaults, no `tls://` entries
- **DoT** — the user's endpoint first, then the two DoT defaults, no `https://` entries

### 2.5 Always-on / kill switch (`always_on_section`)

| Android | Desktop | Status |
|---|---|---|
| Read-only status (inactive / active / lockdown) + a button opening Android's VPN settings | **A real, app-owned kill switch**, because Windows has no OS equivalent | `[ ]` |

Android does not implement a kill switch: the OS does, and the app only reports
`isAlwaysOn()` / `isLockdownEnabled()`, refuses to disconnect while always-on is
active, and drops the notification's Disconnect action. Windows offers nothing
equivalent, so this one setting is *more* than a port — a firewall rule that
blocks traffic outside the tunnel. It must survive an unexpected core exit and
must be removed on clean shutdown, crash recovery, and uninstall; a kill switch
that outlives the app leaves the user with no internet and no obvious cause.

## 3. Appearance (Android kebab menu)

| Setting | Store / key | Default | Options | Status |
|---|---|---|---|---|
| Theme | `white_dns_theme` / `theme` | `system` | System, Light, Dark | `[x]` |
| Language | `white_dns_language` / `language` | `fa` | Persian, English | `[~]` layer, RTL and switcher done; most screen strings not keyed yet |

Android ships 202 strings in each of `values/strings.xml` and
`values-fa/strings.xml`; both catalogues can be lifted directly. Persian also
needs RTL layout. Three Android files still hardcode Persian *validation* text
(`FrontingIp.kt`, `MihomoRuntime.kt`, `UserSubscriptions.kt`) — those need
keys here, not copied literals.

## 4. Subscriptions

| Item | Behaviour | Status |
|---|---|---|
| Selected subscription | `white_dns_user_subscriptions` / `selected_subscription`, default the built-in one | `[ ]` |
| Built-in WhiteDNS catalogue | Encrypted, refreshed every 3 h | `[~]` fetch + decrypt already exist |
| User subscriptions | Add, Edit, Test, Refresh, Delete per card | `[ ]` |
| Import formats | HTTPS URL (HTTP rejected), Clash/Xray JSON, mihomo YAML, or share links; 2 MB cap | `[ ]` |

> The live catalogue is **base64-encoded share links**, not mihomo YAML — 864
> nodes as of 2026-08-04. A link→mihomo converter is required, ported from
> `SubConvConverter.kt`.

## 5. Connection behaviour (no UI, but user-visible if wrong)

| Item | Behaviour | Status |
|---|---|---|
| HTTP health gate | A real request through the local proxy must succeed **before** the tunnel is reported up. URLs: letsencrypt `valid-isrgrootx1`, gstatic `generate_204`, cloudflare `cdn-cgi/trace`. 12 s budget, 2 s quiet probe | `[x]` |
| Delay probes | Metrics only — a failed probe must **not** block connecting | `[x]` satisfied by construction: `internal/session` never probes delay, so nothing on the connect path can be blocked by one. Keep it that way when the connection dialog adds per-row delay |
| Startup IP selection | Cached endpoint first; on failure fall through to a fresh scan | `[ ]` |
| Clean-IP scan | Encrypted IP list, concurrency 200, 4 probes for loss, budgets 3 s / 12 s / 60 s, cache 10 per port | `[ ]` |
| Connect button states | Connect · Connecting… · Disconnect · Disconnecting… · Retry. Disabled only while Stopping | `[ ]` |
| Privacy policy gate | Versioned acceptance on first run (`white_dns_privacy_policy` / `accepted_policy_version`) | `[ ]` |

## 6. Deliberately dropped

| Item | Why |
|---|---|
| DPI bypass (ByeDPI) | `[—]` Dead on Android too: `isEnabled()` returns `false` unconditionally and the store deletes its own key. No UI exists there either |
| Quick Settings tile | `[—]` No Windows equivalent |
| `VpnService`, uid→package resolution | `[—]` Android platform APIs; replaced by process-based split tunnel |
| Firebase Analytics | `[—]` Not ported |
| `DailyLimitReached` state | `[—]` Rendered on Android but never emitted |
| Android's Persian/RTL visual design | `[—]` The desktop keeps its own design language; only settings and behaviour are ported |

---

## Divergences that are intentional

Three places where copying Android exactly would be wrong:

1. **TUN comes from config, not a file descriptor.** Android sets
   `tun.enable: false` and hands the core an fd from `VpnService`. The Windows
   build of the core has no `startTUN` at all, so the desktop sets
   `tun.enable: true` with `auto-route: true` and lets mihomo create the adapter.
   Measured 2026-08-04: this works, and needs no manual route management.

2. **IPv6 must be contained deliberately.** Android sets `ipv6: false` and is
   saved by `VpnService` simply not routing v6. Windows has no such backstop:
   measured on a dual-stack machine, the same config leaks — v4 goes through the
   tunnel while v6 leaves from the physical adapter. Adding `ipv6: true` plus
   `tun.inet6-address` fixes it, but only by winning on route metric; the
   physical v6 default routes remain. Containment is therefore **verified at
   connect time, never assumed**.

3. **Split tunnel matches processes, not packages.** See §1.6.

---

## Picking this up in a new session

Everything below is what someone needs to resume without reading the history.

### Where things stand

The engine is mihomo, the one WhiteVPN for Android runs, built from the same
pinned sources. Connecting works end to end and is verified against the live
catalogue: 864 links in, 845 proxies out, a node selected explicitly, and a real
HTTP request through the proxy before anything is reported connected. The tunnel
works too, with only the engine elevated. The interface has the phone's shape and
the phone's settings, and Persian with right-to-left is wired but only the
navigation is keyed so far.

### Suggested order

1. **Connect button states** — small, and the most visible remaining gap.
2. **The four dashboard rows** (location, node pick, type filter, delay sort) —
   they are one dialog between them, and together they are what makes the app
   feel like the phone. `desktop/country.go` already resolves countries.
3. **Finish the translation** — mechanical: add a key to `frontend/src/i18n.ts`,
   swap the literal for `t(...)`. Android's `values-fa/strings.xml` has 202
   strings already translated; take the wording from there rather than inventing
   it, so both apps say the same thing.
4. **Subscriptions** — selection, user-added entries, import formats.
5. **Clean-IP scan** and **the kill switch** — each is its own session.

### Things that will bite

- **`validateConfig` only catches unparseable YAML.** Measured. It accepts
  unknown proxy types, impossible ports, groups naming absent proxies and empty
  documents. Never treat it as evidence a config will work; the health check is
  what settles that.
- **`startListener` reports success even when the tunnel failed to come up.**
  Confirm a tunnel by looking at the machine's adapters, not by asking the engine.
- **Action `data` is a JSON string for most methods and a bare bool for the
  traffic ones.** The wrong shape panics inside the core rather than returning an
  error. Use the wrappers in `internal/engine/actions.go`.
- **Unknown methods get no reply at all.** Every call needs a deadline.
- **IPv6 containment rests on route metric, not on removing routes.** The
  physical v6 defaults remain and are merely outranked, so containment has to be
  verified after connecting, never assumed.
- **A control that writes to `V2RaySettingsProfile` does nothing.** Only the Xray
  path reads it. Two rounds of dead switches came from this.

### Verifying a change

    cd desktop
    go build ./... && go vet ./... && go test ./...
    cd frontend && npx tsc --noEmit --noUnusedLocals && npm run build

Four Go tests fail on Windows and did before any of this work: they build
`#!/bin/sh` helpers. Anything beyond those four is yours.

The end-to-end tests need the engine built and the catalogue credentials:

    make mihomo-core
    WHITEVPN_CATALOGUE_URL=... WHITEVPN_CATALOGUE_KEY=... go test ./internal/session -run Live -v

`git tag ui-checkpoint-pre-android-nav` is the last interface that predates the
restructure, if one is ever needed.
