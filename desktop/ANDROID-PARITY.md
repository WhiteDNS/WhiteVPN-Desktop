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
| 1.1 | Location filter | `white_dns_connection_location` / `country_code` | unset = Automatic | VPN page row → country dialog | `[x]` |
| 1.2 | Connection (node pick) | `white_dns_connection_selection` / `profile:<subId>` | unset = Automatic | VPN page row → connection dialog | `[x]` |
| 1.3 | Connection type filter | `white_dns_connection_selection` / `types:<subId>` | empty = all types | Inside the connection dialog | `[x]` |
| 1.4 | Sort by delay | `white_dns_connection_selection` / `delay-sort:<subId>` | `false` | Toggle in the connection dialog | `[x]` |
| 1.5 | Split tunnel mode | `white_dns_split_tunnel` / `mode` | `off` | VPN page row → split-tunnel dialog | `[x]` |
| 1.6 | Split tunnel selection | `white_dns_split_tunnel` / `packages` | empty | **Adapted**: Windows processes/`.exe` instead of Android packages | `[x]` |

**Where a node's country comes from.** The catalogue puts it in the name, as a
flag: `🇩🇪 | @WhiteDNS | DE1|36.8MB/s|DNSOK|…`. A flag is a pair of regional
indicator symbols, and those are letters — 🇩🇪 is D then E — so the location
filter reads the code straight off the name. No geoip lookup, nothing to ask the
network for, and no database that can disagree with the catalogue about where a
node is. Measured 2026-08-04: 585 nodes, 29 countries, 5 nodes the catalogue
marks ❓ and leaves without one. Those are reachable only with the filter off.

The four choices are stored flat rather than per subscription, because there is
one subscription; they take the `<subId>` shape when §4 lands.

**What the choices do on the connect path.** They narrow and order the candidate
list, nothing more — every node stays in the configuration, so a later choice
needs no reconnect. A choice nothing matches is refused at the point it is made
and again at connect, rather than falling back to the whole catalogue: a user who
asked for Germany and was quietly given Japan has been lied to about where their
traffic leaves from.

**Changing a choice while connected** moves the live connection onto a node that
satisfies it, through the engine's own `ChangeProxy`, and holds that node to the
same health check connecting uses. A node that carries no traffic leaves the
previous one in place. Nothing is done when the node already in use satisfies
the new choice.

Delay is a view setting only. It is measured through the running engine, so the
dialog says plainly that it needs a connection rather than showing zeroes; the
connect path still never waits on a measurement.

**Where a connection says it leaves from.** The status card carries the country
once connected, from two sources kept deliberately apart. `NodeCountryCode` is
the flag in the node's name — the node's *claim*, free and right immediately.
`ExitCountryCode` is a *measurement*: the country of the egress IP, resolved
through the proxy itself with the cloudflare trace `country.go` already used.
The claim is shown while the measurement is in flight and replaced by it, and
when the two disagree the measured one wins and the tooltip says so. Fronting and
proxy chains make disagreement a real outcome, not a bug.

`ExitChecked` exists so an attempt that found nothing can be told from one still
running; without it a failed lookup leaves a spinner turning over work that
stopped. The measurement is cached per *local* proxy address, which does not
change when the node behind it does, so switching node clears that cache.

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

Until 2026-08-04 this was a control that changed nothing: the setting was read
only by the Xray path, which is not the engine this app runs. `mihomoconf`
fronts the proxies now, on the phone's rules — a node whose server is a name,
carrying TLS or an HTTP-shaped transport, and not using Reality, which pins the
address into its handshake. The address is replaced; the name keeps travelling
in the SNI or the Host header, or the server has no idea which site is being
asked for. Nodes that cannot be fronted stay reachable at their own address
rather than being dropped: a front covering most of a list beats a list cut
down to what it covers.

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
| Language | `white_dns_language` / `language` | `fa` | Persian, English | `[~]` the parity surfaces are keyed — navigation, VPN page, both dashboard dialogs, Settings. The desktop-only tools are not |

Android ships 202 strings in each of `values/strings.xml` and
`values-fa/strings.xml`; both catalogues can be lifted directly. Persian also
needs RTL layout. Three Android files still hardcode Persian *validation* text
(`FrontingIp.kt`, `MihomoRuntime.kt`, `UserSubscriptions.kt`) — those need
keys here, not copied literals.

## 4. Subscriptions

| Item | Behaviour | Status |
|---|---|---|
| Selected subscription | `white_dns_user_subscriptions` / `selected_subscription`, default the built-in one | `[x]` |
| Built-in WhiteDNS catalogue | Encrypted, refreshed every 3 h | `[~]` fetch, decrypt and on-demand refresh exist; its address is never stored or shown |
| User subscriptions | Add, Edit, Test, Refresh, Delete per card | `[ ]` |
| Import formats | HTTPS URL (HTTP rejected), Clash/Xray JSON, mihomo YAML, or share links; 2 MB cap | `[~]` HTTPS enforced and the 2 MB cap was already there; share links, base64 of them and mihomo YAML all connect. Clash/Xray **JSON** does not — nothing converts it yet |

> The live catalogue is **base64-encoded share links**, not mihomo YAML — 864
> nodes as of 2026-08-04. A link→mihomo converter is required, ported from
> `SubConvConverter.kt`.

## 5. Connection behaviour (no UI, but user-visible if wrong)

| Item | Behaviour | Status |
|---|---|---|
| Download and upload counters | Polled from the engine's own `getTraffic` and `getTotalTraffic` once a second | `[x]` |
| HTTP health gate | A real request through the local proxy must succeed **before** the tunnel is reported up. URLs: letsencrypt `valid-isrgrootx1`, gstatic `generate_204`, cloudflare `cdn-cgi/trace`. 12 s budget, 2 s quiet probe | `[x]` |
| Delay probes | Metrics only — a failed probe must **not** block connecting | `[x]` satisfied by construction: `internal/session` never probes delay, so nothing on the connect path can be blocked by one. Keep it that way when the connection dialog adds per-row delay |
| Startup IP selection | Cached endpoint first; on failure fall through to a fresh scan | `[ ]` |
| Clean-IP scan | Encrypted IP list, concurrency 200, 4 probes for loss, budgets 3 s / 12 s / 60 s, cache 10 per port | `[ ]` |
| Connect button states | Connect · Connecting… · Disconnect · Disconnecting… · Retry. Disabled only while Stopping | `[x]` |
| Privacy policy gate | Versioned acceptance on first run (`white_dns_privacy_policy` / `accepted_policy_version`) | `[x]` |

One button, five states, as the phone has it: the same control stops what it
started. Two things had to become true for that to be honest rather than
decorative.

`stopping` is a real runtime status (`model.RuntimeStopping`), not a flag the
interface keeps to itself. Killing the engine and removing its tunnel adapter
takes long enough to be seen, and a stop that fails puts the previous status
back rather than leaving "Disconnecting" on screen forever.

Clicking while connecting **cancels** it. Connecting can take a minute — a
subscription fetch, then up to five nodes each given a health budget — so the
connect runs under a context the stop cancels, `session.Connect` unwinds and
stops any engine it had already spawned, and a session that finishes in the gap
is closed rather than adopted. A cancelled connect ends `disconnected`, not
`failed`: the user asked for this one.

## 5a. Servers, and why it agrees with the dashboard now

The Servers page and the dashboard's connection dialog show the same thing, so
they read the same list: `ListWhiteVPNNodes`, which is the engine's own view of
the selected subscription. They cannot disagree about how many nodes there are
or what protocols they speak, because there is nothing to disagree with.

Before this they read two different parsers of the same subscription. The
Servers page used the Xray-era importer, which accepted protocols the engine
cannot carry, and — once the Xray path went — stopped refreshing at all, so it
showed a frozen count from whenever it was last filled. That is where "862
profiles" against the dialog's 585 came from.

The two views have different jobs. The dialog picks one node quickly. The page
is for finding out which one to pick: test, sort, compare, share.

| | Dialog | Servers |
|---|---|---|
| Search, country and protocol filters | ✓ | ✓ |
| Which subscription | the selected one | any of them, picked at the top |
| Delay | measured through the live engine | measured on an engine of its own |
| Reachability, speed | — | ✓ |
| Sort by any column | — | ✓ |
| Share a node's link | — | ✓ |

The subscription picker is why the two now read `ListSubscriptionNodes` and the
cache is keyed by subscription id rather than being one slot. A user added a
subscription, went to Servers, and did not find it: the page had been showing
the *selected* subscription and there was no way to look at another. Adding one
you cannot inspect until you commit to it is the wrong way round.

A keyed cache is not an optimisation here. `whiteVPNNodesSnapshot` feeds the
connect path — it is what a chosen node's name is validated against — so a
single slot would mean looking at one subscription's servers decided what the
dashboard connected to. Keying it also means measurements taken on one list
survive a look at another and back.

Connecting through a node in a subscription that is not the selected one moves
the selection with it. That cannot happen while a tunnel is up, because the
tunnel was built from the old subscription's servers and there is no way to move
it: `SelectSubscription` refuses while a session is live, and the Servers page
disables the button with "Disconnect first" rather than letting the click fail.

## 5b. Desktop additions

Things the phone has no equivalent for, added because a desktop needs them.

| Item | Behaviour | Status |
|---|---|---|
| Tray icon | Status, connect/disconnect, open, quit — in the app's own language | `[x]` |
| Runs in the background | Closing the window hides it; the app keeps carrying traffic | `[x]` |

Closing a VPN's window means "get out of my way", not "stop protecting my
traffic". But hiding is only offered once there is an icon to come back from:
`hideInsteadOfClosing` checks that the tray actually started, and lets the close
through if it did not, because an app with no window and no icon is one only
Task Manager can end.

The tray's ten words are kept in Go. It is drawn by the system rather than by
the page, so it cannot read `frontend/src/i18n.ts`; the two are kept in step by
hand.

## 6. Deliberately dropped

| Item | Why |
|---|---|
| The Xray path | `[—]` Removed 2026-08-04. mihomo is the engine; keeping a second one meant features written against it — IP fronting was one — were invisible in the app that ships, and the Servers page quietly started a different engine from the VPN page. Took 66 MB of the binary with it |
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

4. **Hysteria2 is offered here and not on the phone.** The phone's converter
   skips it; this engine supports it and a desktop has the bandwidth to make it
   worth having, so `ConvertLinks` reads it. Measured against the live catalogue
   on 2026-08-04: 11 nodes that were being dropped. Everything else the phone
   skips — tuic, socks — is still skipped, because the engine cannot carry it.
   Fronting leaves hysteria2 alone: it is QUIC with its own certificate and has
   no name to move.

4. **Plain HTTP subscriptions are allowed, and marked.** The phone refuses them
   and its reason is good: a server list fetched in the clear can be read and
   replaced by anyone on the path, who on a network that blocks VPNs is the
   party the VPN exists to get past. But providers do serve subscriptions over
   HTTP, and refusing outright means someone's own subscription cannot be used
   here while every other client takes it — which is a decision about their
   subscription that the app should not be making for them. So the address is
   accepted and the risk is shown on the row, every time the list is drawn,
   rather than asked about once and forgotten. Anything that is not a web
   address is still refused.

5. **The privacy notice describes this app, not the phone's.** Every line of it
   states something the code does and can be checked against it. The wording is
   the desktop's own; the published policy is linked rather than restated.

---

## Picking this up in a new session

Everything below is what someone needs to resume without reading the history.

### Where things stand

The engine is mihomo, the one WhiteVPN for Android runs, built from the same
pinned sources, and now the only one: the Xray path was removed on 2026-08-04.
It travels inside the app and unpacks itself beside the app's data on first
connect, so an install is one file. Connecting works end to end and is verified against the live
catalogue: the share links in, proxies out, a node selected explicitly, and a
real HTTP request through the proxy before anything is reported connected. The
catalogue is not a fixed size — 845 proxies measured early on 2026-08-04, 585
later the same day — so treat any count in this file as a reading, not a
constant. The tunnel works too, with only the engine elevated.

The interface has the phone's shape, the phone's settings and now the phone's
dashboard: a connect button with its five states, and rows for location and
connection with the dialogs behind them. Persian with right-to-left is wired,
but only the navigation, the connect button and those dialogs are keyed so far.

### Suggested order

1. **Clean-IP scan**, and the **startup IP selection** that caches its winner.
   These are one feature and they now have somewhere to go: IP fronting works,
   so an address the scan finds is an address the connect path will use. The
   encrypted list is already fetched and decrypted — `whiteDNSVPNFrontingIPListURL`
   and `decryptWhiteDNSVPNIPList` — and `pingV2RayProfilesSnapshot` still does
   plain TCP reachability with no engine behind it. What is missing is the
   phone's parameters (concurrency 200, 4 probes for loss, budgets 3 s / 12 s /
   60 s, cache 10 per port) and picking the best one when the user has set none.
   Today `startWhiteDNSVPNWithMihomo` takes `settings.FrontingIPs[0]` and
   nothing else.

2. **The kill switch.** Its own session, and the riskiest thing left: a firewall
   rule that outlives the app leaves someone with no internet and no visible
   cause. It has to survive an unexpected core exit and be removed on clean
   shutdown, after a crash, and on uninstall.

3. **Finish the translation** — mechanical: add a key to `frontend/src/i18n.ts`,
   swap the literal for `t(...)`. Android's `values-fa/strings.xml` has 202
   strings already translated; take the wording from there rather than inventing
   it, so both apps say the same thing.

   Everything the phone has is keyed: navigation, the VPN page including both
   dashboard dialogs, and the whole Settings page. What is left is the screens
   the phone does not have — Servers, Subscriptions, Logs, Validator, White IP
   Generator, Full Backup — plus the toasts they raise. Strings take `{name}`
   parameters, because a sentence with a number in it does not put that number
   in the same place in both languages.

4. **Clash and Xray JSON subscriptions.** Share links, base64 of them and mihomo
   YAML all connect; JSON does not, because nothing converts it. §4 says so.

5. **Per-card subscription Test.** The phone offers it; refresh is there, test
   is not.

### Building for the other platforms

Measured 2026-08-04, from Windows:

- **Windows** — `wails build` here. Note `make package-windows` runs
  `prepare-embedded-core`, which now checks for the mihomo core rather than
  fetching Xray.
- **Linux** — the code cross-compiles with `CGO_ENABLED=0` (the tray is D-Bus,
  pure Go). Wails packaging still needs a Linux host or Docker:
  `make package-linux-all-docker`.
- **macOS** — **cannot be built from Windows.** Without CGO it does not even
  compile: the tray needs Cocoa. Wails needs the macOS SDK as well. It has to
  run on a Mac: `make package-mac`.

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
- **`setupConfig` carries no path.** It tells the core to read
  `<homeDir>/config.yaml`, so the file has to be written under exactly that
  name; a second engine gets its own home directory rather than its own file
  name. This cost a shipped build: the measuring engine wrote `measure.yaml` and
  every test failed with `GetFileAttributesEx … cannot find the file`.
  `TestLiveMeasurerStartsAndMeasures` runs a real engine and catches it.
- **IPv6 containment rests on route metric, not on removing routes.** The
  physical v6 defaults remain and are merely outranked, so containment has to be
  verified after connecting, never assumed.
- **A control that writes to `V2RaySettingsProfile` does nothing.** Nothing
  reads it any more: it belonged to the Xray path. Three rounds of dead switches
  came from that path before it was removed — the settings profile ones, the
  Servers page's, and IP fronting.
- **A node's country is in its name, and only there.** No geoip call resolves
  it; `countryCodeFromNodeName` reads the flag. A catalogue that stops shipping
  flags takes the location filter with it, and the dialog would show one country:
  none.
- **The mihomo session has no stored profile behind it.** `ActiveConnectionID`
  is empty and no `V2RayProfile` is selected, so anything written against the
  Xray path's idea of an active connection quietly does nothing. That is what
  made Refresh a dead button until it was pointed at stop-then-start.

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
