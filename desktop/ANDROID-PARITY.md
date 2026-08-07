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

**How it reaches the engine, and the weeks it did not.** Both rows above were
marked done while the setting was stored, validated and shown and *nothing
outside the model ever read it*. A user could add a program to the bypass list,
save it, and watch the site it was meant to reach still see the VPN, because
every byte still went through the tunnel. A user reported exactly that. It is
the same shape as IP fronting before it was wired — and a control that changes
nothing is worse than one that is missing, because the missing one does not lie.

It is `PROCESS-NAME` rules now, written ahead of the catch-all because mihomo
takes the first rule that fits. Bypass sends the named programs to `DIRECT`;
vpn-only sends them to the group and replaces the catch-all with `MATCH,DIRECT`,
rather than adding a second one that could never fire. `find-process-mode`
follows whether any rule needs it — looking up which program owns a connection
costs something per connection, and `off` is right when nothing asks.

Naming nothing leaves the routing alone in both modes. Read literally, vpn-only
with an empty list says *send nothing through the tunnel*, which would turn the
VPN off while the interface still said Connected.

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
| Import formats | HTTPS URL (HTTP rejected), Clash/Xray JSON, mihomo YAML, or share links; 2 MB cap | `[x]` share links, mihomo YAML **and** JSON, sing-box JSON, Xray JSON or a list of Xray configs, and base64 around any of them. One entry point — `mihomoconf.ParseSubscription` — so everything downstream sees the same `[]Proxy` |

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

## 5-bis. How a node gets chosen — and a correction

An earlier version of this file, and a comment in `internal/session/session.go`,
said *"a node has to be chosen explicitly, as the phone app does"*. **That was
wrong about the phone app.** It was written from an assumption rather than from
Android's source, and it was the assumption behind a run of user reports saying
the desktop could not connect.

What Android actually does, in `WhiteDnsVpnService.kt`:

```kotlin
val nativeAutomaticStart = topEndpoint == null &&
    !validateConnectivity &&
    explicitProfile == null &&
    selectedAutomaticTypes.isEmpty() &&
    nativeAutomaticGroup != null
```

When the user has narrowed nothing, Android selects the **url-test group**, not a
node — `MihomoSelectionPolicy.desiredSelection` returns a
`MihomoGroupSelection(selectorGroup, selectedGroup)` — and its ordinary connect
path passes `validateConnectivity = false`, so it does not gate on a health
check at all. It starts the engine and lets mihomo choose.

That is the whole reason the phone feels smooth, and it is not subtle. A
`url-test` group measures its members continuously and picks the fastest that
answers; `GroupBase.onDialFailed` re-runs the health check once dialling through
the current node has failed five times in a row, and the group moves itself. A
`select` group pinned to one node does none of that — once pinned, it is pinned
until something outside asks it to change.

The desktop had built the url-test group since the beginning (`AutoGroup`,
`mihomoconf/config.go`, first entry of the selector) and then walked straight
past it: `session.start` selected `candidates[0]`, `candidates[1]`, and so on. So
with a subscription of 800+ nodes, every user on Automatic tried the **same five
nodes, in the same order**, each behind a 12-second health gate, and Retry tried
the same five again. A bad head of the catalogue was enough to tell everybody the
app could not connect — which is a completely different failure from "some nodes
are down", and looks identical from the outside.

**Now:** on Automatic the engine chooses, exactly as on Android. The node-by-node
walk survives only as a fallback for when nothing answers through the group, and
it is ordered by the delays url-test has already measured rather than by
catalogue position. An explicit choice — a country, or a node from the Servers
page — still pins, because that is the user answering the question themselves.

A pinned session recovers by trying other nodes (`Session.Recover`). An automatic
one recovers by re-asserting the group and letting mihomo move, because pinning a
node there would replace something that keeps looking with something that never
looks again.

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
| Edit or delete a config | — | ✓, manual configs only |

### Editing and deleting, and why only some rows offer it

A config added by hand had no way back out short of deleting every manual config
and importing them all again, so correcting one typo meant redoing the lot.
`SaveManualNode` and `DeleteManualNodes` fix that, and `ManualNodeProfile` opens
the form on the stored config rather than on the row — the row holds what the
parser made of the config, which is a subset, and saving that back would silently
drop everything the row does not show.

The buttons appear only where `WhiteVPNNode.ProfileID` is set, which is only for
manual configs. A node from the WhiteDNS catalogue or a remote subscription is a
reading of what a provider is serving: it returns unchanged at the next refresh,
so a delete button on it would undo itself. Removing a whole subscription is the
Subscriptions page's job and already exists.

### What a subscription's nodes get instead

Editing one is not a feature built badly — it is a feature that cannot exist.
`RefreshV2RaySubscription` drops every profile a subscription produced and
re-imports from the remote body with fresh ids built from a timestamp, so a
change does not survive and there is not even a stable id to hang it on. A
subscription served as a mihomo document produces no profiles at all; its nodes
are read straight out of the body.

So two things that are true instead:

**Copy to my configs** (`CopyNodeToManual`) takes the node into the user's own
list, where it is theirs and the edit form already applies. It goes through the
ordinary import so a copied node is parsed by the same code as a pasted one. It
needs a share link, which a document-shaped subscription does not carry — the
same limitation the Share button has, shown the same way.

**Hide** (`SetNodesHidden`) takes a node out of the list and out of the engine's
configuration without claiming to have deleted it. Held by **name**, in
`AppState.HiddenNodes` keyed by subscription id, precisely because ids do not
survive a refresh and this has to. A name goes stale if the provider renames the
node, and then it reappears — the honest failure, and a visible one.

Three things follow from "out of the configuration":

- `session.Options.Exclude` drops the proxies before the config is built, rather
  than expressing them as `Prefer`. Prefer only narrows what an attempt reaches
  for and leaves everything in the group, so a hidden node would still be sitting
  in the url-test group for the engine to pick — and a non-empty Prefer turns
  Automatic into an explicit selection, losing the group that makes Automatic
  work.
- `preferredNodeNames` skips hidden nodes, or a country filter would name nodes
  the engine does not hold.
- Hiding every node is refused. It would leave nothing to build a configuration
  from and surface later as an error about a missing group.

The node stays in the list carrying `Hidden`, rather than being removed from it:
a node dropped from the list could never be put back.

The node-to-profile match is on the share link, not on position. Both sides come
from the same exporter, so the strings are identical where they correspond; on
position they would not be, because the exporter skips profiles it cannot express
and the parser skips proxies it cannot use, and one incomplete profile would
shift every row after it onto the wrong config. Deleting the wrong node because
two lists drifted is not a risk worth taking to save a map.

Three things are refused rather than allowed to go wrong: a config that cannot be
exported as a share link is not stored, because the engine cannot be built from
it either and the row would fail at connect with no clue as to why; a
subscription's config cannot be edited or deleted through this door; and a config
carrying traffic right now cannot be deleted out from under the connection.

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
| Sets the system proxy | In proxy mode, points Windows at the local proxy and puts back what it found | `[x]` |

Closing a VPN's window means "get out of my way", not "stop protecting my
traffic". But hiding is only offered once there is an icon to come back from:
`hideInsteadOfClosing` checks that the tray actually started, and lets the close
through if it did not, because an app with no window and no icon is one only
Task Manager can end.

The system proxy is not a nicety, it is what made proxy mode work at all. The
phone has no equivalent — `VpnService` routes everything — and the desktop was
shipping the half that starts a proxy without the half that sends anything to
it. Connected, healthy, 0 D/s, and a user quite reasonably reporting that none
of the ports work. `TunEnabled` defaults to false, so that was the default
experience.

What was there before the change is written to `system-proxy.json` **before**
the change, and removed only after it has been put back. A crash therefore
leaves the file behind, and `startup` restores from it before anything else can
connect — otherwise the machine is left pointing at a port nothing is listening
on, which is a broken internet connection rather than a broken VPN. A restore
that fails keeps the file, so the next start tries again.

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

Places where copying Android exactly would be wrong:

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

5. **WireGuard is offered here and not on the phone**, for the same reason and
   found the same way: a user's subscription held five links and the app showed
   four. The engine has a WireGuard outbound; nothing was converting the links,
   so the node vanished with no error anywhere — the worst kind of gap, because
   the count on the Subscriptions page agreed with the empty result. Verified
   against that server on 2026-08-05: the node measures. There is no standard
   for `wireguard://`, so the parser reads each field under the two or three
   spellings clients actually emit, splits `address` by family into `ip` and
   `ipv6`, and skips any link missing either half of the key pair rather than
   producing a node that fails at the first packet.

6. **Plain HTTP subscriptions are allowed, and marked.** The phone refuses them
   and its reason is good: a server list fetched in the clear can be read and
   replaced by anyone on the path, who on a network that blocks VPNs is the
   party the VPN exists to get past. But providers do serve subscriptions over
   HTTP, and refusing outright means someone's own subscription cannot be used
   here while every other client takes it — which is a decision about their
   subscription that the app should not be making for them. So the address is
   accepted and the risk is shown on the row, every time the list is drawn,
   rather than asked about once and forgotten. Anything that is not a web
   address is still refused.

7. **The privacy notice describes this app, not the phone's.** Every line of it
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
catalogue: the share links in, proxies out, a selection made, and a
real HTTP request through the proxy before anything is reported connected. On
Automatic the selection is the engine's own url-test group, as on the phone —
see *How a node gets chosen* below. The
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

4. **Per-card subscription Test.** The phone offers it; refresh is there, test
   is not.

### Subscription formats, and why they are all one shape

`mihomoconf.ParseSubscription` reads share links, mihomo YAML or JSON, sing-box
JSON, Xray JSON or a list of Xray configs, and base64 around any of them. All of
them come out as `[]Proxy`, so the Servers page, the delay and speed tests, node
selection and IP fronting cannot tell them apart. One model, not two.

Measured 2026-08-06 against a BPB panel, which serves nine combinations of
`sub/{normal,fragment,raw}` and `?app={clash,sing-box,xray}`: all nine are read,
and three of the four that used to be refused were connected through and passed
real traffic. A 3x-ui/Sanaei subscription is the regression case for share
links.

Two things to know before changing it:

- **A document's nodes are extracted; its groups and rules are not run.** A user
  who picks a node expects that node, not whatever the provider's url-test
  group decides, and the Servers page needs something to list. The one
  exception is `proxy-providers`, where the nodes are fetched by the engine and
  there is nothing to extract — that still passes through, and both paths have
  a test.
- **The TLS name lives under `sni` for trojan and `servername` for everything
  else**, in both the sing-box and Xray converters. Getting it wrong is a
  handshake that fails with nothing to explain it.

Nodes read out of a document have no share link, because the document carried
settings rather than a URL. The Servers page disables Share for them and says
why.

### Building for the other platforms

Measured 2026-08-05, from Windows:

- **Windows** — `wails build` here.
- **Linux** — cross-compiles with `CGO_ENABLED=0` (the tray is D-Bus, pure Go).
  Wails packaging still needs a Linux host or Docker.
- **macOS** — **cannot be built from Windows.** Without CGO it does not compile
  at all: `fyne.io/systray` needs Cocoa. With CGO it needs the macOS SDK. It has
  to run on a Mac, or on a macOS CI runner.

`.github/workflows/desktop-release.yml` already builds all three, on a tag
`vpn-v*` or by hand. What a runner does *not* start with, and how it gets it:

| Not in the repo | How the build gets it |
|---|---|
| `third_party/flclash/core` — the engine source | `prepare-embedded-core` sees no core binary, calls `mihomo-core`, which calls `mihomo-core-setup`, which clones FlClash and mihomo at their pinned refs |
| `cores/mihomo-<os>-<arch>` | built from that source, `CGO_ENABLED=0`, cross-compiles to any target |
| `cores/wintun.dll` | **committed**, because it is a redistributable the engine loads at runtime and cannot build. Without it a fresh checkout produces a Windows build whose TUN mode fails when the user turns it on |

So a runner needs network and git, which GitHub's have. Nothing needs to be
uploaded or cached between runs.

**What is not ready on macOS yet.** The build will produce an app; two things
inside it are Windows-only:

- **The tunnel.** `startElevatedChild` refuses off Windows, so TUN mode cannot
  start. macOS needs a privileged helper — `SMJobBless` or a launchd daemon —
  and that is a notarisation-shaped problem, not a code-shaped one.
- **The kill switch**, which is not written for any platform yet.

The system proxy *is* implemented (`sysproxy_darwin.go`, `networksetup`), which
matters more than it sounds: without it proxy mode is an engine listening on a
port nothing talks to, and on macOS proxy mode is the only mode. It sets every
enabled network service rather than the active one, because a laptop that moves
from Wi-Fi to Ethernet must not lose its VPN on the way.

### Things that will bite

- **`dns-hijack` does not stop a DNS leak on its own.** It catches queries that
  enter the tunnel. A query to the resolver on the local network never does: the
  route to that subnet is directly connected on the physical adapter and beats
  the `0.0.0.0/1` pair the tunnel installs, so lookups went to the home router in
  the clear and a leak test showed the user's own ISP. Tunnel mode only — through
  a proxy the machine never resolves anything itself, it hands the name over and
  mihomo does the lookup, which is why proxy mode looked clean and hid this.
  `strict-route: true` is what closes it: WFP filters on Windows blocking port 53
  for everything but the engine and the tunnel adapter, unreachable policy rules
  on Linux, ignored on macOS. **Android does not set it and does not need to** —
  `VpnService.Builder.addDnsServer` makes the OS route every query into the
  tunnel — so this is the second place, after IPv6 containment, where copying the
  phone literally means shipping a leak.
- **There are two version numbers, and only one of them is the app's.** The
  sidebar reads `appVersion`, set at link time by `-X main.appVersion` from the
  Makefile's `VERSION`. The number Windows shows in Properties → Details is
  `productVersion` in `wails.json`, which the Wails CLI reads directly and which
  no build flag can reach. That second one used to be typed in by hand and had
  already drifted — a build from a `v1.0.3` tag would have carried `1.0.2` in its
  metadata. The Makefile now writes it in for the duration of the build and puts
  the file back afterwards, so the committed value is `0.0.0`: a build that did
  not come through the Makefile is not a release, which is the same thing
  `appVersion` says when it stays at `dev`. Do not "fix" that `0.0.0`.
- **A `0000` language ID makes every string in the exe unreadable.**
  `build/windows/info.json` keys its string table by language, and Wails ships it
  keyed `0000` — language-neutral. The strings are written correctly and are
  there in the binary, but neither Explorer nor .NET's `FileVersionInfo` resolves
  a neutral table, so Properties → Details came up blank for every field while
  the numeric `FileVersionRaw` worked. Keyed `0409` (en-US) they all appear. If
  the table ever looks empty again, check that key first — the resource is
  probably fine.
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
- **A control that writes to `V2RaySettingsProfile` does nothing**, which is why
  the Engine settings page was removed on 2026-08-05. Listen port, inbound type,
  SOCKS authentication, the Iran routing description — every field on it
  belonged to the Xray path and nothing had read any of them since that path
  went. It had teeth, too: `selectedSettingsMissing` could disable the Connect
  button over a listen port the engine never used. The model type and its store
  normalisation stay so existing state files and backups keep loading; the page,
  its five bound methods and seven orphaned helpers do not.
- **A node's country is in its name, and only there.** No geoip call resolves
  it; `countryCodeFromNodeName` reads the flag. A catalogue that stops shipping
  flags takes the location filter with it, and the dialog would show one country:
  none.
- **The context that cancels a connect must not own the engine's lifetime.**
  `engine.Spawn` used `exec.CommandContext`, so the core was killed the moment
  that context was cancelled — and the context handed to it is the cancellable
  one from `beginConnect`, cancelled by `defer cancel()` the instant the connect
  function returns. Every proxy-mode connection therefore died about a second
  after reporting success. TUN was untouched, because `Elevated` spawns through
  `ShellExecuteExW` and no context can reach that: the entire "TUN works, proxy
  mode does not" was this one line. `TestLiveConnectionOutlivesItsConnectContext`
  connects, cancels, and asks the connection to carry a request; it fails within
  three seconds if the old form comes back.
- **A connection proves itself once and was never asked again.** Connecting
  health-checks a node and then pins the group to it for the session. That proof
  has a shelf life: a user's log showed the node behind a CDN answering `502 Bad
  Gateway` to every request while the app reported Connected, green badge, zero
  bytes, for twelve seconds — and nothing was ever going to notice, because
  nothing was looking after the first successful request. `watchHealth` asks
  every 20s and `Session.Recover` moves to another node after two failures. Only
  on Automatic: a node the user chose by hand is theirs, and moving off it would
  answer a question they already answered.
- **`ProxyEnable` and `ProxyServer` are not where Windows keeps the proxy.**
  They are a compatibility shim. The real configuration is a binary blob at
  `Internet Settings\Connections\DefaultConnectionSettings`, and when the two
  disagree the blob wins. Writing only the shim let the app set the proxy, read
  it back, verify it, show a badge — and leave Windows browsing directly,
  because the blob still said `flags=1`, `PROXY_TYPE_DIRECT`. Change it with
  `InternetSetOption(INTERNET_OPTION_PER_CONNECTION_OPTION)`, which updates both
  and cannot drift, and read it back with `InternetQueryOption` rather than from
  the registry — a read-back that goes where the write went proves only that the
  write happened.
- **`wails build -s` skips the frontend.** The Go side rebuilds, the binary
  looks new, and the UI inside it is whatever was in `frontend/dist` from
  whenever it was last built properly. Two rounds of "I fixed that, why is it
  still broken" came from this: the fix was in the source and had never been in
  the build. Check the timestamp on `frontend/dist/assets/*.js`, or look for
  `Compiling frontend: Done` in the output.
- **The dashboard's idle port came from the V2Ray settings profile.** It showed
  `10888` while the engine listened on `2080` — another reader of the removed
  Xray path. `GetLocalProxyEndpoint` is the one source now. `selectedSettings`
  still gates the Connect button through `selectedSettingsMissing`, which is the
  same dead field; it happens to be populated, so it has not bitten yet.
- **A node can be dead in the subscription itself, and it looks exactly like a
  bug here.** Measured 2026-08-05 on a user's own subscription: a REALITY node
  failed every connection while the other four worked. The engine's own debug
  log said `REALITY Authentication: false`, and the panel serving that
  subscription was emitting a **random `sid` on every fetch** — `aa`, `ceb0`,
  `bff1475e32`, `3810c9df3b744624`. Every variant failed: no short-id, each
  advertised short-id, `support-x25519mlkem768`, and plain TCP with no xhttp at
  all. Before rewriting a converter, put the node in front of the engine at
  `log-level: debug` and read what it says; the conversion here matched
  mihomo's own `common/convert` field for field.
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
