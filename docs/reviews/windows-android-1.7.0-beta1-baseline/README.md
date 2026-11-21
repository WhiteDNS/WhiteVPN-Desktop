Evidence collected on 2026-10-04 for the Persian plan review. Empty build logs mean no compiler output; exit codes are recorded in the adjacent JSON files. These are build feasibility probes and existing desktop checks, not native runtime acceptance.

Desktop baseline, from `E:\projects\WhiteVPN-Desktop`:

```powershell
desktop/frontend/node_modules/.bin/tsc.cmd --noEmit --noUnusedLocals --project desktop/frontend/tsconfig.json
npm.cmd run build --prefix desktop/frontend
go -C desktop build ./...
go -C desktop vet ./internal/... .
go -C desktop test -json -count=1 -timeout 180s ./internal/... .
$env:GOOS='windows'
$env:GOARCH='arm64'
$env:CGO_ENABLED='0'
go -C desktop build ./internal/...
```

Engine probe environment: `GOOS=windows`, `GOARCH=amd64` and then `arm64`, `CGO_ENABLED=0`, `GOTOOLCHAIN=go1.26.5`, `GOPROXY=off`, `GOSUMDB=off`; existing dependency cache at `E:\projects\WhiteVPN\build\engines\go-path\pkg\mod`, separate build cache under the Desktop workspace `.cache`. Go module files in `probes` and `awg-probe` preserve the dependencies and local replacements used. Local source paths make these probes machine-specific; their portability is not claimed.

Per-architecture package build commands:

```text
go -C <probes> build -mod=readonly github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon
go -C <probes> build -mod=readonly zeddns
go -C <probes> build -mod=readonly masterdnsvpn-go/mobile
go -C <awg-probe> build -mod=readonly github.com/amnezia-vpn/amneziawg-go/v3/device github.com/amnezia-vpn/amneziawg-go/v3/tun
```

Transport commands used the existing pinned source directories and output executables under Desktop `.cache/plan-review-tor`, without modifying reference source:

```text
go -C <lyrebird-source> build -mod=readonly -trimpath "-ldflags=-s -w -checklinkname=0" -o <output> ./cmd/lyrebird
go -C <snowflake-v2.14.1-source> build -mod=readonly -trimpath "-ldflags=-s -w -checklinkname=0" -o <output> ./client
go -C <conjure-source> build -mod=readonly -trimpath "-ldflags=-s -w -checklinkname=0" -tags=protoreflect -o <output> ./client
```

Source pins: Psiphon `83aa73b9b982e7421e00117f5b0c5aceb5dda452`, MasterDNS `50b447bc41e6c930a0027507a1a9f492b6fc63b9`, VayDNS `a0ff70110d5e96686ab8f4c8e1c44cd09be07a75`, lyrebird `ad08585d979f72a1019470e4e2b18e9ed2550274`, Conjure `505cb48152e89e12a608ec6a0101af8a2d266fb1`, Snowflake `v2.14.1`, AWG Go v3 `v3.1.20260814`. The zeddns source used the already present local DoT validation patch. Tor C core was not built.

`android-reference` holds selected source snapshots read with `git show bf4adc5:<path>` from the separate release checkout. APK metadata/signature logs came from local `aapt` and `apksigner` checks. `reference-identity.json` records local hashes; the first APK hash matches the saved local publication record, not independently fetched current GitHub asset bytes.

No network settings, user VPN profiles, routes, DNS, system proxy, driver installations, or original product source were changed for this review. Ignored frontend outputs and build caches were generated. No MSI/ZIP packaging, real engine connection, elevated helper execution, physical ARM64 acceptance, or race testing was performed.
