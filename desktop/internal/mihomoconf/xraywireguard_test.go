package mihomoconf

import (
	"encoding/base64"
	"testing"
)

// A BPB-style WARP subscription: a plain WARP outbound, and a second one chained
// through it with sockopt.dialerProxy, which is how WoW is expressed.
const warpXrayConfig = `[
  {
    "remarks": "WARP",
    "outbounds": [
      {
        "tag": "warp-out",
        "protocol": "wireguard",
        "settings": {
          "secretKey": "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=",
          "address": ["172.16.0.2/32", "2606:4700:110:8a1b::1a1a/128"],
          "mtu": 1280,
          "reserved": [1, 2, 3],
          "peers": [
            {
              "publicKey": "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5MTIzND0=",
              "endpoint": "162.159.192.1:2408",
              "allowedIPs": ["0.0.0.0/0", "::/0"],
              "keepAlive": 25
            }
          ]
        }
      },
      {
        "tag": "wow-out",
        "protocol": "wireguard",
        "streamSettings": {"sockopt": {"dialerProxy": "warp-out"}},
        "settings": {
          "secretKey": "c2Vjb25ka2V5c2Vjb25ka2V5c2Vjb25ka2V5MTIzND0=",
          "address": ["172.16.0.3/32"],
          "peers": [
            {
              "publicKey": "cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleTEyMz0=",
              "endpoint": "162.159.195.1:2408",
              "allowedIPs": ["0.0.0.0/0"]
            }
          ]
        }
      }
    ]
  }
]`

func TestParseXrayJSONReadsWireGuard(t *testing.T) {
	proxies, err := ParseXrayJSON(warpXrayConfig)
	if err != nil {
		t.Fatalf("ParseXrayJSON: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("wanted both WARP hops, got %d: %+v", len(proxies), proxies)
	}

	first := proxies[0]
	if first["type"] != "wireguard" {
		t.Errorf("type = %v, want wireguard", first["type"])
	}
	if first["name"] != "WARP" {
		t.Errorf("name = %v, want WARP", first["name"])
	}
	if first["server"] != "162.159.192.1" || first["port"] != 2408 {
		t.Errorf("endpoint = %v:%v, want 162.159.192.1:2408", first["server"], first["port"])
	}
	if first["private-key"] != "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI=" {
		t.Errorf("private-key = %v", first["private-key"])
	}
	if first["public-key"] != "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5MTIzND0=" {
		t.Errorf("public-key = %v", first["public-key"])
	}
	// The CIDR suffix is dropped and the families are split, the way the
	// wireguard:// parser does it.
	if first["ip"] != "172.16.0.2" {
		t.Errorf("ip = %v, want 172.16.0.2", first["ip"])
	}
	if first["ipv6"] != "2606:4700:110:8a1b::1a1a" {
		t.Errorf("ipv6 = %v", first["ipv6"])
	}
	if first["mtu"] != 1280 {
		t.Errorf("mtu = %v, want 1280", first["mtu"])
	}
	if first["persistent-keepalive"] != 25 {
		t.Errorf("persistent-keepalive = %v, want 25", first["persistent-keepalive"])
	}
	reserved, ok := first["reserved"].([]int)
	if !ok || len(reserved) != 3 || reserved[0] != 1 || reserved[1] != 2 || reserved[2] != 3 {
		t.Errorf("reserved = %v, want [1 2 3]", first["reserved"])
	}
	allowed, ok := first["allowed-ips"].([]string)
	if !ok || len(allowed) != 2 {
		t.Errorf("allowed-ips = %v", first["allowed-ips"])
	}
	if _, chained := first["dialer-proxy"]; chained {
		t.Errorf("the first hop dials directly, got dialer-proxy = %v", first["dialer-proxy"])
	}

	second := proxies[1]
	if second["name"] != "WARP (wow-out)" {
		t.Errorf("second name = %v, want \"WARP (wow-out)\"", second["name"])
	}
	if second["dialer-proxy"] != "WARP" {
		t.Errorf("dialer-proxy = %v, want WARP", second["dialer-proxy"])
	}
}

func TestParseXrayJSONDropsWireGuardWithAnUnresolvableChain(t *testing.T) {
	// The hop it dials through is not in the configuration, so the node would
	// fail on its first packet rather than carry traffic.
	orphan := `{"outbounds":[{"tag":"wow","protocol":"wireguard",
	  "streamSettings":{"sockopt":{"dialerProxy":"missing"}},
	  "settings":{"secretKey":"a2V5","address":["172.16.0.2/32"],
	    "peers":[{"publicKey":"cHVi","endpoint":"162.159.192.1:2408"}]}}]}`

	if _, err := ParseXrayJSON(orphan); err == nil {
		t.Fatal("wanted the orphaned chain to be refused")
	}
}

func TestParseXrayJSONSkipsIncompleteWireGuard(t *testing.T) {
	cases := map[string]string{
		"no private key":    `{"secretKey":"","address":["172.16.0.2/32"],"peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4:2408"}]}`,
		"no public key":     `{"secretKey":"a2V5","address":["172.16.0.2/32"],"peers":[{"publicKey":"","endpoint":"1.2.3.4:2408"}]}`,
		"no v4 address":     `{"secretKey":"a2V5","address":["2606:4700::1/128"],"peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4:2408"}]}`,
		"bad endpoint":      `{"secretKey":"a2V5","address":["172.16.0.2/32"],"peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4"}]}`,
		"two peers":         `{"secretKey":"a2V5","address":["172.16.0.2/32"],"peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4:2408"},{"publicKey":"cHVi","endpoint":"5.6.7.8:2408"}]}`,
		"port out of range": `{"secretKey":"a2V5","address":["172.16.0.2/32"],"peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4:70000"}]}`,
	}
	for name, settings := range cases {
		t.Run(name, func(t *testing.T) {
			body := `{"outbounds":[{"tag":"wg","protocol":"wireguard","settings":` + settings + `}]}`
			if _, err := ParseXrayJSON(body); err == nil {
				t.Fatal("wanted the incomplete outbound to be refused")
			}
		})
	}
}

func TestParseXrayJSONDropsAMalformedWireGuardReserved(t *testing.T) {
	// Three bytes or none: a partial set would put the tunnel on the wrong
	// session, so the field is left off rather than half-applied.
	body := `{"outbounds":[{"tag":"wg","protocol":"wireguard","settings":{
	  "secretKey":"a2V5","address":["172.16.0.2/32"],"reserved":[1,2],
	  "peers":[{"publicKey":"cHVi","endpoint":"1.2.3.4:2408"}]}}]}`

	proxies, err := ParseXrayJSON(body)
	if err != nil {
		t.Fatalf("ParseXrayJSON: %v", err)
	}
	if _, present := proxies[0]["reserved"]; present {
		t.Errorf("reserved = %v, want it left off", proxies[0]["reserved"])
	}
}

func TestParseXrayJSONStillReadsNonWireGuardConfigs(t *testing.T) {
	// The wireguard path must not shadow the ordinary one.
	body := `[{"remarks":"VLESS","outbounds":[{"tag":"proxy","protocol":"vless",
	  "settings":{"vnext":[{"address":"example.com","port":443,
	    "users":[{"id":"00000000-0000-0000-0000-000000000001"}]}]}}]}]`

	proxies, err := ParseXrayJSON(body)
	if err != nil {
		t.Fatalf("ParseXrayJSON: %v", err)
	}
	if len(proxies) != 1 || proxies[0]["type"] != "vless" || proxies[0]["name"] != "VLESS" {
		t.Fatalf("wanted the vless node untouched, got %+v", proxies)
	}
}

func TestParseSubscriptionReadsWarpEndToEnd(t *testing.T) {
	// The real path a pasted subscription takes. ParseSingBox is tried first and
	// also keys off "outbounds", so this guards against it claiming a WARP
	// configuration and returning something else.
	proxies, _, _, err := ParseSubscriptionWithReport(warpXrayConfig)
	if err != nil {
		t.Fatalf("ParseSubscriptionWithReport: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("wanted both WARP hops, got %d: %+v", len(proxies), proxies)
	}
	for _, proxy := range proxies {
		if proxy["type"] != "wireguard" {
			t.Fatalf("type = %v, want wireguard: %+v", proxy["type"], proxy)
		}
	}
	if proxies[1]["dialer-proxy"] != "WARP" {
		t.Errorf("dialer-proxy = %v, want WARP", proxies[1]["dialer-proxy"])
	}
}

func TestParseSubscriptionReadsBase64WrappedWarp(t *testing.T) {
	// Providers commonly serve the body base64-wrapped.
	encoded := base64.StdEncoding.EncodeToString([]byte(warpXrayConfig))

	proxies, _, _, err := ParseSubscriptionWithReport(encoded)
	if err != nil {
		t.Fatalf("ParseSubscriptionWithReport: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("wanted both WARP hops, got %d: %+v", len(proxies), proxies)
	}
}
