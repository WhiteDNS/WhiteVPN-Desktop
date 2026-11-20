package engineprofiles

type Capabilities struct {
	Proxy            bool `json:"proxy"`
	TUN              bool `json:"tun"`
	Native           bool `json:"native"`
	UDP              bool `json:"udp"`
	DestinationRules bool `json:"destinationRules"`
	AppSplit         bool `json:"appSplit"`
	CustomDNS        bool `json:"customDns"`
	LAN              bool `json:"lan"`
	Chain            bool `json:"chain"`
	Country          bool `json:"country"`
}

// Potential capabilities do not mean an engine binary/runtime is available.
// LAN and native app split stay disabled until their acceptance work is done.
func Policy(kind Kind) Capabilities {
	if kind.SOCKS() {
		return Capabilities{Proxy: true, TUN: true, DestinationRules: true, AppSplit: true, CustomDNS: true, Country: kind == Psiphon}
	}
	if kind == AmneziaWG || kind == IKEv2 {
		return Capabilities{TUN: true, Native: true, UDP: true}
	}
	return Capabilities{}
}

type Availability struct {
	Kind         Kind         `json:"kind"`
	Available    bool         `json:"available"`
	Reason       string       `json:"reason,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
}
