package mihomoconf

// Destinations the user wants kept out of the tunnel.
//
// The request this answers: Iranian sites should not have to travel to another
// country and back, and people were disconnecting the VPN to reach a bank or a
// government form and then forgetting to turn it on again. A connection people
// keep switching off is not protecting them.
//
// Held as the user's own two lists rather than a country switch, and that is a
// deliberate refusal of the obvious design. mihomo can match a country with
// GEOIP, but `NewGEOIP` calls `InitGeoIP`, which downloads a database when one
// is not on disk and returns an error when it cannot — and a rule that fails to
// parse fails the whole configuration. Nothing ships that database with this
// app. So on a filtered network, on the first connection after an install, a
// GEOIP rule would not send Iranian traffic around the tunnel; it would stop
// the tunnel existing, for exactly the people who most need it. That is a bad
// enough trade to be worth writing down rather than discovering.
//
// Two lists cost nothing and cannot fail. `ir` as a domain suffix covers every
// `.ir` address on its own, with no database anywhere, and the rest is names
// people add as they meet them — which also makes this useful to somebody whose
// list has nothing to do with Iran.

import (
	"fmt"
	"strings"
)

// DirectRoute names destinations that leave the machine directly.
type DirectRoute struct {
	// Domains are matched by suffix, so "ir" catches every .ir address and
	// "digikala.com" catches its subdomains too. Written without a leading dot;
	// that is mihomo's spelling and the one people copy out of other clients.
	Domains []string

	// IPs are CIDR ranges. A bare address is accepted and read as a single
	// host, because typing /32 after an address is a step people forget and an
	// error message about it teaches nothing.
	IPs []string
}

// Active reports whether anything here would produce a rule.
func (d DirectRoute) Active() bool {
	return len(cleanDomains(d.Domains)) > 0 || len(cleanIPs(d.IPs)) > 0
}

// Rules renders the direct-routing rules, most specific first.
//
// Addresses before names, because an IP rule can be answered without resolving
// anything while a domain rule cannot, and mihomo takes the first rule that
// fits.
func (d DirectRoute) Rules() []string {
	domains := cleanDomains(d.Domains)
	ips := cleanIPs(d.IPs)

	rules := make([]string, 0, len(domains)+len(ips))
	for _, ip := range ips {
		// no-resolve, so a name is never looked up just to test it against an
		// address range. Without it every request would resolve before routing,
		// which both slows things down and leaks the name to whichever resolver
		// answered — the leak this app closes elsewhere.
		rules = append(rules, fmt.Sprintf("IP-CIDR,%s,DIRECT,no-resolve", ip))
	}
	for _, domain := range domains {
		rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT", domain))
	}
	return rules
}

// cleanDomains normalises what somebody typed into what mihomo matches.
//
// A leading dot, a scheme, a path, a stray uppercase: all of them are what a
// person copying an address out of a browser produces, and all of them would
// silently match nothing. Fixing them here is better than a validation message,
// because there is exactly one thing each could have meant.
func cleanDomains(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		domain := strings.ToLower(strings.TrimSpace(value))
		if scheme := strings.Index(domain, "://"); scheme >= 0 {
			domain = domain[scheme+3:]
		}
		domain, _, _ = strings.Cut(domain, "/")
		// A port would make the suffix match nothing, and "example.com:443" is
		// what someone copies out of a proxy field.
		if host, _, found := strings.Cut(domain, ":"); found {
			domain = host
		}
		domain = strings.Trim(domain, ".")
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, domain)
	}
	return out
}

// cleanIPs keeps what could be a range and gives a bare address its /32.
//
// Deliberately not a full parse: mihomo validates its own rules and reports
// what it could not read, and a second opinion here that disagreed with it
// would be the harder bug to find. This only removes what is plainly empty and
// supplies the mask people leave off.
func cleanIPs(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		entry := strings.TrimSpace(value)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
	}
	return out
}
