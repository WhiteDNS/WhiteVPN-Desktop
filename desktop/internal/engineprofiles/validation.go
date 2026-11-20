package engineprofiles

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func (p Profile) Validate() error {
	if p.Version != SchemaVersion {
		return fmt.Errorf("unsupported engine profile version")
	}
	if !validID(p.ID) {
		return fmt.Errorf("invalid engine profile ID")
	}
	if !p.Kind.Valid() {
		return fmt.Errorf("unknown or retired engine kind")
	}
	if p.Name == "" || len(p.Name) > 400 || utf8.RuneCountInString(p.Name) > 100 || !utf8.ValidString(p.Name) || hasControl(p.Name) {
		return fmt.Errorf("profile name must contain 1–100 characters")
	}
	raw, err := json.Marshal(p.Config)
	if err != nil || len(raw) > MaxProfileBytes {
		return fmt.Errorf("engine configuration is too large")
	}
	// All nonempty union arms count, even ones that do not match Kind.
	n := 0
	for _, present := range []bool{p.Config.SSH != nil, p.Config.Psiphon != nil, p.Config.Tor != nil, p.Config.DNS != nil, p.Config.AmneziaWG != nil, p.Config.IKEv2 != nil} {
		if present {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("engine configuration must have exactly one kind")
	}
	switch p.Kind {
	case SSH:
		c := p.Config.SSH
		if c == nil {
			break
		}
		if !validHost(c.Host) || c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("invalid SSH host or port")
		}
		if strings.TrimSpace(c.Username) == "" || hasControl(c.Username) || len(c.Username) > 256 {
			return fmt.Errorf("SSH username is required")
		}
		if len(c.Password) > MaxConfigBytes || len(c.PrivateKey) > MaxConfigBytes || len(c.KeyPassphrase) > MaxConfigBytes {
			return fmt.Errorf("SSH credential is too large")
		}
		switch c.AuthType {
		case "password":
			if c.Password == "" {
				return fmt.Errorf("SSH password is required")
			}
		case "key":
			if strings.TrimSpace(c.PrivateKey) == "" {
				return fmt.Errorf("SSH private key is required")
			}
		default:
			return fmt.Errorf("invalid SSH authentication")
		}
		return nil
	case Psiphon:
		c := p.Config.Psiphon
		if c == nil {
			break
		}
		if c.Mode != "auto" && c.Mode != "cdn" && c.Mode != "direct" {
			return fmt.Errorf("invalid Psiphon mode")
		}
		if c.Country != "" && (len(c.Country) != 2 || c.Country[0] < 'A' || c.Country[0] > 'Z' || c.Country[1] < 'A' || c.Country[1] > 'Z') {
			return fmt.Errorf("invalid Psiphon country code")
		}
		if len(c.CDNIPs) > 64 {
			return fmt.Errorf("too many CDN IPs")
		}
		for _, ip := range c.CDNIPs {
			if a, err := netip.ParseAddr(ip); err != nil || a.Zone() != "" {
				return fmt.Errorf("invalid CDN IP address")
			}
		}
		if c.CDNSNI != "" && !validHost(c.CDNSNI) {
			return fmt.Errorf("invalid CDN server name")
		}
		return nil
	case Tor:
		c := p.Config.Tor
		if c == nil {
			break
		}
		if c.BridgeMode != "none" && c.BridgeMode != "default" && c.BridgeMode != "custom" {
			return fmt.Errorf("invalid Tor bridge mode")
		}
		if c.Transport != "obfs4" && c.Transport != "snowflake" && c.Transport != "conjure" {
			return fmt.Errorf("invalid Tor transport")
		}
		if len(c.Bridges) > MaxConfigBytes || !utf8.ValidString(c.Bridges) {
			return fmt.Errorf("Tor bridges are too large or invalid")
		}
		if c.BridgeMode == "custom" && strings.TrimSpace(c.Bridges) == "" {
			return fmt.Errorf("custom Tor bridges are required")
		}
		if err := validateBridges(c.Bridges, c.Transport); err != nil {
			return err
		}
		return nil
	case DNS:
		c := p.Config.DNS
		if c == nil {
			break
		}
		if c.Engine != "dnstt" && c.Engine != "vaydns" && c.Engine != "masterdns" {
			return fmt.Errorf("invalid DNS tunnel engine")
		}
		if len(c.Resolvers) > 128 || len(c.Domains) > 128 {
			return fmt.Errorf("too many DNS domains or resolvers")
		}
		if c.Engine == "masterdns" {
			if len(c.Domains) == 0 || c.EncryptionKey == "" {
				return fmt.Errorf("MasterDNS domains and encryption key are required")
			}
			for _, domain := range c.Domains {
				if !validHost(domain) {
					return fmt.Errorf("invalid MasterDNS domain")
				}
			}
			if c.Transport != "udp" || c.EncryptionMethod < 0 || c.EncryptionMethod > 5 {
				return fmt.Errorf("invalid MasterDNS transport or encryption method")
			}
		} else {
			key, err := hex.DecodeString(c.PublicKey)
			if !validHost(c.Domain) || err != nil || len(key) != 32 {
				return fmt.Errorf("invalid DNS tunnel domain or public key")
			}
			if c.Transport != "udp" && c.Transport != "tcp" && c.Transport != "dot" && c.Transport != "doh" {
				return fmt.Errorf("invalid DNS transport")
			}
		}
		if c.Transport == "doh" {
			u, err := url.Parse(c.DoHURL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !validHost(u.Hostname()) || hasControl(c.DoHURL) {
				return fmt.Errorf("DoH requires a valid HTTPS URL")
			}
		} else {
			if len(c.Resolvers) == 0 {
				return fmt.Errorf("DNS resolvers are required")
			}
			for _, r := range c.Resolvers {
				if !numericEndpoint(r) {
					return fmt.Errorf("DNS resolver must be an IP address with an optional port")
				}
			}
		}
		if len(c.EncryptionKey) > MaxConfigBytes || len(c.SOCKSUser) > 255 || len(c.SOCKSPassword) > 255 {
			return fmt.Errorf("DNS credential is too large")
		}
		return nil
	case AmneziaWG:
		c := p.Config.AmneziaWG
		if c == nil {
			break
		}
		if strings.TrimSpace(c.Raw) == "" || len(c.Raw) > MaxConfigBytes || !utf8.ValidString(c.Raw) || strings.ContainsRune(c.Raw, 0) {
			return fmt.Errorf("AmneziaWG configuration is required and limited to 64 KiB")
		}
		// The offline importer/backend must also parse the v3 configuration before start.
		return nil
	case IKEv2:
		c := p.Config.IKEv2
		if c == nil {
			break
		}
		if !validHost(c.Server) || hasControl(c.LocalID) || hasControl(c.ServerID) || len(c.LocalID) > 1024 || len(c.ServerID) > 1024 {
			return fmt.Errorf("invalid IKEv2 gateway or identity")
		}
		if len(c.Password) > MaxConfigBytes || len(c.PSK) > MaxConfigBytes || len(c.CACertPEM) > MaxConfigBytes {
			return fmt.Errorf("IKEv2 credential is too large")
		}
		switch c.AuthType {
		case "eap_mschapv2":
			if strings.TrimSpace(c.Username) == "" || c.Password == "" || hasControl(c.Username) || len(c.Username) > 256 {
				return fmt.Errorf("IKEv2 username and password are required")
			}
		case "psk":
			if c.PSK == "" {
				return fmt.Errorf("IKEv2 PSK is required")
			}
		case "certificate":
			thumb, err := hex.DecodeString(c.CertificateThumbprint)
			if err != nil || len(thumb) != 20 {
				return fmt.Errorf("invalid certificate thumbprint")
			}
			if c.CertificateStore != "CurrentUser\\My" && c.CertificateStore != "LocalMachine\\My" {
				return fmt.Errorf("invalid certificate store")
			}
		default:
			return fmt.Errorf("invalid IKEv2 authentication")
		}
		return nil
	}
	return fmt.Errorf("engine configuration does not match its kind")
}

func hasControl(v string) bool { return strings.IndexFunc(v, unicode.IsControl) >= 0 }

func validHost(host string) bool {
	if host == "" || len(host) > 253 || hasControl(host) || strings.TrimSpace(host) != host {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Zone() == ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

func numericEndpoint(value string) bool {
	if a, err := netip.ParseAddr(value); err == nil {
		return a.Zone() == ""
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	n, pe := strconv.Atoi(port)
	return err == nil && pe == nil && a.Zone() == "" && n > 0 && n <= 65535
}

func validateBridges(raw, transport string) error {
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if hasControl(line) || strings.ContainsAny(line, "\"\\") {
			return fmt.Errorf("invalid Tor bridge line")
		}
		f := strings.Fields(strings.TrimPrefix(line, "Bridge "))
		if len(f) < 2 {
			return fmt.Errorf("invalid Tor bridge line")
		}
		if f[0] == transport {
			f = f[1:]
		} else if f[0] == "obfs4" || f[0] == "snowflake" || f[0] == "conjure" {
			return fmt.Errorf("bridge transport does not match profile")
		}
		if len(f) < 2 || !numericEndpoint(f[0]) {
			return fmt.Errorf("invalid Tor bridge endpoint")
		}
		fp, err := hex.DecodeString(f[1])
		if err != nil || len(fp) != 20 {
			return fmt.Errorf("invalid Tor bridge fingerprint")
		}
		for _, option := range f[2:] {
			if !strings.Contains(option, "=") {
				return fmt.Errorf("invalid Tor bridge option")
			}
		}
	}
	return nil
}
