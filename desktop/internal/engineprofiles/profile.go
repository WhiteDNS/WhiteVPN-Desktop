// Package engineprofiles defines saved connection engines independently of
// Mihomo subscriptions. Profile contains credentials; Summary never does.
package engineprofiles

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	SchemaVersion   = 1
	MaxConfigBytes  = 64 << 10
	MaxProfileBytes = 192 << 10
	MaxProfiles     = 1000
)

type Kind string

const (
	SSH       Kind = "ssh"
	Psiphon   Kind = "psiphon"
	Tor       Kind = "tor"
	DNS       Kind = "dns"
	AmneziaWG Kind = "amneziawg"
	IKEv2     Kind = "ikev2"
)

func Kinds() []Kind { return []Kind{SSH, Psiphon, Tor, DNS, AmneziaWG, IKEv2} }

func (k Kind) Valid() bool {
	switch k {
	case SSH, Psiphon, Tor, DNS, AmneziaWG, IKEv2:
		return true
	}
	return false
}

func (k Kind) SOCKS() bool { return k == SSH || k == Psiphon || k == Tor || k == DNS }

// Revision is an optimistic concurrency token, not a wall-clock timestamp.
type Summary struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     Kind   `json:"kind"`
	Version  int    `json:"version"`
	Revision uint64 `json:"revision"`
}

type Profile struct {
	Summary
	Config Config `json:"config"`
}

// Avoid accidental credential disclosure through fmt/log calls.
func (p Profile) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "EngineProfile{credentials=[redacted]}")
}

type Config struct {
	SSH       *SSHConfig       `json:"ssh,omitempty"`
	Psiphon   *PsiphonConfig   `json:"psiphon,omitempty"`
	Tor       *TorConfig       `json:"tor,omitempty"`
	DNS       *DNSConfig       `json:"dns,omitempty"`
	AmneziaWG *AmneziaWGConfig `json:"amneziawg,omitempty"`
	IKEv2     *IKEv2Config     `json:"ikev2,omitempty"`
}

type SSHConfig struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	AuthType      string `json:"authType"`
	Password      string `json:"password"`
	PrivateKey    string `json:"privateKey"`
	KeyPassphrase string `json:"keyPassphrase"`
}

type PsiphonConfig struct {
	Mode    string   `json:"mode"`
	Country string   `json:"country"`
	CDNIPs  []string `json:"cdnIps"`
	CDNSNI  string   `json:"cdnSni"`
}

type TorConfig struct {
	BridgeMode string `json:"bridgeMode"`
	Transport  string `json:"transport"`
	Bridges    string `json:"bridges"`
}

type DNSConfig struct {
	Engine           string   `json:"engine"`
	Domain           string   `json:"domain"`
	Domains          []string `json:"domains"`
	PublicKey        string   `json:"publicKey"`
	Transport        string   `json:"dnsTransport"`
	Resolvers        []string `json:"resolvers"`
	DoHURL           string   `json:"dohUrl"`
	SOCKSUser        string   `json:"socksUser"`
	SOCKSPassword    string   `json:"socksPass"`
	EncryptionMethod int      `json:"encryptionMethod"`
	EncryptionKey    string   `json:"encryptionKey"`
}

type AmneziaWGConfig struct {
	Raw string `json:"config"`
}

type IKEv2Config struct {
	Server                string `json:"server"`
	LocalID               string `json:"localId"`
	ServerID              string `json:"serverId"`
	AuthType              string `json:"authType"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	PSK                   string `json:"psk"`
	CACertPEM             string `json:"caCertPem"`
	CertificateThumbprint string `json:"certificateThumbprint"`
	CertificateStore      string `json:"certificateStore"`
}

type RouteRef struct {
	Kind            string `json:"kind"`
	SourceID        string `json:"sourceId,omitempty"`
	NodeFingerprint string `json:"nodeFingerprint,omitempty"`
	ProfileID       string `json:"profileId,omitempty"`
}

func (r RouteRef) Validate() error {
	switch r.Kind {
	case "mihomo":
		if strings.TrimSpace(r.SourceID) == "" || len(r.SourceID) > 256 || len(r.NodeFingerprint) > 512 || r.ProfileID != "" {
			return fmt.Errorf("invalid Mihomo selection")
		}
	case "engine":
		if !validID(r.ProfileID) || r.SourceID != "" || r.NodeFingerprint != "" {
			return fmt.Errorf("invalid engine selection")
		}
	default:
		return fmt.Errorf("unknown route profile kind")
	}
	return nil
}

func validID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Decode rejects unknown fields and extra JSON values without echoing input
// (which may contain credentials) in the error returned to the UI.
func Decode(raw []byte) (Profile, error) {
	if len(raw) > MaxProfileBytes {
		return Profile{}, fmt.Errorf("engine profile is too large")
	}
	if !utf8.Valid(raw) || !uniqueJSON(raw) {
		return Profile{}, fmt.Errorf("invalid engine profile JSON")
	}
	var p Profile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("invalid engine profile JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Profile{}, fmt.Errorf("invalid engine profile JSON")
	}
	return p, nil
}

// Reject duplicate object keys and excessive nesting before decoding a typed
// config. Neither parser errors nor untrusted field names are returned to UI.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 16 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return false
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return false
					}
					seen[name] = true
					if !value(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim('}')
			case '[':
				for d.More() {
					if !value(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// Clone avoids sharing mutable config pointers/slices with callers or editors.
func (p Profile) Clone() Profile {
	raw, _ := json.Marshal(p)
	var copy Profile
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func (p Profile) Defaults() Profile {
	p = p.Clone()
	p.Name = strings.TrimSpace(p.Name)
	if c := p.Config.SSH; c != nil {
		if c.Port == 0 {
			c.Port = 22
		}
		if c.AuthType == "" {
			c.AuthType = "password"
		}
		c.Host = strings.TrimSpace(c.Host)
		c.Username = strings.TrimSpace(c.Username)
	}
	if c := p.Config.Psiphon; c != nil {
		if c.Mode == "" {
			c.Mode = "auto"
		}
		c.Country = strings.ToUpper(strings.TrimSpace(c.Country))
	}
	if c := p.Config.Tor; c != nil {
		if c.BridgeMode == "" {
			c.BridgeMode = "default"
		}
		if c.Transport == "" {
			c.Transport = "obfs4"
		}
	}
	if c := p.Config.DNS; c != nil {
		if c.Engine == "" {
			c.Engine = "dnstt"
		}
		if c.Transport == "" {
			c.Transport = "udp"
		}
	}
	if c := p.Config.IKEv2; c != nil {
		if c.AuthType == "" {
			c.AuthType = "eap_mschapv2"
		}
		if c.CertificateStore == "" {
			c.CertificateStore = "CurrentUser\\My"
		}
		c.Server = strings.TrimSpace(c.Server)
	}
	return p
}
