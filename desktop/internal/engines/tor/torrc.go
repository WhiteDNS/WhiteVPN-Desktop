package tor

import (
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"whitevpn-desktop/internal/engineprofiles"
)

// DefaultBridges is the bridge list Android ships as assets/tor/bridges_default.lst.
//
//go:embed bridges_default.lst
var DefaultBridges string

// Default broker/front/STUN settings from pinned Snowflake v2.14.1 client/torrc.
const (
	snowflakeBroker = "https://1098762253.rsc.cdn77.org/"
	snowflakeFronts = "www.cdn77.com,www.phpmyadmin.net"
	snowflakeICE    = "stun:stun.antisip.com:3478,stun:stun.epygi.com:3478," +
		"stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478," +
		"stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443"
)

// pluginExecutable names the transport binary inside the plugin dir, as the
// Tor Expert Bundle ships it: lyrebird serves both obfs4 and snowflake.
func pluginExecutable(transport string) string {
	name := "lyrebird"
	if transport == "conjure" {
		name = "conjure-client"
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// snowflakeBridge carries Android's snowflake-client flags as bridge
// parameters: lyrebird exits on -url/-fronts/-ice, and reads url=, fronts= and
// ice= from the bridge line instead. A line that sets one keeps its own.
func snowflakeBridge(l string) string {
	for _, kv := range [][2]string{{"url", snowflakeBroker}, {"fronts", snowflakeFronts}, {"ice", snowflakeICE}} {
		if !strings.Contains(" "+l, " "+kv[0]+"=") {
			l += " " + kv[0] + "=" + kv[1]
		}
	}
	return l
}

// buildTorrc is Android's TorEngineConfig.build.
func buildTorrc(cfg engineprofiles.TorConfig, pluginDir, dataDir string, port int, defaultBridges string) (string, error) {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("SocksPort 127.0.0.1:%d", port)
	line("DataDirectory %s", quoteTorrc(dataDir))
	line("ClientOnly 1")
	line("AvoidDiskWrites 1")
	line("Log notice stdout")
	mode := valueOr(cfg.BridgeMode, "default")
	if mode == "none" {
		return b.String(), nil
	}
	transport := valueOr(cfg.Transport, "obfs4")
	if transport != "obfs4" && transport != "snowflake" && transport != "conjure" {
		return "", errors.New("tor: invalid bridge transport")
	}
	line("UseBridges 1")
	// Tor splits this option into argv on whitespace; it does not strip quotes.
	// '#' would start a comment and cut the path short, and tor.exe launches the
	// transport through ANSI APIs that mangle non-ASCII.
	if !filepath.IsAbs(pluginDir) || strings.ContainsFunc(pluginDir, func(r rune) bool {
		return unicode.IsSpace(r) || r == '"' || r == '\'' || r == '#' || (runtime.GOOS == "windows" && r > unicode.MaxASCII)
	}) {
		return "", errors.New("tor: the transport directory must be an absolute ASCII path without spaces, quotes or '#'")
	}
	line("ClientTransportPlugin %s exec %s", transport, filepath.Join(pluginDir, pluginExecutable(transport)))
	raw := defaultBridges
	if mode == "custom" {
		raw = cfg.Bridges
	}
	if err := validateBridgeCompatibility(transport, raw); err != nil {
		return "", err
	}
	var bridges []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimPrefix(strings.TrimSpace(l), "Bridge ")
		if !strings.HasPrefix(l, transport+" ") {
			continue
		}
		// Profiles are validated on save; this keeps a bad line from becoming a
		// second torrc directive however it got here.
		if strings.ContainsFunc(l, unicode.IsControl) || strings.ContainsAny(l, "\"\\") {
			return "", errors.New("tor: invalid bridge line")
		}
		if transport == "snowflake" {
			l = snowflakeBridge(l)
		}
		bridges = append(bridges, l)
	}
	if len(bridges) == 0 {
		return "", errors.New("tor: no bridges for the selected transport")
	}
	for _, l := range bridges {
		line("Bridge %s", l)
	}
	return b.String(), nil
}

// validateBridgeCompatibility is Android's TorBridgeCompatibility.validate.
func validateBridgeCompatibility(transport, raw string) error {
	if transport != "conjure" {
		return nil
	}
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimPrefix(strings.TrimSpace(l), "Bridge ")
		if !strings.HasPrefix(l, "conjure ") {
			continue
		}
		options := map[string]string{}
		for _, f := range strings.Fields(l) {
			if k, v, ok := strings.Cut(f, "="); ok {
				options[k] = v
			}
		}
		if r, ok := options["registrar"]; ok && r != "http" {
			return errors.New("tor: this Conjure client supports HTTP registration only")
		}
		if t, ok := options["transport"]; ok && t != "min" {
			return errors.New("tor: this Conjure client supports min transport only")
		}
	}
	return nil
}

func quoteTorrc(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

func valueOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
