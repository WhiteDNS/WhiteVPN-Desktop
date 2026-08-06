//go:build darwin

package sysproxy

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// macOS keeps proxy settings per network service — Wi-Fi, Ethernet, a USB
// tether, each with its own — rather than one setting for the machine. There is
// no API for it that does not need entitlements, so this drives `networksetup`,
// the tool Apple ships for exactly this and the one every VPN client on the
// platform uses.
//
// Every enabled service is set, because the one the user is on now is not
// necessarily the one they will be on in a minute, and a VPN that stops working
// when a laptop moves from Wi-Fi to Ethernet is a VPN that looks broken.
const networksetup = "/usr/sbin/networksetup"

// Current reads the proxy settings of the first service that has any.
//
// Reading one is enough for a faithful restore because Apply writes the same
// state to all of them: they were made to agree when this app last touched
// them, and if it never has, the first service's settings are as good an answer
// as any other's.
func Current() (State, error) {
	services, err := networkServices()
	if err != nil {
		return State{}, err
	}
	for _, service := range services {
		state, err := serviceProxy(service)
		if err != nil {
			continue
		}
		if state.Enabled || state.Server != "" {
			return state, nil
		}
	}
	return State{}, nil
}

// Apply writes the state to every enabled network service.
func Apply(state State) error {
	services, err := networkServices()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("sysproxy: this machine has no network services to configure")
	}

	host, port := splitEndpoint(state.Server)
	script := proxyScript(services, state, host, port)
	command := exec.Command("/usr/bin/osascript", "-e",
		"do shell script "+strconv.Quote(script)+" with administrator privileges")
	if out, err := command.CombinedOutput(); err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			return fmt.Errorf("sysproxy: administrator approval failed: %w", err)
		}
		return fmt.Errorf("sysproxy: administrator approval failed: %w: %s", err, detail)
	}
	return nil
}

// Pointing is the state that points the machine at endpoint.
func Pointing(endpoint string) (State, error) {
	if strings.TrimSpace(endpoint) == "" {
		return State{}, fmt.Errorf("sysproxy: no proxy address to set")
	}
	return State{Enabled: true, Server: endpoint, Override: DefaultBypass}, nil
}

// Verify reads the settings back and reports whether they took.
func Verify(want State) error {
	services, err := networkServices()
	if err != nil {
		return err
	}
	if len(services) == 0 {
		return fmt.Errorf("sysproxy: this machine has no network services to verify")
	}
	return verifyServices(services, want, serviceProxy)
}

func verifyServices(services []string, want State, read func(string) (State, error)) error {
	for _, service := range services {
		got, err := read(service)
		if err != nil {
			return fmt.Errorf("sysproxy: verify %s: %w", service, err)
		}
		if got.Enabled != want.Enabled || !strings.EqualFold(got.Server, want.Server) {
			return fmt.Errorf("sysproxy: %s did not stick — asked for %q (enabled=%t), found %q (enabled=%t)",
				service, want.Server, want.Enabled, got.Server, got.Enabled)
		}
	}
	return nil
}

func proxyScript(services []string, state State, host, port string) string {
	// Web and secure-web are the HTTP and HTTPS proxies; SOCKS is set as well
	// because the engine's mixed port serves all three and some applications
	// reach for SOCKS first.
	kinds := []struct{ set, state string }{
		{"-setwebproxy", "-setwebproxystate"},
		{"-setsecurewebproxy", "-setsecurewebproxystate"},
		{"-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
	}
	var commands []string
	for _, service := range services {
		for _, kind := range kinds {
			if state.Enabled {
				commands = append(commands, shellCommand(networksetup, kind.set, service, host, port))
				continue
			}
			commands = append(commands, shellCommand(networksetup, kind.state, service, "off"))
		}
		if state.Enabled && state.Override != "" {
			// Bypass entries are separate arguments, not one semicolon-joined
			// string as on Windows.
			args := append([]string{networksetup, "-setproxybypassdomains", service}, bypassDomains(state.Override)...)
			commands = append(commands, shellCommand(args...))
		}
	}
	return strings.Join(commands, " && ")
}

func shellCommand(args ...string) string {
	for i := range args {
		args[i] = "'" + strings.ReplaceAll(args[i], "'", "'\"'\"'") + "'"
	}
	return strings.Join(args, " ")
}

// networkServices lists the services that are enabled. A disabled one is
// prefixed with an asterisk in this output and is left alone.
func networkServices() ([]string, error) {
	output, err := output(networksetup, "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("sysproxy: list network services: %w", err)
	}
	var services []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// The first line is a note about the asterisk, not a service.
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		services = append(services, line)
	}
	return services, scanner.Err()
}

// serviceProxy reads one service's HTTPS proxy, which is the one that matters
// most and the one Apply always sets.
func serviceProxy(service string) (State, error) {
	out, err := output(networksetup, "-getsecurewebproxy", service)
	if err != nil {
		return State{}, err
	}
	var state State
	var host, port string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			state.Enabled = strings.EqualFold(value, "yes")
		case "Server":
			host = value
		case "Port":
			port = value
		}
	}
	if host != "" && port != "" && port != "0" {
		state.Server = host + ":" + port
	}
	return state, scanner.Err()
}

func splitEndpoint(endpoint string) (host, port string) {
	host, port, found := strings.Cut(endpoint, ":")
	if !found {
		return endpoint, ""
	}
	return host, port
}

// bypassDomains turns the Windows-shaped list into the arguments networksetup
// wants. The two platforms spell the same idea differently and the stored state
// keeps one spelling, so this is where they meet.
func bypassDomains(override string) []string {
	var out []string
	for _, entry := range strings.Split(override, ";") {
		entry = strings.TrimSpace(entry)
		// `<local>` is a Windows token with no macOS equivalent; the wildcards
		// beside it already cover what it means.
		if entry == "" || entry == "<local>" {
			continue
		}
		out = append(out, entry)
	}
	if len(out) == 0 {
		// networksetup needs at least one argument, and "Empty" is its own word
		// for clearing the list.
		out = append(out, "Empty")
	}
	return out
}

func output(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	out, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
