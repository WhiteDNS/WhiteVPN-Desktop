package session

import (
	"fmt"
	"strings"
)

func verifyTunnelRoutes(output string, ipv6 bool) error {
	routes := make(map[string]bool)
	for _, route := range strings.Fields(output) {
		routes[strings.ToLower(route)] = true
	}
	if !routes["0.0.0.0/0"] && !(routes["0.0.0.0/1"] && routes["128.0.0.0/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv4 traffic")
	}
	if ipv6 && !routes["::/0"] && !(routes["::/1"] && routes["8000::/1"]) {
		return fmt.Errorf("the tunnel has no route covering IPv6 traffic")
	}
	return nil
}
