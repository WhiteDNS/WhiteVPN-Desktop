package main

import (
	"net"
	"strings"
	"time"
)

const localProxyDisplayIP = "127.0.0.1"

func proxyShareIPs(listenIP string, detectNetworkIPv4 func() string) (string, string) {
	if !isWildcardListenIP(listenIP) {
		return "", ""
	}
	if detectNetworkIPv4 == nil {
		return localProxyDisplayIP, ""
	}
	return localProxyDisplayIP, sanitizeShareIPv4(detectNetworkIPv4())
}

func detectShareNetworkIPv4() string {
	return chooseShareNetworkIPv4(activeRouteIPv4, firstPrivateInterfaceIPv4)
}

func chooseShareNetworkIPv4(active, fallback func() string) string {
	if active != nil {
		if ip := sanitizeShareIPv4(active()); ip != "" {
			return ip
		}
	}
	if fallback != nil {
		return sanitizeShareIPv4(fallback())
	}
	return ""
}

func activeRouteIPv4() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 250*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return ""
	}
	if ip := addr.IP.To4(); ip != nil {
		return ip.String()
	}
	return ""
}

func firstPrivateInterfaceIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := ipFromAddr(addr)
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 != nil && ip4.IsPrivate() && sanitizeShareIPv4(ip4.String()) != "" {
				return ip4.String()
			}
		}
	}
	return ""
}

func ipFromAddr(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func sanitizeShareIPv4(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value)).To4()
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return ""
	}
	return ip.String()
}

func isWildcardListenIP(value string) bool {
	switch strings.TrimSpace(value) {
	case "", "0.0.0.0", "::":
		return true
	default:
		return false
	}
}
