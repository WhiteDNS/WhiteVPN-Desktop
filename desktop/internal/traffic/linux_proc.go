package traffic

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type linuxEndpoint struct {
	IP   net.IP
	Port uint16
}

type linuxProcessSocket struct {
	Protocol uint8
	Local    linuxEndpoint
	Remote   linuxEndpoint
	Inode    string
}

func parseLinuxProcNetLine(line string, protocol uint8) (linuxProcessSocket, bool, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 || fields[0] == "sl" {
		return linuxProcessSocket{}, false, nil
	}
	local, err := parseLinuxProcEndpoint(fields[1])
	if err != nil {
		return linuxProcessSocket{}, false, err
	}
	remote, err := parseLinuxProcEndpoint(fields[2])
	if err != nil {
		return linuxProcessSocket{}, false, err
	}
	inode := strings.TrimSpace(fields[9])
	if inode == "" || inode == "0" {
		return linuxProcessSocket{}, false, nil
	}
	return linuxProcessSocket{
		Protocol: protocol,
		Local:    local,
		Remote:   remote,
		Inode:    inode,
	}, true, nil
}

func parseLinuxProcEndpoint(value string) (linuxEndpoint, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return linuxEndpoint{}, fmt.Errorf("invalid proc endpoint %q", value)
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return linuxEndpoint{}, fmt.Errorf("invalid proc endpoint port %q: %w", value, err)
	}
	ip, err := parseLinuxProcIP(parts[0])
	if err != nil {
		return linuxEndpoint{}, err
	}
	return linuxEndpoint{IP: ip, Port: uint16(port)}, nil
}

func parseLinuxProcIP(value string) (net.IP, error) {
	value = strings.TrimSpace(value)
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid proc endpoint IP %q: %w", value, err)
	}
	switch len(raw) {
	case 4:
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]), nil
	case 16:
		ip := make(net.IP, 16)
		for idx := 0; idx < 16; idx += 4 {
			ip[idx] = raw[idx+3]
			ip[idx+1] = raw[idx+2]
			ip[idx+2] = raw[idx+1]
			ip[idx+3] = raw[idx]
		}
		return ip, nil
	default:
		return nil, fmt.Errorf("invalid proc endpoint IP length %d for %q", len(raw), value)
	}
}

func linuxIPMatchesSocket(socketIP, packetIP net.IP) bool {
	if socketIP == nil || packetIP == nil {
		return true
	}
	if socketIP.IsUnspecified() {
		return true
	}
	return socketIP.Equal(packetIP)
}
