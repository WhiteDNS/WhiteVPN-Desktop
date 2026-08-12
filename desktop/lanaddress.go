package main

// Which address another device should be pointed at.
//
// Sharing the connection over a hotspot only works if the person can be told
// where to point the phone, and "127.0.0.1" is the one answer that is useless
// for it — that address means "this machine" on the phone too, so a user copying
// it off the dashboard would be sending the phone to itself.

import "net"

// lanAddress is this machine's address on the local network, or empty when it
// has none worth offering.
//
// Empty rather than a guess. A wrong address here is worse than none: it sends
// somebody to configure a device with a number that cannot work, and the failure
// looks like the VPN's rather than the address's.
func lanAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		// Down, or loopback — neither reaches another device.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			network, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := network.IP.To4()
			// IPv4 only. A phone being set up by hand takes four numbers and a
			// port; handing someone a v6 address with a zone suffix to type into
			// Telegram is not an improvement.
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
