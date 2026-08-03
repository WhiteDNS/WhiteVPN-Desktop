//go:build linux

package traffic

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	linuxProtocolTCP = 6
	linuxProtocolUDP = 17
)

type LinuxSampler struct {
	mu      sync.Mutex
	started bool
	err     error
	totals  Counters
}

type linuxPacket struct {
	Protocol uint8
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Length   int64
}

func NewLinuxSampler() *LinuxSampler {
	return &LinuxSampler{}
}

func (s *LinuxSampler) Sample(ctx context.Context, pid int) (Counters, error) {
	if pid <= 0 {
		return Counters{}, fmt.Errorf("invalid process id: %d", pid)
	}

	s.mu.Lock()
	if !s.started {
		s.started = true
		s.err = s.startCapture(ctx, pid)
	}
	err := s.err
	totals := s.totals
	s.mu.Unlock()
	if err != nil {
		return Counters{}, err
	}
	return totals, nil
}

func (s *LinuxSampler) startCapture(ctx context.Context, pid int) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, htons(unix.ETH_P_ALL))
	if err != nil {
		return fmt.Errorf("Linux traffic monitor unavailable: raw packet capture requires root or CAP_NET_RAW: %w", err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("Linux traffic monitor unavailable: %w", err)
	}

	go func() {
		defer unix.Close(fd)
		s.captureLoop(ctx, pid, fd)
	}()
	return nil
}

func (s *LinuxSampler) captureLoop(ctx context.Context, pid int, fd int) {
	buffer := make([]byte, 65535)
	externalInterfaces := linuxExternalInterfaceIndexes()
	socketMatcher := linuxSocketMatcher{}
	nextRefresh := time.Time{}

	for ctx.Err() == nil {
		now := time.Now()
		if now.After(nextRefresh) {
			socketMatcher = readLinuxSocketMatcher(pid)
			externalInterfaces = linuxExternalInterfaceIndexes()
			nextRefresh = now.Add(time.Second)
		}

		n, addr, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				select {
				case <-ctx.Done():
				case <-time.After(25 * time.Millisecond):
				}
				continue
			}
			s.mu.Lock()
			s.err = fmt.Errorf("Linux traffic monitor unavailable: %w", err)
			s.mu.Unlock()
			return
		}
		linkAddr, ok := addr.(*unix.SockaddrLinklayer)
		if !ok || !externalInterfaces[linkAddr.Ifindex] {
			continue
		}
		packet, ok := parseLinuxEthernetPacket(buffer[:n])
		if !ok {
			continue
		}
		direction := socketMatcher.match(packet)
		if direction == "" {
			continue
		}
		s.mu.Lock()
		if direction == "rx" {
			s.totals.RXBytes += packet.Length
		} else {
			s.totals.TXBytes += packet.Length
		}
		s.mu.Unlock()
	}
}

type linuxSocketMatcher struct {
	sockets []linuxProcessSocket
}

func readLinuxSocketMatcher(pid int) linuxSocketMatcher {
	inodes := readLinuxProcessSocketInodes(pid)
	if len(inodes) == 0 {
		return linuxSocketMatcher{}
	}
	sockets := make([]linuxProcessSocket, 0, len(inodes))
	for _, source := range []struct {
		path     string
		protocol uint8
	}{
		{"/proc/net/tcp", linuxProtocolTCP},
		{"/proc/net/tcp6", linuxProtocolTCP},
		{"/proc/net/udp", linuxProtocolUDP},
		{"/proc/net/udp6", linuxProtocolUDP},
	} {
		sockets = append(sockets, readLinuxProcNetSockets(source.path, source.protocol, inodes)...)
	}
	return linuxSocketMatcher{sockets: sockets}
}

func readLinuxProcessSocketInodes(pid int) map[string]struct{} {
	fdDir := filepath.Join("/proc", fmt.Sprintf("%d", pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
		if inode != "" {
			inodes[inode] = struct{}{}
		}
	}
	return inodes
}

func readLinuxProcNetSockets(path string, protocol uint8, inodes map[string]struct{}) []linuxProcessSocket {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var sockets []linuxProcessSocket
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		socket, ok, err := parseLinuxProcNetLine(scanner.Text(), protocol)
		if err != nil || !ok {
			continue
		}
		if _, exists := inodes[socket.Inode]; exists {
			sockets = append(sockets, socket)
		}
	}
	return sockets
}

func (m linuxSocketMatcher) match(packet linuxPacket) string {
	for _, socket := range m.sockets {
		if socket.Protocol != packet.Protocol {
			continue
		}
		if socket.Local.Port == packet.DstPort && linuxIPMatchesSocket(socket.Local.IP, packet.DstIP) {
			return "rx"
		}
		if socket.Local.Port == packet.SrcPort && linuxIPMatchesSocket(socket.Local.IP, packet.SrcIP) {
			return "tx"
		}
	}
	return ""
}

func linuxExternalInterfaceIndexes() map[int]bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	indexes := make(map[int]bool)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		indexes[iface.Index] = true
	}
	return indexes
}

func parseLinuxEthernetPacket(raw []byte) (linuxPacket, bool) {
	if len(raw) < 14 {
		return linuxPacket{}, false
	}
	offset := 14
	etherType := binary.BigEndian.Uint16(raw[12:14])
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(raw) < offset+4 {
			return linuxPacket{}, false
		}
		etherType = binary.BigEndian.Uint16(raw[offset+2 : offset+4])
		offset += 4
	}
	switch etherType {
	case 0x0800:
		return parseLinuxIPv4Packet(raw[offset:])
	case 0x86dd:
		return parseLinuxIPv6Packet(raw[offset:])
	default:
		return linuxPacket{}, false
	}
}

func parseLinuxIPv4Packet(raw []byte) (linuxPacket, bool) {
	if len(raw) < 20 {
		return linuxPacket{}, false
	}
	headerLen := int(raw[0]&0x0f) * 4
	if headerLen < 20 || len(raw) < headerLen+4 {
		return linuxPacket{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen <= 0 || totalLen > len(raw) {
		totalLen = len(raw)
	}
	protocol := raw[9]
	if protocol != linuxProtocolTCP && protocol != linuxProtocolUDP {
		return linuxPacket{}, false
	}
	srcPort := binary.BigEndian.Uint16(raw[headerLen : headerLen+2])
	dstPort := binary.BigEndian.Uint16(raw[headerLen+2 : headerLen+4])
	return linuxPacket{
		Protocol: protocol,
		SrcIP:    net.IPv4(raw[12], raw[13], raw[14], raw[15]),
		DstIP:    net.IPv4(raw[16], raw[17], raw[18], raw[19]),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   int64(totalLen),
	}, true
}

func parseLinuxIPv6Packet(raw []byte) (linuxPacket, bool) {
	if len(raw) < 44 {
		return linuxPacket{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(raw[4:6]))
	nextHeader := raw[6]
	if nextHeader != linuxProtocolTCP && nextHeader != linuxProtocolUDP {
		return linuxPacket{}, false
	}
	srcPort := binary.BigEndian.Uint16(raw[40:42])
	dstPort := binary.BigEndian.Uint16(raw[42:44])
	return linuxPacket{
		Protocol: nextHeader,
		SrcIP:    append(net.IP(nil), raw[8:24]...),
		DstIP:    append(net.IP(nil), raw[24:40]...),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   int64(40 + payloadLen),
	}, true
}

func htons(value uint16) int {
	return int((value<<8)&0xff00 | value>>8)
}
