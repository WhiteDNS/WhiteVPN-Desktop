package traffic

import (
	"net"
	"testing"
)

func TestParseLinuxProcNetLine(t *testing.T) {
	line := " 46: 3500007F:BEEF 08080808:0035 01 00000000:00000000 00:00000000 00000000 1000 0 123456 1 0000000000000000 20 4 30 10 -1"

	socket, ok, err := parseLinuxProcNetLine(line, 17)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected socket row")
	}
	if socket.Protocol != 17 || socket.Inode != "123456" {
		t.Fatalf("unexpected socket metadata: %#v", socket)
	}
	if !socket.Local.IP.Equal(net.IPv4(127, 0, 0, 53)) || socket.Local.Port != 0xBEEF {
		t.Fatalf("unexpected local endpoint: %#v", socket.Local)
	}
	if !socket.Remote.IP.Equal(net.IPv4(8, 8, 8, 8)) || socket.Remote.Port != 53 {
		t.Fatalf("unexpected remote endpoint: %#v", socket.Remote)
	}
}

func TestParseLinuxProcNetLineIgnoresHeader(t *testing.T) {
	_, ok, err := parseLinuxProcNetLine("sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", 6)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected header row to be ignored")
	}
}
