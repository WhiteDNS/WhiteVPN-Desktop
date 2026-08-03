package traffic

import "testing"

func TestWindowsEventAggregatorFiltersByPIDAndLoopback(t *testing.T) {
	aggregator := WindowsEventAggregator{PID: 42}

	if !aggregator.Add(WindowsNetworkEvent{PID: 42, Bytes: 1000, Receive: true}) {
		t.Fatal("expected receive event to be accepted")
	}
	if !aggregator.Add(WindowsNetworkEvent{PID: 42, Bytes: 500}) {
		t.Fatal("expected transmit event to be accepted")
	}
	if aggregator.Add(WindowsNetworkEvent{PID: 99, Bytes: 2000}) {
		t.Fatal("expected different PID to be ignored")
	}
	if aggregator.Add(WindowsNetworkEvent{PID: 42, Bytes: 2000, Loopback: true}) {
		t.Fatal("expected loopback traffic to be ignored")
	}

	if aggregator.Counters.RXBytes != 1000 || aggregator.Counters.TXBytes != 500 {
		t.Fatalf("unexpected counters: %#v", aggregator.Counters)
	}
}
