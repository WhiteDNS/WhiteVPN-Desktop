package traffic

type WindowsNetworkEvent struct {
	PID       int
	Bytes     int64
	Receive   bool
	Loopback  bool
	Interface string
}

type WindowsEventAggregator struct {
	PID      int
	Counters Counters
}

func (a *WindowsEventAggregator) Add(event WindowsNetworkEvent) bool {
	if event.PID != a.PID || event.Bytes <= 0 || event.Loopback {
		return false
	}
	if event.Receive {
		a.Counters.RXBytes += event.Bytes
	} else {
		a.Counters.TXBytes += event.Bytes
	}
	return true
}
