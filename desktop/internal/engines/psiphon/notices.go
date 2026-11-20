package psiphon

import "encoding/json"

// Notice is one line of the ConsoleClient's JSON notice stream, reduced to
// what the host acts on. These are the callbacks Android's PsiphonTunnel
// HostService receives: onListeningSocksProxyPort, onConnected,
// onAvailableEgressRegions, onExiting and the port/proxy failures.
type Notice struct {
	Type    string
	Port    int
	Count   int
	Regions []string
	// Message is set only for the exit-causing notices, so a failure can say why.
	Message string
}

const (
	NoticeListeningSocks = "ListeningSocksProxyPort"
	NoticeTunnels        = "Tunnels"
	NoticeRegions        = "AvailableEgressRegions"
	NoticeExiting        = "Exiting"
	NoticeSocksInUse     = "SocksProxyPortInUse"
	NoticeUpstreamError  = "UpstreamProxyError"
	NoticeMustUpgrade    = "InproxyMustUpgrade"
	NoticeError          = "Error"
)

// ParseNotice returns false for lines the host has no use for, including
// anything that is not a notice at all.
func ParseNotice(line []byte) (Notice, bool) {
	var raw struct {
		Type string `json:"noticeType"`
		Data struct {
			Port    *int     `json:"port"`
			Count   *int     `json:"count"`
			Regions []string `json:"regions"`
			Message string   `json:"message"`
		} `json:"data"`
	}
	if len(line) > 1<<20 || json.Unmarshal(line, &raw) != nil {
		return Notice{}, false
	}
	n := Notice{Type: raw.Type}
	switch raw.Type {
	case NoticeListeningSocks, NoticeSocksInUse:
		if raw.Data.Port == nil || *raw.Data.Port < 1 || *raw.Data.Port > 65535 {
			return Notice{}, false
		}
		n.Port = *raw.Data.Port
	case NoticeTunnels:
		if raw.Data.Count == nil || *raw.Data.Count < 0 {
			return Notice{}, false
		}
		n.Count = *raw.Data.Count
	case NoticeRegions:
		n.Regions = Normalize(raw.Data.Regions)
	case NoticeExiting, NoticeUpstreamError, NoticeMustUpgrade:
	case NoticeError:
		n.Message = raw.Data.Message
	default:
		return Notice{}, false
	}
	return n, true
}

// Fatal reports the notices Android treats as the engine going away.
func (n Notice) Fatal() bool {
	switch n.Type {
	case NoticeExiting, NoticeSocksInUse, NoticeUpstreamError, NoticeMustUpgrade:
		return true
	}
	return false
}
