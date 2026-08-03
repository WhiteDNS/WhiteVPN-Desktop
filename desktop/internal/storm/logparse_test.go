package storm

import "testing"

func TestParseProgress(t *testing.T) {
	progress, ok := ParseProgress("\x1b[32mWD_PROGRESS phase=mtu percent=42 completed=4 total=10 valid=3 rejected=1\x1b[0m")
	if !ok {
		t.Fatal("expected progress line")
	}
	if progress.Phase != "mtu" || progress.Percent != 42 || progress.Valid != 3 {
		t.Fatalf("unexpected progress: %#v", progress)
	}
}

func TestParseScannerEvent(t *testing.T) {
	event, ok := ParseScannerEvent("2026 [INFO] WD_SCAN event=valid resolver=1.1.1.1:53")
	if !ok {
		t.Fatal("expected scanner event")
	}
	if event.Event != "valid" || event.Resolver != "1.1.1.1:53" {
		t.Fatalf("unexpected scanner event: %#v", event)
	}

	event, ok = ParseScannerEvent("WD_SCAN event=complete total=10 valid=4 rejected=6")
	if !ok {
		t.Fatal("expected scanner complete event")
	}
	if event.Event != "complete" || event.Total != 10 || event.Valid != 4 || event.Rejected != 6 {
		t.Fatalf("unexpected scanner complete event: %#v", event)
	}

	event, ok = ParseScannerEvent("WD_SCAN event=started total=15000")
	if !ok {
		t.Fatal("expected scanner started event")
	}
	if event.Event != "started" || event.Total != 15000 {
		t.Fatalf("unexpected scanner started event: %#v", event)
	}
}

func TestParseResolverState(t *testing.T) {
	state, ok := ParseResolverState("WD_RESOLVERS active=1.1.1.1,8.8.8.8 standby=- valid=1.1.1.1,8.8.8.8")
	if !ok {
		t.Fatal("expected resolver state line")
	}
	if len(state.ActiveResolvers) != 2 || len(state.StandbyResolvers) != 0 || len(state.ValidResolvers) != 2 {
		t.Fatalf("unexpected resolver state: %#v", state)
	}
	if state.ActiveCount != 2 || state.ValidCount != 2 || !state.ActiveComplete || !state.ValidComplete {
		t.Fatalf("unexpected resolver counts: %#v", state)
	}
}

func TestParseSampledResolverState(t *testing.T) {
	state, ok := ParseResolverState("WD_RESOLVERS total_count=250 active_count=100 active_sample=1.1.1.1,8.8.8.8 active_complete=false standby_count=0 standby_sample=- standby_complete=true valid_count=200 valid_sample=1.1.1.1 valid_complete=false rejected_count=40 pending_count=10")
	if !ok {
		t.Fatal("expected resolver state line")
	}
	if state.TotalCount != 250 || state.ActiveCount != 100 || state.ValidCount != 200 || state.RejectedCount != 40 || state.PendingCount != 10 || state.ActiveComplete || state.ValidComplete {
		t.Fatalf("unexpected sampled resolver state: %#v", state)
	}
	if len(state.ActiveResolvers) != 2 || len(state.ValidResolvers) != 1 {
		t.Fatalf("unexpected sampled resolver lists: %#v", state)
	}
}

func TestParseResolverStateLiveRejectedCount(t *testing.T) {
	state, ok := ParseResolverState("WD_RESOLVERS total_count=200 active_count=28 active_sample=1.1.1.1 active_complete=false standby_count=0 standby_sample=- standby_complete=true valid_count=28 valid_sample=1.1.1.1 valid_complete=false rejected_count=172 pending_count=0")
	if !ok {
		t.Fatal("expected resolver state line")
	}
	if state.TotalCount != 200 || state.ValidCount != 28 || state.RejectedCount != 172 || state.PendingCount != 0 {
		t.Fatalf("unexpected live resolver counts: %#v", state)
	}
}

func TestParseMTUResolverRuntimeState(t *testing.T) {
	state, ok := ParseMTUResolverRuntimeState(`
WHITEDNS_MTU_STATE event=valid resolver=1.1.1.1 domain=v.example.com up=120 down=1300 up_chars=180
WHITEDNS_MTU_STATE event=valid resolver=8.8.8.8 domain=v.example.com up=118 down=1280 up_chars=177
WHITEDNS_MTU_STATE event=removed resolver=1.1.1.1 domain=v.example.com up=120 down=1300 up_chars=180 cause=timeout window
WHITEDNS_MTU_STATE event=added resolver=1.1.1.1 domain=v.example.com up=120 down=1300 up_chars=180
WHITEDNS_MTU_STATE event=removed resolver=8.8.8.8 domain=v.example.com up=118 down=1280 up_chars=177 cause=Dropped by MTU Optimizer
`)
	if !ok {
		t.Fatal("expected MTU resolver state")
	}
	if state.ValidCount != 2 || len(state.ValidResolvers) != 2 {
		t.Fatalf("unexpected valid resolvers: %#v", state)
	}
	if state.ActiveCount != 1 || len(state.ActiveResolvers) != 1 || state.ActiveResolvers[0] != "1.1.1.1" {
		t.Fatalf("unexpected active resolvers: %#v", state)
	}
	if len(state.ResolverDetails) != 2 {
		t.Fatalf("expected resolver details: %#v", state)
	}
	first := state.ResolverDetails[0]
	if first.Resolver != "1.1.1.1" || first.Domain != "v.example.com" || first.UploadMTU != 120 || first.DownloadMTU != 1300 || first.UploadMTUChars != 180 || !first.Active || !first.Valid || first.Status != "active" || first.LastEvent != "added" {
		t.Fatalf("unexpected active resolver detail: %#v", first)
	}
	second := state.ResolverDetails[1]
	if second.Resolver != "8.8.8.8" || second.Status != "valid" || second.Active || !second.Valid || second.LastEvent != "removed" || second.Cause != "Dropped by MTU Optimizer" {
		t.Fatalf("unexpected removed resolver detail: %#v", second)
	}
	if !state.ActiveComplete || !state.ValidComplete {
		t.Fatalf("expected complete file-derived state: %#v", state)
	}
}

func TestParseMTUResolverRuntimeStateSupportsLegacyLines(t *testing.T) {
	state, ok := ParseMTUResolverRuntimeState(`
WHITEDNS_MTU_STATE event=valid resolver=1.1.1.1 domain=v.example.com up=120 down=1300
WHITEDNS_MTU_STATE event=removed resolver=1.1.1.1 domain=v.example.com up=120 down=1300
`)
	if !ok {
		t.Fatal("expected MTU resolver state")
	}
	if state.ValidCount != 1 || state.ActiveCount != 0 {
		t.Fatalf("unexpected resolver counts: %#v", state)
	}
	if len(state.ResolverDetails) != 1 {
		t.Fatalf("expected one resolver detail: %#v", state)
	}
	detail := state.ResolverDetails[0]
	if detail.UploadMTU != 120 || detail.DownloadMTU != 1300 || detail.UploadMTUChars != 0 || detail.Status != "valid" || detail.LastEvent != "removed" {
		t.Fatalf("unexpected legacy resolver detail: %#v", detail)
	}
}

func TestParseTrafficStats(t *testing.T) {
	stats, ok := ParseTrafficStats("12.5 KB/s (Total: 1.0 MB) | Download: 2.0 MB/s (Total: 3.5 MB)")
	if !ok {
		t.Fatal("expected traffic stats line")
	}
	if stats.UploadSpeedBytesPerSecond != 12800 {
		t.Fatalf("unexpected upload speed: %#v", stats)
	}
	if stats.DownloadSpeedBytesPerSecond != 2097152 {
		t.Fatalf("unexpected download speed: %#v", stats)
	}
}

func TestParseMachineTrafficStats(t *testing.T) {
	stats, ok := ParseTrafficStats("2026/05/20 [StormDNS Client] [INFO] WD_STATS upload_bps=1234 upload_total=4096 download_bps=5678 download_total=8192")
	if !ok {
		t.Fatal("expected machine traffic stats line")
	}
	if stats.UploadSpeedBytesPerSecond != 1234 || stats.DownloadSpeedBytesPerSecond != 5678 {
		t.Fatalf("unexpected speeds: %#v", stats)
	}
	if stats.TotalDataUsageBytes != 12288 {
		t.Fatalf("unexpected total: %#v", stats)
	}
}

func TestParseCurrentHumanTrafficStats(t *testing.T) {
	stats, ok := ParseTrafficStats("📊 ↑ 1.50 KB/s (Total: 2.00 KB) | ↓ 3.00 KB/s (Total: 4.00 KB)")
	if !ok {
		t.Fatal("expected current human traffic stats line")
	}
	if stats.UploadSpeedBytesPerSecond != 1536 || stats.DownloadSpeedBytesPerSecond != 3072 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestIsTargetServerUnavailableLog(t *testing.T) {
	lines := []string{
		"<red>MTU tests failed: no valid connections after mtu testing</red>",
		"⏱ <yellow>Ping watchdog triggered: no server response for 30s, restarting session</yellow>",
	}
	for _, line := range lines {
		if !IsTargetServerUnavailableLog(line) {
			t.Fatalf("expected unavailable log to match: %s", line)
		}
	}
	if IsTargetServerUnavailableLog("WD_PROGRESS phase=mtu percent=42 completed=4 total=10 valid=3 rejected=1") {
		t.Fatal("progress log should not be treated as unavailable")
	}
	retryable := []string{
		"❌ Session initialization failed: session init failed",
		"Session initialization failed: session init busy: server is at capacity or rejected the request",
	}
	for _, line := range retryable {
		if IsTargetServerUnavailableLog(line) {
			t.Fatalf("retryable session init log should not be treated as unavailable: %s", line)
		}
	}
}

func TestSessionInitLogParsing(t *testing.T) {
	if !IsSessionInitAttemptLog("2026/05/26 05:53:44 [MasterDnsVPN Client] [INFO] Session init attempt with v.adobeinfo.org and resolver 2.188.212.146") {
		t.Fatal("expected session init attempt log to match")
	}
	if !IsSessionInitRetryLog("2026/05/26 05:53:52 [MasterDnsVPN Client] [WARN] Session init retry backoff: 1s") {
		t.Fatal("expected session init retry log to match")
	}
	if IsSessionInitRetryLog("WD_PROGRESS phase=mtu percent=80 completed=121 total=121 valid=46 rejected=75") {
		t.Fatal("progress log should not match session init retry")
	}
}

func TestIsBenignLocalProxyAbortLog(t *testing.T) {
	line := "+0330 2026-05-26 08:27:33 ERROR [2572145833 1.50s] connection: connection upload closed: raw-read tcp4 127.0.0.1:10886->127.0.0.1:51717: An established connection was aborted by the software in your host machine."
	if !IsBenignLocalProxyAbortLog(line) {
		t.Fatal("expected localhost proxy abort to be classified as benign")
	}
}

func TestIsBenignLocalProxyAbortLogRejectsRealErrors(t *testing.T) {
	lines := []string{
		"+0330 2026-05-26 08:27:33 ERROR [2572145833 1.50s] connection: connection upload closed: raw-read tcp4 127.0.0.1:10886->149.154.167.91:443: An established connection was aborted by the software in your host machine.",
		"2026/05/26 05:53:52 [MasterDnsVPN Client] [DEBUG] Debug session initialization attempt failed: attempt=3 err=read udp 192.168.0.141:51859->2.188.212.146:53: i/o timeout",
		"Target server is overloaded / unavailable.",
		"2026/05/26 14:27:58 [MasterDnsVPN Client] [WARN] ❌ Rejected (5358/10000): v.example.com via 1.1.1.1:53 | reason=UPLOAD_MTU | value=0",
	}
	for _, line := range lines {
		if IsBenignLocalProxyAbortLog(line) {
			t.Fatalf("expected real/non-local error to remain visible: %s", line)
		}
	}
}
