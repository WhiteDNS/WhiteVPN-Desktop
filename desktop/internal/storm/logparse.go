package storm

import (
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"whitevpn-desktop/internal/model"
)

var (
	ansiEscapeRegex      = regexp.MustCompile(`\x1b\[[;\d]*m`)
	progressFieldRegex   = regexp.MustCompile(`(\w+)=([^\s]+)`)
	resolverStateRegex   = regexp.MustCompile(`WD_RESOLVERS\s+active=([^\s]+)\s+standby=([^\s]+)\s+valid=([^\s]+)`)
	trafficStatsRegex    = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)/s\s*\(Total:\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)\)\s*\|\s*[^0-9]*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)/s\s*\(Total:\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B)\)`)
	rawReadEndpointRegex = regexp.MustCompile(`raw-read tcp[46]?\s+(\S+)->(\S+)`)
)

type ScannerEvent struct {
	Event    string
	Resolver string
	Total    int
	Valid    int
	Rejected int
}

type MTUResolverStateEvent struct {
	Event          string
	Resolver       string
	Domain         string
	UploadMTU      int
	DownloadMTU    int
	UploadMTUChars int
	Cause          string
}

func CleanLogLine(line string) string {
	return strings.TrimSpace(ansiEscapeRegex.ReplaceAllString(line, ""))
}

func ParseScannerEvent(line string) (ScannerEvent, bool) {
	clean := CleanLogLine(line)
	idx := strings.Index(clean, "WD_SCAN")
	if idx < 0 {
		return ScannerEvent{}, false
	}
	fields := map[string]string{}
	for _, match := range progressFieldRegex.FindAllStringSubmatch(clean[idx+len("WD_SCAN"):], -1) {
		fields[match[1]] = match[2]
	}
	event := strings.ToLower(strings.TrimSpace(fields["event"]))
	if event == "" {
		return ScannerEvent{}, false
	}
	return ScannerEvent{
		Event:    event,
		Resolver: fields["resolver"],
		Total:    atoi(fields["total"]),
		Valid:    atoi(fields["valid"]),
		Rejected: atoi(fields["rejected"]),
	}, true
}

func ParseProgress(line string) (model.ConnectionProgress, bool) {
	clean := CleanLogLine(line)
	idx := strings.Index(clean, "WD_PROGRESS")
	if idx < 0 {
		return model.ConnectionProgress{}, false
	}
	fields := map[string]string{}
	for _, match := range progressFieldRegex.FindAllStringSubmatch(clean[idx+len("WD_PROGRESS"):], -1) {
		fields[match[1]] = match[2]
	}
	phase := strings.ToLower(fields["phase"])
	if phase == "" {
		return model.ConnectionProgress{}, false
	}
	completed := atoi(fields["completed"])
	total := atoi(fields["total"])
	percent, ok := atoiOK(fields["percent"])
	if !ok {
		percent = inferProgressPercent(phase, completed, total)
	}
	return model.ConnectionProgress{
		Phase:     phase,
		Percent:   clampPercent(percent),
		Completed: completed,
		Total:     total,
		Valid:     atoi(fields["valid"]),
		Rejected:  atoi(fields["rejected"]),
	}, true
}

func ParseMTUResolverStateEvent(line string) (MTUResolverStateEvent, bool) {
	clean := CleanLogLine(line)
	idx := strings.Index(clean, "WHITEDNS_MTU_STATE")
	if idx < 0 {
		return MTUResolverStateEvent{}, false
	}
	fields := map[string]string{}
	for _, match := range progressFieldRegex.FindAllStringSubmatch(clean[idx+len("WHITEDNS_MTU_STATE"):], -1) {
		fields[strings.ToLower(match[1])] = match[2]
	}
	event := strings.ToLower(strings.TrimSpace(fields["event"]))
	resolver := strings.TrimSpace(fields["resolver"])
	if resolver == "" || resolver == "-" {
		return MTUResolverStateEvent{}, false
	}
	switch event {
	case "valid", "removed", "added":
		return MTUResolverStateEvent{
			Event:          event,
			Resolver:       resolver,
			Domain:         cleanOptionalMTUField(fields["domain"]),
			UploadMTU:      atoi(firstMTUField(fields, "up", "up_mtu")),
			DownloadMTU:    atoi(firstMTUField(fields, "down", "down_mtu")),
			UploadMTUChars: atoi(firstMTUField(fields, "up_chars", "up_mtu_chars")),
			Cause:          parseMTUStateCause(clean, fields),
		}, true
	default:
		return MTUResolverStateEvent{}, false
	}
}

func ParseMTUResolverRuntimeState(raw string) (model.ResolverRuntimeState, bool) {
	detailByKey := map[string]int{}
	var details []model.ResolverRuntimeDetail

	found := false
	for _, line := range strings.Split(raw, "\n") {
		event, ok := ParseMTUResolverStateEvent(line)
		if !ok {
			continue
		}
		found = true
		key := mtuResolverDetailKey(event.Resolver, event.Domain)
		idx, ok := detailByKey[key]
		if !ok {
			idx = len(details)
			detailByKey[key] = idx
			details = append(details, model.ResolverRuntimeDetail{
				Resolver: event.Resolver,
				Domain:   event.Domain,
			})
		}
		detail := details[idx]
		detail.Resolver = event.Resolver
		if event.Domain != "" {
			detail.Domain = event.Domain
		}
		if event.UploadMTU > 0 {
			detail.UploadMTU = event.UploadMTU
		}
		if event.DownloadMTU > 0 {
			detail.DownloadMTU = event.DownloadMTU
		}
		if event.UploadMTUChars > 0 {
			detail.UploadMTUChars = event.UploadMTUChars
		}
		detail.LastEvent = event.Event
		detail.Cause = event.Cause
		detail.Valid = true
		switch event.Event {
		case "valid", "added":
			detail.Active = true
		case "removed":
			detail.Active = false
		}
		detail.Status = resolverRuntimeDetailStatus(detail)
		details[idx] = detail
	}
	if !found {
		return model.ResolverRuntimeState{}, false
	}
	active, valid := resolverDetailLists(details)
	return model.ResolverRuntimeState{
		ActiveResolvers:  active,
		StandbyResolvers: []string{},
		ValidResolvers:   valid,
		ResolverDetails:  details,
		TotalCount:       len(valid),
		ActiveCount:      len(active),
		StandbyCount:     0,
		ValidCount:       len(valid),
		RejectedCount:    0,
		PendingCount:     0,
		ActiveComplete:   true,
		StandbyComplete:  true,
		ValidComplete:    true,
	}, true
}

func mtuResolverDetailKey(resolver string, domain string) string {
	return resolver + "\x00" + domain
}

func resolverRuntimeDetailStatus(detail model.ResolverRuntimeDetail) string {
	if detail.Active {
		return "active"
	}
	if detail.Valid {
		return "valid"
	}
	return "inactive"
}

func resolverDetailLists(details []model.ResolverRuntimeDetail) ([]string, []string) {
	activeSet := map[string]bool{}
	validSet := map[string]bool{}
	var active []string
	var valid []string
	for _, detail := range details {
		resolver := strings.TrimSpace(detail.Resolver)
		if resolver == "" || resolver == "-" {
			continue
		}
		if detail.Valid && !validSet[resolver] {
			validSet[resolver] = true
			valid = append(valid, resolver)
		}
		if detail.Active && !activeSet[resolver] {
			activeSet[resolver] = true
			active = append(active, resolver)
		}
	}
	return active, valid
}

func firstMTUField(fields map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fields[key]); value != "" {
			return value
		}
	}
	return ""
}

func cleanOptionalMTUField(value string) string {
	value = strings.TrimSpace(value)
	if value == "-" {
		return ""
	}
	return value
}

func parseMTUStateCause(clean string, fields map[string]string) string {
	cause := cleanOptionalMTUField(fields["cause"])
	if idx := strings.Index(clean, " cause="); idx >= 0 {
		cause = cleanOptionalMTUField(clean[idx+len(" cause="):])
	}
	return cause
}

func ParseResolverState(line string) (model.ResolverRuntimeState, bool) {
	clean := CleanLogLine(line)
	if idx := strings.Index(clean, "WD_RESOLVERS"); idx >= 0 {
		fields := map[string]string{}
		for _, match := range progressFieldRegex.FindAllStringSubmatch(clean[idx+len("WD_RESOLVERS"):], -1) {
			fields[match[1]] = match[2]
		}
		if fields["active_count"] != "" || fields["valid_count"] != "" || fields["standby_count"] != "" {
			active := parseResolverList(fields["active_sample"])
			standby := parseResolverList(fields["standby_sample"])
			valid := parseResolverList(fields["valid_sample"])
			activeCount := atoi(fields["active_count"])
			standbyCount := atoi(fields["standby_count"])
			validCount := atoi(fields["valid_count"])
			totalCount := atoi(fields["total_count"])
			rejectedCount := atoi(fields["rejected_count"])
			pendingCount := atoi(fields["pending_count"])
			return model.ResolverRuntimeState{
				ActiveResolvers:  active,
				StandbyResolvers: standby,
				ValidResolvers:   valid,
				TotalCount:       totalCount,
				ActiveCount:      activeCount,
				StandbyCount:     standbyCount,
				ValidCount:       validCount,
				RejectedCount:    rejectedCount,
				PendingCount:     pendingCount,
				ActiveComplete:   parseBoolDefault(fields["active_complete"], len(active) == activeCount),
				StandbyComplete:  parseBoolDefault(fields["standby_complete"], len(standby) == standbyCount),
				ValidComplete:    parseBoolDefault(fields["valid_complete"], len(valid) == validCount),
			}, true
		}
	}
	match := resolverStateRegex.FindStringSubmatch(clean)
	if match == nil {
		return model.ResolverRuntimeState{}, false
	}
	active := parseResolverList(match[1])
	standby := parseResolverList(match[2])
	valid := parseResolverList(match[3])
	return model.ResolverRuntimeState{
		ActiveResolvers:  active,
		StandbyResolvers: standby,
		ValidResolvers:   valid,
		ActiveCount:      len(active),
		StandbyCount:     len(standby),
		ValidCount:       len(valid),
		ActiveComplete:   true,
		StandbyComplete:  true,
		ValidComplete:    true,
	}, true
}

func ParseTrafficStats(line string) (model.TrafficStats, bool) {
	clean := CleanLogLine(line)
	if stats, ok := parseMachineTrafficStats(clean); ok {
		return stats, true
	}
	match := trafficStatsRegex.FindStringSubmatch(clean)
	if match == nil {
		return model.TrafficStats{}, false
	}
	uploadSpeed, ok := parseDataAmount(match[1], match[2])
	if !ok {
		return model.TrafficStats{}, false
	}
	uploadTotal, ok := parseDataAmount(match[3], match[4])
	if !ok {
		return model.TrafficStats{}, false
	}
	downloadSpeed, ok := parseDataAmount(match[5], match[6])
	if !ok {
		return model.TrafficStats{}, false
	}
	downloadTotal, ok := parseDataAmount(match[7], match[8])
	if !ok {
		return model.TrafficStats{}, false
	}
	return model.TrafficStats{
		DownloadBytes:               downloadTotal,
		UploadBytes:                 uploadTotal,
		DownloadSpeedBytesPerSecond: downloadSpeed,
		UploadSpeedBytesPerSecond:   uploadSpeed,
		TotalDataUsageBytes:         downloadTotal + uploadTotal,
	}, true
}

func IsTargetServerUnavailableLog(line string) bool {
	clean := strings.ToLower(CleanLogLine(line))
	switch {
	case strings.Contains(clean, "mtu tests failed: no valid connections"):
		return true
	case strings.Contains(clean, "no valid connections found after mtu testing"):
		return true
	case strings.Contains(clean, "ping watchdog triggered: no server response"):
		return true
	default:
		return false
	}
}

func IsSessionInitAttemptLog(line string) bool {
	clean := strings.ToLower(CleanLogLine(line))
	return strings.Contains(clean, "session init attempt with ")
}

func IsSessionInitRetryLog(line string) bool {
	clean := strings.ToLower(CleanLogLine(line))
	return strings.Contains(clean, "session init retry backoff")
}

func IsBenignLocalProxyAbortLog(line string) bool {
	clean := strings.ToLower(CleanLogLine(line))
	if !strings.Contains(clean, "connection upload closed") ||
		!strings.Contains(clean, "an established connection was aborted by the software in your host machine") {
		return false
	}
	match := rawReadEndpointRegex.FindStringSubmatch(clean)
	if len(match) != 3 {
		return false
	}
	return isLoopbackLogEndpoint(match[1]) && isLoopbackLogEndpoint(match[2])
}

func isLoopbackLogEndpoint(endpoint string) bool {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), ":")
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func parseMachineTrafficStats(clean string) (model.TrafficStats, bool) {
	idx := strings.Index(clean, "WD_STATS")
	if idx < 0 {
		return model.TrafficStats{}, false
	}
	fields := map[string]string{}
	for _, match := range progressFieldRegex.FindAllStringSubmatch(clean[idx+len("WD_STATS"):], -1) {
		fields[match[1]] = match[2]
	}
	uploadSpeed, ok := atoi64OK(fields["upload_bps"])
	if !ok {
		return model.TrafficStats{}, false
	}
	uploadTotal, ok := atoi64OK(fields["upload_total"])
	if !ok {
		return model.TrafficStats{}, false
	}
	downloadSpeed, ok := atoi64OK(fields["download_bps"])
	if !ok {
		return model.TrafficStats{}, false
	}
	downloadTotal, ok := atoi64OK(fields["download_total"])
	if !ok {
		return model.TrafficStats{}, false
	}
	return model.TrafficStats{
		DownloadBytes:               downloadTotal,
		UploadBytes:                 uploadTotal,
		DownloadSpeedBytesPerSecond: downloadSpeed,
		UploadSpeedBytesPerSecond:   uploadSpeed,
		TotalDataUsageBytes:         downloadTotal + uploadTotal,
	}, true
}

func parseResolverList(raw string) []string {
	if raw == "-" || strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func inferProgressPercent(phase string, completed, total int) int {
	switch {
	case phase == "mtu" && total > 0:
		return int(math.Round(10 + (float64(clamp(completed, 0, total))/float64(total))*70))
	case phase == "starting":
		return 5
	case phase == "selecting":
		return 85
	case phase == "session":
		return 90
	case phase == "runtime":
		return 98
	case phase == "connected":
		return 100
	default:
		return 0
	}
}

func parseDataAmount(value, unit string) (int64, bool) {
	amount, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	multiplier := map[string]float64{
		"B":  1,
		"KB": 1024,
		"MB": 1024 * 1024,
		"GB": 1024 * 1024 * 1024,
		"TB": 1024 * 1024 * 1024 * 1024,
	}[strings.ToUpper(unit)]
	if multiplier == 0 {
		return 0, false
	}
	return int64(math.Round(amount * multiplier)), true
}

func atoi(value string) int {
	out, _ := atoiOK(value)
	return out
}

func atoiOK(value string) (int, bool) {
	out, err := strconv.Atoi(value)
	return out, err == nil
}

func atoi64OK(value string) (int64, bool) {
	out, err := strconv.ParseInt(value, 10, 64)
	return out, err == nil
}

func parseBoolDefault(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func clampPercent(value int) int {
	return clamp(value, 0, 100)
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
