package tunnelengine

import "math"

func computeMetrics(res ScanResult) Metrics {
	attempts := append([]AttemptMetric{}, res.TCP.Attempts...)
	attempts = append(attempts, res.UDP.Attempts...)
	attempts = append(attempts, res.DNS.Attempts...)
	var successful []int64
	timeouts := 0
	for _, a := range attempts {
		if a.Success {
			successful = append(successful, a.DurationMs)
		}
		if a.ErrorCategory == "timeout" {
			timeouts++
		}
	}
	jitter := int64(0)
	if len(successful) > 1 {
		var sum float64
		for _, v := range successful {
			sum += float64(v)
		}
		mean := sum / float64(len(successful))
		var variance float64
		for _, v := range successful {
			delta := float64(v) - mean
			variance += delta * delta
		}
		jitter = int64(math.Sqrt(variance / float64(len(successful))))
	}
	rtt := res.TCP.MedianRTTMs
	if rtt == 0 {
		rtt = median(successful)
	}
	loss := 1.0 - successRatio(attempts)
	timeoutFreq := 0.0
	if len(attempts) > 0 {
		timeoutFreq = float64(timeouts) / float64(len(attempts))
	}
	stability := 100.0 * (1.0 - loss)
	if jitter > 250 {
		stability -= 15
	}
	if timeoutFreq > 0.25 {
		stability -= 20
	}
	if stability < 0 {
		stability = 0
	}
	return Metrics{RTTMs: rtt, JitterMs: jitter, PacketLossEstimate: round(loss * 100), StabilityPercent: round(stability), TimeoutFrequency: round(timeoutFreq * 100)}
}

func score(res ScanResult) ScoreResult {
	points := 0
	var reasons []string
	if res.TCP.Success {
		points += 25
		reasons = append(reasons, "tcp_connectivity")
	}
	if res.TCP.Consistency >= 0.67 {
		points += 15
		reasons = append(reasons, "retry_consistency")
	}
	if res.TLS.Success {
		points += 20
		reasons = append(reasons, "tls_handshake")
	}
	if res.HTTP.Success {
		points += 8
		reasons = append(reasons, "http_behavior")
	}
	if res.WebSocket.Success {
		points += 10
		reasons = append(reasons, "websocket_upgrade")
	}
	if res.QUIC.Success {
		points += 8
		reasons = append(reasons, "quic_handshake")
	}
	if res.DNS.UDPResponsive || res.DNS.TCPResponsive {
		points += 6
		reasons = append(reasons, "dns_responsive")
	}
	if res.Metrics.RTTMs > 0 && res.Metrics.RTTMs < 150 {
		points += 5
	}
	if res.Metrics.JitterMs < 80 {
		points += 5
	}
	if res.Metrics.StabilityPercent >= 90 {
		points += 8
	}
	if points > 100 {
		points = 100
	}

	falsePositive := res.TCP.Success && res.TCP.Consistency < 0.67
	if res.TCP.Success && !res.TLS.Success && !res.HTTP.Success && !res.WebSocket.Success && !res.QUIC.Success && !res.DNS.UDPResponsive && !res.DNS.TCPResponsive {
		falsePositive = true
	}
	classification := "Blocked"
	switch {
	case falsePositive:
		classification = "False Positive"
	case points >= 82 && res.TCP.Consistency >= 0.67 && (res.TLS.Success || res.WebSocket.Success || res.QUIC.Success):
		classification = "Tunnel Ready"
	case points >= 58:
		classification = "Partially Usable"
	case points >= 38:
		classification = "Unstable"
	}
	return ScoreResult{
		Numeric:        points,
		Grade:          grade(points),
		Classification: classification,
		Confidence:     round(confidence(res, falsePositive)),
		FalsePositive:  falsePositive,
		Reasons:        reasons,
	}
}

func grade(points int) string {
	switch {
	case points >= 94:
		return "A+"
	case points >= 85:
		return "A"
	case points >= 72:
		return "B"
	case points >= 58:
		return "C"
	case points >= 38:
		return "D"
	default:
		return "F"
	}
}

func confidence(res ScanResult, falsePositive bool) float64 {
	c := res.TCP.Consistency * 45
	if res.TLS.Success {
		c += 20
	}
	if res.HTTP.Success || res.WebSocket.Success || res.QUIC.Success {
		c += 20
	}
	if res.Metrics.StabilityPercent >= 85 {
		c += 15
	}
	if falsePositive {
		c -= 25
	}
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 100
	}
	return c
}

func round(v float64) float64 {
	return math.Round(v*100) / 100
}
