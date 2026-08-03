package tunnelengine

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"sync"
	"time"
)

func ScanEndpoint(requestJSON string) string {
	var req ScanRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return encodeError("", 0, err)
	}
	result := scanOne(context.Background(), normalizeRequest(req))
	return mustJSON(result)
}

func ScanBatch(requestJSON string) string {
	var req BatchRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return mustJSON(map[string]any{"results": []ScanResult{}, "error": err.Error()})
	}
	results, err := ScanBatchWithContext(context.Background(), req, nil)
	if err != nil {
		return mustJSON(map[string]any{"results": results, "error": err.Error()})
	}
	return mustJSON(map[string]any{"results": results})
}

func ScanEndpointWithContext(ctx context.Context, req ScanRequest) ScanResult {
	if ctx == nil {
		ctx = context.Background()
	}
	return scanOne(ctx, normalizeRequest(req))
}

func ScanBatchWithContext(ctx context.Context, req BatchRequest, onResult func(index int, result ScanResult)) ([]ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	limit := req.AdaptiveLimit
	if limit <= 0 {
		limit = runtime.NumCPU() * 8
	}
	if limit > 96 {
		limit = 96
	}
	results := make([]ScanResult, len(req.Endpoints))
	type scanJob struct {
		index    int
		endpoint ScanRequest
	}
	jobs := make(chan scanJob)
	var wg sync.WaitGroup
	for worker := 0; worker < limit; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := scanOne(ctx, normalizeRequest(job.endpoint))
				results[job.index] = result
				if onResult != nil {
					onResult(job.index, result)
				}
			}
		}()
	}
	for i, endpoint := range req.Endpoints {
		if endpoint.TimeoutMillis == 0 {
			endpoint.TimeoutMillis = req.TimeoutMillis
		}
		if endpoint.Retries == 0 {
			endpoint.Retries = req.DefaultRetries
		}
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		case jobs <- scanJob{index: i, endpoint: endpoint}:
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func normalizeRequest(req ScanRequest) ScanRequest {
	if req.TimeoutMillis <= 0 {
		req.TimeoutMillis = 3500
	}
	if req.Retries <= 0 {
		req.Retries = 3
	}
	if req.Retries > 8 {
		req.Retries = 8
	}
	if len(req.HTTPPaths) == 0 {
		req.HTTPPaths = []string{"/"}
	}
	if req.DNSQuestion == "" {
		req.DNSQuestion = "cloudflare.com."
	}
	return req
}

func scanOne(parent context.Context, req ScanRequest) ScanResult {
	timeout := time.Duration(req.TimeoutMillis) * time.Millisecond
	ctx, cancel := context.WithTimeout(parent, timeout*time.Duration(req.Retries+5))
	defer cancel()

	res := ScanResult{
		Endpoint:       endpoint(req.Host, req.Port),
		Host:           req.Host,
		Port:           req.Port,
		ProtocolMatrix: map[string]bool{},
	}
	if req.Host == "" || req.Port <= 0 || req.Port > 65535 {
		res.Errors = append(res.Errors, "invalid endpoint")
		res.Score = score(res)
		return res
	}
	res.TCP = testTCP(ctx, req, timeout)
	res.ProtocolMatrix["tcp"] = res.TCP.Success
	if res.TCP.Success {
		res.TLS = testTLS(ctx, req, timeout)
		res.ProtocolMatrix["tls"] = res.TLS.Success
		res.HTTP = testHTTP(ctx, req, timeout)
		res.ProtocolMatrix["http"] = res.HTTP.Success
		if req.EnableWebSocket {
			res.WebSocket = testWebSocket(ctx, req, timeout)
			res.ProtocolMatrix["websocket"] = res.WebSocket.Success
		}
	}
	if req.EnableUDP {
		res.UDP = testUDP(ctx, req, timeout)
		res.ProtocolMatrix["udp"] = res.UDP.Reachable
	}
	if req.EnableQUIC {
		res.QUIC = testQUIC(ctx, req, timeout)
		res.ProtocolMatrix["quic"] = res.QUIC.Success
	}
	if req.EnableDNS {
		res.DNS = testDNS(ctx, req, timeout)
		res.ProtocolMatrix["dns_udp"] = res.DNS.UDPResponsive
		res.ProtocolMatrix["dns_tcp"] = res.DNS.TCPResponsive
	}
	res.Metrics = computeMetrics(res)
	res.Score = score(res)
	return res
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"json encode failed"}`
	}
	return string(b)
}

func encodeError(host string, port int, err error) string {
	if err == nil {
		err = errors.New("unknown error")
	}
	return mustJSON(ScanResult{Host: host, Port: port, Endpoint: endpoint(host, port), Errors: []string{err.Error()}, Score: ScoreResult{Grade: "F", Classification: "Blocked"}})
}
