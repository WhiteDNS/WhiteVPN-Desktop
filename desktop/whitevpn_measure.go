package main

// Testing nodes.
//
// Three tests, and the user picks which to run:
//
//   - Reachability: a TCP connection to the node's address. No engine, no
//     credentials, no protocol — it answers "is anything listening" and nothing
//     more, which is why it is fast enough to run across a whole catalogue.
//   - Delay: a real request through the node, measured by the engine.
//   - Speed: a download through the node, measured end to end.
//
// The last two need an engine, and they get one of their own rather than the
// one carrying the user's traffic — see session.StartMeasurer. That is what
// makes speed testing possible without moving a live connection onto every node
// in turn, and what lets any of this run while disconnected.

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"whitevpn-desktop/internal/model"
	"whitevpn-desktop/internal/session"
)

const (
	// Defaults the user can change. They are the phone's where the phone has an
	// opinion, and chosen to finish in a reasonable time where it does not.
	defaultReachabilityTimeout = 3500 * time.Millisecond
	defaultReachabilityWorkers = 64
	defaultDelayTimeout        = 5 * time.Second
	defaultDelayWorkers        = 16
	defaultSpeedBudget         = 8 * time.Second
	defaultSpeedURL            = "https://speed.cloudflare.com/__down?bytes=10000000"

	// Speed is serial by nature, so it is capped separately: the engine carries
	// one node at a time and a hundred of them is twenty minutes of waiting.
	maxSpeedNodes = 25
)

// measureState is the engine tests borrow, and the run in progress.
type measureState struct {
	mu       sync.Mutex
	measurer *session.Measurer
	cancel   context.CancelFunc
	running  bool
}

// StartNodeTest measures the nodes named, with the tests asked for.
//
// It returns as soon as the run starts; results arrive as `nodes:test` events
// so a catalogue of hundreds reports as it goes rather than in one silence
// followed by one answer.
func (a *App) StartNodeTest(request model.NodeTestRequest) error {
	request = model.NormalizeNodeTestRequest(request)
	if len(request.Nodes) == 0 {
		return fmt.Errorf("no nodes to test")
	}

	a.measure.mu.Lock()
	if a.measure.running {
		a.measure.mu.Unlock()
		return fmt.Errorf("a test is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.measure.running = true
	a.measure.cancel = cancel
	a.measure.mu.Unlock()

	go func() {
		defer func() {
			a.measure.mu.Lock()
			a.measure.running = false
			a.measure.cancel = nil
			a.measure.mu.Unlock()
			a.emit("nodes:test-done", struct{}{})
		}()
		a.runNodeTest(ctx, request)
	}()
	return nil
}

// CancelNodeTest stops a run part-way. What was measured stays measured.
func (a *App) CancelNodeTest() {
	a.measure.mu.Lock()
	cancel := a.measure.cancel
	a.measure.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *App) runNodeTest(ctx context.Context, request model.NodeTestRequest) {
	nodes := a.nodesByName(request.Nodes)
	if len(nodes) == 0 {
		return
	}

	if request.Reachability {
		a.measureReachability(ctx, nodes, request)
	}
	if ctx.Err() != nil {
		return
	}
	if !request.Delay && !request.Speed {
		return
	}

	measurer, err := a.startMeasurer(ctx)
	if err != nil {
		a.emit("nodes:test-error", err.Error())
		return
	}
	defer func() {
		_ = measurer.Close()
		a.measure.mu.Lock()
		a.measure.measurer = nil
		a.measure.mu.Unlock()
	}()

	if request.Delay {
		names := make([]string, 0, len(nodes))
		for _, node := range nodes {
			names = append(names, node.Name)
		}
		measurer.DelayAll(ctx, names, request.DelayURL, request.DelayTimeout(), request.DelayWorkers,
			func(name string, delayMS int, err error) {
				a.recordNodeMeasurement(name, func(node *model.WhiteVPNNode) {
					node.DelayTested = true
					node.DelayOK = err == nil
					node.DelayMs = delayMS
				})
			})
	}
	if ctx.Err() != nil || !request.Speed {
		return
	}

	// Serial, and capped: each one is a download.
	speedNodes := nodes
	if len(speedNodes) > maxSpeedNodes {
		speedNodes = speedNodes[:maxSpeedNodes]
	}
	for _, node := range speedNodes {
		if ctx.Err() != nil {
			return
		}
		rate, err := measurer.Speed(ctx, node.Name, request.SpeedURL, request.SpeedBudget())
		a.recordNodeMeasurement(node.Name, func(stored *model.WhiteVPNNode) {
			stored.SpeedTested = true
			stored.SpeedOK = err == nil
			stored.SpeedBytesPerSecond = rate
		})
	}
}

// measureReachability opens a TCP connection to each node's address.
//
// It says nothing about whether the node will carry traffic — only that
// something is listening — which is exactly why it can be run across hundreds
// of nodes in the time the other tests take for one.
func (a *App) measureReachability(ctx context.Context, nodes []model.WhiteVPNNode, request model.NodeTestRequest) {
	gate := make(chan struct{}, request.ReachabilityWorkers)
	var wg sync.WaitGroup
	for _, node := range nodes {
		if strings.TrimSpace(node.Server) == "" || node.Port <= 0 {
			// Nothing to dial. Recorded as tested and failed rather than left
			// looking untested, which would be a row that never resolves.
			a.recordNodeMeasurement(node.Name, func(stored *model.WhiteVPNNode) {
				stored.ReachTested, stored.ReachOK, stored.ReachMs = true, false, 0
			})
			continue
		}
		wg.Add(1)
		go func(target model.WhiteVPNNode) {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			case <-ctx.Done():
				return
			}

			address := net.JoinHostPort(target.Server, fmt.Sprint(target.Port))
			started := time.Now()
			dialer := net.Dialer{Timeout: request.ReachabilityTimeout()}
			conn, err := dialer.DialContext(ctx, "tcp", address)
			latency := int(time.Since(started).Milliseconds())
			if conn != nil {
				_ = conn.Close()
			}
			a.recordNodeMeasurement(target.Name, func(stored *model.WhiteVPNNode) {
				stored.ReachTested = true
				stored.ReachOK = err == nil
				if err == nil {
					stored.ReachMs = latency
				} else {
					stored.ReachMs = 0
				}
			})
		}(node)
	}
	wg.Wait()
}

// startMeasurer brings up the engine tests run on, from the same subscription
// the app would connect with, so a measurement is of the node as it would be
// reached rather than of some other version of it.
func (a *App) startMeasurer(ctx context.Context) (*session.Measurer, error) {
	corePath, err := findMihomoCore()
	if err != nil {
		return nil, err
	}
	subscription, err := a.subscriptionBody(ctx)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	settings := model.NormalizeWhiteVPNSettings(a.state.WhiteVPN)
	a.mu.Unlock()
	frontingIP := ""
	if len(settings.FrontingIPs) > 0 {
		frontingIP = settings.FrontingIPs[0]
	}

	measurer, err := session.StartMeasurer(ctx, session.MeasureOptions{
		CorePath:     corePath,
		HomeDir:      filepath.Join(a.configDir, "mihomo-measure"),
		Subscription: subscription,
		FrontingIP:   frontingIP,
	})
	if err != nil {
		return nil, err
	}
	a.measure.mu.Lock()
	a.measure.measurer = measurer
	a.measure.mu.Unlock()
	return measurer, nil
}

// nodesByName resolves the request against the catalogue, keeping its order.
func (a *App) nodesByName(names []string) []model.WhiteVPNNode {
	all := a.whiteVPNNodesSnapshot()
	if len(all) == 0 {
		list, err := a.ListWhiteVPNNodes(false)
		if err != nil {
			return nil
		}
		all = list.Nodes
	}
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[name] = true
	}
	out := make([]model.WhiteVPNNode, 0, len(names))
	for _, node := range all {
		if wanted[node.Name] {
			out = append(out, node)
		}
	}
	return out
}

// recordNodeMeasurement stores one result and tells the interface, so a long
// run fills the table as it goes.
func (a *App) recordNodeMeasurement(name string, apply func(*model.WhiteVPNNode)) {
	a.nodesMu.Lock()
	var updated model.WhiteVPNNode
	found := false
	for i := range a.nodes {
		if a.nodes[i].Name == name {
			apply(&a.nodes[i])
			updated = a.nodes[i]
			found = true
			break
		}
	}
	a.nodesMu.Unlock()
	if found {
		a.emit("nodes:test", updated)
	}
}
