package session

// A second engine, for measuring.
//
// Testing a node means sending traffic through it, and the only engine the app
// had was the one carrying the user's traffic. Measuring on that one means
// either moving the live connection onto every node in turn — which is not a
// test, it is an outage — or measuring nothing.
//
// So measurements get their own engine: same subscription, different ports, no
// tunnel, and no health gate, because a measurement session is not claiming to
// be a working connection. It is what makes speed testing possible at all, and
// it makes delay testing work while disconnected, which is when someone most
// wants to know which node to pick.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"whitevpn-desktop/internal/engine"
	"whitevpn-desktop/internal/mihomoconf"
)

// MeasureOptions describes a measuring engine.
type MeasureOptions struct {
	CorePath     string
	HomeDir      string
	Subscription string

	// FrontingIP is applied as it is for a real connection, so a measurement
	// reflects how the node will actually be reached.
	FrontingIP string

	CoreStdout io.Writer
	CoreStderr io.Writer

	// PipeSecurityDescriptor widens the Windows control channel, as it does for
	// a real session. Leave empty in production.
	PipeSecurityDescriptor string
}

// Measurer is a running engine that carries no user traffic.
type Measurer struct {
	process   *engine.Process
	mixedPort int
	names     []string
}

// Names are the nodes this engine holds, in catalogue order.
func (m *Measurer) Names() []string { return m.names }

// StartMeasurer brings up an engine for testing and nothing else.
//
// It picks its own ports so it cannot collide with a live session, and refuses
// no node: unlike Connect, reaching the end of this proves only that the engine
// is running, which is all a measurement needs.
func StartMeasurer(ctx context.Context, opts MeasureOptions) (*Measurer, error) {
	mixedPort, err := freePort()
	if err != nil {
		return nil, err
	}
	controlPort, err := freePort()
	if err != nil {
		return nil, err
	}

	prepared := Options{
		CorePath:     opts.CorePath,
		HomeDir:      opts.HomeDir,
		Subscription: opts.Subscription,
		FrontingIP:   opts.FrontingIP,
		MixedPort:    mixedPort,
		ControlPort:  controlPort,
		// No tunnel: a measuring engine must never touch the machine's routing,
		// and creating an adapter would ask for Administrator besides.
		Tun: mihomoconf.TunOptions{Enabled: false},
	}
	document, names, err := PrepareConfig(prepared)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opts.HomeDir, 0o755); err != nil {
		return nil, fmt.Errorf("session: prepare measuring directory: %w", err)
	}
	// config.yaml, not a name of our choosing: SetupConfig does not carry a path,
	// it tells the core to read <homeDir>/config.yaml. The measuring engine gets
	// its own home directory instead, which is what keeps it from treading on the
	// live session's config.
	configPath := filepath.Join(opts.HomeDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(document), 0o600); err != nil {
		return nil, fmt.Errorf("session: write measuring config: %w", err)
	}

	process, err := engine.Spawn(ctx, engine.SpawnOptions{
		CorePath:           opts.CorePath,
		WorkingDir:         opts.HomeDir,
		ConnectTimeout:     20 * time.Second,
		Stdout:             opts.CoreStdout,
		Stderr:             opts.CoreStderr,
		Elevated:           false,
		SecurityDescriptor: opts.PipeSecurityDescriptor,
	})
	if err != nil {
		return nil, err
	}

	measurer := &Measurer{process: process, mixedPort: mixedPort, names: names}
	if err := measurer.startCore(ctx, opts.HomeDir, configPath); err != nil {
		_ = measurer.Close()
		return nil, err
	}
	return measurer, nil
}

func (m *Measurer) startCore(ctx context.Context, homeDir, configPath string) error {
	setupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := m.process.Init(setupCtx, homeDir, 36); err != nil {
		return fmt.Errorf("session: initialise measuring engine: %w", err)
	}
	if err := m.process.ValidateConfig(setupCtx, configPath); err != nil {
		return fmt.Errorf("session: %w", err)
	}
	if err := m.process.SetupConfig(setupCtx, map[string]string{}, mihomoconf.DelayTestURL); err != nil {
		return fmt.Errorf("session: apply measuring config: %w", err)
	}
	if err := m.process.StartListener(setupCtx); err != nil {
		return fmt.Errorf("session: start measuring listener: %w", err)
	}
	return nil
}

// Close stops the measuring engine.
func (m *Measurer) Close() error {
	if m.process == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return m.process.Stop(ctx)
}

// Delay measures one node, in milliseconds.
func (m *Measurer) Delay(ctx context.Context, node string, testURL string, timeout time.Duration) (int, error) {
	if testURL == "" {
		testURL = mihomoconf.DelayTestURL
	}
	return m.process.TestDelayMS(ctx, node, testURL, int(timeout/time.Millisecond))
}

// Speed measures one node by downloading through it, in bytes per second.
//
// Unlike delay, this cannot be done concurrently across nodes: the engine has
// one selected node at a time and the download has to travel through it. So it
// is one node after another, and the caller decides how many are worth the wait.
func (m *Measurer) Speed(ctx context.Context, node string, testURL string, budget time.Duration) (int64, error) {
	if testURL == "" {
		testURL = DefaultSpeedURL
	}
	selectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := m.process.ChangeProxy(selectCtx, mihomoconf.SelectGroup, node)
	cancel()
	if err != nil {
		return 0, fmt.Errorf("select %q: %w", node, err)
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", m.mixedPort))
	if err != nil {
		return 0, err
	}
	// No client timeout: the deadline below covers the whole thing, and a client
	// timeout would count the handshake against the download budget.
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	defer client.CloseIdleConnections()

	// Reaching the far side through a node takes as long as it takes — a
	// handshake, a TLS negotiation, and the node's own latency — and that is not
	// what is being measured. It gets its own allowance so that a node with a
	// slow start reports as slow rather than as failed.
	deadline, cancelDownload := context.WithTimeout(ctx, budget+speedConnectAllowance)
	defer cancelDownload()
	request, err := http.NewRequestWithContext(deadline, http.MethodGet, testURL, nil)
	if err != nil {
		return 0, err
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, fmt.Errorf("speed test returned HTTP %d", response.StatusCode)
	}

	// The clock starts at the first byte, so the rate is the rate of the
	// transfer and not of the transfer plus everything it took to begin.
	started := time.Now()
	read, err := io.Copy(io.Discard, &deadlineReader{reader: response.Body, deadline: started.Add(budget)})
	elapsed := time.Since(started)
	if read == 0 {
		if err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("the node accepted the request and sent nothing")
	}
	if elapsed <= 0 {
		return 0, fmt.Errorf("speed test finished immediately")
	}
	return int64(float64(read) / elapsed.Seconds()), nil
}

// speedConnectAllowance is what a node gets to reach the far side before the
// download budget starts counting.
const speedConnectAllowance = 15 * time.Second

// DefaultSpeedURL is what a speed test downloads when nothing else is asked for.
// Ten megabytes: enough that a fast node is not measuring its own start-up, and
// small enough that a slow one is not still going when the budget runs out.
const DefaultSpeedURL = "https://speed.cloudflare.com/__down?bytes=10000000"

// deadlineReader stops a download at a wall-clock time rather than at the end of
// the file. What is being measured is a rate; a file that runs out early
// measures it just as well, and one that does not must not run forever.
type deadlineReader struct {
	reader   io.Reader
	deadline time.Time
}

func (r *deadlineReader) Read(p []byte) (int, error) {
	if !time.Now().Before(r.deadline) {
		return 0, io.EOF
	}
	return r.reader.Read(p)
}

// freePort asks the system for one and hands it straight back, which is as
// close to reserving one as a process can get without holding it.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("session: find a free port: %w", err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(port)
}

// DelayAll measures many nodes at once, bounded, and reports each as it lands.
func (m *Measurer) DelayAll(ctx context.Context, nodes []string, testURL string, timeout time.Duration, concurrency int, report func(node string, delayMS int, err error)) {
	if concurrency <= 0 {
		concurrency = 16
	}
	gate := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
				defer func() { <-gate }()
			case <-ctx.Done():
				return
			}
			callCtx, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
			defer cancel()
			delay, err := m.Delay(callCtx, name, testURL, timeout)
			report(name, delay, err)
		}(node)
	}
	wg.Wait()
}
