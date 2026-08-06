package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The wrappers below exist so that no caller has to remember which methods want
// a JSON string, which want a bare bool, and which want no data at all. Getting
// that wrong does not produce an error: the core's handler type-asserts and
// panics, and the caller sees an internal error from a call that looked fine.

// Init points the core at its working directory. It must be the first call:
// everything afterwards resolves paths relative to it, including the config
// file, which the core reads from disk rather than receiving over this protocol.
//
// The version number is the platform's API level on Android. Off Android the
// core only records it, so any plausible value serves.
func (c *Client) Init(ctx context.Context, homeDir string, version int) error {
	params, err := json.Marshal(map[string]any{"home-dir": homeDir, "version": version})
	if err != nil {
		return err
	}
	_, err = c.invoke(ctx, "initClash", string(params))
	return err
}

// SetupConfig makes the core read <homeDir>/config.yaml and apply it. The
// configuration itself does not travel over this call — only the pre-selected
// proxies and the URL used for delay tests — so the file must already be written.
//
// The reply is unusual: an empty string means success, and anything else is the
// core describing what it disliked about the config.
func (c *Client) SetupConfig(ctx context.Context, selected map[string]string, testURL string) error {
	if selected == nil {
		selected = map[string]string{}
	}
	params, err := json.Marshal(map[string]any{
		"selected-map": selected,
		"test-url":     testURL,
	})
	if err != nil {
		return err
	}
	raw, err := c.invoke(ctx, "setupConfig", string(params))
	if err != nil {
		return err
	}
	if message := decodeString(raw); message != "" {
		return fmt.Errorf("engine: config rejected: %s", message)
	}
	return nil
}

// ValidateConfig checks a config file without applying it. An empty result means
// it is acceptable.
func (c *Client) ValidateConfig(ctx context.Context, path string) error {
	raw, err := c.invoke(ctx, "validateConfig", path)
	if err != nil {
		return err
	}
	if message := decodeString(raw); message != "" {
		return fmt.Errorf("engine: config invalid: %s", message)
	}
	return nil
}

// StartListener brings up the inbound listeners the config declares, and the TUN
// interface with them when the config enables it.
//
// Its return value is not evidence that any of that worked. A tunnel that fails
// to create its adapter — for want of Administrator rights, most often — has
// still been observed to answer this call with success, so callers must confirm
// the tunnel some other way before telling a user they are connected.
func (c *Client) StartListener(ctx context.Context) error {
	_, err := c.invoke(ctx, "startListener", nil)
	return err
}

// StopListener takes the listeners and any tunnel back down.
func (c *Client) StopListener(ctx context.Context) error {
	_, err := c.invoke(ctx, "stopListener", nil)
	return err
}

// Proxies returns the proxy set and groups the core currently holds.
func (c *Client) Proxies(ctx context.Context) (json.RawMessage, error) {
	return c.invoke(ctx, "getProxies", nil)
}

// ChangeProxy selects proxy within group. The proxy may itself be a group, which
// is how automatic selection is handed to the core's url-test group.
//
// Its reply follows the same unusual convention as SetupConfig: the call
// succeeds at the protocol level either way, and an empty string is the only
// thing that means the selection was made. "Not found group" and "Group is not
// selectable" arrive as ordinary successful replies. Ignoring the payload — which
// this did — meant a selection that never happened was reported as one that did,
// and the health check that followed measured whatever node was already in
// place. A connection could therefore be reported on a node nobody chose.
func (c *Client) ChangeProxy(ctx context.Context, group, proxy string) error {
	params, err := json.Marshal(map[string]string{"group-name": group, "proxy-name": proxy})
	if err != nil {
		return err
	}
	raw, err := c.invoke(ctx, "changeProxy", string(params))
	if err != nil {
		return err
	}
	if message := decodeString(raw); message != "" {
		return fmt.Errorf("engine: could not select %q in %q: %s", proxy, group, message)
	}
	return nil
}

// TestDelay measures one proxy. The measurement is a metric, not a gate: a proxy
// that fails to answer here may still carry traffic, so a failure must not by
// itself stop a connection attempt.
func (c *Client) TestDelay(ctx context.Context, proxy, testURL string, timeoutMS int) (json.RawMessage, error) {
	params, err := json.Marshal(map[string]any{
		"proxy-name": proxy,
		"test-url":   testURL,
		"timeout":    timeoutMS,
	})
	if err != nil {
		return nil, err
	}
	return c.invoke(ctx, "asyncTestDelay", string(params))
}

// ErrNoDelay means the core measured nothing: the proxy is not in its set, or
// it did not answer within the timeout. The core says so with -1, and that must
// not reach a caller as if it were a delay.
var ErrNoDelay = errors.New("engine: no delay measurement")

// TestDelayMS is TestDelay with the reply read: milliseconds through the proxy.
//
// The reply is a JSON string holding {"name","url","value"}, which is two
// layers of encoding for one number; doing that unwrapping here means no caller
// has to know it happens.
func (c *Client) TestDelayMS(ctx context.Context, proxy, testURL string, timeoutMS int) (int, error) {
	raw, err := c.TestDelay(ctx, proxy, testURL, timeoutMS)
	if err != nil {
		return 0, err
	}
	body := decodeString(raw)
	if strings.TrimSpace(body) == "" {
		return 0, ErrNoDelay
	}
	var measurement struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		Value int32  `json:"value"`
	}
	if err := json.Unmarshal([]byte(body), &measurement); err != nil {
		return 0, fmt.Errorf("engine: unreadable delay reply: %w", err)
	}
	if measurement.Value <= 0 {
		return 0, ErrNoDelay
	}
	return int(measurement.Value), nil
}

// Traffic is the current rate; TotalTraffic is the session total.
//
// Note the bare bool: these two methods assert on a boolean rather than a JSON
// string, unlike every other call here.
func (c *Client) Traffic(ctx context.Context, onlyProxy bool) (json.RawMessage, error) {
	return c.invoke(ctx, "getTraffic", onlyProxy)
}

func (c *Client) TotalTraffic(ctx context.Context, onlyProxy bool) (json.RawMessage, error) {
	return c.invoke(ctx, "getTotalTraffic", onlyProxy)
}

// TrafficRate is Traffic with the reply read: bytes per second, up and down.
func (c *Client) TrafficRate(ctx context.Context, onlyProxy bool) (up int64, down int64, err error) {
	raw, err := c.Traffic(ctx, onlyProxy)
	if err != nil {
		return 0, 0, err
	}
	return decodeTraffic(raw)
}

// TrafficTotal is TotalTraffic with the reply read: bytes since the engine
// started, up and down.
func (c *Client) TrafficTotal(ctx context.Context, onlyProxy bool) (up int64, down int64, err error) {
	raw, err := c.TotalTraffic(ctx, onlyProxy)
	if err != nil {
		return 0, 0, err
	}
	return decodeTraffic(raw)
}

// decodeTraffic unwraps {"up":N,"down":N}, which arrives as a JSON string like
// most of this protocol's replies.
func decodeTraffic(raw json.RawMessage) (int64, int64, error) {
	body := decodeString(raw)
	if strings.TrimSpace(body) == "" {
		return 0, 0, fmt.Errorf("engine: empty traffic reply")
	}
	var counters struct {
		Up   int64 `json:"up"`
		Down int64 `json:"down"`
	}
	if err := json.Unmarshal([]byte(body), &counters); err != nil {
		return 0, 0, fmt.Errorf("engine: unreadable traffic reply: %w", err)
	}
	return counters.Up, counters.Down, nil
}

// CountryCode resolves an address to a country, using the core's bundled
// geodata, so the answer costs no network round trip.
func (c *Client) CountryCode(ctx context.Context, ip string) (string, error) {
	raw, err := c.invoke(ctx, "getCountryCode", ip)
	if err != nil {
		return "", err
	}
	return decodeString(raw), nil
}

// UpdateDNS re-points the core's resolver, for when the underlying network
// changes beneath a live tunnel.
func (c *Client) UpdateDNS(ctx context.Context, dns string) error {
	_, err := c.invoke(ctx, "updateDns", dns)
	return err
}

// Shutdown asks the core to stop cleanly. Prefer it over killing the process:
// an abrupt exit can leave a tunnel adapter and its routes behind.
func (c *Client) Shutdown(ctx context.Context) error {
	_, err := c.invoke(ctx, "shutdown", nil)
	return err
}

// StartLog and StopLog control whether the core streams log lines as events.
func (c *Client) StartLog(ctx context.Context) error {
	_, err := c.invoke(ctx, "startLog", nil)
	return err
}

func (c *Client) StopLog(ctx context.Context) error {
	_, err := c.invoke(ctx, "stopLog", nil)
	return err
}

// decodeString unwraps a JSON string reply, tolerating a bare one.
func decodeString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(raw))
}
