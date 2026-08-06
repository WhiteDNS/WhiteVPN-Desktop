package session

import (
	"context"
	"encoding/json"
	"math"
	"sort"
)

// What the engine reports about the proxies it is holding. Only the fields this
// app reads are named; the payload carries a good deal more.
type proxyView struct {
	Type    string         `json:"type"`
	Now     string         `json:"now"`
	History []delayHistory `json:"history"`
}

type delayHistory struct {
	Delay int `json:"delay"`
}

// noDelay stands for "never measured, or measured and failed". It sorts last,
// which is the whole point: a node nothing is known about must not displace one
// that answered.
const noDelay = math.MaxInt32

// proxySnapshot reads the engine's current view of every proxy and group.
func proxySnapshot(ctx context.Context, process proxyReader) (map[string]proxyView, error) {
	raw, err := process.Proxies(ctx)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Proxies map[string]proxyView `json:"proxies"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	return payload.Proxies, nil
}

// proxyReader is the part of the engine this file needs, so the ordering can be
// tested without one.
type proxyReader interface {
	Proxies(ctx context.Context) (json.RawMessage, error)
}

// resolveGroup follows a group to the node actually carrying traffic.
//
// A url-test group answers with whichever node its last measurement liked, and
// that node is what the interface has to name — "WhiteDNS Auto" tells a user
// nothing about where their traffic leaves from. Groups can point at groups, so
// this follows the chain rather than assuming one hop.
func resolveGroup(proxies map[string]proxyView, name string) string {
	for hops := 0; hops < 8; hops++ {
		view, ok := proxies[name]
		if !ok || view.Now == "" {
			return name
		}
		name = view.Now
	}
	return name
}

// lastDelay is the most recent measurement for a node, or noDelay when there is
// none. A zero delay in the history means the measurement failed, which is not
// the same as "instant" and must not sort first.
func lastDelay(proxies map[string]proxyView, name string) int {
	view, ok := proxies[name]
	if !ok || len(view.History) == 0 {
		return noDelay
	}
	delay := view.History[len(view.History)-1].Delay
	if delay <= 0 {
		return noDelay
	}
	return delay
}

// byMeasuredDelay orders candidates fastest-first, keeping the original order
// among nodes nothing is known about.
//
// It exists because the fallback used to walk the catalogue from the top, which
// meant every user on Automatic tried the same first five nodes, and Retry tried
// them again. With eight hundred nodes in the subscription, a bad head of the
// list was enough to tell everybody the app could not connect. By the time this
// ordering is needed the url-test group has already measured, so the numbers to
// choose by are sitting there unused.
func byMeasuredDelay(candidates []string, proxies map[string]proxyView) []string {
	ordered := make([]string, len(candidates))
	copy(ordered, candidates)

	position := make(map[string]int, len(candidates))
	for i, name := range candidates {
		position[name] = i
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := lastDelay(proxies, ordered[i]), lastDelay(proxies, ordered[j])
		if left != right {
			return left < right
		}
		return position[ordered[i]] < position[ordered[j]]
	})
	return ordered
}
