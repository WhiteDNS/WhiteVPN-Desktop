//go:build darwin

package sysproxy

import (
	"fmt"
	"strings"
)

// macOS keeps one proxy configuration per network service — Wi-Fi, Ethernet, a
// USB tether. The store exposes each as its own target, because they never had
// identical settings to begin with and putting one service's old state into
// another is how a VPN rewrites history.

type networkServiceStore struct{}

// SystemStore is this platform's proxy-setting store.
func SystemStore() Store { return networkServiceStore{} }

func (networkServiceStore) Targets() ([]Target, error) {
	services, err := networkServices()
	if err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("sysproxy: this machine has no enabled network services")
	}
	targets := make([]Target, 0, len(services))
	for _, name := range services {
		targets = append(targets, Target{ID: name, Kind: "network-service"})
	}
	return targets, nil
}

func (networkServiceStore) Read(t Target) (State, error) { return serviceProxy(t.ID) }

func (networkServiceStore) Write(t Target, state State) error { return applyService(t.ID, state) }

func (networkServiceStore) Check(t Target, want State) error {
	got, err := serviceProxy(t.ID)
	if err != nil {
		return fmt.Errorf("sysproxy: verify %s: %w", t.ID, err)
	}
	if got.Enabled != want.Enabled || !strings.EqualFold(got.Server, want.Server) {
		return &ReadbackMismatch{Target: t.ID, Want: want, Got: got}
	}
	return nil
}
