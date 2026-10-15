package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"whitevpn-desktop/internal/fragment"
)

func TestFragmentFallbackCleansUpBeforeRetry(t *testing.T) {
	s := fragment.Default()
	s.Enabled = true
	events := []string{}
	owned := &Session{}
	got, err := runFragmentVariants(context.Background(), Options{Subscription: sampleLinks, Fragments: s, FrontingIP: "1.2.3.4"},
		func(ctx context.Context, o Options) (*Session, error) {
			if o.FrontingIP != "1.2.3.4" || o.Subscription != sampleLinks {
				t.Fatal("unrelated options changed")
			}
			if o.Fragments.Enabled {
				events = append(events, "start-fragment")
				return owned, errors.New("failed")
			}
			events = append(events, "start-normal")
			return &Session{}, nil
		}, func(s *Session) error {
			if s != owned {
				t.Fatal("wrong owner")
			}
			events = append(events, "stop")
			return nil
		})
	if err != nil || got.FragmentMode() != "normal" || strings.Join(events, ",") != "start-fragment,stop,start-fragment,stop,start-normal" {
		t.Fatalf("%v %v", events, err)
	}
	if !s.Enabled {
		t.Fatal("fallback changed persisted setting")
	}
}

func TestFragmentFallbackRetainsOwnerOnCleanupFailure(t *testing.T) {
	s := fragment.Default()
	s.Enabled = true
	owned := &Session{}
	starts := 0
	cleanupErr := errors.New("still running")
	got, err := runFragmentVariants(context.Background(), Options{Fragments: s}, func(context.Context, Options) (*Session, error) { starts++; return owned, errors.New("failed") }, func(*Session) error { return cleanupErr })
	if got != owned || !errors.Is(err, cleanupErr) || starts != 1 {
		t.Fatalf("owner lost or retried: %p %v %d", got, err, starts)
	}
}

func TestFragmentFallbackStopsOnCancellation(t *testing.T) {
	s := fragment.Default()
	s.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	starts := 0
	owned := &Session{}
	got, err := runFragmentVariants(ctx, Options{Fragments: s}, func(context.Context, Options) (*Session, error) { starts++; cancel(); return owned, context.Canceled }, func(*Session) error { t.Fatal("cleanup belongs to caller after cancellation"); return nil })
	if got != owned || !errors.Is(err, context.Canceled) || starts != 1 {
		t.Fatal("cancelled startup retried")
	}
}

func TestPrepareConfigAppliesFragmentsToLinksAndDocuments(t *testing.T) {
	s := fragment.Default()
	s.Enabled = true
	for _, body := range []string{sampleLinks, `proxies: [{name: Node, type: trojan, server: proxy.example, port: 443, password: pw}]`} {
		doc, _, err := PrepareConfig(Options{Subscription: body, Fragments: s})
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(doc), &parsed); err != nil {
			t.Fatal(err)
		}
		for _, p := range parsed.Proxies {
			if len(p["fragments"].([]any)) != 2 {
				t.Fatal("fragment stages missing")
			}
		}
	}
}
