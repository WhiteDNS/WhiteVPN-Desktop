package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"whitevpn-desktop/internal/fragment"
)

// A retry may start only after the previous engine has confirmed cleanup.
// On cleanup failure the partial session remains owned by the main manager.
func connectFragmentVariants(ctx context.Context, opts Options, start func(context.Context, Options) (*Session, error)) (*Session, error) {
	return runFragmentVariants(ctx, opts, start, func(s *Session) error {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.Stop(cleanup); err != nil {
			return err
		}
		if !opts.Tun.Enabled {
			return nil
		}
		for {
			interfaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			present := false
			for _, iface := range interfaces {
				if iface.Name == opts.Tun.Device {
					present = true
					break
				}
			}
			if !present {
				return nil
			}
			select {
			case <-cleanup.Done():
				return fmt.Errorf("the previous tunnel adapter is still present")
			case <-time.After(100 * time.Millisecond):
			}
		}
	})
}

func runFragmentVariants(ctx context.Context, opts Options, start func(context.Context, Options) (*Session, error), stop func(*Session) error) (*Session, error) {
	if opts.Fragments.Enabled {
		valid, err := fragment.Validate(opts.Fragments)
		if err != nil {
			return nil, fmt.Errorf("fragment settings: %w", err)
		}
		opts.Fragments = valid
	}
	variants := fragment.StartupVariants(opts.Fragments)
	for i, variant := range variants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next := opts.Clone()
		next.Fragments = variant.Settings
		attemptCtx := ctx
		cancel := func() {}
		if opts.Fragments.Enabled {
			attemptCtx, cancel = context.WithTimeout(ctx, 90*time.Second)
			if opts.CoreStdout != nil {
				fmt.Fprintf(opts.CoreStdout, "Fragments: connecting with %s settings\n", variant.Name)
			}
		}
		s, err := start(attemptCtx, next)
		cancel()
		if err == nil {
			if s != nil && opts.Fragments.Enabled {
				s.fragmentMode = variant.Name
			}
			return s, nil
		}
		if i == len(variants)-1 || ctx.Err() != nil {
			return s, err
		}
		if s != nil {
			if cleanupErr := stop(s); cleanupErr != nil {
				return s, fmt.Errorf("fragment attempt failed and cleanup could not be confirmed: %w", cleanupErr)
			}
		}
		if opts.CoreStdout != nil {
			fmt.Fprintf(opts.CoreStdout, "Fragments: %s failed; retrying %s\n", variant.Name, variants[i+1].Name)
		}
	}
	return nil, fmt.Errorf("no fragment startup variant succeeded")
}
