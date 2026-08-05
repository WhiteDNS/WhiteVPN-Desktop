//go:build !windows

package sysproxy

import "errors"

// ErrUnsupported is what every call returns off Windows. macOS wants
// `networksetup` per network service and Linux has no single answer at all, so
// neither is guessed at here: a caller that cannot point the machine at the
// proxy should say so rather than quietly succeed.
var ErrUnsupported = errors.New("sysproxy: setting the system proxy is only implemented on Windows")

func Current() (State, error)           { return State{}, ErrUnsupported }
func Apply(State) error                 { return ErrUnsupported }
func Pointing(string) (State, error)    { return State{}, ErrUnsupported }
func Verify(State) error                { return ErrUnsupported }
