//go:build !windows && !darwin

package sysproxy

import "errors"

// ErrUnsupported is what every call returns on the platforms left.
//
// Windows and macOS each have one answer; Linux has none — GNOME, KDE and a
// bare window manager keep it in three different places and none of them binds
// anything that is not already asking. A caller that cannot point the machine at
// the proxy should say so rather than quietly succeed.
var ErrUnsupported = errors.New("sysproxy: setting the system proxy is implemented on Windows and macOS")

func Current() (State, error)        { return State{}, ErrUnsupported }
func Apply(State) error              { return ErrUnsupported }
func Pointing(string) (State, error) { return State{}, ErrUnsupported }
func Verify(State) error             { return ErrUnsupported }
