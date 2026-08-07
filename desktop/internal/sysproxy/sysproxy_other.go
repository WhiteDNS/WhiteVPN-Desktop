//go:build !windows && !darwin && !linux

package sysproxy

import "errors"

// ErrUnsupported is what every call returns on the platforms left.
//
// Windows, macOS and Linux each have an answer. What is left is the platforms
// with no desktop proxy setting at all, and a caller that cannot point the
// machine at the proxy should say so rather than quietly succeed.
var ErrUnsupported = errors.New("sysproxy: setting the system proxy is implemented on Windows, macOS and Linux")

func Current() (State, error)        { return State{}, ErrUnsupported }
func Apply(State) error              { return ErrUnsupported }
func Pointing(string) (State, error) { return State{}, ErrUnsupported }
func Verify(State) error             { return ErrUnsupported }
