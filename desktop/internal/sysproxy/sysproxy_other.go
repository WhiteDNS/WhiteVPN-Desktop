//go:build !windows && !darwin && !linux

package sysproxy

import "errors"

// The platforms left have no desktop proxy setting at all, and every call says
// so plainly rather than quietly succeeding.
var errNothingToConfigure = errors.New("sysproxy: setting the system proxy is implemented on Windows, macOS and Linux")

func Current() (State, error)        { return State{}, errNothingToConfigure }
func Apply(State) error              { return errNothingToConfigure }
func Pointing(string) (State, error) { return State{}, ErrUnsupported }
func Verify(State) error             { return errNothingToConfigure }

// SystemStore is the store for this platform. Here it has no targets at all,
// which Capture reports as unsupported.
func SystemStore() Store { return nullStore{} }

type nullStore struct{}

func (nullStore) Targets() ([]Target, error) { return nil, ErrUnsupported }
func (nullStore) Read(Target) (State, error) { return State{}, errNothingToConfigure }
func (nullStore) Write(Target, State) error  { return errNothingToConfigure }
func (nullStore) Check(Target, State) error  { return errNothingToConfigure }
