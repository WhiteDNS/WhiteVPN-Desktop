//go:build !darwin

package main

func raiseProcessFileDescriptorLimit() error {
	return nil
}
