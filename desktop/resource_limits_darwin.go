//go:build darwin

package main

import "golang.org/x/sys/unix"

const desiredProcessFileDescriptorLimit uint64 = 65536

func raiseProcessFileDescriptorLimit() error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return err
	}
	target := desiredProcessFileDescriptorLimit
	if limit.Max > 0 && target > limit.Max {
		target = limit.Max
	}
	if target <= limit.Cur {
		return nil
	}
	limit.Cur = target
	return unix.Setrlimit(unix.RLIMIT_NOFILE, &limit)
}
