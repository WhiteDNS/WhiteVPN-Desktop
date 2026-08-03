//go:build !windows

package main

import "os/exec"

func hideConsoleWindow(_ *exec.Cmd) {}
