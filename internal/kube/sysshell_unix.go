//go:build !windows

package kube

import "os/exec"

func applyNewConsole(*exec.Cmd) {}
