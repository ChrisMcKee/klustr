//go:build !windows

package kube

import "errors"

func startInNewConsole([]string) error {
	return errors.New("a new console window is Windows-only")
}
