//go:build windows

package kube

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// applyNewConsole gives a console subsystem child its own window. Klustr is
// built as a GUI app, so a bare powershell.exe would otherwise start with
// no console at all.
func applyNewConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE,
	}
}
