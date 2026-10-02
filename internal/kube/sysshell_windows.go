//go:build windows

package kube

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// startInNewConsole starts argv in a console window of its own. Klustr is a
// GUI app, so a bare powershell.exe would otherwise start with no console.
// exec.Cmd can't do this: it always sets STARTF_USESTDHANDLES and passes NUL
// for nil stdio, which wins over the new console, so PowerShell reads EOF and
// exits at once.
func startInNewConsole(argv []string) error {
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(argv))
	if err != nil {
		return err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdLine, nil, nil, false, windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi); err != nil {
		return err
	}
	_ = windows.CloseHandle(pi.Thread)
	return windows.CloseHandle(pi.Process)
}
