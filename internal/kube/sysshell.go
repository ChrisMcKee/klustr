package kube

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

// SystemTerminal is a terminal app discovered on the host. The frontend
// renders these as a "Preferred terminal" picker so the user gets to
// pick (e.g.) Ghostty over the macOS default Terminal.app.
type SystemTerminal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// shellQuote wraps s in single quotes for safe interpolation into a /bin/sh
// script. Single quotes disable all expansion, so $(...), backticks and $VARS
// are inert; an embedded single quote is closed, escaped, and reopened. Use
// this instead of %q for any value reaching a sourced shell: %q yields a
// double-quoted form that still runs $(...).
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// psQuoteEscaper doubles every character PowerShell accepts as a single
// quote: besides ', the tokenizer also takes the curly quotes U+2018-U+201B,
// so doubling ' alone lets a ’ in the value close the string.
var psQuoteEscaper = strings.NewReplacer(
	"'", "''",
	"‘", "‘‘",
	"’", "’’",
	"‚", "‚‚",
	"‛", "‛‛",
)

// psQuote single-quotes s for PowerShell. A single-quoted string is literal
// except for an embedded quote, which is doubled, so $(...), backticks and
// $vars cannot break out. The context name comes from the kubeconfig.
func psQuote(s string) string {
	return "'" + psQuoteEscaper.Replace(s) + "'"
}

type darwinTerminalApp struct {
	id      string
	name    string
	appName string
	relPath string
}

var darwinKnownTerminals = []darwinTerminalApp{
	{"terminal", "Terminal", "Terminal", "Terminal.app"},
	{"iterm", "iTerm2", "iTerm", "iTerm.app"},
	{"ghostty", "Ghostty", "Ghostty", "Ghostty.app"},
	{"warp", "Warp", "Warp", "Warp.app"},
	{"alacritty", "Alacritty", "Alacritty", "Alacritty.app"},
	{"kitty", "kitty", "kitty", "kitty.app"},
	{"wezterm", "WezTerm", "WezTerm", "WezTerm.app"},
	{"hyper", "Hyper", "Hyper", "Hyper.app"},
}

// ListSystemTerminals returns the terminal emulators installed on the
// host. On macOS this scans /Applications + ~/Applications; on Linux it
// probes PATH. Windows has no picker list: an empty appID opens Windows
// Terminal, or a new console when wt is not on PATH.
func (m *ClientManager) ListSystemTerminals() []SystemTerminal {
	switch runtime.GOOS {
	case "darwin":
		return listDarwinTerminals()
	case "linux":
		return listLinuxTerminals()
	}
	return []SystemTerminal{}
}

// OpenPodExecInSystemTerminal opens an external terminal running `kubectl
// exec` into the pod against a single-context KUBECONFIG. An empty shellPath
// means /bin/sh; an empty container lets kubectl pick the first.
func (m *ClientManager) OpenPodExecInSystemTerminal(
	contextName, namespace, podName, container, shellPath, appID string,
) error {
	if contextName == "" || namespace == "" || podName == "" {
		return fmt.Errorf("context, namespace and pod are required")
	}
	if shellPath == "" {
		shellPath = "/bin/sh"
	}

	kubeconfigPath, err := writeContextKubeconfig(m.rules, contextName)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		script := windowsExecScript(kubeconfigPath, contextName, namespace, podName, container, shellPath)
		if err := launchWindowsTerminal(script, appID, false); err != nil {
			_ = os.Remove(kubeconfigPath)
			return err
		}
		return nil
	}
	scriptPath, err := writePodExecLauncher(kubeconfigPath, contextName, namespace, podName, container, shellPath)
	if err != nil {
		_ = os.Remove(kubeconfigPath)
		return err
	}
	if err := launchExternalTerminal(scriptPath, appID); err != nil {
		_ = os.Remove(kubeconfigPath)
		_ = os.Remove(scriptPath)
		return err
	}
	return nil
}

func writePodExecLauncher(kubeconfigPath, contextName, namespace, podName, container, shellPath string) (string, error) {
	suffix := ".sh"
	if runtime.GOOS == "darwin" {
		suffix = ".command"
	}
	f, err := os.CreateTemp("", "klustr-exec-*"+suffix)
	if err != nil {
		return "", err
	}
	path := f.Name()

	containerArg := ""
	if container != "" {
		containerArg = "-c " + shellQuote(container) + " "
	}

	// We explicitly check for kubectl before invoking it so that if the
	// user opens this on a machine without kubectl on PATH, they get a
	// readable message instead of the terminal flashing closed with
	// exit 127.
	body := fmt.Sprintf(`#!/bin/sh
KC=%s
SCRIPT=%s
trap 'rm -f "$KC" "$SCRIPT"' EXIT
export KUBECONFIG="$KC"
export KLUSTR_CONTEXT=%s
export KUBE_CONTEXT=%s
if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl not found on PATH. Install kubectl or use the in-app Exec tab."
  echo
  printf "Press Enter to close. "
  read _
  exit 127
fi
kubectl exec -it -n %s %s%s -- %s
`, shellQuote(kubeconfigPath), shellQuote(path), shellQuote(contextName), shellQuote(contextName), shellQuote(namespace), containerArg, shellQuote(podName), shellQuote(shellPath))

	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// OpenInSystemTerminal opens the user's login shell in an external terminal
// with KUBECONFIG set to a single-context copy; an EXIT trap deletes the temp
// kubeconfig and launcher script. appID is an id from ListSystemTerminals;
// empty means the macOS .command handler, the Linux priority list, or
// Windows Terminal (a new console when wt is not on PATH).
func (m *ClientManager) OpenInSystemTerminal(contextName, appID string) error {
	if contextName == "" {
		return fmt.Errorf("context name is required")
	}

	kubeconfigPath, err := writeContextKubeconfig(m.rules, contextName)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := launchWindowsTerminal(windowsShellScript(kubeconfigPath, contextName), appID, true); err != nil {
			_ = os.Remove(kubeconfigPath)
			return err
		}
		return nil
	}
	scriptPath, err := writeLauncherScript(kubeconfigPath, contextName)
	if err != nil {
		_ = os.Remove(kubeconfigPath)
		return err
	}
	if err := launchExternalTerminal(scriptPath, appID); err != nil {
		_ = os.Remove(kubeconfigPath)
		_ = os.Remove(scriptPath)
		return err
	}
	return nil
}

func writeLauncherScript(kubeconfigPath, contextName string) (string, error) {
	suffix := ".sh"
	if runtime.GOOS == "darwin" {
		// .command is the macOS double-clickable shell-script extension;
		// `open` routes it to the user's preferred terminal app.
		suffix = ".command"
	}

	f, err := os.CreateTemp("", "klustr-shell-*"+suffix)
	if err != nil {
		return "", err
	}
	path := f.Name()

	// shellQuote single-quotes every interpolated value: the context name
	// comes from an untrusted kubeconfig, and Go's %q leaves $(...) and
	// backticks live inside shell double quotes (a host-RCE vector). The
	// EXIT trap cleans up both files even when the user closes the terminal
	// window — only an outright SIGKILL leaks them.
	body := fmt.Sprintf(`#!/bin/sh
KC=%s
SCRIPT=%s
trap 'rm -f "$KC" "$SCRIPT"' EXIT
export KUBECONFIG="$KC"
export KLUSTR_CONTEXT=%s
export KUBE_CONTEXT=%s
cd "$HOME" 2>/dev/null || true
"${SHELL:-/bin/sh}" -l
`, shellQuote(kubeconfigPath), shellQuote(path), shellQuote(contextName), shellQuote(contextName))

	if _, err := f.WriteString(body); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func launchExternalTerminal(scriptPath, appID string) error {
	switch runtime.GOOS {
	case "darwin":
		return launchDarwinTerminal(scriptPath, appID)
	case "linux":
		return launchLinuxTerminal(scriptPath, appID)
	default:
		return fmt.Errorf("opening a system terminal is not supported on %s", runtime.GOOS)
	}
}

func windowsPowerShellPath() (string, error) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("PowerShell is not on PATH")
}

// launchWindowsTerminal runs script in a new PowerShell tab or window. The
// script goes in as -EncodedCommand rather than a temp .ps1: execution
// policy covers script files only, and a Group Policy one (AllSigned, say)
// overrides -ExecutionPolicy Bypass. -NoExit keeps the prompt once the
// script returns.
func launchWindowsTerminal(script, appID string, interactive bool) error {
	if appID != "" {
		return fmt.Errorf("unknown terminal app %q", appID)
	}
	shell, err := windowsPowerShellPath()
	if err != nil {
		return err
	}
	args := []string{"-NoLogo"}
	if interactive {
		args = append(args, "-NoExit")
	}
	args = append(args, "-EncodedCommand", psEncode(script))
	if wt, err := exec.LookPath("wt.exe"); err == nil {
		return startDetached(exec.Command(wt, append([]string{"new-tab", "--", shell}, args...)...))
	}
	return startInNewConsole(append([]string{shell}, args...))
}

// psEncode encodes script the way -EncodedCommand takes it: base64 over
// UTF-16LE.
func psEncode(script string) string {
	var b []byte
	for _, c := range utf16.Encode([]rune(script)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// windowsShellScript sets up the interactive session. It finishes before the
// prompt appears under -NoExit, so a try/finally would delete the kubeconfig
// at once; the exit event runs when the session exits. It deletes through
// .NET: the runspace is already closing and can't load a module, so a
// Remove-Item whose module isn't loaded yet fails, silently under
// SilentlyContinue. The open handle, which shares read and write but not
// delete, keeps SweepStaleLaunchFiles off the kubeconfig while the session
// lives. It reaches the action through a global: PowerShell.Exiting leaves
// $Event.MessageData null.
func windowsShellScript(kubeconfigPath, contextName string) string {
	return fmt.Sprintf(`$env:KUBECONFIG = %s
$env:KLUSTR_CONTEXT = %s
$env:KUBE_CONTEXT = %s
Set-Location -ErrorAction SilentlyContinue $env:USERPROFILE
$global:KlustrKubeconfigLock = [IO.File]::Open($env:KUBECONFIG, 'Open', 'Read', 'ReadWrite')
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    $global:KlustrKubeconfigLock.Dispose()
    [IO.File]::Delete(%s)
}
`, psQuote(kubeconfigPath), psQuote(contextName), psQuote(contextName), psQuote(kubeconfigPath))
}

func windowsExecScript(kubeconfigPath, contextName, namespace, podName, container, shellPath string) string {
	containerArg := ""
	if container != "" {
		containerArg = "-c " + psQuote(container) + " "
	}
	// The lock keeps SweepStaleLaunchFiles off the kubeconfig, as in
	// windowsShellScript.
	return fmt.Sprintf(`$env:KUBECONFIG = %s
$env:KLUSTR_CONTEXT = %s
$env:KUBE_CONTEXT = %s
$kubeconfigLock = [IO.File]::Open($env:KUBECONFIG, 'Open', 'Read', 'ReadWrite')
try {
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-Host 'kubectl not found on PATH. Install kubectl or use the in-app Exec tab.'
        Write-Host ''
        Read-Host 'Press Enter to close'
        exit 127
    }
    kubectl exec -it -n %s %s%s -- %s
} finally {
    $kubeconfigLock.Dispose()
    Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue
}
`, psQuote(kubeconfigPath), psQuote(contextName), psQuote(contextName), psQuote(namespace), containerArg, psQuote(podName), psQuote(shellPath), psQuote(kubeconfigPath))
}

// staleLaunchFileAge covers the moment before a new terminal opens its
// kubeconfig, which another klustr instance's sweep could otherwise hit.
const staleLaunchFileAge = 24 * time.Hour

// SweepStaleLaunchFiles deletes the temp kubeconfigs that external Windows
// terminals leave behind: closing the window skips PowerShell's Exiting
// handler. Unix launchers clean up in their EXIT trap instead. A live
// terminal, in-app or external, holds its kubeconfig open without
// FILE_SHARE_DELETE, so Windows refuses to delete it and the sweep only
// takes abandoned ones.
func (m *ClientManager) SweepStaleLaunchFiles() {
	if runtime.GOOS != "windows" {
		return
	}
	sweepStaleLaunchFiles(os.TempDir(), time.Now().Add(-staleLaunchFileAge))
}

func sweepStaleLaunchFiles(dir string, cutoff time.Time) {
	matches, _ := filepath.Glob(filepath.Join(dir, "klustr-kubeconfig-*.yaml"))
	for _, path := range matches {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.Remove(path)
	}
}

// startDetached starts a launcher process and reaps it in the background. The
// external terminal apps fork their own window and the launcher exits within a
// second; without a Wait() that exited process lingers as a zombie in klustr's
// process table until the app quits.
func startDetached(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func launchDarwinTerminal(scriptPath, appID string) error {
	if appID == "" {
		// macOS picks whichever app is registered as the .command
		// handler — usually Terminal.app, or whatever the user set in
		// Finder > Get Info > Open With.
		return startDetached(exec.Command("open", scriptPath))
	}
	for _, t := range darwinKnownTerminals {
		if t.id != appID {
			continue
		}
		return startDetached(exec.Command("open", "-a", t.appName, scriptPath))
	}
	return fmt.Errorf("unknown terminal app %q", appID)
}

func listDarwinTerminals() []SystemTerminal {
	dirs := []string{
		"/Applications",
		"/Applications/Utilities",
		// Apple moved Terminal.app under /System on Catalina+. We still
		// scan /Applications/Utilities for older systems and bundles
		// users have placed there manually.
		"/System/Applications/Utilities",
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	out := make([]SystemTerminal, 0, len(darwinKnownTerminals))
	seen := map[string]bool{}
	for _, t := range darwinKnownTerminals {
		if seen[t.id] {
			continue
		}
		for _, d := range dirs {
			if _, err := os.Stat(filepath.Join(d, t.relPath)); err == nil {
				out = append(out, SystemTerminal{ID: t.id, Name: t.name})
				seen[t.id] = true
				break
			}
		}
	}
	return out
}

type terminalLauncher struct {
	id    string
	label string
	bin   string
	args  func(script string) []string
	// flatpakID, if non-empty, lets the detector pick this terminal up
	// from a Flatpak install when the native binary is not on PATH —
	// the common case on Fedora Silverblue / Bazzite / immutable distros.
	flatpakID string
}

var linuxKnownTerminals = []terminalLauncher{
	{"gnome-terminal", "GNOME Terminal", "gnome-terminal", func(s string) []string { return []string{"--", s} }, "org.gnome.Terminal"},
	{"konsole", "Konsole", "konsole", func(s string) []string { return []string{"-e", s} }, "org.kde.konsole"},
	{"xfce4-terminal", "Xfce Terminal", "xfce4-terminal", func(s string) []string { return []string{"-e", s} }, ""},
	{"tilix", "Tilix", "tilix", func(s string) []string { return []string{"-e", s} }, ""},
	{"ghostty", "Ghostty", "ghostty", func(s string) []string { return []string{"-e", s} }, "com.mitchellh.ghostty"},
	{"kitty", "kitty", "kitty", func(s string) []string { return []string{s} }, "net.kovidgoyal.kitty"},
	{"alacritty", "Alacritty", "alacritty", func(s string) []string { return []string{"-e", s} }, "org.alacritty.Alacritty"},
	{"wezterm", "WezTerm", "wezterm", func(s string) []string { return []string{"start", "--", s} }, "org.wezfurlong.wezterm"},
	{"foot", "foot", "foot", func(s string) []string { return []string{s} }, ""},
	{"xterm", "xterm", "xterm", func(s string) []string { return []string{"-e", s} }, ""},
}

const flatpakPrefix = "flatpak:"

func listLinuxTerminals() []SystemTerminal {
	seen := map[string]bool{}
	out := make([]SystemTerminal, 0, len(linuxKnownTerminals)+2)

	// xdg-terminal-exec is the freedesktop "default terminal" launcher.
	// When the user has set a default via ~/.config/xdg-terminals.list
	// (newer GNOME / KDE / xdg-utils), this is the right thing to honor
	// — surface it as a first-class option labeled accordingly.
	if _, err := exec.LookPath("xdg-terminal-exec"); err == nil {
		out = append(out, SystemTerminal{ID: "xdg-default", Name: "System default (xdg-terminal-exec)"})
	}

	for _, c := range linuxKnownTerminals {
		if _, err := exec.LookPath(c.bin); err == nil {
			out = append(out, SystemTerminal{ID: c.id, Name: c.label})
			seen[c.id] = true
		}
	}

	// Probe Flatpak-installed terminals: useful on immutable distros
	// (Silverblue, Bazzite, …) where the canonical install location is
	// not PATH but `flatpak run <app-id>`. Dedup by friendly id so a
	// native install is preferred when both are present.
	installed := flatpakInstalledApps()
	for _, c := range linuxKnownTerminals {
		if seen[c.id] || c.flatpakID == "" {
			continue
		}
		if installed[c.flatpakID] {
			out = append(out, SystemTerminal{
				ID:   flatpakPrefix + c.id,
				Name: c.label + " (Flatpak)",
			})
		}
	}
	return out
}

// flatpakInstalledApps returns the set of Flatpak application ids the
// user has installed. Empty when flatpak is not on PATH or the call
// fails — we deliberately swallow errors so absence is treated as "no
// flatpak terminals", not a hard failure.
func flatpakInstalledApps() map[string]bool {
	if _, err := exec.LookPath("flatpak"); err != nil {
		return nil
	}
	out, err := exec.Command("flatpak", "list", "--app", "--columns=application").Output()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = true
		}
	}
	return set
}

func launchLinuxTerminal(scriptPath, appID string) error {
	if appID == "xdg-default" {
		bin, err := exec.LookPath("xdg-terminal-exec")
		if err != nil {
			return fmt.Errorf("xdg-terminal-exec is no longer on PATH")
		}
		return startDetached(exec.Command(bin, scriptPath))
	}
	if id, ok := strings.CutPrefix(appID, flatpakPrefix); ok {
		for _, c := range linuxKnownTerminals {
			if c.id != id || c.flatpakID == "" {
				continue
			}
			// `flatpak run <app-id> <args>` — the app inside the
			// sandbox receives the args verbatim, so each terminal's
			// per-binary flag form (e.g. `--`, `-e`) still applies.
			args := append([]string{"run", c.flatpakID}, c.args(scriptPath)...)
			return startDetached(exec.Command("flatpak", args...))
		}
		return fmt.Errorf("unknown flatpak terminal app %q", appID)
	}
	if appID != "" {
		for _, c := range linuxKnownTerminals {
			if c.id != appID {
				continue
			}
			bin, err := exec.LookPath(c.bin)
			if err != nil {
				return fmt.Errorf("%s is not on PATH", c.bin)
			}
			return startDetached(exec.Command(bin, c.args(scriptPath)...))
		}
		return fmt.Errorf("unknown terminal app %q", appID)
	}

	// Empty appID — walk a fallback chain that prefers the freedesktop
	// "default terminal" spec, then the Debian alternatives system,
	// then a tiling-WM convention, then a user override, then the
	// known list in priority order.
	for _, bin := range []string{"xdg-terminal-exec", "x-terminal-emulator", "i3-sensible-terminal"} {
		if path, err := exec.LookPath(bin); err == nil {
			if bin == "xdg-terminal-exec" {
				return startDetached(exec.Command(path, scriptPath))
			}
			return startDetached(exec.Command(path, "-e", scriptPath))
		}
	}
	if pref := os.Getenv("KLUSTR_TERMINAL"); pref != "" {
		if bin, err := exec.LookPath(pref); err == nil {
			return startDetached(exec.Command(bin, scriptPath))
		}
	}
	for _, c := range linuxKnownTerminals {
		bin, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}
		return startDetached(exec.Command(bin, c.args(scriptPath)...))
	}
	return fmt.Errorf("no supported terminal emulator found on PATH (set $KLUSTR_TERMINAL or install gnome-terminal/konsole/kitty/alacritty/wezterm)")
}
