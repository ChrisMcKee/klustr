package kube

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func TestShellQuoteNeutralizesSubstitution(t *testing.T) {
	got := shellQuote(`$(touch /tmp/pwned)`)
	if got != `'$(touch /tmp/pwned)'` {
		t.Fatalf("shellQuote = %q, want single-quoted", got)
	}
	// An embedded single quote must not break out of the quoting.
	if q := shellQuote(`a'b`); q != `'a'\''b'` {
		t.Fatalf("shellQuote(a'b) = %q", q)
	}
}

// A launcher built from a hostile kubeconfig context name must not embed a
// live command substitution — the value has to land single-quoted so /bin/sh
// treats it as data, not code.
func TestWriteLauncherScriptQuotesContextName(t *testing.T) {
	const evil = `$(touch /tmp/klustr_pwned)`

	path, err := writeLauncherScript("/tmp/kc.yaml", evil)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)

	if strings.Contains(script, `KLUSTR_CONTEXT="$(`) || strings.Contains(script, `KUBE_CONTEXT="$(`) {
		t.Fatalf("context name interpolated as live substitution:\n%s", script)
	}
	if !strings.Contains(script, contextAssign(evil)) {
		t.Fatalf("context name not quoted:\n%s", script)
	}
}

func TestWritePodExecLauncherQuotesInputs(t *testing.T) {
	const evil = `$(touch /tmp/klustr_pwned)`

	path, err := writePodExecLauncher("/tmp/kc.yaml", evil, "default", "web", "app", "/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)

	if strings.Contains(script, `"$(`) {
		t.Fatalf("value interpolated as live substitution:\n%s", script)
	}
	if !strings.Contains(script, contextAssign(evil)) {
		t.Fatalf("context name not quoted:\n%s", script)
	}
}

func contextAssign(contextName string) string {
	return "KLUSTR_CONTEXT=" + shellQuote(contextName)
}

func TestPSQuote(t *testing.T) {
	if got := psQuote(`$(Invoke-Expression 'hi')`); got != `'$(Invoke-Expression ''hi'')'` {
		t.Fatalf("psQuote = %q", got)
	}
	if got := psQuote("a'b"); got != "'a''b'" {
		t.Fatalf("psQuote = %q", got)
	}
	// PowerShell closes a single-quoted string on a curly quote too.
	if got := psQuote("x’; calc.exe; ‘"); got != "'x’’; calc.exe; ‘‘'" {
		t.Fatalf("psQuote = %q", got)
	}
}

func TestWindowsLauncherScriptsQuoteBreakout(t *testing.T) {
	const evil = "’; calc.exe ’; calc.exe ‘"
	quoted := psQuote(evil)
	shellScript := windowsShellScript(`C:\temp\kc.yaml`, evil)
	execScript := windowsExecScript(`C:\temp\kc.yaml`, evil, evil, evil, evil, evil)
	for _, script := range []string{shellScript, execScript} {
		if !strings.Contains(script, "$env:KLUSTR_CONTEXT = "+quoted) {
			t.Fatalf("context name not PowerShell-quoted:\n%s", script)
		}
	}
	if !strings.Contains(execScript, "kubectl exec -it -n "+quoted+" -c "+quoted+" "+quoted+" -- "+quoted) {
		t.Fatalf("kubectl args not quoted:\n%s", execScript)
	}
}

func TestPSEncodeIsBase64UTF16LE(t *testing.T) {
	const script = "$env:KLUSTR_CONTEXT = ‘prod-ü-😀’\n"
	raw, err := base64.StdEncoding.DecodeString(psEncode(script))
	if err != nil {
		t.Fatal(err)
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if got := string(utf16.Decode(units)); got != script {
		t.Fatalf("decoded = %q, want %q", got, script)
	}
}

func TestSweepStaleLaunchFilesRemovesOnlyOldLaunchFiles(t *testing.T) {
	dir := t.TempDir()
	cutoff := time.Now().Add(-staleLaunchFileAge)
	old := cutoff.Add(-time.Hour)
	write := func(name string, mtime time.Time) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return path
	}
	stale := []string{
		write("klustr-kubeconfig-1.yaml", old),
	}
	kept := []string{
		write("klustr-kubeconfig-2.yaml", time.Now()),
		write("other-kubeconfig-1.yaml", old),
	}

	sweepStaleLaunchFiles(dir, cutoff)

	for _, p := range stale {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stale file %s not removed", filepath.Base(p))
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("file %s removed: %v", filepath.Base(p), err)
		}
	}
}

// A live terminal holds its kubeconfig open; the sweep relies on Windows
// refusing to delete it.
func TestSweepStaleLaunchFilesSkipsOpenKubeconfig(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("an open file blocks deletion only on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "klustr-kubeconfig-1.yaml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleLaunchFileAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	lock, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	sweepStaleLaunchFiles(dir, time.Now().Add(-staleLaunchFileAge))

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("open kubeconfig removed: %v", err)
	}
}
