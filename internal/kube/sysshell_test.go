package kube

import (
	"os"
	"runtime"
	"strings"
	"testing"
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
	if runtime.GOOS == "windows" {
		return "$env:KLUSTR_CONTEXT = " + psQuote(contextName)
	}
	return "KLUSTR_CONTEXT=" + shellQuote(contextName)
}

func TestPSQuote(t *testing.T) {
	if got := psQuote(`$(Invoke-Expression 'hi')`); got != `'$(Invoke-Expression ''hi'')'` {
		t.Fatalf("psQuote = %q", got)
	}
	if got := psQuote("a'b"); got != "'a''b'" {
		t.Fatalf("psQuote = %q", got)
	}
}

func TestWriteWindowsLaunchersQuoteBreakout(t *testing.T) {
	const evil = `'; calc.exe '`
	shellPath, err := writeWindowsShellLauncher(`C:\temp\kc.yaml`, evil)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(shellPath)
	execPath, err := writeWindowsExecLauncher(`C:\temp\kc.yaml`, evil, evil, evil, evil, evil)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(execPath)

	quoted := psQuote(evil)
	for _, path := range []string{shellPath, execPath} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		script := string(body)
		if !strings.Contains(script, "$env:KLUSTR_CONTEXT = "+quoted) {
			t.Fatalf("context name not PowerShell-quoted in %s:\n%s", path, script)
		}
	}
	execBody, err := os.ReadFile(execPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(execBody), "kubectl exec -it -n "+quoted+" -c "+quoted+" "+quoted+" -- "+quoted) {
		t.Fatalf("kubectl args not quoted:\n%s", execBody)
	}
}
