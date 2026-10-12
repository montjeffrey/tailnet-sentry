package tsutil

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests run a harmless stand-in script named tailscale from a temporary
// directory, never the real CLI: trustedPaths is pointed at the temp dir and
// PATH is changed only inside the test process.

func fakeStatus(id string) string {
	return `{"BackendState":"Running","Version":"fake","Self":{"ID":"` + id + `","DNSName":"fake."}}`
}

// writeFakeTailscale writes a script named tailscale into dir that prints a
// status for node id and records SENTRY_WEBHOOK, bracketed, in
// dir/marker.txt. It returns the script's path.
func writeFakeTailscale(t *testing.T, dir, id string) string {
	t.Helper()
	var name, body string
	if runtime.GOOS == "windows" {
		name = "tailscale.bat"
		body = "@echo off\r\n" +
			"echo [%SENTRY_WEBHOOK%]>\"%~dp0marker.txt\"\r\n" +
			"echo " + fakeStatus(id) + "\r\n"
	} else {
		name = "tailscale"
		body = "#!/bin/sh\n" +
			"printf '[%s]\\n' \"$SENTRY_WEBHOOK\" > \"$(dirname \"$0\")/marker.txt\"\n" +
			"echo '" + fakeStatus(id) + "'\n"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func useTrusted(t *testing.T, paths ...string) {
	t.Helper()
	saved := trustedPaths
	trustedPaths = func() []string { return paths }
	t.Cleanup(func() { trustedPaths = saved })
}

// A tailscale earlier in PATH must not shadow the installed CLI.
func TestBinaryPrefersInstallLocationOverPath(t *testing.T) {
	installed := writeFakeTailscale(t, t.TempDir(), "nINSTALLED")
	pathDir := t.TempDir()
	writeFakeTailscale(t, pathDir, "nFROMPATH")
	useTrusted(t, filepath.Join(t.TempDir(), "missing"), installed)
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if got, err := binary(); err != nil || got != installed {
		t.Fatalf("binary() = %q, %v; want the install location %q", got, err, installed)
	}
	_, self, err := Inventory(context.Background())
	if err != nil || self.ID != "nINSTALLED" {
		t.Fatalf("ran the wrong CLI: self=%+v err=%v", self, err)
	}
}

func TestBinaryFallsBackToPath(t *testing.T) {
	pathDir := t.TempDir()
	onPath := writeFakeTailscale(t, pathDir, "nFROMPATH")
	useTrusted(t, filepath.Join(t.TempDir(), "missing"))
	t.Setenv("PATH", pathDir)
	if got, err := binary(); err != nil || !strings.EqualFold(got, onPath) {
		t.Fatalf("binary() = %q, %v; want %q", got, err, onPath)
	}
}

func TestBinaryRefusesWritableLocation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses ACLs, which mode bits do not describe")
	}
	dir := t.TempDir()
	p := writeFakeTailscale(t, dir, "nANY")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	useTrusted(t, p)
	if _, err := binary(); err == nil || !strings.Contains(err.Error(), "writable by other users") {
		t.Fatalf("binary() err = %v, want a refusal", err)
	}
}

// The subprocess gets a minimal environment: no credential, and nothing
// else secret this process holds, such as the webhook URL.
func TestSubprocessGetsMinimalEnvironment(t *testing.T) {
	dir := t.TempDir()
	useTrusted(t, writeFakeTailscale(t, dir, "nINSTALLED"))
	t.Setenv("SENTRY_WEBHOOK", "https://hooks.example.invalid/not-a-real-secret")
	t.Setenv("TS_API_KEY", "tskey-api-should-not-pass")
	if _, _, err := Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(dir, "marker.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(marker)); got != "[]" {
		t.Errorf("the subprocess saw SENTRY_WEBHOOK=%s", got)
	}
}
