package testkeys_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/montjeffrey/tailnet-sentry/internal/testkeys"
	"github.com/montjeffrey/tailnet-sentry/internal/tsapi"
)

// The fixtures must still look like keys to the redactor, or the tests that
// use them would stop testing redaction.
func TestFakeIsRecognisedAsAKey(t *testing.T) {
	for _, kind := range []string{"api", "client", "auth"} {
		k := testkeys.Fake(kind, "marker-0000")
		if !strings.HasPrefix(k, testkeys.Prefix+kind+"-") {
			t.Errorf("Fake(%q) = %q", kind, k)
		}
		if got := tsapi.Redact("token " + k + " echoed"); got != "token [redacted] echoed" {
			t.Errorf("Redact did not recognise Fake(%q): %q", kind, got)
		}
	}
}

// No test may write a key-shaped literal again: GitHub secret scanning flags
// it. Use testkeys.Fake.
func TestNoKeyShapedLiteralsInTests(t *testing.T) {
	// The pattern is built from pieces so this file does not match itself.
	literal := regexp.MustCompile(`tsk` + `ey-[A-Za-z]+-[A-Za-z0-9]`)
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if loc := literal.FindIndex(b); loc != nil {
			t.Errorf("%s holds a key-shaped literal at byte %d; build it with testkeys.Fake", path, loc[0])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
