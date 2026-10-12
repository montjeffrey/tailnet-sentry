// Package audit keeps an append-only, hash-chained record of every isolate
// and release, dry runs included.
//
// Each line is one JSON entry whose "prev" field is the SHA-256 of the line
// before it. Editing or deleting a line in the middle breaks the chain, and
// `sentry audit verify` reports where. The chain is tamper-evident, not
// tamper-proof: someone able to rewrite the whole file can rebuild a valid
// chain. For that threat, ship the log off the machine (the README shows
// how).
//
// Apply runs write two entries: an "intent" line before any change and an
// outcome line after. If the process dies between them, the log still shows
// that a change was attempted.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Actions and modes.
const (
	ActionIsolate = "isolate"
	ActionRelease = "release"

	ModeDryRun = "dry-run"
	ModeApply  = "apply"

	ResultPlanned = "planned" // dry run: nothing was changed
	ResultIntent  = "intent"  // apply: about to change something
	ResultOK      = "ok"      // apply: every step succeeded
)

// Entry is one line of the log. It holds device metadata and the operator's
// local identity, never a credential: errors are redacted before they get
// here.
type Entry struct {
	Time         time.Time `json:"time"`
	Action       string    `json:"action"`
	Mode         string    `json:"mode"`
	DeviceID     string    `json:"deviceId"`
	DeviceName   string    `json:"deviceName"`
	PreviousTags []string  `json:"previousTags"`
	NewTags      []string  `json:"newTags"`
	Deauthorize  bool      `json:"deauthorize,omitempty"`
	Reauthorize  bool      `json:"reauthorize,omitempty"`
	Forced       bool      `json:"forced,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	Operator     string    `json:"operator"`
	Result       string    `json:"result"`
	// Steps holds, on an apply's outcome line, what happened to each planned
	// API call in order, so a run that failed part-way shows exactly which
	// changes were made.
	Steps []StepResult `json:"steps,omitempty"`
	Prev  string       `json:"prev"`
}

// StepResult is the outcome of one planned API call.
type StepResult struct {
	Step   string `json:"step"`   // e.g. "set-authorized", "set-tags"
	Result string `json:"result"` // ResultOK, "error: ...", or StepSkipped
}

// StepSkipped marks a step not attempted because an earlier one failed.
const StepSkipped = "skipped"

// Log is an audit file.
type Log struct{ path string }

// Open prepares the log at path, creating it (and its directory) private to
// the current user. It fails if the file cannot be opened for appending, so
// callers can refuse to act before changing anything.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &Log{path: path}, nil
}

// Path returns the file the log writes to.
func (l *Log) Path() string { return l.path }

// Append chains e to the last line and writes it with O_APPEND, so an
// existing line is never rewritten. One sentry process at a time is
// assumed; two appending at once could fork the chain, which verify would
// then report.
func (l *Log) Append(e Entry) error {
	data, err := os.ReadFile(l.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("audit log: %w", err)
	}
	e.Prev = ""
	if last := lastLine(data); last != nil {
		e.Prev = hashLine(last)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("audit log: %w", err)
	}
	return f.Close()
}

// Read returns every entry in order.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("audit log line %d: %w", n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Verify checks the hash chain and returns the number of entries. The error
// names the first line whose "prev" does not match the line before it.
// Removing or editing lines at the end of the file cannot be detected from
// the file alone: nothing after them carries their hash.
func Verify(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	prev := ""
	n := 0
	for i, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue // as Read does; the hash covers only entry lines
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return n, fmt.Errorf("line %d is not a valid entry: %w", i+1, err)
		}
		if e.Prev != prev {
			return n, fmt.Errorf("chain broken at line %d: an earlier line was changed, removed or inserted", i+1)
		}
		prev = hashLine(line)
		n++
	}
	return n, nil
}

// Isolation is what release needs to know about a device's current
// quarantine: the tags it had before, and whether sentry deauthorized it.
type Isolation struct {
	Since        time.Time
	PreviousTags []string
	Deauthorized bool
}

// OpenIsolation summarises every isolate of deviceID since its last
// completed release, or returns nil if there is none.
//
// The tags to restore come from the FIRST applied isolate in that span,
// whatever its result: its intent line is written before anything changes,
// so it holds the original tags even if the run then failed half-way. A
// later retry would only record tag:quarantine. Deauthorized is set if any
// applied isolate in the span asked to deauthorize.
func OpenIsolation(path, deviceID string) (*Isolation, error) {
	entries, err := Read(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var open *Isolation
	for _, e := range entries {
		if e.DeviceID != deviceID || e.Mode != ModeApply {
			continue
		}
		switch e.Action {
		case ActionIsolate:
			if open == nil {
				open = &Isolation{Since: e.Time, PreviousTags: e.PreviousTags}
			}
			open.Deauthorized = open.Deauthorized || e.Deauthorize
		case ActionRelease:
			if e.Result == ResultOK {
				open = nil
			}
		}
	}
	return open, nil
}

func lastLine(data []byte) []byte {
	data = bytes.TrimRight(data, "\n")
	if len(data) == 0 {
		return nil
	}
	if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
		return data[i+1:]
	}
	return data
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}
