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
	"io"
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

// StepDeauthorize is the label of an isolate's deauthorize step.
const StepDeauthorize = "set-authorized=false"

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

// maxLine bounds one entry. Read, Verify and Append all refuse a longer
// line rather than buffer it.
const maxLine = 1 << 20

// Append chains e to the last line and writes it with O_APPEND, so an
// existing line is never rewritten. From reading the last line to writing
// the new one it holds an exclusive lock on "<log>.lock", so sentry
// processes running at once take turns instead of forking the chain. Only
// the end of the log is read, so an append costs the same however long the
// log has grown.
func (l *Log) Append(e Entry) error {
	unlock, err := l.lock()
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	defer unlock()
	last, err := readLastLine(l.path)
	if err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	e.Prev = ""
	if last != nil {
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

// lock takes the append lock and returns the function that releases it. The
// lock lives on a separate file because Windows locks are mandatory: locking
// the log itself would block anyone reading it.
func (l *Log) lock() (func(), error) {
	f, err := os.OpenFile(l.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", f.Name(), err)
	}
	return func() {
		_ = unlockFile(f)
		f.Close()
	}, nil
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
	sc.Buffer(make([]byte, 64<<10), maxLine)
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
// the file alone: nothing after them carries their hash. The log is read a
// line at a time, so memory does not grow with it.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	prev := ""
	n := 0
	for i := 1; ; i++ {
		line, err := readLine(r)
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, fmt.Errorf("line %d: %w", i, err)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue // as Read does; the hash covers only entry lines
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return n, fmt.Errorf("line %d is not a valid entry: %w", i, err)
		}
		if e.Prev != prev {
			return n, fmt.Errorf("chain broken at line %d: an earlier line was changed, removed or inserted", i)
		}
		prev = hashLine(line)
		n++
	}
}

var errLongLine = fmt.Errorf("longer than %d bytes", maxLine)

// readLine returns the next line without its "\n", or io.EOF after the
// last. A final line without "\n" is still returned.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine+1 {
			return nil, errLongLine
		}
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return line, nil
		default:
			return nil, err
		}
	}
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
// later retry would only record tag:quarantine. Deauthorized is set only if
// an outcome line in the span shows the deauthorize step succeeded: release
// re-approves on the strength of it, and must not approve a device that
// someone else disconnected after sentry's own attempt failed.
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
			open.Deauthorized = open.Deauthorized || deauthorized(e)
		case ActionRelease:
			if e.Result == ResultOK {
				open = nil
			}
		}
	}
	return open, nil
}

// deauthorized reports whether e records a deauthorize that took effect.
// Intent lines are written before anything changes, so they never count; a
// run interrupted after one leaves release to the operator's --reauthorize.
// Outcome lines written before per-step results existed ran deauthorize as
// the last step, so only a fully successful one did it.
func deauthorized(e Entry) bool {
	if !e.Deauthorize || e.Result == ResultIntent {
		return false
	}
	if len(e.Steps) == 0 {
		return e.Result == ResultOK
	}
	for _, s := range e.Steps {
		if s.Step == StepDeauthorize {
			return s.Result == ResultOK
		}
	}
	return false
}

// readLastLine returns the log's last line, ignoring trailing newlines, or
// nil if the log is missing or empty. It reads backwards from the end, so
// its cost does not depend on the log's size.
func readLastLine(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const chunk = 64 << 10
	var tail []byte
	for end := st.Size(); end > 0; {
		n := min(int64(chunk), end)
		end -= n
		buf := make([]byte, n, int(n)+len(tail))
		if _, err := f.ReadAt(buf, end); err != nil {
			return nil, err
		}
		tail = append(buf, tail...)
		data := bytes.TrimRight(tail, "\n")
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			return checkLast(data[i+1:])
		}
		if len(tail) > maxLine+chunk {
			return nil, fmt.Errorf("last line is %w", errLongLine)
		}
	}
	if data := bytes.TrimRight(tail, "\n"); len(data) > 0 {
		return checkLast(data)
	}
	return nil, nil
}

// checkLast refuses a last line Read and Verify would refuse, so the chain
// is never extended from one.
func checkLast(line []byte) ([]byte, error) {
	if len(line) > maxLine {
		return nil, fmt.Errorf("last line is %w", errLongLine)
	}
	return line, nil
}

func hashLine(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}
