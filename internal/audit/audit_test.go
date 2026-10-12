package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newLog(t *testing.T) *Log {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "state", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func entry(action, mode, result string) Entry {
	return Entry{Time: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC), Action: action, Mode: mode,
		DeviceID: "nKALI", DeviceName: "kali", PreviousTags: []string{"tag:ci"}, NewTags: []string{"tag:quarantine"},
		Operator: "alice@desktop", Result: result}
}

func TestAppendChainsAndVerifies(t *testing.T) {
	l := newLog(t)
	for _, e := range []Entry{
		entry(ActionIsolate, ModeDryRun, ResultPlanned),
		entry(ActionIsolate, ModeApply, ResultIntent),
		entry(ActionIsolate, ModeApply, ResultOK),
	} {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(l.Path())
	if err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v", n, err)
	}
	entries, err := Read(l.Path())
	if err != nil || len(entries) != 3 {
		t.Fatalf("Read = %d entries, %v", len(entries), err)
	}
	if entries[0].Prev != "" || entries[1].Prev == "" || entries[1].Prev == entries[2].Prev {
		t.Errorf("chain not built: %q %q %q", entries[0].Prev, entries[1].Prev, entries[2].Prev)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	l := newLog(t)
	for i := 0; i < 3; i++ {
		if err := l.Append(entry(ActionIsolate, ModeApply, ResultOK)); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(l.Path())
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")

	cases := map[string][]string{
		"edited":  {lines[0], strings.Replace(lines[1], `"kali"`, `"laptop"`, 1), lines[2]},
		"deleted": {lines[0], lines[2]},
		"swapped": {lines[1], lines[0], lines[2]},
	}
	for name, ls := range cases {
		p := filepath.Join(t.TempDir(), name+".jsonl")
		if err := os.WriteFile(p, []byte(strings.Join(ls, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(p); err == nil || !strings.Contains(err.Error(), "chain broken") {
			t.Errorf("%s: Verify = %v, want chain broken", name, err)
		}
	}
}

func TestAppendNeverRewrites(t *testing.T) {
	l := newLog(t)
	if err := l.Append(entry(ActionIsolate, ModeApply, ResultOK)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(l.Path())
	if err := l.Append(entry(ActionRelease, ModeApply, ResultOK)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(l.Path())
	if !strings.HasPrefix(string(after), string(before)) {
		t.Error("existing content changed on append")
	}
}

func appendAll(t *testing.T, l *Log, es ...Entry) {
	t.Helper()
	for _, e := range es {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
}

func withTags(e Entry, tags ...string) Entry { e.PreviousTags = tags; return e }

func withDeauth(e Entry) Entry { e.Deauthorize = true; return e }

// withSteps adds step results given as step, result pairs.
func withSteps(e Entry, pairs ...string) Entry {
	for i := 0; i+1 < len(pairs); i += 2 {
		e.Steps = append(e.Steps, StepResult{Step: pairs[i], Result: pairs[i+1]})
	}
	return e
}

func TestOpenIsolation(t *testing.T) {
	tests := []struct {
		name      string
		entries   []Entry
		wantNil   bool
		wantTags  string
		wantDeath bool
	}{
		{name: "none", wantNil: true},
		{name: "dry runs only", entries: []Entry{entry(ActionIsolate, ModeDryRun, ResultPlanned)}, wantNil: true},
		{name: "one isolate", entries: []Entry{
			entry(ActionIsolate, ModeApply, ResultIntent), entry(ActionIsolate, ModeApply, ResultOK),
		}, wantTags: "tag:ci"},
		// Tags replaced, then deauthorize failed; the retry finds the device
		// already tagged and records tag:quarantine. The original tags must
		// still come back.
		{name: "partial failure then retry", entries: []Entry{
			withDeauth(entry(ActionIsolate, ModeApply, ResultIntent)),
			withDeauth(entry(ActionIsolate, ModeApply, "error: step 2 failed")),
			withTags(withDeauth(entry(ActionIsolate, ModeApply, ResultIntent)), "tag:quarantine"),
			withTags(withDeauth(entry(ActionIsolate, ModeApply, ResultOK)), "tag:quarantine"),
		}, wantTags: "tag:ci", wantDeath: true},
		{name: "interrupted after intent", entries: []Entry{entry(ActionIsolate, ModeApply, ResultIntent)}, wantTags: "tag:ci"},
		// Only a deauthorize the log shows succeeding lets release re-approve.
		{name: "deauthorize failed", entries: []Entry{
			withDeauth(entry(ActionIsolate, ModeApply, ResultIntent)),
			withSteps(withDeauth(entry(ActionIsolate, ModeApply, "error: step 1 failed")),
				StepDeauthorize, "error: 500", "set-tags=tag:quarantine", StepSkipped),
		}, wantTags: "tag:ci"},
		{name: "deauthorized then tags failed", entries: []Entry{
			withDeauth(entry(ActionIsolate, ModeApply, ResultIntent)),
			withSteps(withDeauth(entry(ActionIsolate, ModeApply, "error: step 2 failed")),
				StepDeauthorize, ResultOK, "set-tags=tag:quarantine", "error: 500"),
		}, wantTags: "tag:ci", wantDeath: true},
		{name: "interrupted after deauthorize intent", entries: []Entry{
			withDeauth(entry(ActionIsolate, ModeApply, ResultIntent)),
		}, wantTags: "tag:ci"},
		{name: "released", entries: []Entry{
			entry(ActionIsolate, ModeApply, ResultOK), entry(ActionRelease, ModeApply, ResultOK),
		}, wantNil: true},
		{name: "failed release keeps it open", entries: []Entry{
			entry(ActionIsolate, ModeApply, ResultOK), entry(ActionRelease, ModeApply, "error: 403"),
		}, wantTags: "tag:ci"},
		// A second cycle must not inherit the first cycle's tags.
		{name: "second cycle", entries: []Entry{
			withTags(entry(ActionIsolate, ModeApply, ResultOK)),
			entry(ActionRelease, ModeApply, ResultOK),
			withTags(entry(ActionIsolate, ModeApply, ResultOK), "tag:web"),
		}, wantTags: "tag:web"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLog(t)
			appendAll(t, l, tt.entries...)
			other := entry(ActionIsolate, ModeApply, ResultOK)
			other.DeviceID = "nOTHER"
			appendAll(t, l, other)
			got, err := OpenIsolation(l.Path(), "nKALI")
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("want none, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("want an open isolation")
			}
			if strings.Join(got.PreviousTags, ",") != tt.wantTags || got.Deauthorized != tt.wantDeath {
				t.Errorf("got %+v, want tags %q deauthorized %v", got, tt.wantTags, tt.wantDeath)
			}
		})
	}
	if got, err := OpenIsolation(filepath.Join(t.TempDir(), "none.jsonl"), "nKALI"); got != nil || err != nil {
		t.Errorf("missing log: %v, %v", got, err)
	}
}

func TestVerifySkipsBlankLines(t *testing.T) {
	l := newLog(t)
	appendAll(t, l, entry(ActionIsolate, ModeApply, ResultOK), entry(ActionIsolate, ModeApply, ResultOK))
	data, _ := os.ReadFile(l.Path())
	p := filepath.Join(t.TempDir(), "blank.jsonl")
	_ = os.WriteFile(p, []byte("\n"+strings.Replace(string(data), "\n", "\n\n", 1)), 0o600)
	if n, err := Verify(p); err != nil || n != 2 {
		t.Errorf("Verify = %d, %v", n, err)
	}
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	_ = os.WriteFile(empty, []byte("\n\n"), 0o600)
	if n, err := Verify(empty); err != nil || n != 0 {
		t.Errorf("empty: %d, %v", n, err)
	}
}

// Two Log values on one file stand in for two sentry processes: each append
// opens its own lock handle, so they contend exactly as processes would.
// Without the lock this forks the chain within a few lines.
func TestConcurrentAppendersKeepTheChain(t *testing.T) {
	a := newLog(t)
	b, err := Open(a.Path())
	if err != nil {
		t.Fatal(err)
	}
	const per = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, l := range []*Log{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < per; j++ {
				e := entry(ActionIsolate, ModeDryRun, ResultPlanned)
				e.Reason = fmt.Sprintf("writer %d entry %d", i, j)
				if err := l.Append(e); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if n, err := Verify(a.Path()); err != nil || n != 2*per {
		t.Fatalf("Verify = %d, %v; want %d entries and an intact chain", n, err, 2*per)
	}
}

// readLastLine must agree with splitting the whole file, including when the
// last line straddles the 64 KiB read chunks.
func TestReadLastLine(t *testing.T) {
	long := strings.Repeat("x", 70<<10)
	tests := []struct{ name, data, want string }{
		{"empty", "", ""},
		{"only newlines", "\n\n\n", ""},
		{"one line", `{"a":1}`, `{"a":1}`},
		{"one line newline", "{\"a\":1}\n", `{"a":1}`},
		{"two lines", "first\nsecond\n", "second"},
		{"trailing blank lines", "first\nsecond\n\n\n", "second"},
		{"long last line", "first\n" + long + "\n", long},
		{"long last line alone", long, long},
		{"newline on a chunk edge", strings.Repeat("y", 64<<10-1) + "\nlast\n", "last"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "log.jsonl")
			if err := os.WriteFile(p, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := readLastLine(p)
			if err != nil || string(got) != tt.want {
				t.Errorf("readLastLine = %d bytes %.20q, %v; want %d bytes %.20q", len(got), got, err, len(tt.want), tt.want)
			}
		})
	}
	if got, err := readLastLine(filepath.Join(t.TempDir(), "missing.jsonl")); got != nil || err != nil {
		t.Errorf("missing: %q, %v", got, err)
	}
}

// A line longer than any entry can be is refused, not buffered: by Verify,
// and by Append, which would otherwise read it to hash it.
func TestOverlongLineIsRefused(t *testing.T) {
	l := newLog(t)
	appendAll(t, l, entry(ActionIsolate, ModeApply, ResultOK))
	f, err := os.OpenFile(l.Path(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(bytes.Repeat([]byte("z"), maxLine+2))
	f.Close()
	if _, err := Verify(l.Path()); err == nil || !strings.Contains(err.Error(), "line 2: longer than") {
		t.Errorf("Verify error = %v", err)
	}
	if err := l.Append(entry(ActionIsolate, ModeApply, ResultOK)); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("Append error = %v", err)
	}
}
