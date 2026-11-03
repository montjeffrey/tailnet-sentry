package tsapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// validateAPI answers POST /tailnet/-/acl/validate with a fixed status and
// body, and records what it was sent.
type validateAPI struct {
	status int
	body   string

	mu          sync.Mutex
	got         []string // request bodies
	contentType string
	asked       []string // scopes of token exchanges
}

func (v *validateAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		v.mu.Lock()
		v.asked = append(v.asked, r.PostForm.Get("scope"))
		v.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tskey-api-validatetoken", "expires_in": 3600})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/tailnet/-/acl/validate" {
		http.NotFound(w, r)
		return
	}
	b, _ := io.ReadAll(r.Body)
	v.mu.Lock()
	v.got = append(v.got, string(b))
	v.contentType = r.Header.Get("Content-Type")
	v.mu.Unlock()
	if v.status != 0 {
		w.WriteHeader(v.status)
	}
	_, _ = io.WriteString(w, v.body)
}

func TestValidatePolicy(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		want     []string
		wantErr  string
		denied   bool // ScopeDenied(err)
		noSecret bool
	}{
		{name: "empty body passes"},
		{name: "empty object passes", body: `{}`},
		{name: "no message passes", body: `{"data":[]}`},
		{name: "failed tests, one line each", body: `{"message":"test(s) failed","data":[` +
			`{"user":"100.64.0.1","errors":["address \"100.64.0.3:22\": want: Drop, got: Accept"]},` +
			`{"user":"tag:quarantine","errors":["address \"100.64.0.3:445\": want: Drop, got: Accept","x"]}]}`,
			want: []string{`100.64.0.1: address "100.64.0.3:22": want: Drop, got: Accept`,
				`tag:quarantine: address "100.64.0.3:445": want: Drop, got: Accept`, "tag:quarantine: x"}},
		{name: "warnings alone pass", body: `{"message":"warning(s) found","data":[{"user":"group:x","warnings":["not syncing"]}]}`},
		{name: "a message with no details fails as itself", body: `{"message":"line 3: unknown key \"grnts\""}`,
			want: []string{`line 3: unknown key "grnts"`}},
		{name: "a failure echoing the key is redacted", body: `{"message":"bad","data":[{"errors":["saw tskey-api-kTEST0000CNTRL-ThisIsNotARealKey"]}]}`,
			noSecret: true},
		{name: "401 is an error", status: 401, body: `{"message":"unauthorized"}`, wantErr: "401"},
		{name: "403 is a scope denial", status: 403, body: `{"message":"not allowed"}`, wantErr: "403", denied: true},
		{name: "500 is an error", status: 500, body: `oops`, wantErr: "500"},
		{name: "a body that is not JSON is an error", body: `<html>`, wantErr: "not a JSON object"},
		{name: "errors without a message still fail", body: `{"data":[{"errors":["x"]}]}`, want: []string{"x"}},
		{name: "a null body is an error", body: `null`, wantErr: "not a JSON object"},
		{name: "an array body is an error", body: `[]`, wantErr: "not a JSON object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &validateAPI{status: tc.status, body: tc.body}
			srv := httptest.NewServer(api)
			defer srv.Close()
			c := New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopePolicyRead, Options{BaseURL: srv.URL})
			got, err := c.ValidatePolicy(context.Background(), []byte(`{"grants":[]}`))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				if ScopeDenied(err) != tc.denied {
					t.Errorf("ScopeDenied = %v, want %v", ScopeDenied(err), tc.denied)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.noSecret {
				if len(got) != 1 || strings.Contains(got[0], "ThisIsNotARealKey") {
					t.Errorf("failures = %q, want one redacted line", got)
				}
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("failures = %q, want %q", got, tc.want)
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			if len(api.got) != 1 || api.got[0] != `{"grants":[]}` || api.contentType != "application/json" {
				t.Errorf("sent %q as %q", api.got, api.contentType)
			}
		})
	}
}

// The validate call reads the policy and nothing else: an OAuth client is
// asked for policy_file:read, never the write scope policy_file.
func TestValidatePolicyAsksOnlyForPolicyRead(t *testing.T) {
	api := &validateAPI{body: `{}`}
	srv := httptest.NewServer(api)
	defer srv.Close()
	creds := Credentials{ClientID: "kCLIENT", ClientSecret: NewSecret("tskey-client-goodsecret")}
	if _, err := New(creds, "-", ScopePolicyRead, Options{BaseURL: srv.URL}).ValidatePolicy(context.Background(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if !slices.Equal(api.asked, []string{"policy_file:read"}) {
		t.Errorf("scopes asked for %v, want [policy_file:read]", api.asked)
	}
}

func TestWithTestsReplacesThePolicysOwnTests(t *testing.T) {
	policy := []byte(`{"grants":[{"src":["100.64.0.1"],"dst":["100.64.0.3"],"ip":["22"]}],` +
		`"tests":[{"src":"100.64.0.1","accept":["100.64.0.3:22"]}],"Tests":[],"sshTests":[{"src":"x"}],"n":12345678901234567890}`)
	pinned := []byte(`[{"src":"100.64.0.3","deny":["100.64.0.1:22"]}]`)
	out, err := WithTests(policy, pinned)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	var tests []map[string]any
	if err := json.Unmarshal(got["tests"], &tests); err != nil || len(tests) != 1 || tests[0]["src"] != "100.64.0.3" {
		t.Errorf("tests = %s, want only sentry's %s", got["tests"], pinned)
	}
	if _, ok := got["Tests"]; ok {
		t.Error("a differently cased tests key survived")
	}
	if _, ok := got["sshTests"]; ok {
		t.Error("the policy's own sshTests survived")
	}
	if string(got["n"]) != "12345678901234567890" {
		t.Errorf("a large number was rewritten: %s", got["n"])
	}
	if !strings.Contains(string(got["grants"]), `"100.64.0.3"`) {
		t.Errorf("grants lost: %s", got["grants"])
	}

	if _, err := WithTests([]byte(`[]`), pinned); err == nil {
		t.Error("a policy that is not an object was accepted")
	}
	if _, err := WithTests(policy, []byte(`{}`)); err == nil {
		t.Error("tests that are not an array were accepted")
	}
}

func TestParsePolicyKeepsTheRawFile(t *testing.T) {
	raw := []byte(`{"grants":[]}`)
	p, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 'X' // the caller's buffer may be reused
	if string(p.Raw) != `{"grants":[]}` {
		t.Errorf("Raw = %q", p.Raw)
	}
}
