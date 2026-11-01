package tsapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestParsePolicyDigestIgnoresFormattingOnly(t *testing.T) {
	a, err := ParsePolicy([]byte(`{"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"ip":["*"]}],"tagOwners":{"tag:quarantine":["autogroup:admin"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParsePolicy([]byte(`{
	  "tagOwners": { "tag:quarantine": ["autogroup:admin"] },
	  "grants": [ { "ip": ["*"], "dst": ["autogroup:member"], "src": ["autogroup:member"] } ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 != b.SHA256 || len(a.SHA256) != 64 {
		t.Errorf("same policy, different digests: %s %s", a.SHA256, b.SHA256)
	}
	c, _ := ParsePolicy([]byte(`{"grants":[{"src":["*"],"dst":["autogroup:member"],"ip":["*"]}],"tagOwners":{"tag:quarantine":["autogroup:admin"]}}`))
	if c.SHA256 == a.SHA256 {
		t.Error("a changed src did not change the digest")
	}
	if _, err := ParsePolicy([]byte(`["not", "an", "object"]`)); err == nil {
		t.Error("want an error for a non-object policy")
	}
}

func TestParsePolicyReadsEverySpellingOfASection(t *testing.T) {
	p, err := ParsePolicy([]byte(`{
	  "hosts": {"everything": "100.64.0.0/10"},
	  "ACLs": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
	  "acls": [{"action": "accept", "users": ["autogroup:member"], "ports": ["autogroup:member:*"]}],
	  "Grants": [{"src": "everything", "dst": ["tag:server"], "ip": ["22"]}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 3 {
		t.Fatalf("want 3 rules (both acls keys and the grant), got %+v", p.Rules)
	}
	var srcs []string
	for _, r := range p.Rules {
		srcs = append(srcs, r.Name()+"="+strings.Join(r.Src, ","))
	}
	got := strings.Join(srcs, " ")
	for _, want := range []string{"acls[0]=*", "acls[1]=autogroup:member", "grants[0]=everything"} {
		if !strings.Contains(got, want) {
			t.Errorf("rules %s lack %s", got, want)
		}
	}
	if p.Hosts["everything"] != "100.64.0.0/10" {
		t.Errorf("hosts = %v", p.Hosts)
	}
}

// scopedAPI grants OAuth tokens only for the scopes in allow, answering
// other scopes the way an OAuth server refuses one, and serves fixed
// control-plane responses.
type scopedAPI struct {
	allow  map[string]bool
	mu     sync.Mutex
	asked  []string
	bodies map[string]string
	status map[string]int
}

func (s *scopedAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		scope := r.PostForm.Get("scope")
		s.mu.Lock()
		s.asked = append(s.asked, scope)
		s.mu.Unlock()
		if !s.allow[scope] {
			http.Error(w, `{"error":"invalid_scope"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tskey-api-scoped-" + scope, "expires_in": 3600})
		return
	}
	if code := s.status[r.URL.Path]; code != 0 {
		http.Error(w, `{"message":"nope"}`, code)
		return
	}
	body, ok := s.bodies[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(body))
}

func TestEachControlReadAsksForItsOwnScope(t *testing.T) {
	api := &scopedAPI{
		allow:  map[string]bool{string(ScopePolicyRead): true},
		bodies: map[string]string{"/tailnet/-/acl": `{"acls":[]}`, "/tailnet/-/dns/nameservers": `{"dns":["1.1.1.1"]}`},
	}
	srv := httptest.NewServer(api)
	defer srv.Close()
	creds := Credentials{ClientID: "kCLIENT", ClientSecret: NewSecret("tskey-client-goodsecret")}
	ctx := context.Background()

	if _, err := New(creds, "-", ScopePolicyRead, Options{BaseURL: srv.URL}).Policy(ctx); err != nil {
		t.Fatalf("policy with its scope granted: %v", err)
	}
	_, err := New(creds, "-", ScopeDNSRead, Options{BaseURL: srv.URL}).DNS(ctx)
	if err == nil || !ScopeDenied(err) {
		t.Fatalf("DNS without dns:read: want a scope denial, got %v", err)
	}
	if strings.Contains(err.Error(), "goodsecret") {
		t.Errorf("secret leaked: %v", err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if !slices.Equal(api.asked, []string{"policy_file:read", "dns:read"}) {
		t.Errorf("scopes asked for %v", api.asked)
	}
}

func TestScopeDeniedOnlyForRefusals(t *testing.T) {
	api := &scopedAPI{status: map[string]int{
		"/tailnet/-/users": http.StatusForbidden, "/tailnet/-/acl": http.StatusInternalServerError,
		"/tailnet/-/keys": http.StatusUnauthorized,
	}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopeRead, Options{BaseURL: srv.URL})
	ctx := context.Background()
	if _, err := c.Users(ctx); !ScopeDenied(err) {
		t.Errorf("403: want denied, got %v", err)
	}
	if _, err := c.Policy(ctx); err == nil || ScopeDenied(err) {
		t.Errorf("500 is a failure, not a missing scope: %v", err)
	}
	// A 401 on an endpoint means the key itself is bad, not that it lacks
	// a scope; only the token exchange's refusals count as denials.
	if _, err := c.AuthKeys(ctx); err == nil || ScopeDenied(err) {
		t.Errorf("401 on an endpoint is not a scope denial: %v", err)
	}
	if _, err := c.DNS(ctx); err == nil || ScopeDenied(err) {
		t.Errorf("404 is not a scope denial: %v", err)
	}
	if ScopeDenied(nil) {
		t.Error("nil is not denied")
	}
}

func TestAuthKeysFetchesDetailsForBareIDs(t *testing.T) {
	api := &scopedAPI{bodies: map[string]string{
		"/tailnet/-/keys": `{"keys":[{"id":"kBARE"},{"id":"kFULL","keyType":"auth","created":"2026-10-01T00:00:00Z",
			"expires":"2026-12-30T00:00:00Z","revoked":"2026-10-05T00:00:00Z",
			"capabilities":{"devices":{"create":{"reusable":true,"preauthorized":true,"tags":["tag:ci"]}}}},
			{"id":"kAPI","keyType":"api","created":"2026-10-01T00:00:00Z"}]}`,
		"/tailnet/-/keys/kBARE": `{"id":"kBARE","keyType":"auth","created":"2026-10-02T00:00:00Z","expires":"2026-10-03T00:00:00Z",
			"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":true}}}}`,
	}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	keys, err := New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopeKeysRead, Options{BaseURL: srv.URL}).AuthKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(*keys) != 3 {
		t.Fatalf("keys = %+v", *keys)
	}
	byID := map[string]int{}
	for i, k := range *keys {
		byID[k.ID] = i
	}
	bare, full, tok := (*keys)[byID["kBARE"]], (*keys)[byID["kFULL"]], (*keys)[byID["kAPI"]]
	if bare.Created.IsZero() || !bare.Ephemeral || bare.Reusable || !bare.EnrolsDevices() {
		t.Errorf("bare key not filled in from its detail: %+v", bare)
	}
	if !full.Reusable || !full.Preauthorized || !full.Revoked || len(full.Tags) != 1 {
		t.Errorf("full key mapped wrongly: %+v", full)
	}
	if tok.EnrolsDevices() {
		t.Errorf("an API token does not enrol devices: %+v", tok)
	}
}

func TestDNSAndUsersMapping(t *testing.T) {
	api := &scopedAPI{bodies: map[string]string{
		"/tailnet/-/dns/nameservers": `{"dns":["1.1.1.1"]}`,
		"/tailnet/-/dns/split-dns":   `{"Corp.Example.":["10.0.0.53"],"gone.example":null}`,
		"/tailnet/-/users":           `{"users":[{"id":"u1","loginName":"alice@github","role":"Owner","type":"member","status":"active"}]}`,
	}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopeRead, Options{BaseURL: srv.URL})
	dns, err := c.DNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(dns.Nameservers) != 1 || len(dns.SplitDNS) != 1 || dns.SplitDNS["corp.example"][0] != "10.0.0.53" {
		t.Errorf("dns = %+v", dns)
	}
	users, err := c.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(*users) != 1 || (*users)[0].Role != "owner" || (*users)[0].LoginName != "alice@github" {
		t.Errorf("users = %+v", *users)
	}
}
