package tsapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI is an httptest stand-in for api.tailscale.com. It serves the
// recorded device list and records every write, so tests can assert exactly
// what the client sent.
type fakeAPI struct {
	t       *testing.T
	devices []byte
	writes  []string   // "METHOD path body"
	scopes  []string   // scope of each token exchange
	mu      sync.Mutex // the handler runs on the server's goroutines
	tokens  atomic.Int32
	status  int    // forced status for every request, when non-zero
	body    string // body sent with a forced status
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	t.Helper()
	b, err := os.ReadFile("testdata/devices.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPI{t: t, devices: b}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth/token" {
		_ = r.ParseForm()
		if r.PostForm.Get("client_secret") != "tskey-client-goodsecret" || r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"message":"invalid client"}`, http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		f.scopes = append(f.scopes, r.PostForm.Get("scope"))
		f.mu.Unlock()
		n := f.tokens.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tskey-api-oauthtoken" + string(rune('0'+n)),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.PostForm.Get("scope"),
		})
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer tskey-") {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	status, body := f.status, f.body
	f.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/tailnet/") && strings.HasSuffix(r.URL.Path, "/devices"):
		if r.URL.Query().Get("fields") != "all" {
			f.t.Errorf("device list requested without fields=all: %s", r.URL)
		}
		_, _ = w.Write(f.devices)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/device/"):
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.writes = append(f.writes, r.Method+" "+r.URL.EscapedPath()+" "+strings.TrimSpace(string(b)))
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func keyClient(srv *httptest.Server) *Client {
	return New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopeRead, Options{BaseURL: srv.URL})
}

func TestListDevicesMapsEveryField(t *testing.T) {
	_, srv := newFakeAPI(t)
	inv, err := keyClient(srv).ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Source != "api" || len(inv.Devices) != 4 {
		t.Fatalf("got source %q with %d devices", inv.Source, len(inv.Devices))
	}
	byID := map[string]int{}
	for i, d := range inv.Devices {
		byID[d.ID] = i
	}
	nas := inv.Devices[byID["nNASCNTRL"]]
	if nas.Owner != "alice@github" || nas.OS != "linux" || !nas.KeyExpiryDisabled ||
		len(nas.Tags) != 1 || nas.Tags[0] != "tag:server" ||
		len(nas.AdvertisedRoutes) != 1 || nas.AdvertisedRoutes[0] != "192.168.1.0/24" || !nas.Online {
		t.Errorf("nas mapped wrongly: %+v", nas)
	}
	laptop := inv.Devices[byID["nLAPTOPCNTRL"]]
	if !laptop.UpdateAvailable || laptop.Online || laptop.LastSeen.IsZero() ||
		!laptop.Expires.Equal(time.Date(2026, 12, 1, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("laptop mapped wrongly: %+v", laptop)
	}
	shared := inv.Devices[byID["nSHAREDCNTRL"]]
	if !shared.External || !shared.MultipleConnections {
		t.Errorf("external device mapped wrongly: %+v", shared)
	}
	// Sorted by short name for stable output.
	if inv.Devices[0].ShortName() != "bobs-box" {
		t.Errorf("not sorted: first is %s", inv.Devices[0].ShortName())
	}
}

func TestListDevicesEscapesTailnet(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_, _ = io.WriteString(w, `{"devices":[]}`)
	}))
	defer srv.Close()
	c := New(Credentials{APIKey: NewSecret(fakeKey)}, "../device/x", ScopeRead, Options{BaseURL: srv.URL})
	if _, err := c.ListDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got != "/tailnet/..%2Fdevice%2Fx/devices" {
		t.Errorf("tailnet not path-escaped: %s", got)
	}
}

func TestSetTagsAndAuthorizedBodies(t *testing.T) {
	f, srv := newFakeAPI(t)
	c := keyClient(srv)
	ctx := context.Background()
	if err := c.SetTags(ctx, "nLAPTOPCNTRL", []string{"tag:quarantine"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAuthorized(ctx, "nLAPTOPCNTRL", false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTags(ctx, "n/../../x", nil); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`POST /device/nLAPTOPCNTRL/tags {"tags":["tag:quarantine"]}`,
		`POST /device/nLAPTOPCNTRL/authorized {"authorized":false}`,
		`POST /device/n%2F..%2F..%2Fx/tags {"tags":[]}`,
	}
	if strings.Join(f.writes, "\n") != strings.Join(want, "\n") {
		t.Errorf("writes:\n%s\nwant:\n%s", strings.Join(f.writes, "\n"), strings.Join(want, "\n"))
	}
}

func TestOAuthExchangesAndCachesScopedToken(t *testing.T) {
	f, srv := newFakeAPI(t)
	creds := Credentials{ClientID: "kCLIENT", ClientSecret: NewSecret("tskey-client-goodsecret")}
	c := New(creds, "-", ScopeRead, Options{BaseURL: srv.URL})
	for i := 0; i < 3; i++ {
		if _, err := c.ListDevices(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens.Load() != 1 {
		t.Errorf("token exchanged %d times, want 1 (cached)", f.tokens.Load())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) != 1 || f.scopes[0] != "devices:core:read" {
		t.Errorf("requested scopes %v, want [devices:core:read]", f.scopes)
	}
}

func TestOAuthBadSecretIsRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// A hostile or buggy server echoing the secret back.
		http.Error(w, `{"message":"bad secret `+r.PostForm.Get("client_secret")+`"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	creds := Credentials{ClientID: "kCLIENT", ClientSecret: NewSecret("plain-secret-without-prefix")}
	_, err := New(creds, "-", ScopeRead, Options{BaseURL: srv.URL}).ListDevices(context.Background())
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "plain-secret-without-prefix") {
		t.Errorf("secret leaked in error: %v", err)
	}
}

func TestErrorsNeverContainTheKey(t *testing.T) {
	f, srv := newFakeAPI(t)
	f.status = http.StatusForbidden
	f.body = `{"message":"token ` + fakeKey + ` may not set tag:quarantine"}`
	err := keyClient(srv).SetTags(context.Background(), "nX", []string{"tag:quarantine"})
	if err == nil {
		t.Fatal("want error")
	}
	msg := err.Error()
	if strings.Contains(msg, "NotARealSecretValue") {
		t.Errorf("key leaked: %s", msg)
	}
	if !strings.Contains(msg, "403") || !strings.Contains(msg, "may not set tag:quarantine") || !strings.Contains(msg, "tag ownership") {
		t.Errorf("error lost useful detail: %s", msg)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := keyClient(srv).ListDevices(context.Background())
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Errorf("want a 307 error, got %v", err)
	}
	if leaked.Load() {
		t.Error("client followed the redirect")
	}
}

// leakyTransport fails every request with an error that quotes the
// Authorization header, as a misbehaving proxy or a verbose TLS error might.
type leakyTransport struct{}

func (leakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("proxy rejected request with " + r.Header.Get("Authorization"))
}

func TestTransportErrorIsRedacted(t *testing.T) {
	c := New(Credentials{APIKey: NewSecret(fakeKey)}, "-", ScopeRead,
		Options{BaseURL: "http://api.invalid", HTTPClient: &http.Client{Transport: leakyTransport{}}})
	_, err := c.ListDevices(context.Background())
	if err == nil || !strings.Contains(err.Error(), "proxy rejected request with Bearer [redacted]") {
		t.Fatalf("want a redacted transport error, got %v", err)
	}
	if strings.Contains(err.Error(), "NotARealSecretValue") {
		t.Errorf("key leaked: %v", err)
	}
}

func TestRejectedOAuthTokenIsDropped(t *testing.T) {
	f, srv := newFakeAPI(t)
	creds := Credentials{ClientID: "kCLIENT", ClientSecret: NewSecret("tskey-client-goodsecret")}
	c := New(creds, "-", ScopeRead, Options{BaseURL: srv.URL})
	if _, err := c.ListDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.status, f.body = http.StatusUnauthorized, `{"message":"token revoked"}`
	f.mu.Unlock()
	if _, err := c.ListDevices(context.Background()); err == nil {
		t.Fatal("want 401")
	}
	f.mu.Lock()
	f.status = 0
	f.mu.Unlock()
	if _, err := c.ListDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.tokens.Load(); n != 2 {
		t.Errorf("token exchanged %d times, want 2 (re-exchanged after the 401)", n)
	}
}

func TestDefaultBaseURLIsTailscale(t *testing.T) {
	u, err := url.Parse(DefaultBaseURL)
	if err != nil || u.Scheme != "https" || u.Host != "api.tailscale.com" {
		t.Errorf("DefaultBaseURL = %s", DefaultBaseURL)
	}
	c := New(Credentials{}, "", ScopeRead, Options{})
	if c.base != DefaultBaseURL || c.tailnet != "-" {
		t.Errorf("defaults: base %s tailnet %s", c.base, c.tailnet)
	}
}
