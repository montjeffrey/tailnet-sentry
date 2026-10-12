// Package tsapi is a minimal client for the parts of the Tailscale API that
// tailnet-sentry needs: listing devices, setting a device's tags and
// (de)authorizing a device.
//
// It is written against net/http rather than Tailscale's Go client so the
// binary has no third-party dependencies to audit, and so every request it
// can make is visible in this one file.
//
// Field names follow the published OpenAPI spec at
// https://api.tailscale.com/api/v2?outputOpenapiSchema=true.
package tsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// DefaultBaseURL is the only API endpoint the CLI ever talks to. It is not
// configurable from flags or the environment: a setting that redirected API
// calls would also redirect the credential that authenticates them.
const DefaultBaseURL = "https://api.tailscale.com/api/v2"

// Scope is an OAuth scope requested when exchanging client credentials.
type Scope string

const (
	// ScopeRead lists devices. It is all that scan and baseline need.
	ScopeRead Scope = "devices:core:read"
	// ScopeWrite also sets tags and authorization. Only isolate and release
	// ask for it.
	ScopeWrite Scope = "devices:core"
)

const (
	maxBodyBytes  = 32 << 20 // a device list for a large tailnet, with room to spare
	maxErrorBytes = 4 << 10
)

// Options exist for tests, which point the client at an httptest server.
type Options struct {
	BaseURL    string
	HTTPClient *http.Client
	UserAgent  string
}

// Client calls the Tailscale API for one tailnet.
type Client struct {
	base    string
	tailnet string
	creds   Credentials
	scope   Scope
	http    *http.Client
	agent   string

	mu       sync.Mutex
	token    Secret
	tokenExp time.Time
}

// New returns a client for tailnet ("-" means the credential's own tailnet)
// that requests scope when it authenticates with an OAuth client. An API
// access token cannot be narrowed, so scope is ignored for one.
func New(creds Credentials, tailnet string, scope Scope, opt Options) *Client {
	if tailnet == "" {
		tailnet = "-"
	}
	base := opt.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	hc := opt.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// Never follow a redirect. The API has no reason to send one, and
	// following it would replay the request (and, to the same host, the
	// Authorization header) to wherever it pointed.
	clone := *hc
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	agent := opt.UserAgent
	if agent == "" {
		agent = "tailnet-sentry"
	}
	return &Client{
		base:    strings.TrimSuffix(base, "/"),
		tailnet: tailnet,
		creds:   creds,
		scope:   scope,
		http:    &clone,
		agent:   agent,
	}
}

// apiTime accepts the empty string the API sends for unknown dates (for
// example "created" on an external device) as the zero time.
type apiTime struct{ time.Time }

func (t *apiTime) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}

// apiDevice mirrors the Device schema. Only fields sentry uses are decoded;
// advertisedRoutes, enabledRoutes and multipleConnections are present only
// with ?fields=all.
type apiDevice struct {
	ID                  string   `json:"id"`
	NodeID              string   `json:"nodeId"`
	Addresses           []string `json:"addresses"`
	User                string   `json:"user"`
	Name                string   `json:"name"`
	Hostname            string   `json:"hostname"`
	ClientVersion       string   `json:"clientVersion"`
	UpdateAvailable     bool     `json:"updateAvailable"`
	OS                  string   `json:"os"`
	ConnectedToControl  bool     `json:"connectedToControl"`
	LastSeen            apiTime  `json:"lastSeen"`
	KeyExpiryDisabled   bool     `json:"keyExpiryDisabled"`
	Expires             apiTime  `json:"expires"`
	Authorized          bool     `json:"authorized"`
	IsExternal          bool     `json:"isExternal"`
	MultipleConnections bool     `json:"multipleConnections"`
	Tags                []string `json:"tags"`
	AdvertisedRoutes    []string `json:"advertisedRoutes"`
	EnabledRoutes       []string `json:"enabledRoutes"`
}

func (d apiDevice) toDevice() inventory.Device {
	id := d.NodeID
	if id == "" {
		id = d.ID
	}
	return inventory.Device{
		ID:                  id,
		Name:                strings.TrimSuffix(d.Name, "."),
		Hostname:            d.Hostname,
		Owner:               d.User,
		OS:                  d.OS,
		Tags:                d.Tags,
		Addresses:           d.Addresses,
		ClientVersion:       d.ClientVersion,
		UpdateAvailable:     d.UpdateAvailable,
		KeyExpiryDisabled:   d.KeyExpiryDisabled,
		Expires:             d.Expires.Time,
		Authorized:          d.Authorized,
		External:            d.IsExternal,
		AdvertisedRoutes:    d.AdvertisedRoutes,
		EnabledRoutes:       d.EnabledRoutes,
		Online:              d.ConnectedToControl,
		LastSeen:            d.LastSeen.Time,
		MultipleConnections: d.MultipleConnections,
	}
}

// ListDevices returns every device in the tailnet, with all fields.
func (c *Client) ListDevices(ctx context.Context) (inventory.Inventory, error) {
	path := "/tailnet/" + url.PathEscape(c.tailnet) + "/devices?fields=all"
	var out struct {
		Devices []apiDevice `json:"devices"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return inventory.Inventory{}, err
	}
	inv := inventory.Inventory{Source: inventory.SourceAPI, Taken: time.Now().UTC()}
	for _, d := range out.Devices {
		dev := d.toDevice()
		if dev.ID == "" {
			return inventory.Inventory{}, errors.New("tailscale API returned a device with no ID")
		}
		inv.Devices = append(inv.Devices, dev)
	}
	inv.Sort()
	return inv, nil
}

// SetTags replaces the device's tags with exactly tags.
func (c *Client) SetTags(ctx context.Context, deviceID string, tags []string) error {
	if tags == nil {
		tags = []string{}
	}
	return c.do(ctx, http.MethodPost, "/device/"+url.PathEscape(deviceID)+"/tags",
		map[string]any{"tags": tags}, nil)
}

// SetAuthorized authorizes or deauthorizes the device.
func (c *Client) SetAuthorized(ctx context.Context, deviceID string, authorized bool) error {
	return c.do(ctx, http.MethodPost, "/device/"+url.PathEscape(deviceID)+"/authorized",
		map[string]any{"authorized": authorized}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return c.wrap(method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == http.StatusUnauthorized && c.creds.IsOAuth() {
			c.dropToken()
		}
		return c.statusError(method, path, resp, token)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out); err != nil {
		return fmt.Errorf("tailscale API: %s %s: decode response: %w", method, trimQuery(path), err)
	}
	return nil
}

// accessToken returns the bearer token: the API key itself, or a cached OAuth
// token that is refreshed a minute before it expires.
func (c *Client) accessToken(ctx context.Context) (Secret, error) {
	if !c.creds.IsOAuth() {
		if c.creds.APIKey.Empty() {
			return Secret{}, ErrNoCredentials
		}
		return c.creds.APIKey, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.token.Empty() && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	form := url.Values{
		"client_id":     {c.creds.ClientID},
		"client_secret": {c.creds.ClientSecret.Reveal()},
		"grant_type":    {"client_credentials"},
	}
	if c.scope != "" {
		form.Set("scope", string(c.scope))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Secret{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	resp, err := c.http.Do(req)
	if err != nil {
		return Secret{}, c.wrap(http.MethodPost, "/oauth/token", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Secret{}, c.statusError(http.MethodPost, "/oauth/token", resp, Secret{})
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBytes)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return Secret{}, errors.New("tailscale API: POST /oauth/token: no access token in response")
	}
	// Refresh a minute early, or halfway through a lifetime shorter than two
	// minutes, so a request never goes out with a token about to expire.
	life := time.Duration(tok.ExpiresIn) * time.Second
	if life <= 0 {
		life = time.Hour
	}
	c.token = NewSecret(tok.AccessToken)
	c.tokenExp = time.Now().Add(life - min(time.Minute, life/2))
	return c.token, nil
}

// dropToken forgets a cached OAuth token the API has rejected, so the next
// call exchanges the client credentials again instead of reusing it.
func (c *Client) dropToken() {
	c.mu.Lock()
	c.token, c.tokenExp = Secret{}, time.Time{}
	c.mu.Unlock()
}

// statusError builds an error from a non-2xx response. The API's message is
// kept, because "tag:quarantine is not owned by ..." is exactly what the
// operator needs, but it is redacted first in case it echoes a credential.
func (c *Client) statusError(method, path string, resp *http.Response, token Secret) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
	var apiErr struct {
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &apiErr) == nil && apiErr.Message != "" {
		msg = apiErr.Message
	}
	msg = Redact(msg, token, c.creds.APIKey, c.creds.ClientSecret)
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	hint := ""
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		hint = " (check the credential is valid and not expired)"
	case http.StatusForbidden:
		hint = " (the credential lacks the scope or tag ownership this needs)"
	}
	if msg != "" {
		msg = ": " + msg
	}
	return fmt.Errorf("tailscale API: %s %s: %s%s%s", method, trimQuery(path), resp.Status, msg, hint)
}

// wrap redacts transport errors, whose text includes the request URL.
func (c *Client) wrap(method, path string, err error) error {
	return fmt.Errorf("tailscale API: %s %s: %s", method, trimQuery(path),
		Redact(err.Error(), c.creds.APIKey, c.creds.ClientSecret))
}

func trimQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}
