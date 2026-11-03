package tsapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/montjeffrey/tailnet-sentry/internal/inventory"
)

// The calls in this file read the tailnet's control-plane configuration:
// what an admin login can change without touching any device. Each needs a
// scope of its own (see the Scope constants); build the client with it.

func (c *Client) tailnetPath(rest string) string {
	return "/tailnet/" + url.PathEscape(c.tailnet) + rest
}

// Policy returns the tailnet policy file. Needs ScopePolicyRead.
func (c *Client) Policy(ctx context.Context) (*inventory.Policy, error) {
	// Accept: application/json (set by do) makes the API convert the HuJSON
	// file to plain JSON, comments and trailing commas removed.
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, c.tailnetPath("/acl"), nil, &raw); err != nil {
		return nil, err
	}
	return ParsePolicy(raw)
}

// ParsePolicy digests a policy file in JSON form and extracts its acls and
// grants. The digest is over a canonical re-encoding (sorted keys, no
// whitespace), so only a change in content changes it.
//
// The file is walked generically rather than decoded into a struct: Go's
// decoder matches keys case-insensitively and keeps only the last duplicate,
// so "ACLs" beside "acls" could otherwise hide a rule from the checks while
// Tailscale still applies it. Every key that folds to "acls", "grants" or
// "ssh" is read.
func ParsePolicy(raw []byte) (*inventory.Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("tailscale API: policy file is not JSON: %w", err)
	}
	top, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("tailscale API: policy file is not a JSON object")
	}
	canon, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	p := &inventory.Policy{SHA256: hex.EncodeToString(sum[:]), Raw: bytes.Clone(raw)}
	for _, v := range fold(top, "hosts") {
		hosts, _ := v.(map[string]any)
		for name, addr := range hosts {
			if a, ok := addr.(string); ok {
				if p.Hosts == nil {
					p.Hosts = map[string]string{}
				}
				p.Hosts[name] = a
			}
		}
	}
	for _, v := range fold(top, "ipsets") {
		sets, _ := v.(map[string]any)
		for name, entries := range sets {
			if p.IPSets == nil {
				p.IPSets = map[string][]string{}
			}
			p.IPSets[name] = append(p.IPSets[name], strs(entries)...)
		}
	}
	// Without either section Tailscale falls back to allowing everything.
	p.NoRules = len(fold(top, "acls")) == 0 && len(fold(top, "grants")) == 0
	for _, section := range []string{"acls", "grants", "ssh"} {
		i := 0
		for _, list := range fold(top, section) {
			entries, _ := list.([]any)
			for _, e := range entries {
				m, _ := e.(map[string]any)
				r := inventory.PolicyRule{Section: section, Index: i}
				i++
				srcKeys, dstKeys := fold(m, "src"), fold(m, "dst")
				// "users" and "ports" are the legacy names of an ACL's src
				// and dst; Tailscale still accepts them. In an ssh rule
				// "users" means local login names instead.
				if section == "acls" {
					srcKeys, dstKeys = append(srcKeys, fold(m, "users")...), append(dstKeys, fold(m, "ports")...)
				}
				for _, v := range srcKeys {
					r.Src = append(r.Src, strs(v)...)
				}
				for _, v := range dstKeys {
					r.Dst = append(r.Dst, strs(v)...)
				}
				p.Rules = append(p.Rules, r)
			}
		}
	}
	return p, nil
}

// maxValidateBytes bounds the validate response, whose size grows with the
// number of failing tests.
const maxValidateBytes = 1 << 20

// ValidatePolicy asks Tailscale's own evaluator to parse policy, a whole
// policy file in JSON form, and run the tests in it. Nothing is saved.
// Needs ScopePolicyRead.
//
// It returns one line per failed test, or nil when the file parsed and every
// test passed. The API answers 200 either way and puts any problem in the
// body; a non-2xx status, or a body that cannot be read, is an error.
func (c *Client) ValidatePolicy(ctx context.Context, policy []byte) ([]string, error) {
	path := c.tailnetPath("/acl/validate")
	resp, token, err := c.request(ctx, http.MethodPost, path, policy)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxValidateBytes))
	if err != nil {
		return nil, c.wrap(http.MethodPost, path, err)
	}
	// An empty body, {}, or a body without a message means everything passed.
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var out struct {
		Message string `json:"message"`
		Data    []struct {
			User     string   `json:"user"`
			Errors   []string `json:"errors"`
			Warnings []string `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("tailscale API: POST %s: response is not JSON: %w", path, err)
	}
	if out.Message == "" {
		return nil, nil
	}
	var failures []string
	warned := false
	for _, d := range out.Data {
		for _, e := range d.Errors {
			line := e
			if d.User != "" {
				line = d.User + ": " + e
			}
			failures = append(failures, Redact(line, token, c.creds.APIKey, c.creds.ClientSecret))
		}
		warned = warned || len(d.Warnings) > 0
	}
	// Warnings alone (a group not syncing from SCIM, say) are not a failure.
	if len(failures) == 0 && !warned {
		failures = append(failures, Redact(out.Message, token, c.creds.APIKey, c.creds.ClientSecret))
	}
	return failures, nil
}

// WithTests returns policy, a policy file in JSON form, with its "tests"
// replaced by tests, a JSON array. The policy's own tests are dropped (every
// key that folds to "tests"), so that a failure can only be one of sentry's,
// and an edit that deletes or weakens the policy's tests changes nothing.
func WithTests(policy, tests []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(policy))
	dec.UseNumber()
	var top map[string]any
	if err := dec.Decode(&top); err != nil || top == nil {
		return nil, errors.New("policy file is not a JSON object")
	}
	var list []any
	if err := json.Unmarshal(tests, &list); err != nil {
		return nil, errors.New("pinned tests are not a JSON array")
	}
	for k := range top {
		if strings.EqualFold(k, "tests") {
			delete(top, k)
		}
	}
	top["tests"] = list
	return json.Marshal(top)
}

// fold returns the values of every key in m equal to name under case folding,
// in a stable order.
func fold(m map[string]any, name string) []any {
	var keys []string
	for k := range m {
		if strings.EqualFold(k, name) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = m[k]
	}
	return out
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

type apiKey struct {
	ID           string          `json:"id"`
	KeyType      string          `json:"keyType"`
	Description  string          `json:"description"`
	Created      apiTime         `json:"created"`
	Expires      apiTime         `json:"expires"`
	Revoked      json.RawMessage `json:"revoked"` // a timestamp once revoked
	Invalid      bool            `json:"invalid"`
	Capabilities *struct {
		Devices struct {
			Create struct {
				Reusable      bool     `json:"reusable"`
				Ephemeral     bool     `json:"ephemeral"`
				Preauthorized bool     `json:"preauthorized"`
				Tags          []string `json:"tags"`
			} `json:"create"`
		} `json:"devices"`
	} `json:"capabilities"`
}

func (k apiKey) toAuthKey() inventory.AuthKey {
	out := inventory.AuthKey{
		ID: k.ID, KeyType: k.KeyType, Description: k.Description,
		Created: k.Created.Time, Expires: k.Expires.Time, Invalid: k.Invalid,
	}
	switch strings.TrimSpace(string(k.Revoked)) {
	case "", "null", `""`, "false":
	default:
		out.Revoked = true
	}
	if k.Capabilities != nil {
		cr := k.Capabilities.Devices.Create
		out.Reusable, out.Ephemeral, out.Preauthorized, out.Tags = cr.Reusable, cr.Ephemeral, cr.Preauthorized, cr.Tags
	}
	return out
}

// maxKeyDetails bounds the per-key requests made for a list that carries
// IDs only, so a huge list cannot turn one scan into thousands of calls.
const maxKeyDetails = 200

// AuthKeys lists the tailnet's keys, every user's. Needs ScopeKeysRead.
// Older API versions list IDs only; each such key is then fetched on its own.
func (c *Client) AuthKeys(ctx context.Context) (*[]inventory.AuthKey, error) {
	var out struct {
		Keys []apiKey `json:"keys"`
	}
	if err := c.do(ctx, http.MethodGet, c.tailnetPath("/keys?all=true"), nil, &out); err != nil {
		return nil, err
	}
	keys := []inventory.AuthKey{}
	fetched := 0
	for _, k := range out.Keys {
		if k.ID == "" {
			return nil, errors.New("tailscale API: key list has a key with no ID")
		}
		if k.Created.IsZero() && k.Capabilities == nil {
			if fetched++; fetched > maxKeyDetails {
				return nil, fmt.Errorf("tailscale API: key list has more than %d keys without details", maxKeyDetails)
			}
			var full apiKey
			if err := c.do(ctx, http.MethodGet, c.tailnetPath("/keys/"+url.PathEscape(k.ID)), nil, &full); err != nil {
				return nil, err
			}
			full.ID = k.ID
			k = full
		}
		keys = append(keys, k.toAuthKey())
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	return &keys, nil
}

// DNS returns the global nameservers and split DNS. Needs ScopeDNSRead.
func (c *Client) DNS(ctx context.Context) (*inventory.DNS, error) {
	var ns struct {
		DNS []string `json:"dns"`
	}
	if err := c.do(ctx, http.MethodGet, c.tailnetPath("/dns/nameservers"), nil, &ns); err != nil {
		return nil, err
	}
	var split map[string][]string
	if err := c.do(ctx, http.MethodGet, c.tailnetPath("/dns/split-dns"), nil, &split); err != nil {
		return nil, err
	}
	out := &inventory.DNS{Nameservers: ns.DNS}
	if out.Nameservers == nil {
		out.Nameservers = []string{}
	}
	for domain, servers := range split {
		if len(servers) == 0 { // a domain mapped to null has no split DNS
			continue
		}
		if out.SplitDNS == nil {
			out.SplitDNS = map[string][]string{}
		}
		d := strings.ToLower(strings.TrimSuffix(domain, "."))
		out.SplitDNS[d] = append(out.SplitDNS[d], servers...)
	}
	return out, nil
}

// Users lists every user of the tailnet, members and shared-in alike.
// Needs ScopeUsersRead.
func (c *Client) Users(ctx context.Context) (*[]inventory.User, error) {
	var out struct {
		Users []struct {
			ID        string `json:"id"`
			LoginName string `json:"loginName"`
			Role      string `json:"role"`
			Type      string `json:"type"`
			Status    string `json:"status"`
		} `json:"users"`
	}
	if err := c.do(ctx, http.MethodGet, c.tailnetPath("/users"), nil, &out); err != nil {
		return nil, err
	}
	users := []inventory.User{}
	for _, u := range out.Users {
		if u.ID == "" {
			return nil, errors.New("tailscale API: user list has a user with no ID")
		}
		users = append(users, inventory.User{ID: u.ID, LoginName: u.LoginName, Role: strings.ToLower(u.Role), Type: u.Type, Status: u.Status})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return &users, nil
}
