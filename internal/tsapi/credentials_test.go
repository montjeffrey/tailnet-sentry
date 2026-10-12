package tsapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const fakeKey = "tskey-api-kFAKE0000CNTRL-NotARealSecretValue0000"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestFromEnv(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		wantOAuth bool
		wantErr   bool
	}{
		{"none", nil, false, true},
		{"api key", map[string]string{EnvAPIKey: fakeKey}, false, false},
		{"oauth", map[string]string{EnvOAuthClientID: "kID", EnvOAuthClientSecret: "tskey-client-x"}, true, false},
		{"oauth wins over key", map[string]string{EnvAPIKey: fakeKey, EnvOAuthClientID: "kID", EnvOAuthClientSecret: "s"}, true, false},
		{"half an oauth client", map[string]string{EnvOAuthClientID: "kID"}, false, true},
		{"whitespace only", map[string]string{EnvAPIKey: "  "}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := FromEnv(envOf(tt.env))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && c.IsOAuth() != tt.wantOAuth {
				t.Errorf("IsOAuth = %v, want %v", c.IsOAuth(), tt.wantOAuth)
			}
		})
	}
}

// A credential must not escape through any formatting or encoding path.
func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret(fakeKey)
	c := Credentials{APIKey: s, ClientSecret: s}
	var outs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		outs = append(outs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, c))
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(b), fmt.Sprint(s), s.String())
	for _, o := range outs {
		if strings.Contains(o, "NotARealSecretValue") {
			t.Errorf("secret leaked: %s", o)
		}
	}
	if s.Reveal() != fakeKey {
		t.Error("Reveal must return the value")
	}
}

func TestRedact(t *testing.T) {
	custom := NewSecret("hunter2-custom-secret")
	tests := []struct{ in, want string }{
		{"bad token " + fakeKey + " rejected", "bad token [redacted] rejected"},
		{"other key tskey-auth-abc123-DEF was echoed", "other key [redacted] was echoed"},
		{"mentions hunter2-custom-secret here", "mentions [redacted] here"},
		{"nothing secret", "nothing secret"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in, custom); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
