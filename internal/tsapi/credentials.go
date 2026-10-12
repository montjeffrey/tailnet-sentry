package tsapi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Environment variables that hold credentials. They are the only place
// tailnet-sentry reads a credential from: there is deliberately no flag, so a
// secret never lands in shell history, `ps` output or a scheduler's stored
// command line.
const (
	EnvAPIKey            = "TS_API_KEY"
	EnvOAuthClientID     = "TS_OAUTH_CLIENT_ID"
	EnvOAuthClientSecret = "TS_OAUTH_CLIENT_SECRET"
)

// CredentialEnv lists every variable above, so callers can keep them out of
// child processes.
var CredentialEnv = []string{EnvAPIKey, EnvOAuthClientID, EnvOAuthClientSecret}

// ErrNoCredentials means none of the credential variables is set.
var ErrNoCredentials = errors.New("no Tailscale API credentials: set " + EnvAPIKey +
	", or " + EnvOAuthClientID + " and " + EnvOAuthClientSecret)

// Secret holds a credential. Every way Go has of printing or encoding it
// yields a placeholder, so a stray log line, %v, %#v or json.Marshal cannot
// leak it. Only Reveal returns the value, and only the HTTP layer calls it.
type Secret struct{ v string }

const redacted = "[redacted]"

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the raw value. Call it only to build a request.
func (s Secret) Reveal() string { return s.v }

// Empty reports whether no value is held.
func (s Secret) Empty() bool { return s.v == "" }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }

// Credentials are what the client authenticates with: either an API access
// token, or an OAuth client that is exchanged for short-lived tokens.
type Credentials struct {
	APIKey       Secret
	ClientID     string
	ClientSecret Secret
}

// IsOAuth reports whether the credentials are an OAuth client.
func (c Credentials) IsOAuth() bool { return !c.ClientSecret.Empty() }

// FromEnv reads credentials through getenv (os.Getenv in production). An
// OAuth client wins over an API key when both are set, because its tokens
// can be scoped and expire within the hour.
func FromEnv(getenv func(string) string) (Credentials, error) {
	id := strings.TrimSpace(getenv(EnvOAuthClientID))
	secret := strings.TrimSpace(getenv(EnvOAuthClientSecret))
	key := strings.TrimSpace(getenv(EnvAPIKey))
	switch {
	case id != "" && secret != "":
		return Credentials{ClientID: id, ClientSecret: NewSecret(secret)}, nil
	case id != "" || secret != "":
		return Credentials{}, errors.New("set both " + EnvOAuthClientID + " and " + EnvOAuthClientSecret)
	case key != "":
		return Credentials{APIKey: NewSecret(key)}, nil
	}
	return Credentials{}, ErrNoCredentials
}

// HasCredentials reports whether getenv holds any credential variable,
// without validating it.
func HasCredentials(getenv func(string) string) bool {
	for _, k := range CredentialEnv {
		if strings.TrimSpace(getenv(k)) != "" {
			return true
		}
	}
	return false
}

// tokenPattern matches every Tailscale key format (tskey-api-, tskey-client-,
// tskey-auth-, ...), so a token the server echoes back is scrubbed even if it
// is not one this process holds.
var tokenPattern = regexp.MustCompile(`tskey-[A-Za-z0-9_-]+`)

// Redact removes every given secret, and anything shaped like a Tailscale
// key, from s. Error text that came from the network passes through here
// before it can reach a terminal, a log or the audit file.
func Redact(s string, secrets ...Secret) string {
	for _, sec := range secrets {
		if v := sec.Reveal(); len(v) >= 4 {
			s = strings.ReplaceAll(s, v, redacted)
		}
	}
	return tokenPattern.ReplaceAllString(s, redacted)
}
