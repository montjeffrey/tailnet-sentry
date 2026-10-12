package report

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://hooks.example.com/services/T000/B000/XXXX", true},
		{"http://127.0.0.1:9000/hook", true},
		{"http://localhost/hook", true},
		{"http://[::1]/hook", true},
		{"http://hooks.example.com/hook", false},
		{"ftp://example.com/x", false},
		{"/relative", false},
		{"not a url", false},
	}
	for _, tt := range tests {
		if _, err := ValidateWebhookURL(tt.url); (err == nil) != tt.ok {
			t.Errorf("ValidateWebhookURL(%q) err = %v, want ok=%v", tt.url, err, tt.ok)
		}
	}
}

func TestPostWebhook(t *testing.T) {
	var got webhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad request %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	}))
	defer srv.Close()
	if err := PostWebhook(context.Background(), srv.Client(), srv.URL+"/hook", sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Text, "tailnet-sentry: 3 findings") || len(got.Findings) != 3 || got.Summary.Anomalous != 1 {
		t.Errorf("payload = %+v", got)
	}
}

func TestPostWebhookErrorsHideThePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	err := PostWebhook(context.Background(), srv.Client(), srv.URL+"/services/SECRET-TOKEN-PATH", sample())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want 403, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET-TOKEN-PATH") {
		t.Errorf("webhook path leaked: %v", err)
	}
	err = PostWebhook(context.Background(), nil, "http://127.0.0.1:1/services/SECRET-TOKEN-PATH", sample())
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN-PATH") {
		t.Errorf("transport error leaked path or succeeded: %v", err)
	}
}

func TestPostWebhookDoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if err := PostWebhook(context.Background(), srv.Client(), srv.URL, sample()); err == nil {
		t.Error("a redirect must be an error")
	}
	if hit.Load() {
		t.Error("redirect was followed")
	}
}
