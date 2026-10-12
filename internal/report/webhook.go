package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// webhookPayload is the report plus a "text" line, which Slack, Mattermost
// and most chat webhooks display as the message.
type webhookPayload struct {
	Text string `json:"text"`
	Report
}

// ValidateWebhookURL accepts https URLs, and http only to a loopback host
// (a local relay). Findings name devices and owners, so they should not
// cross a network in clear text.
func ValidateWebhookURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("webhook: not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return u, nil
		}
		return nil, fmt.Errorf("webhook: plain http is allowed only to localhost, not %s", host)
	}
	return nil, fmt.Errorf("webhook: unsupported scheme %q", u.Scheme)
}

// PostWebhook sends the report to rawURL. Redirects are not followed, and
// errors name only the host: webhook URLs often embed their own secret in
// the path (Slack's do), so the full URL is never printed.
func PostWebhook(ctx context.Context, hc *http.Client, rawURL string, r Report) error {
	u, err := ValidateWebhookURL(rawURL)
	if err != nil {
		return err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	clone := *hc
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	body, err := json.Marshal(webhookPayload{Text: r.Headline(), Report: r})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook to %s: invalid request", u.Host)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tailnet-sentry")
	resp, err := clone.Do(req)
	if err != nil {
		// url.Error's own text repeats the URL; its inner error does not.
		cause := "request failed"
		var ue *url.Error
		if errors.As(err, &ue) && ue.Err != nil {
			cause = ue.Err.Error()
		}
		return fmt.Errorf("webhook to %s: %s", u.Host, cause)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook to %s: %s", u.Host, resp.Status)
	}
	return nil
}
