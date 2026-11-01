//go:build windows

package tsutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

// checked accepts only a CLI that resolves to one of Tailscale's own install
// locations. Windows permissions are ACLs that mode bits do not describe, and
// Program Files is writable only by administrators, so the location is the
// check: a tailscale.exe found anywhere else on PATH is refused rather than
// trusted.
func checked(p string) (string, error) {
	target, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
	}
	for _, t := range trustedPaths() {
		if tt, err := filepath.EvalSymlinks(t); err == nil && strings.EqualFold(tt, target) {
			return p, nil
		}
	}
	return "", fmt.Errorf("refusing to run the tailscale CLI at %s: on Windows only Tailscale's install location (%s) is trusted",
		p, strings.Join(trustedPaths(), " or "))
}
