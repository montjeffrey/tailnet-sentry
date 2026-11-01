//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package tsutil

// Elsewhere the found CLI is used as is: Tailscale ships no CLI for these
// platforms, so there is no install layout to check against.
func checked(p string) (string, error) { return p, nil }
