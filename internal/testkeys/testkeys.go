// Package testkeys builds Tailscale-key-shaped strings for tests.
//
// A test that needs something the key redactor will recognise must not carry
// a "tskey-..." literal: secret scanners flag it, whatever it says in the
// rest of the string. Fake assembles the string at run time instead, so no
// key-shaped literal exists in the source. Only tests import this package.
package testkeys

// Prefix starts every Tailscale key, written in two pieces so the source
// never holds it whole.
const Prefix = "tsk" + "ey-"

// Fake returns "tskey-<kind>-<tail>", for kind "api", "client" or "auth".
// Put a recognisable marker in tail so a test can search an output for it to
// prove a credential did not leak.
func Fake(kind, tail string) string {
	return Prefix + kind + "-" + tail
}
