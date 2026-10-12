//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package audit

import "os"

// Elsewhere appends are not locked: one sentry process at a time is assumed,
// and verify reports a fork if that is broken.
func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
