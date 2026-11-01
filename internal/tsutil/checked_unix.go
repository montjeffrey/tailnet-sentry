//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package tsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// checked returns p unless someone other than root or the current user could
// replace what it runs. That covers the file, every directory above it, and,
// when p is a symlink (Homebrew links /usr/local/bin/tailscale into its
// Cellar), every directory above its target too: each must be owned by root
// or the current user and not writable by group or others. A world-writable
// directory passes only with the sticky bit (/tmp), which stops others from
// replacing entries they do not own; the next component's owner is checked
// in turn.
func checked(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
	}
	target, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
	}
	paths := append(ancestors(filepath.Dir(abs)), ancestors(filepath.Dir(target))...)
	for _, q := range append(paths, target) {
		if err := safe(q); err != nil {
			return "", fmt.Errorf("refusing to run the tailscale CLI at %s: %w", p, err)
		}
	}
	return p, nil
}

// ancestors lists dir and every directory above it, root first.
func ancestors(dir string) []string {
	var out []string
	for {
		out = append(out, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	slices.Reverse(out)
	return out
}

func safe(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not root or the current user", path, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 && !(fi.IsDir() && fi.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by other users", path)
	}
	return nil
}
