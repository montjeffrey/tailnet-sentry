//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package tsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
)

// maxHops bounds the symlink chain checked follows, as the kernel does.
const maxHops = 40

// checked returns p unless someone other than root or the current user could
// replace what it runs. It follows p's symlink chain hop by hop (Homebrew
// links /usr/local/bin/tailscale into its Cellar), and at every hop checks
// the link itself, every directory above it, and every directory above where
// that directory really is. Each must be owned by root or the current user
// and not writable by others. Group write is accepted only for root's group
// and, on macOS, admin (/Applications is root:admin 0775), whose members can
// become root anyway. A world-writable directory passes only with the sticky
// bit (/tmp), which stops others from replacing entries they do not own.
func checked(p string) (string, error) {
	cur, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
	}
	for range maxHops {
		dir, err := filepath.EvalSymlinks(filepath.Dir(cur))
		if err != nil {
			return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
		}
		for _, q := range append(append(ancestors(filepath.Dir(cur)), ancestors(dir)...), cur) {
			if err := safe(q); err != nil {
				return "", fmt.Errorf("refusing to run the tailscale CLI at %s: %w", p, err)
			}
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			return p, nil
		}
		link, err := os.Readlink(cur)
		if err != nil {
			return "", fmt.Errorf("tailscale CLI %s: %w", p, err)
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(dir, link)
		}
		cur = link
	}
	return "", fmt.Errorf("refusing to run the tailscale CLI at %s: more than %d symlinks", p, maxHops)
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

// adminGID is macOS's admin group, whose members may already sudo.
const adminGID = 80

// safe checks one path without following it if it is a symlink: a link's
// mode bits mean nothing, but its owner can repoint it.
func safe(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner of " + path)
	}
	if st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not root or the current user", path, st.Uid)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	perm := fi.Mode().Perm()
	if perm&0o002 != 0 && !(fi.IsDir() && fi.Mode()&os.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by other users", path)
	}
	if perm&0o020 != 0 && st.Gid != 0 && !(runtime.GOOS == "darwin" && st.Gid == adminGID) {
		return fmt.Errorf("%s is writable by other users (group %d)", path, st.Gid)
	}
	return nil
}
