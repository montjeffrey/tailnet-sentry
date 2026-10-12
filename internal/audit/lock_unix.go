//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package audit

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on f, waiting for any other
// holder. The lock belongs to the open file, so it is released on close or
// when the process exits, however it exits: a crash cannot leave it stuck.
func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
