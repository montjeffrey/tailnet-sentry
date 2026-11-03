//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
