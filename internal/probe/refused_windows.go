package probe

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WinSock's "connection refused". syscall has no name for
// it, and on Windows syscall.ECONNREFUSED is an invented value that connectex
// never returns.
const wsaeconnrefused = syscall.Errno(10061)

func refused(err error) bool {
	return errors.Is(err, wsaeconnrefused) || errors.Is(err, syscall.ECONNREFUSED)
}
