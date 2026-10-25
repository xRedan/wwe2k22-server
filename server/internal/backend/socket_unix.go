//go:build !windows

package backend

import (
	"syscall"
)

func socketControl(network, address string, c syscall.RawConn) error { return nil }
