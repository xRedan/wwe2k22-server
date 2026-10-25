//go:build windows

package backend

import (
	"golang.org/x/sys/windows"
	"syscall"
)

// Preserve the Python listener's exclusive bind and ignore remote UDP ICMP resets.
func socketControl(network, address string, c syscall.RawConn) error {
	var operation error
	e := c.Control(func(fd uintptr) {
		operation = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^int(windows.SO_REUSEADDR), 1)
		if operation == nil && network == "udp4" {
			var disabled [4]byte
			var returned uint32
			operation = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET, &disabled[0], 4, nil, 0, &returned, nil, 0)
		}
	})
	if e != nil {
		return e
	}
	return operation
}
