//go:build !windows

package backend

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockLease(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func unlockLease(f *os.File)     { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
