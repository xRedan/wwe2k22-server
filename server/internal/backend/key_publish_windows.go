package backend

import (
	"errors"
	"golang.org/x/sys/windows"
)

func transientKeyIO(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}

// MoveFileEx without REPLACE_EXISTING atomically publishes only an absent
// destination. Unlike a hard link, this also works on Windows filesystems
// and restricted environments which do not permit CreateHardLink.
func publishKeyFile(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}
