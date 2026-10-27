//go:build !windows

package backend

import "os"

func transientKeyIO(error) bool { return false }

// Same-directory hard links publish a complete file without replacing an
// existing key. Both paths are on the same persistent data filesystem.
func publishKeyFile(source, destination string) error {
	return os.Link(source, destination)
}
