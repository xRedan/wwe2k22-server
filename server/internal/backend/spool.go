package backend

import (
	"bytes"
	"errors"
	"io"
	"os"
)

const spoolMemory = 256 * 1024

// Spills only large opaque uploads/snapshots; the caller owns Close.
type spool struct {
	buffer    bytes.Buffer
	file      *os.File
	pos, size int64
}

func (s *spool) Write(p []byte) (int, error) {
	if s.file == nil && s.size+int64(len(p)) > spoolMemory {
		f, e := os.CreateTemp("", "wwe-content-*")
		if e != nil {
			return 0, e
		}
		if _, e = f.Write(s.buffer.Bytes()); e != nil {
			f.Close()
			os.Remove(f.Name())
			return 0, e
		}
		// The file now owns these bytes; Reset would retain the 256 KiB backing array.
		s.buffer = bytes.Buffer{}
		s.file = f
	}
	var n int
	var e error
	if s.file != nil {
		n, e = s.file.Write(p)
	} else {
		n, e = s.buffer.Write(p)
	}
	s.size += int64(n)
	return n, e
}
func (s *spool) Read(p []byte) (int, error) {
	if s.file != nil {
		return s.file.Read(p)
	}
	if s.pos >= s.size {
		return 0, io.EOF
	}
	n := copy(p, s.buffer.Bytes()[s.pos:])
	s.pos += int64(n)
	return n, nil
}
func (s *spool) Seek(off int64, whence int) (int64, error) {
	if s.file != nil {
		return s.file.Seek(off, whence)
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		off += s.pos
	case io.SeekEnd:
		off += s.size
	default:
		return 0, errors.New("invalid seek")
	}
	if off < 0 {
		return 0, errors.New("negative seek")
	}
	s.pos = off
	return off, nil
}
func (s *spool) Close() error {
	if s.file != nil {
		name := s.file.Name()
		e := s.file.Close()
		os.Remove(name)
		s.file = nil
		return e
	}
	s.buffer.Reset()
	return nil
}
