package backend

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Synthetic high-entropy RGBA pixels keep compression representative without
// retaining any captured image or depending on machine-specific random data.
func benchmarkSyncDDS(width int) []byte {
	b := make([]byte, 128+width*width*4)
	copy(b, "DDS ")
	put := binary.LittleEndian.PutUint32
	put(b[4:], 124)
	put(b[8:], 0x100f)
	put(b[12:], uint32(width))
	put(b[16:], uint32(width))
	put(b[20:], uint32(width*4))
	put(b[76:], 32)
	put(b[80:], 0x41)
	put(b[88:], 32)
	put(b[92:], 0xff)
	put(b[96:], 0xff00)
	put(b[100:], 0xff0000)
	put(b[104:], 0xff000000)
	put(b[108:], 0x1000)
	state := uint32(0x4d595df4)
	for i := 128; i < len(b); i++ {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		b[i] = byte(state)
	}
	return b
}

func BenchmarkImageSyncUnchanged(b *testing.B) {
	for _, size := range []struct {
		name  string
		width int
	}{{"1MiB", 512}, {"4MiB", 1024}} {
		b.Run(size.name, func(b *testing.B) {
			s, e := newContentStore("", 32<<20)
			if e != nil {
				b.Fatal(e)
			}
			defer s.close()
			owner, id := strings.Repeat("11", 16), strings.Repeat("22", 16)
			dds := benchmarkSyncDDS(size.width)
			if _, e = s.syncImage(owner, id, 31, dds); e != nil {
				b.Fatal(e)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(dds)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, e := s.syncImage(owner, id, 31, dds)
				if e != nil || result["status"] != "unchanged" {
					b.Fatal(result, e)
				}
			}
		})
	}
}
