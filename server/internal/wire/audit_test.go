package wire

import (
	"encoding/binary"
	"testing"
)

func TestDecodeLimitsAliasedPayloadCopies(t *testing.T) {
	for _, kind := range []uint32{Blob, String} {
		const count = 9
		const size = 128 * 1024
		raw := make([]byte, 16*(count+1)+size)
		for i := 0; i < count; i++ {
			p := raw[i*16:]
			binary.BigEndian.PutUint32(p, uint32(i+1))
			binary.BigEndian.PutUint32(p[4:], kind)
			binary.BigEndian.PutUint32(p[12:], size)
		}
		for i := 16 * (count + 1); i < len(raw)-1; i++ {
			raw[i] = 'a'
		}
		if _, err := Decode(raw, false); err == nil {
			t.Fatalf("kind %x allows payload amplification beyond MaxBody", kind)
		}
	}
}
func TestDecodeOwnsBlobAndAcceptsBoundedAliases(t *testing.T) {
	raw, err := Encode([]Field{Binary(1, []byte("content")), Binary(2, nil)})
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(raw[16+8:], 0)
	binary.BigEndian.PutUint32(raw[16+12:], 7)
	f, err := Decode(raw, false)
	if err != nil {
		t.Fatal("small shared offsets must remain supported:", err)
	}
	raw[len(raw)-1] = 'X'
	if string(f[1][0].Data) != "content" || string(f[2][0].Data) != "content" {
		t.Fatal("decoded blobs alias caller buffer")
	}
}
func TestEncodeUDPIntoHandlesOverlapAndShortBuffer(t *testing.T) {
	buffer := make([]byte, 64)
	copy(buffer, "payload")
	frame, err := EncodeUDPInto(buffer, Datagram{Namespace: 1, Kind: 3, Payload: buffer[:7]})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUDP(frame)
	if err != nil || string(decoded.Payload) != "payload" {
		t.Fatal("overlapping buffer corrupted payload")
	}
	frame, err = EncodeUDPInto(make([]byte, 0, 1), Datagram{Namespace: 1, Kind: 3, Payload: []byte("payload")})
	if err != nil || len(frame) != 11 {
		t.Fatal("short scratch buffer failed")
	}
}

func BenchmarkSortFields(b *testing.B) {
	base := make([]Field, 128)
	for i := range base {
		base[i] = Num(uint32(1+(127-i)/4), Int64, uint64(i))
	}
	records := make([]Field, len(base))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(records, base)
		Sorted(records)
	}
}
