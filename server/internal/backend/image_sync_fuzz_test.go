package backend

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// Fuzz only owned synthetic frames; parsing must not panic or change pixels.
func FuzzImageSyncFrame(f *testing.F) {
	for _, kind := range []uint16{0, 31, 61} {
		image := make([]byte, 132)
		copy(image, "DDS ")
		binary.LittleEndian.PutUint32(image[4:], 124)
		binary.LittleEndian.PutUint32(image[12:], 1)
		binary.LittleEndian.PutUint32(image[16:], 1)
		binary.LittleEndian.PutUint32(image[76:], 32)
		image[128] = byte(kind)
		frame := make([]byte, 44+len(image))
		copy(frame, "W2IMG001")
		binary.LittleEndian.PutUint16(frame[12:], kind)
		frame[24] = 17
		binary.LittleEndian.PutUint32(frame[40:], uint32(len(image)))
		copy(frame[44:], image)
		f.Add(frame)
	}
	f.Add([]byte("W2IMG001"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64*1024 {
			t.Skip()
		}
		id, kind, image, err := parseImageSync(raw)
		if err != nil {
			return
		}
		if len(id) != 32 || id == strings.Repeat("0", 32) || id != hex.EncodeToString(raw[24:40]) {
			t.Fatal("accepted a different native identity")
		}
		packet, err := packImage(image, kind, 17, 1)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := inspectImage(packet)
		if err != nil || decoded.Codec != 2 || decoded.Kind != kind || !bytes.Equal(decoded.DDS, image) {
			t.Fatal("accepted frame did not preserve native pixels", err)
		}
	})
}
