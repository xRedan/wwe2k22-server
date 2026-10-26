package backend

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Construct synthetic layout examples with explicit expected payload sizes.
func layoutDDS(width, height, levels, flags, bits uint32, fourCC string, payload int) []byte {
	b := make([]byte, 128+payload)
	copy(b, "DDS ")
	put := binary.LittleEndian.PutUint32
	put(b[4:], 124)
	put(b[12:], height)
	put(b[16:], width)
	put(b[28:], levels)
	put(b[76:], 32)
	put(b[80:], flags)
	put(b[88:], bits)
	copy(b[84:88], fourCC)
	return b
}

func TestDDSKnownLayoutMinimums(t *testing.T) {
	for _, item := range []struct {
		name                               string
		width, height, levels, flags, bits uint32
		fourCC                             string
		payload                            int
	}{
		{"dxt1-small", 1, 1, 0, 4, 0, "DXT1", 8},
		{"dxt2-small", 1, 1, 1, 4, 0, "DXT2", 16},
		{"dxt3-odd", 5, 7, 1, 4, 0, "DXT3", 64},
		{"dxt4-rect", 8, 2, 1, 4, 0, "DXT4", 32},
		{"dxt5-flat", 512, 512, 1, 4, 0, "DXT5", 262144},
		{"dxt5-small", 2, 1, 0, 4, 0, "DXT5", 16},
		{"dxt5-odd-mips", 7, 5, 3, 4, 0, "DXT5", 96},
		{"dxt1-rect-mips", 8, 2, 4, 4, 0, "DXT1", 40},
		{"rgb8", 3, 2, 1, 0x40, 8, "", 6},
		{"rgb16", 3, 2, 1, 0x40, 16, "", 12},
		{"rgb24", 3, 2, 1, 0x40, 24, "", 18},
		{"rgba32", 3, 2, 1, 0x41, 32, "", 24},
		{"rgba32-stale-dxt5", 1, 1, 1, 0x41, 32, "DXT5", 4},
		{"rgba32-stale-dx10", 1, 1, 1, 0x41, 32, "DX10", 4},
		{"rgba32-mips", 5, 3, 3, 0x41, 32, "", 72},
	} {
		t.Run(item.name, func(t *testing.T) {
			// DDSD_MIPMAPCOUNT is deliberately absent, including for mip chains.
			dds := layoutDDS(item.width, item.height, item.levels, item.flags, item.bits, item.fourCC, item.payload)
			w, h, e := ddsDimensions(dds)
			if e != nil || w != item.width || h != item.height {
				t.Fatal(w, h, e)
			}
			if _, _, e = ddsDimensions(dds[:len(dds)-1]); e == nil {
				t.Fatal("truncated known layout accepted")
			}
			// Legacy row padding and additional surfaces may add more bytes.
			if _, _, e = ddsDimensions(append(dds, make([]byte, 17)...)); e != nil {
				t.Fatal("additional storage rejected", e)
			}
		})
	}
}

func TestDDSOpaqueCompatibilityAndDX10Extension(t *testing.T) {
	for _, dds := range [][]byte{
		layoutDDS(64, 32, 0, 0, 0, "", 0),
		layoutDDS(64, 32, 0, 0, 32, "", 1),
		layoutDDS(64, 32, 0, 0, 32, "DXT1", 0),
		layoutDDS(64, 32, 0, 0, 32, "DXT5", 0),
		layoutDDS(64, 32, 0, 0, 32, "DX10", 0),
		layoutDDS(64, 32, 0, 4, 0, "ZZZZ", 0),
		layoutDDS(64, 32, 0, 0x44, 32, "ZZZZ", 0),
		layoutDDS(64, 32, 0, 0x40, 12, "", 0),
	} {
		if _, _, e := ddsDimensions(dds); e != nil {
			t.Fatal("unknown legacy layout no longer opaque", e)
		}
	}
	for _, flags := range []uint32{4, 0x44} {
		for size := 0; size < 20; size++ {
			if _, _, e := ddsDimensions(layoutDDS(4, 4, 0, flags, 0, "DX10", size)); e == nil {
				t.Fatal("short DX10 extension accepted", flags, size)
			}
		}
		if _, _, e := ddsDimensions(layoutDDS(4, 4, 0, flags, 0, "DX10", 20)); e != nil {
			t.Fatal("complete opaque DX10 extension rejected", e)
		}
	}
}

func TestDDSKnownLayoutRejectsHugeBoundsAndSync(t *testing.T) {
	for _, dds := range [][]byte{
		layoutDDS(512, 512, 1, 4, 0, "DXT5", 1),
		layoutDDS(16384, 16384, 0, 0x40, 32, "", 1),
		layoutDDS(16384, 16384, 0, 4, 0, "DXT1", 1),
		layoutDDS(1, 1, ^uint32(0), 4, 0, "DXT5", 16),
		layoutDDS(^uint32(0), ^uint32(0), 0, 4, 0, "DXT5", 16),
	} {
		if _, _, e := ddsDimensions(dds); e == nil {
			t.Fatal("impossible known layout accepted")
		}
	}
	store := newSyncStore(t)
	truncated := layoutDDS(512, 512, 1, 4, 0, "DXT5", 1)
	for _, kind := range []int{0, 31, 61} {
		if _, e := packImage(truncated, kind, 1, 1); e == nil {
			t.Fatal("truncated pixels packed")
		}
		id := strings.Repeat("12", 16)
		if _, _, _, e := parseImageSync(syncFrame(id, kind, truncated)); statusCode(e, 0) != 400 {
			t.Fatal("truncated sync frame accepted", e)
		}
		if _, e := store.syncImage(strings.Repeat("13", 16), id, kind, truncated); statusCode(e, 0) != 400 {
			t.Fatal("truncated sync asset stored", e)
		}
	}
	summary, e := store.summary()
	if e != nil || summary["contents"] != int64(0) || summary["assets"] != int64(0) {
		t.Fatal("invalid image mutated storage", summary, e)
	}
}

func TestDDSImageSyncHTTPRejectsTruncatedPixels(t *testing.T) {
	s := testServer(t, true)
	code, _, login := request(t, s, "/api/Login", map[string]any{"Login": "dds-layout-test"}, nil)
	if code != 200 {
		t.Fatal(code, string(login))
	}
	headers := map[string]string{"X-Sessionid": str(object(t, login)["SessionID"])}
	for _, dds := range [][]byte{
		layoutDDS(512, 512, 1, 4, 0, "DXT5", 1),
		layoutDDS(4, 4, 0, 4, 0, "DX10", 19),
	} {
		for _, kind := range []int{0, 31, 61} {
			code, _, raw := request(t, s, "/lab/images/sync", syncFrame(strings.Repeat("25", 16), kind, dds), headers)
			if code != 400 || strings.Contains(string(raw), "25") {
				t.Fatal("truncated DDS POST acknowledged or exposed identity", code, string(raw))
			}
		}
	}
	summary, e := s.content.summary()
	if e != nil || summary["contents"] != int64(0) || summary["assets"] != int64(0) {
		t.Fatal("invalid DDS POST mutated storage", summary, e)
	}
}

func FuzzDDSLayout(f *testing.F) {
	f.Add(layoutDDS(1, 1, 0, 4, 0, "DXT1", 8))
	f.Add(layoutDDS(7, 5, 3, 4, 0, "DXT5", 96))
	f.Add(layoutDDS(5, 3, 3, 0x41, 32, "", 72))
	f.Add(layoutDDS(4, 4, 0, 4, 0, "DX10", 20))
	f.Add(layoutDDS(64, 32, 0, 0, 0, "", 1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _, _ = ddsDimensions(raw)
	})
}
