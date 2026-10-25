package backend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestPythonImagePackagesAndNativeHash(t *testing.T) {
	raw, e := os.ReadFile("testdata/python_images.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		DDS     string `json:"dds_hex"`
		Hash    uint64
		SHA     string `json:"sha256"`
		Packets []struct {
			Kind    int
			Preview bool
			Hex     string
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	dds, _ := hex.DecodeString(fixture.DDS)
	if contentHash(dds) != fixture.Hash {
		t.Fatal("native checksum differs")
	}
	for _, p := range fixture.Packets {
		packet, _ := hex.DecodeString(p.Hex)
		v, e := inspectImage(packet)
		if e != nil || v.Kind != p.Kind || v.SHA != fixture.SHA || !bytes.Equal(v.DDS, dds) {
			t.Fatal("Python package differs", e)
		}
		codec := 1
		if p.Preview {
			codec = 2
		}
		if v.Codec != codec {
			t.Fatal("preview profile differs")
		}
		packet, e = packImage(dds, p.Kind, 17, 1)
		if e != nil {
			t.Fatal(e)
		}
		v, e = inspectImage(packet)
		if e != nil || v.Codec != 2 || !bytes.Equal(v.DDS, dds) {
			t.Fatal("Go image package lost original pixels")
		}
		packet[8] ^= 1
		if _, e = inspectImage(packet); e == nil {
			t.Fatal("invalid checksum accepted")
		}
	}
}
func FuzzImagePackage(f *testing.F) {
	f.Add([]byte("DDS "))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = inspectImage(b) })
}
func TestSettingsAndJSONLimits(t *testing.T) {
	for _, raw := range []string{`{"port":1,"port":2}`, `[]`, `{}x`, `{"x":NaN}`} {
		if _, e := DecodeSettings([]byte(raw)); e == nil {
			t.Fatal("bad settings accepted")
		}
	}
	if _, e := DecodeSettings([]byte("\xef\xbb\xbf{}")); e != nil {
		t.Fatal(e)
	}
	raw := bytes.Repeat([]byte{'['}, 130)
	raw = append(raw, bytes.Repeat([]byte{']'}, 130)...)
	if _, e := jsonObject(raw, true); e == nil {
		t.Fatal("JSON recursion unbounded")
	}
}
