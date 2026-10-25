package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestPythonWireVectors(t *testing.T) {
	var fixture struct {
		Vectors []struct {
			Fields []struct {
				ID, Kind  uint32
				N         uint64
				Hex, Text string
				Address   struct {
					IP        string
					Port, Tag uint16
				}
			}
			Hex     string
			GzipHex string `json:"gzip_hex"`
		}
		Repeated string   `json:"repeated_hex"`
		Catalog  string   `json:"catalog_hex"`
		Invalid  []string `json:"invalid_hex"`
	}
	raw, e := os.ReadFile("testdata/python.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	for i, v := range fixture.Vectors {
		records := []Field{}
		for _, f := range v.Fields {
			data, _ := hex.DecodeString(f.Hex)
			field := Field{ID: f.ID, Kind: f.Kind, N: f.N, Data: data, Text: f.Text}
			if f.Kind == Address {
				field.Endpoint = Endpoint{netip.MustParseAddr(f.Address.IP), f.Address.Port, f.Address.Tag}
			}
			records = append(records, field)
		}
		actual, e := Encode(records)
		if e != nil || hex.EncodeToString(actual) != v.Hex {
			t.Fatalf("vector %d encode differs: %v", i, e)
		}
		decoded, e := Decode(actual, false)
		if e != nil || len(decoded) != len(records) {
			t.Fatalf("vector %d decode: %v", i, e)
		}
		for _, f := range records {
			got := decoded[f.ID][0]
			if got.Kind != f.Kind || got.N != f.N || got.Text != f.Text || !bytes.Equal(got.Data, f.Data) || got.Endpoint != f.Endpoint {
				t.Fatalf("vector %d field %d differs", i, f.ID)
			}
		}
		gz, _ := hex.DecodeString(v.GzipHex)
		if _, e = Decode(gz, false); e != nil {
			t.Fatal(e)
		}
	}
	rep, _ := hex.DecodeString(fixture.Repeated)
	if f, e := Decode(rep, true); e != nil || len(f[77]) != 3 || len(f[88]) != 2 {
		t.Fatal("repeated fields")
	}
	if _, e := Decode(rep, false); e == nil {
		t.Fatal("duplicate fields accepted")
	}
	if hex.EncodeToString(Catalog()) != fixture.Catalog {
		t.Fatal("service catalog bytes differ")
	}
	for i, s := range fixture.Invalid {
		raw, _ := hex.DecodeString(s)
		if _, e := Decode(raw, true); e == nil {
			t.Fatalf("invalid vector %d accepted", i)
		}
	}
}
func TestSessionNativeTypes(t *testing.T) {
	raw := Session(0x1000000000023, Catalog(), time.UnixMilli(1700000000123))
	fields, e := Decode(raw, false)
	if e != nil {
		t.Fatal(e)
	}
	if fields[0x7e6f0a6e][0].Kind != Time64 || fields[0x428ed19c][0].N != 1700000060123 || fields[SessionKey][0].N != 0x1000000000023 {
		t.Fatal("session key or time type differs")
	}
}
func TestUDPFramingAndACK(t *testing.T) {
	p := make([]byte, 22)
	p[2] = 22
	lePut(p[4:], 0x85912ac9)
	p[8] = 77
	f := Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: p}
	raw, e := EncodeUDP(f)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeUDP(raw)
	if e != nil || !IsApplicationACK(decoded, 77) || IsApplicationACK(decoded, 78) {
		t.Fatal("ACK recognition")
	}
	for _, raw := range [][]byte{nil, {0, 0, 0}, {4, 0, 0, 0, 1}} {
		if _, e := DecodeUDP(raw); e == nil {
			t.Fatal("invalid UDP accepted")
		}
	}
}
func lePut(b []byte, n uint32) {
	for i := 0; i < 4; i++ {
		b[i] = byte(n >> (8 * i))
	}
}
func FuzzNetField(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, true) })
}
func FuzzDatagram(f *testing.F) {
	f.Add([]byte{4, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := DecodeUDP(b)
		if e == nil {
			_, _, _ = Targeted(v)
			_, _ = EncodeUDP(v)
		}
	})
}
