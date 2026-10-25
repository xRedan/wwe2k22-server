package backend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"
	"wwe2k22-server/internal/wire"
)

func TestPythonDirectoryTranscript(t *testing.T) {
	raw, e := os.ReadFile("testdata/python_directory.json")
	if e != nil {
		t.Fatal(e)
	}
	var steps []struct {
		Kind, Op              string
		Key                   uint64
		RequestHex            string `json:"request_hex"`
		ResponseHex           string `json:"response_hex"`
		EntropyHex            string `json:"entropy_hex"`
		Status, Rooms, Groups int
		Payload               map[string]any
		Response              map[string]any
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if e = decoder.Decode(&steps); e != nil {
		t.Fatal(e)
	}
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	d.Next = 101
	now := time.Unix(100, 0)
	live := map[uint64]bool{11: true, 22: true, 33: true}
	for i, step := range steps {
		b, _ := hex.DecodeString(step.RequestHex)
		f, e := wire.Decode(b, true)
		if step.Kind != "lobby" && e != nil {
			t.Fatal(e)
		}
		switch step.Kind {
		case "match":
			entropy, _ := hex.DecodeString(step.EntropyHex)
			d.Random = bytes.NewReader(entropy)
			actual, e := d.response(step.Op, step.Key, f, now)
			code := 200
			if e != nil {
				code = statusCode(e, 500)
			}
			if code != step.Status {
				t.Fatalf("step %d %s: code=%d expected=%d, %v", i, step.Op, code, step.Status, e)
			}
			if code == 200 && hex.EncodeToString(actual) != step.ResponseHex {
				t.Fatalf("step %d: native response bytes differ", i)
			}
			if len(d.Rooms) != step.Rooms || len(d.Groups) != step.Groups {
				t.Fatalf("step %d: membership mutated", i)
			}
		case "lobby":
			actual, e := d.lobby(step.Op, step.Key, step.Payload, live, now)
			if e != nil {
				t.Fatalf("step %d: %v", i, e)
			}
			a, _ := marshalJSON(actual)
			b, _ := marshalJSON(step.Response)
			if !bytes.Equal(a, b) {
				t.Fatalf("step %d: JSON differs", i)
			}
		case "native":
			actual, e := d.nativeList(step.Key, f, live, now)
			if e != nil || hex.EncodeToString(actual) != step.ResponseHex {
				t.Fatalf("step %d: native list differs: %v", i, e)
			}
		}
	}
}
func TestFailedAdmissionPreservesMembership(t *testing.T) {
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	now := time.Now()
	_, e := d.response("create", 1, wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1001)}, maxParticipants: {wire.Num(maxParticipants, wire.Int64, 1)}}, now)
	if e != nil {
		t.Fatal(e)
	}
	g := d.Sessions[1]
	before := bytes.Clone(g.Token)
	_, e = d.response("search", 2, wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1002)}, matchID: {wire.Num(matchID, wire.Int64, g.Room)}}, now)
	if e == nil || len(d.Groups) != 1 || !reflect.DeepEqual(g.Token, before) {
		t.Fatal("failed admission mutated relay")
	}
}
