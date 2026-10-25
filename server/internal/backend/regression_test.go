package backend

import (
	"bytes"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
	"wwe2k22-server/internal/wire"
)

func TestCapacityConflictsAndInactiveReplacement(t *testing.T) {
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	now := time.Now()
	f := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1001)}, maxParticipants: {wire.Num(maxParticipants, wire.Int64, 2)}}
	if _, e := d.response("create", 1, f, now); e != nil {
		t.Fatal(e)
	}
	rid := d.Sessions[1].Room
	join := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1002)}, matchID: {wire.Num(matchID, wire.Int64, rid)}}
	if _, e := d.response("search", 2, join, now); e != nil {
		t.Fatal(e)
	}
	r := d.Rooms[rid]
	rev := r.Revision
	raw, e := d.response("interlocked_update", 1, wire.Fields{revisionID: {wire.Num(revisionID, wire.Int64, 1)}, maxParticipants: {wire.Num(maxParticipants, wire.Int64, 1)}}, now)
	if e != nil {
		t.Fatal(e)
	}
	decoded, _ := wire.Decode(raw, true)
	if decoded[wire.Result][0].N != 0x48a161bd || r.Revision != rev || *r.Capacity != 2 {
		t.Fatal("conflict changed capacity")
	}
	old := d.Sessions[2]
	old.Closed = true
	if _, e = d.response("search", 3, join, now); e != nil {
		t.Fatal(e)
	}
	if d.Sessions[2] != nil || d.Groups[old.ID] != nil || d.Sessions[3].ID <= old.ID || len(r.Groups) != 2 {
		t.Fatal("inactive replacement reused a reliable group")
	}
}
func TestProfileAndCounterValidationIsAtomic(t *testing.T) {
	for _, m := range []map[string]any{{"DisplayName": string([]byte{0})}, {"CreatorRank": -1}, {"SSOEnable": 1}, {"ContentListUploadSub": []any{1}}} {
		if _, e := profileChanges(m); e == nil {
			t.Fatal("invalid profile patch")
		}
	}
	key := counterKey{"user", "a", "wins"}
	current := map[counterKey]int64{key: math.MaxInt64}
	_, e := counterChanges(current, "user", map[string]any{"Leaderboards": []any{"b", "a"}, "RankKey": "wins", "Value": 1}, false)
	if e == nil || len(current) != 1 || current[key] != math.MaxInt64 {
		t.Fatal("counter overflow partly committed")
	}
}
func TestPrivateTransitionAndPublicationExpiry(t *testing.T) {
	s := testServer(t, false)
	now := time.Now()
	d := s.dir
	d.mu.Lock()
	defer d.mu.Unlock()
	_, e := d.response("create", 1, wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 76561198000000001)}}, now)
	if e != nil {
		t.Fatal(e)
	}
	r := d.Rooms[d.Sessions[1].Room]
	id := uint64(1<<56 | 8<<52 | 0x60000<<32 | 99)
	payload := map[string]any{"lobby_id": decimal(id), "match_id": decimal(r.ID), "visibility": "public", "joinable": true, "metadata": map[string]any{"spec_dev": "dev", "spec_vc_matchid": decimal(r.ID), "spec_hostID": "76561198000000001", "spec_pubOpen": "2", "spec_privOpen": "0"}}
	live := map[uint64]bool{1: true}
	if _, e = d.lobby("publish", 1, payload, live, now); e != nil {
		t.Fatal(e)
	}
	payload["visibility"] = "private"
	if _, e = d.lobby("publish", 1, payload, live, now); e != nil || len(d.Publications) != 0 {
		t.Fatal("private room still advertised")
	}
	payload["visibility"] = "public"
	d.lobby("publish", 1, payload, live, now)
	d.expirePublic(live, now.Add(90*time.Second))
	if len(d.Publications) != 0 {
		t.Fatal("expired public room retained")
	}
}
func TestMultipartRejectsDuplicateHeadersAndEpilogues(t *testing.T) {
	boundary := "abc"
	valid := []byte("--abc\r\nContent-Disposition: form-data; name=\"Params\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--abc\r\nContent-Disposition: form-data; name=\"content\"\r\n\r\nx\r\n--abc--\r\n")
	for _, raw := range [][]byte{append(bytes.Clone(valid), 'x'), bytes.Replace(valid, []byte("Content-Type: application/json"), []byte("Content-Type:\r\nContent-Type: application/json"), 1)} {
		_, _, cleanup, e := parseMultipart("multipart/form-data; boundary="+boundary, bytes.NewReader(raw), int64(len(raw)))
		cleanup()
		if e == nil {
			t.Fatal("invalid multipart accepted")
		}
	}
	if _, _, cleanup, e := parseMultipart("multipart/form-data; boundary=\"bad boundary\"", bytes.NewReader(valid), int64(len(valid))); e == nil {
		cleanup()
		t.Fatal("invalid boundary accepted")
	}
}
func TestDatabaseSchemaPreservedOnUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite3")
	d, e := openDatabase(path)
	if e != nil {
		t.Fatal(e)
	}
	d.DB.Exec("PRAGMA user_version=9")
	d.close()
	if s, e := newState(path); e == nil {
		s.Database.close()
		t.Fatal("unsupported schema accepted")
	}
	if _, e = os.Stat(path); e != nil {
		t.Fatal("existing database removed")
	}
}
func TestImmediateShutdownAndSessionExpiry(t *testing.T) {
	c := DefaultConfig()
	c.HTTPPort = 0
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = s.Serve(); e != nil {
		t.Fatal(e)
	}
	s = testServer(t, false)
	key := loginNative(t, s)
	s.mu.Lock()
	for k := range s.pegasus {
		s.pegasus[k] = time.Now().Add(-time.Second)
	}
	s.mu.Unlock()
	raw, _ := wire.Encode(nil)
	code, _, _ := request(t, s, "/Session/update", raw, map[string]string{"S": key})
	if code != 401 {
		t.Fatal("expired session revived")
	}
}
func BenchmarkRelayTwoPeers(b *testing.B) {
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	now := time.Now()
	for i := uint64(1); i <= 2; i++ {
		fields := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, i)}}
		op := "create"
		if i == 2 {
			op = "search"
			fields[matchID] = []wire.Field{wire.Num(matchID, wire.Int64, d.Sessions[1].Room)}
		}
		if _, e := d.response(op, i, fields, now); e != nil {
			b.Fatal(e)
		}
		g := d.Sessions[i]
		g.Address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+i))
		d.Addresses[g.Address] = g
	}
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1800, Payload: make([]byte, 128)})
	from := netip.MustParseAddrPort("127.0.0.1:10001")
	packet := make([]byte, wire.MaxDatagram)
	replies := make([]udpReply, 0, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := d.udpReplies(raw, from, now, packet, replies); e != nil {
			b.Fatal(e)
		}
	}
}
