package backend

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
	"wwe2k22-server/internal/wire"
)

func TestContentTransactionPanicRollback(t *testing.T) {
	s, err := newContentStore("", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err = s.exec("CREATE TABLE audit_transaction (value INTEGER)"); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("transaction did not propagate panic")
			}
		}()
		_ = s.transaction(func() error {
			if err := s.exec("INSERT INTO audit_transaction VALUES (1)"); err != nil {
				t.Fatal(err)
			}
			panic("interrupted operation")
		})
	}()
	rows, err := s.rows("SELECT COUNT(*) FROM audit_transaction")
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][0].(int64) != 0 {
		t.Fatal("panic retained an uncommitted partial write")
	}
	if err = s.transaction(func() error { return s.exec("INSERT INTO audit_transaction VALUES (2)") }); err != nil {
		t.Fatal("database unusable after panic:", err)
	}
}

type auditBlockedBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *auditBlockedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func (b *auditBlockedBody) Close() error { return nil }
func TestCloseWaitsForAdmittedHTTPHandler(t *testing.T) {
	s := testServer(t, false)
	body := &auditBlockedBody{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(body.release) })
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		r := httptest.NewRequest("POST", "/api/Login", body)
		r.ContentLength = 2
		s.ServeHTTP(httptest.NewRecorder(), r)
	}()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("handler not started")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	<-s.ctx.Done()
	select {
	case <-closed:
		t.Error("storage closed while an admitted request was still running")
	case <-time.After(30 * time.Millisecond):
	}
	release.Do(func() { close(body.release) })
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not finish")
	}
}
func TestServeCannotStartTwoReaders(t *testing.T) {
	s := testServer(t, false)
	request(t, s, "/health", nil, nil)
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("duplicate Serve accepted")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second Serve started another accept loop")
	}
}
func TestClosedServerRejectsRequests(t *testing.T) {
	s := testServer(t, false)
	s.Close()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 503 {
		t.Fatalf("closed server accepted a request: %d", w.Code)
	}
}
func BenchmarkNetworkAdmission(b *testing.B) {
	c := DefaultConfig()
	c.UDPRate = 50000
	p, e := newPolicy(c, "")
	if e != nil {
		b.Fatal(e)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now = now.Add(time.Microsecond * 25)
		if !p.admit(ip, "udp", now) {
			b.Fatal("unexpected rate rejection")
		}
	}
}
func BenchmarkKnownRequestPath(b *testing.B) {
	paths := []string{"/api/Ping", "/lab/vconline/match/update", "/lab/lobbies/list", "/api/ContentMetaGet"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := paths[i&3]
		if safePath(p) != p {
			b.Fatal("known path lost")
		}
	}
}

func TestNetfieldReplyRemainsIndependent(t *testing.T) {
	data := []byte("payload")
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	f := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1)}, userData: {wire.Binary(userData, data)}}
	if _, e := d.response("create", 1, f, time.Now()); e != nil {
		t.Fatal(e)
	}
	data[0] = 'X'
	if strings.Contains(string(d.Sessions[1].Data), "X") {
		t.Fatal("room retained caller-owned mutable data")
	}
}
func BenchmarkContentSearch(b *testing.B) {
	s, e := newContentStore("", 32<<20)
	if e != nil {
		b.Fatal(e)
	}
	defer s.close()
	e = s.transaction(func() error {
		for i := 0; i < 512; i++ {
			meta := `{"ContentType":1,"Tag0":"Stra\u00dfe","Title":"` + strings.Repeat("x", 4096) + `"}`
			if err := s.exec("INSERT INTO content VALUES (?,?,?,?,?)", decimal(uint64(i+1)), "owner", 0, int64(i), meta); err != nil {
				return err
			}
		}
		return nil
	})
	if e != nil {
		b.Fatal(e)
	}
	q := contentQuery{Limit: 64, Tags: []string{"STRASSE"}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ids, total, e := s.search("owner", q)
		if e != nil || total != 512 || len(ids) != 64 {
			b.Fatalf("search failed: %d %d %v", len(ids), total, e)
		}
	}
}
func TestMaintenanceDoesNotExpireNewPublicationFromOldSessionSnapshot(t *testing.T) {
	s := testServer(t, false)
	now := time.Now()
	s.mu.Lock()
	s.access["audit-marker"] = now.Add(-time.Second)
	s.mu.Unlock()
	d := s.dir
	d.mu.Lock()
	locked := true
	defer func() {
		if locked {
			d.mu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() { s.maintenance(now); close(done) }()
	publish := func() {
		s.pegasus[17] = now.Add(time.Hour)
		if _, err := d.response("create", 17, wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1001)}}, now); err != nil {
			t.Fatal(err)
		}
		g := d.Sessions[17]
		d.Publications[9] = &publication{Lobby: 9, Room: d.Rooms[g.Room], Group: g, Session: 17, Refreshed: now}
	}
	// The marker proves the old implementation has captured auth and is waiting
	// for d.mu. The corrected implementation keeps auth locked until expiry ends.
	inserted := false
	deadline := time.Now().Add(60 * time.Millisecond)
	for time.Now().Before(deadline) {
		if s.mu.TryLock() {
			_, present := s.access["audit-marker"]
			if !present {
				publish()
				inserted = true
			}
			s.mu.Unlock()
			if inserted {
				break
			}
		}
		time.Sleep(time.Millisecond)
	}
	d.mu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance deadlock")
	}
	s.mu.Lock()
	d.mu.Lock()
	if !inserted {
		publish()
	}
	_, exists := d.Publications[9]
	d.mu.Unlock()
	s.mu.Unlock()
	if !exists {
		t.Fatal("fresh live publication was removed using an earlier auth snapshot")
	}
}
func TestReusableRelayTargetingAndACKIsolation(t *testing.T) {
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	now := time.Now()
	for i := uint64(1); i <= 3; i++ {
		op := "create"
		f := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, i)}}
		if i == 2 {
			op = "search"
			f[matchID] = []wire.Field{wire.Num(matchID, wire.Int64, d.Sessions[1].Room)}
		}
		if _, err := d.response(op, i, f, now); err != nil {
			t.Fatal(err)
		}
		g := d.Sessions[i]
		g.Address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+i))
		d.Addresses[g.Address] = g
	}
	packet := make([]byte, wire.MaxDatagram)
	out := make([]udpReply, 0, 100)
	guest := d.Sessions[2]
	foreign := d.Sessions[3]
	payload := make([]byte, 4+8*3+5)
	put32(payload, 3)
	put64(payload[4:], guest.ID)
	put64(payload[12:], guest.ID)
	put64(payload[20:], foreign.ID)
	copy(payload[28:], "hello")
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x800, Payload: payload})
	original := append([]byte(nil), raw...)
	replies, err := d.udpReplies(raw, d.Sessions[1].Address, now, packet, out)
	if err != nil || len(replies) != 1 || replies[0].Address != guest.Address {
		t.Fatalf("duplicates or other-room recipients leaked: %v %d", err, len(replies))
	}
	decoded, err := wire.DecodeUDP(replies[0].Data)
	if err != nil || decoded.Flags != 0 || string(decoded.Payload) != "hello" {
		t.Fatal("target vector not stripped")
	}
	if string(raw) != string(original) {
		t.Fatal("relay modified the input frame")
	}
	raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1800, Payload: []byte("next")})
	replies, err = d.udpReplies(raw, d.Sessions[1].Address, now, packet, replies)
	if err != nil || len(replies) != 1 {
		t.Fatal("buffer reuse retained a previous recipient")
	}
	decoded, _ = wire.DecodeUDP(replies[0].Data)
	if string(decoded.Payload) != "next" {
		t.Fatal("buffer reuse retained previous payload")
	}
	raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: []byte("heartbeat")})
	replies, err = d.udpReplies(raw, d.Sessions[1].Address, now, packet, replies)
	if err != nil || len(replies) != 2 {
		t.Fatal("heartbeat no longer reaches the sender")
	}
}
func TestPolicyBudgetsRemainSeparateAndBounded(t *testing.T) {
	c := DefaultConfig()
	c.HTTPRate = 1
	c.UDPRate = 1
	p, err := newPolicy(c, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := netip.MustParseAddr("127.0.0.1")
	for i := 0; i < 2; i++ {
		if !p.admit(ip, "http", now) {
			t.Fatal("burst denied early")
		}
	}
	if p.admit(ip, "http", now) || !p.admit(ip, "udp", now) || !p.admit(ip, "http", now.Add(time.Second)) {
		t.Fatal("HTTP/UDP budgets or refill changed")
	}
	for i := 0; i < 5000; i++ {
		p.admit(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), "udp", now)
	}
	if len(p.Buckets) > 4096 {
		t.Fatal("rate table grew past its bound")
	}
	if !p.admit(netip.MustParseAddr("10.200.0.1"), "udp", now.Add(121*time.Second)) {
		t.Fatal("stale budgets prevented a new client")
	}
}
func TestContentSearchKeepsUnicodePrivateAndRankingSemantics(t *testing.T) {
	s, err := newContentStore("", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	for i, meta := range []string{`{"Tag0":"Stra\u00dfe","ContentType":1}`, `{"Tag0":"Stra\u00dfe","ContentType":1}`, `{"Tag0":"Stra\u00dfe","_NativeDependency":true}`, `{"Tag0":"Stra\u00dfe","ContentType":1}`} {
		private := 0
		if i == 3 {
			private = 1
		}
		if err = s.exec("INSERT INTO content VALUES (?,?,?,?,?)", decimal(uint64(i+1)), "owner", private, int64(i), meta); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.exec("INSERT INTO saved VALUES (?,?)", "viewer", "1"); err != nil {
		t.Fatal(err)
	}
	ids, total, err := s.search("viewer", contentQuery{Limit: 64, Tags: []string{"STRASSE"}, Saves: true})
	if err != nil || total != 2 || len(ids) != 2 || ids[0] != "1" || ids[1] != "2" {
		t.Fatalf("public ranking changed: %v %d %v", ids, total, err)
	}
	ids, total, err = s.search("owner", contentQuery{Private: true, Limit: 64, Tags: []string{"STRASSE"}})
	if err != nil || total != 1 || len(ids) != 1 || ids[0] != "4" {
		t.Fatal("owner-only content changed")
	}
	ids, total, err = s.search("viewer", contentQuery{Private: true, Limit: 64})
	if err != nil || total != 0 || len(ids) != 0 {
		t.Fatal("private content leaked")
	}
}

func TestClosedUDPSocketStopsWorker(t *testing.T) {
	c := DefaultConfig()
	c.HTTPPort = 0
	c.UDPPort = 0
	c.Matchmaking = true
	s, err := NewServer(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	done := make(chan struct{})
	go func() { s.serveUDP(); close(done) }()
	s.udp.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed socket caused a retry loop")
	}
}
func TestContentSchemaRejectionReleasesLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if s, err := newContentStore(path, 1<<20); err == nil {
		s.close()
		t.Fatal("unknown schema accepted")
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal("unknown schema was changed")
	}
	if _, err = db.Exec("PRAGMA user_version=0"); err != nil {
		t.Fatal(err)
	}
	s, err := newContentStore(path, 1<<20)
	if err != nil {
		t.Fatal("failed open leaked database lease:", err)
	}
	s.close()
}
func TestJSONFastPathKeepsDepthNumbersAndDuplicateRules(t *testing.T) {
	m, err := jsonObject([]byte(`{"x":18446744073709551615,"same":0,"same":1}`), false)
	if err != nil || m["x"] != json.Number("18446744073709551615") || m["same"] != json.Number("1") {
		t.Fatal("exact JSON numbers or duplicate policy changed")
	}
	if _, err = jsonObject([]byte(`{"x":1,"x":2}`), true); err == nil {
		t.Fatal("strict duplicate check was lost")
	}
	for _, unique := range []bool{false, true} {
		if _, err = jsonObject([]byte(`{"x":`+strings.Repeat("[", 127)+`0`+strings.Repeat("]", 127)+`}`), unique); err != nil {
			t.Fatal("valid nested JSON rejected")
		}
		if _, err = jsonObject([]byte(`{"x":`+strings.Repeat("[", 128)+`0`+strings.Repeat("]", 128)+`}`), unique); err == nil {
			t.Fatal("nesting limit lost")
		}
	}
}
func FuzzJSONDecoderParity(f *testing.F) {
	for _, seed := range []string{`{}`, `{"x":1,"x":2}`, `{"x":[null,true,"Stra\u00dfe",18446744073709551615]}`, `{"x":1} false`, `[]`, `{"x":` + strings.Repeat("[", 128) + `0` + strings.Repeat("]", 128) + `}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 || !utf8.Valid(raw) {
			return
		}
		got, gotErr := jsonObject(raw, false)
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		v, wantErr := readJSONValue(d, false, 0)
		if wantErr == nil {
			if _, err := d.Token(); err != io.EOF {
				wantErr = io.ErrUnexpectedEOF
			}
		}
		want, ok := v.(map[string]any)
		if !ok && wantErr == nil {
			wantErr = io.ErrUnexpectedEOF
		}
		if (gotErr == nil) != (wantErr == nil) || (gotErr == nil && !reflect.DeepEqual(got, want)) {
			t.Fatalf("decoder mismatch on %q", raw)
		}
	})
}
