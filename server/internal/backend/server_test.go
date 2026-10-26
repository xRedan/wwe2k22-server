package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"wwe2k22-server/internal/wire"
)

func testServer(t *testing.T, content bool) *Server {
	t.Helper()
	c := DefaultConfig()
	c.HTTPPort = 0
	c.UDPPort = 0
	c.Matchmaking = true
	c.CustomContent = content
	c.HTTPRate = 1000
	c.UDPRate = 50000
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		s.Close()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return s
}
func request(t *testing.T, s *Server, path string, data any, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var raw []byte
	switch v := data.(type) {
	case []byte:
		raw = v
	case nil:
	default:
		var e error
		raw, e = marshalJSON(v)
		if e != nil {
			t.Fatal(e)
		}
	}
	method := "POST"
	if data == nil {
		method = "GET"
	}
	r, e := http.NewRequest(method, s.Origin()+path, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	response, e := (&http.Client{Timeout: 5 * time.Second}).Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	out, e := io.ReadAll(response.Body)
	if e != nil {
		t.Fatal(e)
	}
	return response.StatusCode, response.Header, out
}
func object(t *testing.T, b []byte) map[string]any {
	t.Helper()
	m, e := jsonObject(b, false)
	if e != nil {
		t.Fatalf("invalid response: %s", b)
	}
	return m
}
func loginREST(t *testing.T, s *Server, name string) (string, string) {
	t.Helper()
	code, _, b := request(t, s, "/api/Login", map[string]any{"Login": name}, nil)
	if code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	m := object(t, b)
	return str(m["SessionID"]), str(m["UserID"])
}
func loginNative(t *testing.T, s *Server) string {
	t.Helper()
	raw, _ := wire.Encode(nil)
	code, h, b := request(t, s, "/Session/login", raw, nil)
	if code != 200 || h.Get("VCFIELDLIST_SIZE") != fmt.Sprint(len(b)) {
		t.Fatalf("native login %d", code)
	}
	f, e := wire.Decode(b, false)
	if e != nil {
		t.Fatal(e)
	}
	return fmt.Sprint(f[wire.SessionKey][0].N)
}
func TestHTTPBootstrapProfilesAndNotices(t *testing.T) {
	s := testServer(t, false)
	code, _, b := request(t, s, "/health", nil, nil)
	if code != 200 || object(t, b)["protocol"] != ProtocolID {
		t.Fatal("health")
	}
	for _, path := range []string{"/api/Version", "/api/GetPresets", "/api/GetParams", "/api/Ping", "/api/ResourceList", "/api/EulaGet", "/api/PrivacyGet", "/api/TOSGet"} {
		code, _, _ := request(t, s, path, map[string]any{}, nil)
		if code != 200 {
			t.Fatal(path, code)
		}
	}
	sid, uid := loginREST(t, s, "test-player")
	other, _ := loginREST(t, s, "other-player")
	headers := map[string]string{"X-Sessionid": sid}
	code, _, b = request(t, s, "/api/PlayerGetMe", map[string]any{}, headers)
	if code != 200 || object(t, b)["ID"] != uid {
		t.Fatal("profile")
	}
	patch := map[string]any{"DisplayName": "Example name", "Language": "en", "SSOEnable": true, "BlockedSIDs": []string{"blocked"}}
	code, _, _ = request(t, s, "/api/PlayerSet", patch, headers)
	if code != 200 {
		t.Fatal("patch")
	}
	code, _, b = request(t, s, "/api/PlayerGetMe", map[string]any{}, map[string]string{"X-Sessionid": other})
	if code != 200 || str(object(t, b)["DisplayName"]) != "Giocatore locale" {
		t.Fatal("profile ownership")
	}
	code, _, _ = request(t, s, "/api/PlayerSet", map[string]any{"DisplayName": "bad", "CreatorRank": -1}, headers)
	if code != 400 {
		t.Fatal("invalid patch")
	}
	_, _, b = request(t, s, "/api/PlayerGetMe", map[string]any{}, headers)
	if str(object(t, b)["DisplayName"]) != "Example name" {
		t.Fatal("partial patch mutation")
	}
	code, _, _ = request(t, s, "/api/ContentBlacklist", map[string]any{"ContentIDs": []string{strings.Repeat("0", 32), strings.Repeat("1", 32)}}, headers)
	if code != 200 {
		t.Fatal("CAW blacklist")
	}
	for _, op := range []string{"Inc", "Max"} {
		code, _, _ = request(t, s, "/api/LeaderboardPlayer"+op, map[string]any{"Leaderboards": []string{"test-board"}, "RankKey": "wins", "Value": 3}, headers)
		if code != 200 {
			t.Fatal("leaderboard", op)
		}
	}
	code, _, _ = request(t, s, "/api/EulaAccept", map[string]any{"Login": "test-player", "Version": 2}, nil)
	if code != 200 {
		t.Fatal("notice accept")
	}
	_, _, b = request(t, s, "/api/EulaGet", map[string]any{"Login": "test-player"}, nil)
	n, _ := jint(object(t, b)["Accepted"])
	if n != 2 {
		t.Fatal("notice state")
	}
	_, _, b = request(t, s, "/api/EulaGet", map[string]any{"Login": "other-player"}, nil)
	n, _ = jint(object(t, b)["Accepted"])
	if n != 0 {
		t.Fatal("notice ownership")
	}
	key := loginNative(t, s)
	raw, _ := wire.Encode(nil)
	code, _, b = request(t, s, "/Session/update", raw, map[string]string{"S": key})
	if code != 200 {
		t.Fatal("session update")
	}
	f, _ := wire.Decode(b, false)
	if fmt.Sprint(f[wire.SessionKey][0].N) != key {
		t.Fatal("session key changed")
	}
}
func TestHTTPNativeLobbyAndUDPRelay(t *testing.T) {
	s := testServer(t, false)
	owner, guest := loginNative(t, s), loginNative(t, s)
	native := func(path, key string, fields []wire.Field) wire.Fields {
		raw, _ := wire.Encode(wire.Sorted(fields))
		code, h, b := request(t, s, "/lab/vconline/match/"+path, raw, map[string]string{"S": key})
		if code != 200 || h.Get("VCFIELDLIST_SIZE") != fmt.Sprint(len(b)) {
			t.Fatalf("%s: %d %s", path, code, b)
		}
		f, e := wire.Decode(b, true)
		if e != nil {
			t.Fatal(e)
		}
		return f
	}
	desc := make([]byte, 608)
	desc[0] = 10
	desc[4] = 0x60
	desc[5] = 2
	desc[0x56] = 0x80
	desc[0x57] = 0x3f
	put64(desc[0x150:], 76561198000000001)
	f := native("create", owner, []wire.Field{wire.Num(userIDs, wire.Int64, 76561198000000001), wire.Num(maxParticipants, wire.Int64, 2), wire.Num(attributesID, wire.Int64, 0x10b3000001234), wire.Binary(sessionData, desc)})
	rid, gid := f[matchID][0].N, f[localGroup][0].N
	hostToken := bytes.Clone(f[0x6a9160cc][0].Data)
	lobby := uint64(1<<56 | 8<<52 | 0x60000<<32 | 77)
	payload := map[string]any{"lobby_id": decimal(lobby), "match_id": decimal(rid), "visibility": "public", "joinable": true, "member_limit": 8, "member_count": 1, "metadata": map[string]string{"spec_dev": "dev", "spec_hostID": "76561198000000001", "spec_vc_matchid": decimal(rid), "spec_pubOpen": "2", "spec_privOpen": "0"}}
	code, _, b := request(t, s, "/lab/lobbies/publish", payload, map[string]string{"S": owner})
	if code != 200 {
		t.Fatal("publish", code, string(b))
	}
	list := native("list", guest, nil)
	if list[0xa25aa38a][0].N != 1 || list[0xba769d4f][0].N != 2 || list[0x3f8d6d18][0].N != 1 || list[matchID][0].N != rid {
		t.Fatal("native row counters")
	}
	f = native("search", guest, []wire.Field{wire.Num(userIDs, wire.Int64, 76561198000000002), wire.Num(matchID, wire.Int64, rid)})
	guestID := f[localGroup][0].N
	guestToken := f[0x6a9160cc][0].Data
	if guestID <= gid {
		t.Fatal("native host election changed")
	}
	openPeer := func(id uint64, token []byte) *net.UDPConn {
		peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { peer.Close() })
		p := make([]byte, 24)
		copy(p, token)
		put64(p[16:], id)
		raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Payload: p})
		peer.SetDeadline(time.Now().Add(2 * time.Second))
		peer.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr))
		buf := make([]byte, 100)
		n, _, e := peer.ReadFromUDP(buf)
		if e != nil || n != 16 {
			t.Fatal("relay binding", e)
		}
		return peer
	}
	host, peer := openPeer(gid, hostToken), openPeer(guestID, guestToken)
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: []byte("heartbeat")})
	host.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr))
	for _, c := range []*net.UDPConn{host, peer} {
		buf := make([]byte, 100)
		n, _, e := c.ReadFromUDP(buf)
		if e != nil {
			t.Fatal("heartbeat echo", e)
		}
		frame, _ := wire.DecodeUDP(buf[:n])
		if string(frame.Payload) != "heartbeat" {
			t.Fatal("relay payload changed")
		}
	}
	ack := make([]byte, 22)
	ack[2] = 22
	put32(ack[4:], 0x85912ac9)
	put64(ack[8:], gid)
	raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: ack})
	host.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr))
	buf := make([]byte, 100)
	if _, _, e := peer.ReadFromUDP(buf); e != nil {
		t.Fatal("remote ACK", e)
	}
	host.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, e := host.ReadFromUDP(buf); e == nil {
		t.Fatal("ACK reflected to sender")
	}
}
func put64(b []byte, n uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(n >> (8 * i))
	}
}
func put32(b []byte, n uint32) {
	for i := 0; i < 4; i++ {
		b[i] = byte(n >> (8 * i))
	}
}
func TestDatabaseLeaseAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local-state.sqlite3")
	a, e := newState(path)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := newState(path); e == nil {
		b.Database.close()
		t.Fatal("second writer allowed")
	}
	p := player("identity", time.Now())
	if e = a.profile("identity", p); e != nil {
		t.Fatal(e)
	}
	if e = a.notice("identity", "Eula", 2); e != nil {
		t.Fatal(e)
	}
	if e = a.counters(map[counterKey]int64{{"identity", "board", "key"}: 8}); e != nil {
		t.Fatal(e)
	}
	a.Database.close()
	b, e := newState(path)
	if e != nil {
		t.Fatal("lease not released", e)
	}
	defer b.Database.close()
	profiles, notices, counters, e := b.load()
	if e != nil || profiles["identity"]["ID"] != "identity" || notices["identity"]["Eula"] != 2 || counters[counterKey{"identity", "board", "key"}] != 8 {
		t.Fatal("persisted state differs", e)
	}
}
func TestFailedStartupReleasesDatabases(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	c.HTTPPort = 0
	c.StateFile = filepath.Join(dir, "state.sqlite3")
	c.CustomContent = true
	c.TLSCert = filepath.Join(dir, "absent.pem")
	c.TLSKey = filepath.Join(dir, "absent.key")
	if s, e := NewServer(c); e == nil {
		s.Close()
		t.Fatal("invalid TLS accepted")
	}
	state, e := newState(c.StateFile)
	if e != nil {
		t.Fatal("failed startup retained lease", e)
	}
	state.Database.close()
	store, e := newContentStore(contentDBPath(c.StateFile), 1024)
	if e != nil {
		t.Fatal(e)
	}
	store.close()
}
func TestContentStorageStreamingAndPrivateAccess(t *testing.T) {
	store, e := newContentStore("", 8*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer store.close()
	payload := bytes.Repeat([]byte{0, 255, 35, 17}, 512*1024)
	id, e := store.create("owner", map[string]any{"ContentType": 1, "Title": "test", "Tag0": "Stra\u00dfe", "Private": true}, map[string]binaryPart{"content": {bytes.NewReader(payload), int64(len(payload))}, "thumb1": {bytes.NewReader([]byte{0, 255}), 2}})
	if e != nil {
		t.Fatal(e)
	}
	m, e := store.metadata(id, "owner", []string{"thumb1"}, 1024)
	if e != nil || m["Thumbnail1"] != "00ff" {
		t.Fatal("native thumbnail encoding", e)
	}
	if _, e = store.metadata(id, "other", nil, 1024); statusCode(e, 0) != 404 {
		t.Fatal("private metadata exposed")
	}
	snapshot, e := store.snapshot(str(m["FileID"]), "owner")
	if e != nil {
		t.Fatal(e)
	}
	if snapshot.file == nil {
		t.Fatal("large asset was not spooled")
	}
	copied, _ := io.ReadAll(snapshot)
	snapshot.Close()
	if !bytes.Equal(copied, payload) {
		t.Fatal("asset bytes changed")
	}
	ids, total, e := store.search("owner", contentQuery{Private: true, Tags: []string{"STRASSE"}, Limit: 15})
	if e != nil || total != 1 || len(ids) != 1 {
		t.Fatal("Unicode tag matching", e)
	}
	if e = store.save("owner", id); e != nil {
		t.Fatal(e)
	}
	if e = store.save("owner", id); e != nil {
		t.Fatal(e)
	}
	m, e = store.metadata(id, "owner", nil, 0)
	if e != nil || m["Saves"] != int64(1) {
		t.Fatal("save not idempotent", e)
	}
}
func TestConcurrentProfileUpdates(t *testing.T) {
	s := testServer(t, false)
	sid, _ := loginREST(t, s, "concurrent")
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, _, _ := request(t, s, "/api/PlayerSet", map[string]any{"DisplayName": fmt.Sprint("name", i)}, map[string]string{"X-Sessionid": sid})
			if code != 200 {
				t.Error("concurrent update", code)
			}
		}(i)
	}
	wg.Wait()
	code, _, _ := request(t, s, "/api/PlayerGetMe", map[string]any{}, map[string]string{"X-Sessionid": sid})
	if code != 200 {
		t.Fatal("profile unavailable")
	}
}
func TestTLSAndSharedKey(t *testing.T) {
	dir := t.TempDir()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	cert, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certFile, keyFile, accessFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "access.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
	shared := strings.Repeat("a", 64)
	os.WriteFile(accessFile, []byte(shared), 0600)
	c := DefaultConfig()
	c.HTTPPort = 0
	c.TLSCert = certFile
	c.TLSKey = keyFile
	c.AccessKeyFile = accessFile
	s, e := NewServer(c)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	defer func() { s.Close(); <-done }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 2 * time.Second}
	for _, hasKey := range []bool{false, true} {
		r, _ := http.NewRequest("GET", s.Origin()+"/health", nil)
		if hasKey {
			r.Header.Set("X-WWE-Lab-Key", shared)
		}
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		wanted := 401
		if hasKey {
			wanted = 200
		}
		if resp.StatusCode != wanted {
			t.Fatal("access policy", resp.StatusCode)
		}
	}
}
func TestUDPAddressPolicy(t *testing.T) {
	c := DefaultConfig()
	p, e := newPolicy(c, "")
	if e != nil {
		t.Fatal(e)
	}
	if p.admit(netip.MustParseAddr("203.0.113.1"), "udp", time.Now()) {
		t.Fatal("public source admitted")
	}
	c.AllowedNetworks = []string{"0.0.0.0/0"}
	if _, e = newPolicy(c, ""); e == nil {
		t.Fatal("public mode without TLS/key")
	}
}
