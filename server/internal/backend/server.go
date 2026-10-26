package backend

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"wwe2k22-server/internal/wire"
)

type restSession struct {
	User    string
	Expires time.Time
}
type refreshSession struct {
	Account string
	Expires time.Time
}
type Server struct {
	lifeMu                                sync.Mutex
	closing, serving                      bool
	Config                                Config
	mu                                    sync.Mutex
	state                                 *stateStore
	content                               *contentStore
	dir                                   *directory
	policy                                *networkPolicy
	key, origin                           string
	started                               time.Time
	catalog                               []byte
	documents                             map[string]any
	profiles                              map[string]map[string]any
	notices                               map[string]map[string]int64
	counters                              map[counterKey]int64
	rest                                  map[string]restSession
	pegasus                               map[uint64]time.Time
	access                                map[string]time.Time
	refresh                               map[string]refreshSession
	listener                              net.Listener
	udp                                   *net.UDPConn
	http                                  *http.Server
	ctx                                   context.Context
	cancel                                context.CancelFunc
	wg, handlers                          sync.WaitGroup
	closeOnce                             sync.Once
	uploads, downloads                    chan struct{}
	responses, unsupported, storageErrors atomic.Uint64
	logger                                *eventLogger
	imageImport                           map[string]any
	imageMu                               sync.Mutex
	imageChanged                          chan struct{}
	imageWaiters                          int
	imageCreated, imageUpdated            atomic.Uint64
	imageUnchanged                        atomic.Uint64
}

func NewServer(c Config) (s *Server, err error) {
	if err = c.Validate(); err != nil {
		return nil, err
	}
	key, e := readAccessKey(c.AccessKeyFile)
	if e != nil {
		return nil, e
	}
	policy, e := newPolicy(c, key)
	if e != nil {
		return nil, e
	}
	state, e := newState(c.StateFile)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s = &Server{Config: c, state: state, key: key, policy: policy, ctx: ctx, cancel: cancel, started: time.Now(), rest: map[string]restSession{}, pegasus: map[uint64]time.Time{}, access: map[string]time.Time{}, refresh: map[string]refreshSession{}, uploads: make(chan struct{}, 1), downloads: make(chan struct{}, 4), logger: newEventLogger(c.LogFile, c.VerboseLog)}
	owned := s
	defer func() {
		if err != nil {
			owned.Close()
		}
	}()
	s.profiles, s.notices, s.counters, err = state.load()
	if err != nil {
		return nil, errors.New("cannot load local state; preserve the existing file")
	}
	s.documents, err = jsonObject(documentsJSON, false)
	if err != nil {
		return nil, err
	}
	if c.CustomContent {
		s.content, err = newContentStore(contentDBPath(c.StateFile), int64(c.ContentQuotaMiB)*1024*1024)
		if err != nil {
			return nil, err
		}
		if c.ImportImages != "" {
			s.imageImport, err = s.content.importImages(c.ImportImages, c.ImageOwner, c.UpgradeImages)
			if err != nil {
				return nil, err
			}
		}
	}
	listenConfig := net.ListenConfig{Control: socketControl}
	ln, e := listenConfig.Listen(ctx, "tcp4", net.JoinHostPort(c.BindHost, strconv.Itoa(c.HTTPPort)))
	if e != nil {
		return nil, e
	}
	s.listener = ln
	port := ln.Addr().(*net.TCPAddr).Port
	if c.AdvertiseHTTPPort != 0 {
		port = c.AdvertiseHTTPPort
	}
	s.Config.AdvertiseHTTPPort = port
	scheme := "http"
	if c.TLSCert != "" {
		scheme = "https"
	}
	s.origin = scheme + "://" + strings.ToLower(c.HTTPHost) + ":" + strconv.Itoa(port)
	if c.Matchmaking {
		addr := &net.UDPAddr{IP: net.ParseIP(c.BindHost), Port: c.UDPPort}
		packetConn, e := listenConfig.ListenPacket(ctx, "udp4", addr.String())
		err = e
		if e == nil {
			s.udp = packetConn.(*net.UDPConn)
		}
		if err != nil {
			return nil, err
		}
		s.udp.SetReadBuffer(256 * 1024)
		s.udp.SetWriteBuffer(256 * 1024)
		port = s.udp.LocalAddr().(*net.UDPAddr).Port
		if c.AdvertiseUDPPort != 0 {
			port = c.AdvertiseUDPPort
		}
		s.dir = newDirectory(wire.Endpoint{IP: netip.MustParseAddr(c.AdvertiseHost), Port: uint16(port), Tag: 1})
	}
	if c.Matchmaking || c.Catalog {
		s.catalog = wire.Catalog()
	}
	s.listener = &boundedListener{Listener: s.listener, slots: make(chan struct{}, c.MaxConnections), policy: policy}
	if c.TLSCert != "" {
		cert, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if e != nil {
			return nil, errors.New("cannot load TLS certificate/key")
		}
		s.listener = tls.NewListener(s.listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	}
	s.http = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second, WriteTimeout: 120 * time.Second, MaxHeaderBytes: 32 * 1024, ErrorLog: log.New(io.Discard, "", 0)}
	s.http.SetKeepAlivesEnabled(false)
	return s, nil
}
func (s *Server) Origin() string { return s.origin }
func (s *Server) UDPAddress() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}
func (s *Server) Serve() error {
	s.lifeMu.Lock()
	if s.closing {
		s.lifeMu.Unlock()
		return nil
	}
	if s.serving {
		s.lifeMu.Unlock()
		return errors.New("server already serving")
	}
	s.serving = true
	s.logger.start()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.maintenance(time.Now())
			}
		}
	}()
	if s.udp != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serveUDP() }()
	}
	s.lifeMu.Unlock()
	e := s.http.Serve(s.listener)
	if errors.Is(e, http.ErrServerClosed) || errors.Is(e, net.ErrClosed) {
		return nil
	}
	return e
}
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() {
		s.lifeMu.Lock()
		s.closing = true
		s.cancel()
		s.lifeMu.Unlock()
		if s.udp != nil {
			s.udp.Close()
		}
		if s.http != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if s.http.Shutdown(ctx) != nil {
				s.http.Close()
			}
			cancel()
		}
		if s.listener != nil {
			s.listener.Close()
		}
		s.wg.Wait()
		// Admission is closed before waiting, so no handler can be added here.
		s.handlers.Wait()
		s.content.close()
		if s.state != nil {
			s.state.Database.close()
		}
		s.logger.close()
	})
}
func (s *Server) live(now time.Time) map[uint64]bool {
	out := map[uint64]bool{}
	for id, expiry := range s.pegasus {
		if expiry.After(now) {
			out[id] = true
		}
	}
	return out
}
func (s *Server) maintenance(now time.Time) {
	s.mu.Lock()
	for k, v := range s.access {
		if !v.After(now) {
			delete(s.access, k)
		}
	}
	for k, v := range s.refresh {
		if !v.Expires.After(now) {
			delete(s.refresh, k)
		}
	}
	for k, v := range s.rest {
		if !v.Expires.After(now) {
			delete(s.rest, k)
		}
	}
	for k, v := range s.pegasus {
		if !v.After(now) {
			delete(s.pegasus, k)
		}
	}
	live := s.live(now)
	// Keep auth and directory expiry atomic, in the same lock order as publish.
	if s.dir != nil {
		d := s.dir
		d.mu.Lock()
		stale := []*group{}
		for _, g := range d.Groups {
			idle := now.Sub(g.Active)
			if idle >= time.Duration(s.Config.RoomIdleSeconds)*time.Second || (!live[g.Session] && idle >= 300*time.Second) {
				stale = append(stale, g)
			}
		}
		for _, g := range stale {
			d.remove(g)
		}
		d.expirePublic(live, now)
		d.mu.Unlock()
	}
	s.mu.Unlock()
	s.logger.event(map[string]any{"server_summary": map[string]any{"responses": s.responses.Load(), "unsupported": s.unsupported.Load(), "storage_errors": s.storageErrors.Load()}})
}
func (s *Server) status() (map[string]any, error) {
	s.mu.Lock()
	now := time.Now()
	live := s.live(now)
	out := map[string]any{"protocol": ProtocolID, "implementation": "go", "release": Release, "uptime_seconds": int(time.Since(s.started).Seconds()), "durable_metadata": s.state.Persistent, "tls": s.Config.TLSCert != "", "access_key_required": s.key != "", "logging": "summary", "rest_sessions": len(s.rest), "pegasus_sessions": len(s.pegasus), "profiles": len(s.profiles), "local_counters": len(s.counters), "http": map[string]uint64{"responses": s.responses.Load(), "unsupported": s.unsupported.Load(), "storage_errors": s.storageErrors.Load(), "log_write_errors": s.logger.errors.Load()}}
	if s.Config.VerboseLog {
		out["logging"] = "verbose"
	}
	if s.dir != nil {
		s.dir.mu.Lock()
		out["rooms"] = s.dir.summary()
		out["lobbies"] = s.dir.lobbySummary(live, now)
		stats := map[string]uint64{}
		for k, v := range s.dir.UDP {
			stats[k] = v
		}
		out["udp"] = stats
		s.dir.mu.Unlock()
	}
	s.mu.Unlock()
	out["capabilities"] = map[string]any{"private_match_experimental": s.dir != nil, "local_lobby_directory_experimental": s.dir != nil, "public_lobby_browser": s.dir != nil, "same_room_native_reconnect": false, "full_match_end_verified": false, "separate_pc_verified": false, "vps_verified": false, "current_revision_native_gameplay_verified": false, "public_lobby_browser_verified": false, "custom_content_experimental": s.content != nil, "custom_superstar_gameplay_verified": false, "native_image_package_client_verified": false}
	if s.content != nil {
		v, e := s.content.summary()
		if e != nil {
			return nil, e
		}
		out["custom_content"] = v
	}
	out["capabilities"].(map[string]any)["native_image_sync"] = s.content != nil
	out["native_image_sync"] = map[string]uint64{"created": s.imageCreated.Load(), "updated": s.imageUpdated.Load(), "unchanged": s.imageUnchanged.Load()}
	if s.imageImport != nil {
		out["native_image_import"] = s.imageImport
	}
	return out, nil
}
func (s *Server) reply(w http.ResponseWriter, r *http.Request, status int, data any) {
	body, e := marshalJSON(data)
	if e != nil {
		status = 500
		body = []byte(`{"error":"Response unavailable"}`)
	}
	s.replyBytes(w, r, status, body, "application/json; charset=utf-8", false)
}
func (s *Server) replyBytes(w http.ResponseWriter, r *http.Request, status int, body []byte, ct string, binaryFields bool) {
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-cache")
	h.Set("X-2k-Server-Time", strconv.FormatInt(time.Now().Unix(), 10))
	h.Set("Connection", "close")
	h.Set("Server", "WWEPrivateLabGo")
	if binaryFields {
		// Preserve the established native spelling on the wire. Header.Set would
		// canonicalize this underscore-containing name to Vcfieldlist_size.
		h["VCFIELDLIST_SIZE"] = []string{strconv.Itoa(len(body))}
	}
	s.responses.Add(1)
	if status == 501 {
		s.unsupported.Add(1)
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	if status >= 400 || s.Config.VerboseLog {
		s.logger.event(map[string]any{"method": r.Method, "path": safePath(r.URL.Path), "status": status, "response_bytes": len(body)})
	}
}
func safePath(path string) string {
	switch path {
	case "/lab/images/sync":
		return path
	case "/health", "/status", "/discovery/v1/services", "/api/Version", "/api/Login", "/Session/login", "/Session/update", "/api/GetPresets", "/api/GetParams", "/api/ContentBlacklist", "/api/PlayerGetMe", "/api/PlayerSet", "/api/LeaderboardPlayerGet", "/api/LeaderboardPlayerInc", "/api/LeaderboardPlayerMax", "/api/Ping", "/api/ResourceList", "/api/EulaGet", "/api/EulaAccept", "/api/PrivacyGet", "/api/PrivacyAccept", "/api/TOSGet", "/api/TOSAccept", "/core/sso/v1/auth/tokens", "/core/ssoRefresh/v1/auth/tokens", "/core/ssoHeartBeat/v1/presence/heartbeats", "/lab/vconline/match/create", "/lab/vconline/match/search", "/lab/vconline/match/update", "/lab/vconline/match/interlocked_update", "/lab/vconline/match/list", "/lab/lobbies/publish", "/lab/lobbies/withdraw", "/lab/lobbies/list", "/api/ContentUpload", "/api/ContentSave", "/api/ContentMetaGet", "/api/ContentSearch":
		return path
	}
	if strings.HasPrefix(path, cdnNamespace) {
		return "<custom-asset>"
	}
	return "<unreconstructed>"
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.lifeMu.Lock()
	if s.closing {
		s.lifeMu.Unlock()
		w.Header().Set("Connection", "close")
		http.Error(w, "Server is shutting down", http.StatusServiceUnavailable)
		return
	}
	s.handlers.Add(1)
	s.lifeMu.Unlock()
	defer s.handlers.Done()
	defer func() {
		if recover() != nil {
			s.logger.event(map[string]any{"request_failed": true})
			panic(http.ErrAbortHandler)
		}
	}()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(10 * time.Second))
	if s.key != "" {
		values := r.Header.Values("X-WWE-Lab-Key")
		if len(values) != 1 || !accessMatches(values[0], s.key) {
			s.reply(w, r, 401, errorJSON("Private server access key required"))
			return
		}
	}
	if len(r.TransferEncoding) > 0 || len(r.Header.Values("Content-Length")) > 1 {
		s.reply(w, r, 400, errorJSON("Unsupported HTTP request framing"))
		return
	}
	if r.Method == "GET" {
		s.get(w, r)
		return
	}
	if r.Method != "POST" {
		s.reply(w, r, 501, errorJSON("Protocol endpoint not reconstructed"))
		return
	}
	path := r.URL.Path
	switch path {
	case "/api/Version":
		s.reply(w, r, 200, map[string]any{"Version": 1})
	case "/Session/login", "/Session/update", "/api/Login":
		s.login(w, r)
	case "/core/sso/v1/auth/tokens", "/core/ssoRefresh/v1/auth/tokens", "/core/ssoHeartBeat/v1/presence/heartbeats":
		s.core(w, r)
	case "/lab/images/sync":
		s.imageSync(w, r)
	case "/api/ContentUpload", "/api/ContentSave", "/api/ContentMetaGet", "/api/ContentSearch":
		s.nativeContent(w, r)
	default:
		if strings.HasPrefix(path, "/lab/vconline/match/") {
			s.match(w, r)
		} else if path == "/lab/lobbies/publish" || path == "/lab/lobbies/withdraw" || path == "/lab/lobbies/list" {
			s.lobbies(w, r)
		} else if safePath(path) != "<unreconstructed>" && strings.HasPrefix(path, "/api/") {
			s.restContent(w, r)
		} else {
			s.reply(w, r, 501, map[string]any{"error": "Protocol endpoint not reconstructed", "stage": "experimental-private-match"})
		}
	}
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		var udp any
		if s.dir != nil {
			udp = s.dir.Endpoint.Port
		}
		s.reply(w, r, 200, map[string]any{"stage": "experimental-private-match", "multiplayer": false, "protocol": ProtocolID, "target_sha256": TargetSHA, "advertised_host": s.Config.AdvertiseHost, "http_port": s.Config.AdvertiseHTTPPort, "udp_port": udp, "matchmaking": s.dir != nil, "transport": map[bool]string{true: "https", false: "http-over-trusted-network"}[s.Config.TLSCert != ""], "access_key_required": s.key != "", "release": Release, "implementation": "go"})
	case "/status":
		v, e := s.status()
		if e != nil {
			s.reply(w, r, 503, errorJSON("Local content storage is unavailable"))
		} else {
			s.reply(w, r, 200, v)
		}
	case "/discovery/v1/services":
		entries := []any{}
		for _, name := range strings.Fields("unknown sso ssoHeartBeat ssoRefresh ssoLegalDocuments ssoAccountLinking telemetry discovery entitlements codes license store catalog promotions promotionsV2 wallet purchase matchmaker clouddata cloudprograms ssoAccountCreation") {
			context := "/core/" + name + "/v1"
			scheme := "http"
			if s.Config.TLSCert != "" {
				scheme = "https"
			}
			entries = append(entries, map[string]any{"serviceId": name, "name": name, "baseUrl": s.origin + context, "scheme": scheme, "host": strings.TrimPrefix(s.origin, scheme+"://"), "contextPath": context, "tags": []any{}})
		}
		w.Header().Set("X-2k-Result-Total", strconv.Itoa(len(entries)))
		w.Header().Set("X-2k-Result-Count", strconv.Itoa(len(entries)))
		w.Header().Set("X-2k-Result-More", "false")
		s.reply(w, r, 200, entries)
	default:
		if strings.HasPrefix(r.URL.Path, cdnNamespace) {
			s.asset(w, r)
		} else {
			s.reply(w, r, 501, map[string]any{"error": "Protocol endpoint not reconstructed", "stage": "experimental-private-match"})
		}
	}
}
func body(r *http.Request, min, max int64) ([]byte, error) {
	if r.ContentLength < min || r.ContentLength > max {
		return nil, fail(413, "Invalid request length")
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, r.ContentLength+1))
	if e != nil || int64(len(b)) != r.ContentLength {
		return nil, fail(400, "Incomplete request")
	}
	return b, nil
}
func requestJSON(r *http.Request, min, max int64) (map[string]any, error) {
	raw, e := body(r, min, max)
	if e != nil {
		return nil, e
	}
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if encoding == "" {
		encoding = "identity"
	}
	raw, e = wire.Decompress(raw, encoding, wire.MaxBody)
	if e != nil {
		return nil, fail(400, "Invalid JSON")
	}
	if len(raw) == 0 && min == 0 && encoding == "identity" {
		return map[string]any{}, nil
	}
	prefix := bytes.TrimLeft(raw, " \r\n\t")
	if len(prefix) > 1 && (prefix[0] == '{' || prefix[0] == '[') && prefix[1] != 0 {
		raw = bytes.TrimRight(raw, "\x00")
	}
	raw, e = jsonEncoding(raw)
	if e != nil {
		return nil, e
	}
	return jsonObject(raw, false)
}
func jsonEncoding(b []byte) ([]byte, error) {
	if bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}) {
		return b[3:], nil
	}
	little, bits := false, 0
	if bytes.HasPrefix(b, []byte{0xff, 0xfe, 0, 0}) {
		little = true
		bits = 32
		b = b[4:]
	} else if bytes.HasPrefix(b, []byte{0, 0, 0xfe, 0xff}) {
		bits = 32
		b = b[4:]
	} else if bytes.HasPrefix(b, []byte{0xff, 0xfe}) {
		little = true
		bits = 16
		b = b[2:]
	} else if bytes.HasPrefix(b, []byte{0xfe, 0xff}) {
		bits = 16
		b = b[2:]
	} else if len(b) >= 4 {
		if b[0] == 0 && b[1] == 0 {
			bits = 32
		} else if b[1] == 0 && b[2] == 0 && b[3] == 0 {
			bits = 32
			little = true
		} else if b[0] == 0 {
			bits = 16
		} else if b[1] == 0 {
			bits = 16
			little = true
		}
	}
	if bits == 0 {
		return b, nil
	}
	var order binary.ByteOrder = binary.BigEndian
	if little {
		order = binary.LittleEndian
	}
	out := []byte{}
	if len(b)%(bits/8) != 0 {
		return nil, errors.New("invalid JSON encoding")
	}
	if bits == 32 {
		for i := 0; i < len(b); i += 4 {
			r := rune(order.Uint32(b[i:]))
			if !utf8.ValidRune(r) {
				return nil, errors.New("invalid JSON encoding")
			}
			out = utf8.AppendRune(out, r)
		}
	} else {
		values := make([]uint16, len(b)/2)
		for i := range values {
			values[i] = order.Uint16(b[2*i:])
		}
		for i := 0; i < len(values); i++ {
			v := values[i]
			if v >= 0xd800 && v <= 0xdbff {
				if i+1 >= len(values) || values[i+1] < 0xdc00 || values[i+1] > 0xdfff {
					return nil, errors.New("invalid JSON encoding")
				}
				i++
			} else if v >= 0xdc00 && v <= 0xdfff {
				return nil, errors.New("invalid JSON encoding")
			}
		}
		for _, r := range utf16.Decode(values) {
			out = utf8.AppendRune(out, r)
		}
	}
	return out, nil
}
func sessionHeader(r *http.Request) (uint64, error) {
	v := r.Header.Values("S")
	if len(v) != 1 || len(v[0]) < 1 || len(v[0]) > 20 || !digits(v[0]) {
		return 0, errors.New("invalid session header")
	}
	n, e := strconv.ParseUint(v[0], 10, 64)
	if e != nil || n == 0 {
		return 0, errors.New("invalid session header")
	}
	return n, nil
}
func (s *Server) restUser(r *http.Request, touch bool) (string, error) {
	v := r.Header.Values("X-Sessionid")
	if len(v) > 1 || (len(v) == 1 && len(v[0]) > 256) {
		return "", fail(400, "Invalid REST session header")
	}
	if len(v) == 0 {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, has := s.rest[v[0]]
	if !has || !session.Expires.After(time.Now()) {
		delete(s.rest, v[0])
		return "", nil
	}
	if touch {
		session.Expires = time.Now().Add(time.Hour)
		s.rest[v[0]] = session
	}
	return session.User, nil
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/api/Login" {
		data, e := requestJSON(r, 1, wire.MaxBody)
		if e != nil {
			s.reply(w, r, statusCode(e, 400), errorJSON("Invalid or unsupported Pegasus request format"))
			return
		}
		if v, has := data["Login"]; has {
			login, ok := jstr(v)
			if !ok || len([]rune(login)) < 1 || len([]rune(login)) > 256 {
				s.reply(w, r, 400, errorJSON("Invalid or unsupported Pegasus request format"))
				return
			}
		}
		uid := identity(data)
		sid, e := randomHex(24)
		if e != nil {
			s.reply(w, r, 503, errorJSON("Local session unavailable"))
			return
		}
		s.mu.Lock()
		if len(s.rest) >= 4096 {
			s.mu.Unlock()
			s.reply(w, r, 503, errorJSON("Local session capacity reached"))
			return
		}
		if s.profiles[uid] == nil {
			if len(s.profiles) >= maxProfiles {
				s.mu.Unlock()
				s.reply(w, r, 503, errorJSON("Local profile capacity reached"))
				return
			}
			p := player(uid, time.Now())
			if e = s.state.profile(uid, p); e != nil {
				s.mu.Unlock()
				s.stateFailure(w, r)
				return
			}
			s.profiles[uid] = p
		}
		s.rest[sid] = restSession{uid, time.Now().Add(time.Hour)}
		s.mu.Unlock()
		s.reply(w, r, 200, map[string]any{"Result": 0, "SessionID": sid, "UserID": uid, "NewUser": false})
		return
	}
	raw, e := body(r, 1, wire.MaxBody)
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if e == nil && encoding != "" && encoding != "identity" && encoding != "gzip" {
		e = errors.New("unsupported encoding")
	}
	if e == nil {
		_, e = wire.Decode(raw, false)
	}
	if e != nil {
		s.reply(w, r, statusCode(e, 400), errorJSON("Invalid or unsupported Pegasus request format"))
		return
	}
	var key uint64
	s.mu.Lock()
	if path == "/Session/update" {
		key, e = sessionHeader(r)
		if e != nil {
			s.mu.Unlock()
			s.reply(w, r, 400, errorJSON("Invalid or unsupported Pegasus request format"))
			return
		}
		if !s.pegasus[key].After(time.Now()) {
			delete(s.pegasus, key)
			s.mu.Unlock()
			s.reply(w, r, 401, errorJSON("Unknown or expired local session"))
			return
		}
	} else {
		if len(s.pegasus) >= 4096 {
			s.mu.Unlock()
			s.reply(w, r, 503, errorJSON("Local session capacity reached"))
			return
		}
		var seed [8]byte
		if _, e = rand.Read(seed[:]); e != nil {
			s.mu.Unlock()
			s.reply(w, r, 503, errorJSON("Local session unavailable"))
			return
		}
		key = binary.LittleEndian.Uint64(seed[:])&((1<<48)-1) | 1<<48
	}
	s.pegasus[key] = time.Now().Add(time.Hour)
	s.mu.Unlock()
	s.replyBytes(w, r, 200, wire.Session(key, s.catalog, time.Now()), "application/octet-stream", true)
}
func (s *Server) stateFailure(w http.ResponseWriter, r *http.Request) {
	s.storageErrors.Add(1)
	s.reply(w, r, 503, errorJSON("Local state unavailable; mutation was not acknowledged"))
}
func (s *Server) issue(account string) (map[string]any, error) {
	return s.issueTokens(account, nil)
}
func (s *Server) issueTokens(account string, previous *string) (map[string]any, error) {
	refresh, e := randomHex(32)
	if e != nil {
		return nil, e
	}
	access, e := randomHex(32)
	if e != nil {
		return nil, e
	}
	access = "local-" + access
	s.mu.Lock()
	defer s.mu.Unlock()
	refreshCount := len(s.refresh)
	if previous != nil {
		old, has := s.refresh[*previous]
		if !has || !old.Expires.After(time.Now()) {
			return nil, fail(401, "Unknown local refresh token")
		}
		account = old.Account
		refreshCount--
	}
	if refreshCount >= 4096 || len(s.access) >= 4096 {
		return nil, fail(503, "Local session capacity reached")
	}
	// Retire the old credential only after all fallible preparation succeeded.
	if previous != nil {
		delete(s.refresh, *previous)
	}
	s.refresh[refresh] = refreshSession{account, time.Now().Add(24 * time.Hour)}
	s.access[access] = time.Now().Add(time.Hour)
	return map[string]any{"accessToken": access, "accessTokenExpiresIn": 3600, "refreshToken": refresh, "refreshTokenExpiresIn": 86400, "accountId": account, "accountType": 2, "parentAccountId": "", "displayName": "Giocatore#0001"}, nil
}
func (s *Server) core(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/core/ssoHeartBeat/v1/presence/heartbeats" {
		token := ""
		if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
			token = strings.TrimPrefix(authorization, "Bearer ")
		}
		s.mu.Lock()
		valid := s.access[token].After(time.Now())
		s.mu.Unlock()
		if !valid {
			s.reply(w, r, 401, errorJSON("Unknown or expired local access token"))
			return
		}
		s.reply(w, r, 201, map[string]any{})
		return
	}
	data, e := requestJSON(r, 1, wire.MaxBody)
	if e != nil {
		s.reply(w, r, statusCode(e, 400), errorJSON("Invalid JSON"))
		return
	}
	if data["accountType"] != "platform" {
		s.reply(w, r, 400, errorJSON("Expected platform credentials"))
		return
	}
	credentials, ok := data["credentials"].(map[string]any)
	if !ok {
		s.reply(w, r, 400, errorJSON("Missing credentials object"))
		return
	}
	account := ""
	var previous *string
	switch credentials["type"] {
	case "refresh":
		token, ok := jstr(credentials["refreshToken"])
		if !ok {
			s.reply(w, r, 400, errorJSON("Invalid refresh token type"))
			return
		}
		previous = &token
	case "steam":
		steamID, ok := jstr(credentials["steamUserId"])
		if !ok || !digits(steamID) {
			s.reply(w, r, 400, errorJSON("Expected decimal Steam ID string"))
			return
		}
		ticket, ok := jstr(credentials["encryptedAppTicket"])
		if !ok || ticket == "" {
			s.reply(w, r, 400, errorJSON("Expected ticket string"))
			return
		}
		account = localAccount(steamID)
	default:
		s.reply(w, r, 400, errorJSON("Unsupported credential type"))
		return
	}
	response, e := s.issueTokens(account, previous)
	if e != nil {
		s.reply(w, r, statusCode(e, 503), errorJSON("Local session unavailable"))
		return
	}
	s.reply(w, r, 200, response)
}

type boundedListener struct {
	net.Listener
	slots  chan struct{}
	policy *networkPolicy
}
type boundedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *boundedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		a, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok || !l.policy.admit(a.AddrPort().Addr().Unmap(), "http", time.Now()) {
			c.Close()
			continue
		}
		select {
		case l.slots <- struct{}{}:
			return &boundedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
