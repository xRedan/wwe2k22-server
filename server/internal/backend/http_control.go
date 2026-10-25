package backend

import (
	"net/http"
	"strings"
	"time"
	"wwe2k22-server/internal/wire"
)

func (s *Server) restContent(w http.ResponseWriter, r *http.Request) {
	minimum := int64(1)
	if r.URL.Path == "/api/Ping" {
		minimum = 0
	}
	data, e := requestJSON(r, minimum, wire.MaxBody)
	if e != nil {
		s.reply(w, r, statusCode(e, 400), errorJSON("Invalid REST content request"))
		return
	}
	path := r.URL.Path
	if path == "/api/GetPresets" {
		if v, has := data["Have"]; has {
			m, ok := v.(map[string]any)
			if !ok {
				s.reply(w, r, 400, errorJSON("Invalid REST content request"))
				return
			}
			for _, v := range m {
				if _, ok := jint(v); !ok {
					s.reply(w, r, 400, errorJSON("Invalid REST content request"))
					return
				}
			}
		}
	}
	if strings.HasSuffix(path, "Get") && (strings.HasPrefix(path, "/api/Eula") || strings.HasPrefix(path, "/api/Privacy") || strings.HasPrefix(path, "/api/TOS")) {
		if v, has := data["Lang"]; has {
			if _, ok := jstr(v); !ok {
				s.reply(w, r, 400, errorJSON("Invalid REST content request"))
				return
			}
		}
	}
	uid, e := s.restUser(r, true)
	if e != nil {
		s.reply(w, r, 400, errorJSON("Invalid REST content request"))
		return
	}
	for _, name := range []string{"Eula", "Privacy", "TOS"} {
		if path == "/api/"+name+"Get" || path == "/api/"+name+"Accept" {
			s.notice(w, r, name, data)
			return
		}
	}
	switch path {
	case "/api/GetPresets", "/api/GetParams":
		s.reply(w, r, 200, map[string]any{"Values": map[string]any{}})
		return
	case "/api/Ping":
		s.reply(w, r, 200, map[string]any{})
		return
	case "/api/ResourceList":
		s.reply(w, r, 200, map[string]any{"Items": []any{}})
		return
	}
	if uid == "" {
		s.reply(w, r, 401, errorJSON("Unknown or expired local REST session"))
		return
	}
	if path == "/api/ContentBlacklist" {
		v, e := blacklist(data)
		if e != nil {
			s.reply(w, r, statusCode(e, 400), errorJSON("Invalid REST content request"))
		} else {
			s.reply(w, r, 200, v)
		}
		return
	}
	s.mu.Lock()
	session := s.rest[r.Header.Get("X-Sessionid")]
	profile := s.profiles[uid]
	if session.User != uid || !session.Expires.After(time.Now()) || profile == nil {
		s.mu.Unlock()
		s.reply(w, r, 401, errorJSON("Unknown or expired local REST session"))
		return
	}
	switch path {
	case "/api/PlayerGetMe":
		response := copyObject(profile)
		s.mu.Unlock()
		s.reply(w, r, 200, response)
	case "/api/PlayerSet":
		changes, e := profileChanges(data)
		if e != nil {
			s.mu.Unlock()
			message := "Invalid REST content request"
			if statusCode(e, 400) == 501 {
				message = e.Error()
			}
			s.reply(w, r, statusCode(e, 400), errorJSON(message))
			return
		}
		updated := copyObject(profile)
		for k, v := range changes {
			updated[k] = v
		}
		if e = s.state.profile(uid, updated); e != nil {
			s.mu.Unlock()
			if statusCode(e, 503) == 413 {
				s.reply(w, r, 413, errorJSON("Local profile is too large"))
				return
			}
			s.stateFailure(w, r)
			return
		}
		s.profiles[uid] = updated
		s.mu.Unlock()
		s.reply(w, r, 200, map[string]any{})
	case "/api/LeaderboardPlayerGet":
		s.mu.Unlock()
		s.reply(w, r, 200, map[string]any{"Results": []any{}})
	case "/api/LeaderboardPlayerInc", "/api/LeaderboardPlayerMax":
		changes, e := counterChanges(s.counters, uid, data, strings.HasSuffix(path, "Max"))
		if e != nil {
			s.mu.Unlock()
			message := "Invalid REST content request"
			if statusCode(e, 400) == 501 {
				message = e.Error()
			}
			s.reply(w, r, statusCode(e, 400), errorJSON(message))
			return
		}
		if e = s.state.counters(changes); e != nil {
			s.mu.Unlock()
			s.stateFailure(w, r)
			return
		}
		for k, v := range changes {
			s.counters[k] = v
		}
		s.mu.Unlock()
		s.reply(w, r, 200, map[string]any{})
	default:
		s.mu.Unlock()
		s.reply(w, r, 501, errorJSON("Protocol endpoint not reconstructed"))
	}
}
func (s *Server) notice(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	login, has := data["Login"]
	if login == nil {
		has = false
	}
	loginString := ""
	if has {
		v, ok := jstr(login)
		if !ok || len([]rune(v)) < 1 || len([]rune(v)) > 256 {
			s.reply(w, r, 400, errorJSON("Invalid local notice identity"))
			return
		}
		loginString = v
	}
	accept := strings.HasSuffix(r.URL.Path, "Accept")
	doc := s.documents[name].([]any)
	current, _ := jint(doc[0])
	version, valid := jint(data["Version"])
	if accept {
		if loginString == "" || !valid || version < 1 {
			s.reply(w, r, 400, errorJSON("Expected Login and integer Version"))
			return
		}
		if version != current {
			s.reply(w, r, 409, errorJSON("Unknown local document version"))
			return
		}
	}
	uid := ""
	if has {
		uid = identity(map[string]any{"Login": loginString})
	}
	s.mu.Lock()
	if accept {
		if s.notices[uid] == nil && len(s.notices) >= maxNoticeUsers {
			s.mu.Unlock()
			s.reply(w, r, 503, errorJSON("Local notice capacity reached"))
			return
		}
		if e := s.state.notice(uid, name, version); e != nil {
			s.mu.Unlock()
			s.stateFailure(w, r)
			return
		}
		if s.notices[uid] == nil {
			s.notices[uid] = map[string]int64{}
		}
		s.notices[uid][name] = version
	}
	accepted := s.notices[uid][name]
	s.mu.Unlock()
	if accept {
		s.reply(w, r, 200, map[string]any{})
	} else {
		s.reply(w, r, 200, map[string]any{"Version": current, "Accepted": accepted, "Text": doc[1]})
	}
}
func (s *Server) match(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.URL.Path, "/lab/vconline/match/")
	if s.catalog == nil || (op != "search" && op != "create" && op != "update" && op != "interlocked_update" && op != "list") {
		s.reply(w, r, 501, errorJSON("Unknown local matchmaking operation"))
		return
	}
	key, e := sessionHeader(r)
	if e != nil {
		s.reply(w, r, 400, errorJSON("Invalid local matchmaking request"))
		return
	}
	s.mu.Lock()
	valid := s.pegasus[key].After(time.Now())
	s.mu.Unlock()
	if !valid {
		s.reply(w, r, 401, errorJSON("Unknown or expired local session"))
		return
	}
	raw, e := body(r, 1, wire.MaxBody)
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if e == nil && encoding != "" && encoding != "identity" && encoding != "gzip" {
		e = wire.ErrFormat
	}
	var f wire.Fields
	if e == nil {
		f, e = wire.Decode(raw, true)
	}
	if e != nil {
		s.reply(w, r, statusCode(e, 400), errorJSON("Invalid local matchmaking request"))
		return
	}
	if s.dir == nil {
		s.reply(w, r, 501, map[string]any{"error": "Matchmaking response not reconstructed", "stage": "catalog-installed-request-observation"})
		return
	}
	s.mu.Lock()
	now := time.Now()
	if !s.pegasus[key].After(now) {
		s.mu.Unlock()
		s.reply(w, r, 401, errorJSON("Unknown or expired local session"))
		return
	}
	s.dir.mu.Lock()
	var response []byte
	if op == "list" {
		response, e = s.dir.nativeList(key, f, s.live(now), now)
	} else {
		response, e = s.dir.response(op, key, f, now)
	}
	s.dir.mu.Unlock()
	s.mu.Unlock()
	if e != nil {
		code := statusCode(e, 400)
		msg := "Invalid local matchmaking request"
		if code == 404 {
			msg = "Unknown local match"
		}
		s.reply(w, r, code, errorJSON(msg))
		return
	}
	s.replyBytes(w, r, 200, response, "application/octet-stream", true)
}
func (s *Server) lobbies(w http.ResponseWriter, r *http.Request) {
	key, e := sessionHeader(r)
	if e != nil {
		s.reply(w, r, 400, errorJSON("Invalid local lobby request"))
		return
	}
	s.mu.Lock()
	valid := s.pegasus[key].After(time.Now())
	s.mu.Unlock()
	if !valid {
		s.reply(w, r, 401, errorJSON("Unknown or expired local session"))
		return
	}
	if s.dir == nil {
		s.reply(w, r, 501, errorJSON("Local lobby directory requires native matchmaking"))
		return
	}
	enc := r.Header.Values("Content-Encoding")
	if len(enc) > 1 || (len(enc) == 1 && strings.ToLower(strings.TrimSpace(enc[0])) != "identity") {
		s.reply(w, r, 415, errorJSON("Local lobby requests require identity encoding"))
		return
	}
	data, e := requestJSON(r, 1, 65536)
	if e != nil {
		s.reply(w, r, statusCode(e, 400), errorJSON("Invalid local lobby request"))
		return
	}
	s.mu.Lock()
	now := time.Now()
	live := s.live(now)
	if !live[key] {
		s.mu.Unlock()
		s.reply(w, r, 401, errorJSON("Unknown or expired local session"))
		return
	}
	s.dir.mu.Lock()
	response, e := s.dir.lobby(strings.TrimPrefix(r.URL.Path, "/lab/lobbies/"), key, data, live, now)
	s.dir.mu.Unlock()
	s.mu.Unlock()
	if e != nil {
		code := statusCode(e, 400)
		msg := "Invalid local lobby request"
		if code == 403 {
			msg = "Native match ownership required"
		}
		s.reply(w, r, code, errorJSON(msg))
		return
	}
	if strings.HasSuffix(r.URL.Path, "/list") && len(r.Header.Values("Accept")) == 1 && r.Header.Get("Accept") == "application/vnd.wwe2k22.lobby-ids" {
		raw, e := lobbyIDs(response)
		if e != nil {
			s.reply(w, r, 500, errorJSON("Lobby response unavailable"))
			return
		}
		s.replyBytes(w, r, 200, raw, "application/vnd.wwe2k22.lobby-ids", false)
		return
	}
	s.reply(w, r, 200, response)
}
