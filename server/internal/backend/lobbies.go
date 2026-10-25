package backend

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"wwe2k22-server/internal/wire"
)

const heartbeat = 90 * time.Second

var numericPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,9})$`)
var buildPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)
var metadataKeys = map[string]bool{"spec_dev": true, "spec_fps": true, "build_no": true, "spec_pubOpen": true, "spec_privOpen": true, "spec_hostID": true, "spec_vc_matchid": true, "spec_team": true, "spec_team_num": true, "spec_tagteamflag": true, "spec_voiceChat": true, "spec_migrate": true}

type publication struct {
	Lobby        uint64
	Room         *room
	Group        *group
	Session      uint64
	Metadata     map[string]string
	Refreshed    time.Time
	Limit, Count *int
	Descriptor   []byte
}

func numeric32(s string) (int64, bool) {
	if !numericPattern.MatchString(s) {
		return 0, false
	}
	n, e := strconv.ParseInt(s, 10, 32)
	return n, e == nil
}
func isNumericKey(s string) bool { _, ok := numeric32(s); return ok }
func (d *directory) expirePublic(live map[uint64]bool, now time.Time) {
	for id, e := range d.Publications {
		if now.Sub(e.Refreshed) >= heartbeat || !live[e.Session] || d.Rooms[e.Room.ID] != e.Room || d.Sessions[e.Session] != e.Group || d.Groups[e.Group.ID] != e.Group || e.Room.Groups[e.Group.ID] != e.Group || e.Room.Owner != e.Group.ID {
			delete(d.Publications, id)
		}
	}
}
func full(e *publication) bool {
	return (e.Room.Capacity != nil && uint64(participants(e.Room)) >= *e.Room.Capacity) || (e.Limit != nil && e.Count != nil && *e.Count >= *e.Limit)
}
func publicOrder(d *directory) []*publication {
	ids := make([]uint64, 0, len(d.Publications))
	for id := range d.Publications {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]*publication, 0, len(ids))
	for _, id := range ids {
		out = append(out, d.Publications[id])
	}
	return out
}
func (d *directory) lobbySummary(live map[uint64]bool, now time.Time) map[string]any {
	d.expirePublic(live, now)
	n := 0
	for _, e := range d.Publications {
		if e.Descriptor != nil {
			n++
		}
	}
	return map[string]any{"published": len(d.Publications), "limit": 128, "heartbeat_seconds": 90, "native_descriptors": n, "last_native_list": d.LastScan}
}
func (d *directory) lobby(op string, key uint64, data map[string]any, live map[uint64]bool, now time.Time) (map[string]any, error) {
	d.expirePublic(live, now)
	if !live[key] {
		return nil, fail(403, "Native match ownership required")
	}
	if op == "list" {
		return d.listJSON(data)
	}
	allowed := []string{"lobby_id", "match_id"}
	if op == "publish" {
		allowed = append(allowed, "metadata", "visibility", "joinable", "member_limit", "member_count", "native_descriptor")
	} else if op != "withdraw" {
		return nil, errors.New("unknown lobby operation")
	}
	if !fieldsAllowed(data, allowed...) {
		return nil, errors.New("invalid lobby fields")
	}
	id, e := canonicalID(data["lobby_id"])
	if e != nil {
		return nil, e
	}
	instance := (id >> 32) & 0xfffff
	if (id>>52)&15 != 8 || (instance != 0x40000 && instance != 0x60000) || id>>56 < 1 || id>>56 > 4 || uint32(id) == 0 {
		return nil, errors.New("invalid Steam lobby ID")
	}
	rid, e := canonicalID(data["match_id"])
	if e != nil {
		return nil, e
	}
	r, g := d.Rooms[rid], d.Sessions[key]
	if r == nil || g == nil || g.Room != rid || r.Groups[g.ID] != g || d.Groups[g.ID] != g || r.Owner != g.ID {
		return nil, fail(403, "Native match ownership required")
	}
	if old := d.Publications[id]; old != nil && (old.Room != r || old.Group != g || old.Session != key) {
		return nil, fail(403, "Native match ownership required")
	}
	if op == "withdraw" {
		_, found := d.Publications[id]
		delete(d.Publications, id)
		return map[string]any{"withdrawn": found}, nil
	}
	visibility, ok := jstr(data["visibility"])
	joinable, valid := jbool(data["joinable"])
	if !ok || !valid || (visibility != "public" && visibility != "private") {
		return nil, errors.New("invalid visibility")
	}
	raw, ok := data["metadata"].(map[string]any)
	if !ok || len(raw) < 1 || len(raw) > 64 {
		return nil, errors.New("invalid metadata")
	}
	meta := map[string]string{}
	size := 0
	for k, v := range raw {
		s, ok := jstr(v)
		if !ok || (!metadataKeys[k] && !isNumericKey(k)) || utf8.RuneCountInString(s) > 256 || !noControls(s) {
			return nil, errors.New("invalid metadata")
		}
		size += len(k) + len(s)
		meta[k] = s
		if k == "spec_pubOpen" || k == "spec_privOpen" {
			n, valid := numeric32(s)
			if !valid || n < 0 || n > 100 {
				return nil, errors.New("invalid slots")
			}
		}
		if k == "spec_fps" {
			n, valid := numeric32(s)
			if !valid || n < 0 || n > 1000 {
				return nil, errors.New("invalid fps")
			}
		}
		if k == "build_no" && (len(s) > 32 || !buildPattern.MatchString(s)) {
			return nil, errors.New("invalid build")
		}
	}
	_, hostErr := canonicalID(meta["spec_hostID"])
	pub, pok := meta["spec_pubOpen"]
	_, qok := meta["spec_privOpen"]
	if size > 16384 || meta["spec_vc_matchid"] != decimal(rid) || hostErr != nil || len(meta["spec_dev"]) < 1 || utf8.RuneCountInString(meta["spec_dev"]) > 32 || !pok || !qok {
		return nil, errors.New("missing metadata")
	}
	var limit, count *int
	_, hasL := data["member_limit"]
	_, hasC := data["member_count"]
	if hasL || hasC {
		l, ok := jint(data["member_limit"])
		c, valid := jint(data["member_count"])
		if !ok || !valid || l < 1 || l > 100 || c < 0 || c > l {
			return nil, errors.New("invalid member counts")
		}
		a, b := int(l), int(c)
		limit, count = &a, &b
	}
	var desc []byte
	if value, has := data["native_descriptor"]; has {
		s, ok := jstr(value)
		if !ok || len(s) != 1216 {
			return nil, errors.New("invalid descriptor encoding")
		}
		desc, e = hex.DecodeString(s)
		owner, _ := canonicalID(meta["spec_hostID"])
		var a, b [8]byte
		binary.LittleEndian.PutUint64(a[:], id)
		binary.LittleEndian.PutUint64(b[:], rid)
		if e != nil || descriptorRejection(desc, owner) != "" || (!bytes.Contains(desc, a[:]) && !bytes.Contains(desc, b[:])) {
			return nil, errors.New("invalid descriptor identity")
		}
	}
	slots, _ := numeric32(pub)
	public := visibility == "public" && joinable && slots > 0
	for lobby, entry := range d.Publications {
		if entry.Room == r {
			delete(d.Publications, lobby)
		}
	}
	if public {
		if len(d.Publications) >= 128 {
			return nil, errors.New("lobby capacity")
		}
		d.Publications[id] = &publication{id, r, g, key, meta, now, limit, count, desc}
	}
	return map[string]any{"published": public, "heartbeat_seconds": 90}, nil
}
func descriptorRejection(b []byte, owner uint64) string {
	if len(b) == 0 {
		return "descriptor_missing"
	}
	if len(b) < 0x161 || len(b) > 0x260 {
		return "length"
	}
	if binary.LittleEndian.Uint32(b) != 10 || binary.LittleEndian.Uint32(b[4:]) != 0x260 {
		return "header"
	}
	if binary.LittleEndian.Uint64(b[0x150:]) != owner {
		return "owner"
	}
	end := bytes.IndexByte(b[0x15b:], 0)
	if end < 0 {
		return "name"
	}
	if len(b) != 0x260 && len(b) != 0x161+end {
		return "length"
	}
	v := math.Float32frombits(binary.LittleEndian.Uint32(b[0x54:]))
	if v == 0 || math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
		return "marker"
	}
	return ""
}
func (d *directory) nativeList(key uint64, f wire.Fields, live map[uint64]bool, now time.Time) ([]byte, error) {
	limit, e := number(f, 0xcf4286e1, wire.Int64, 15)
	if e != nil || limit < 1 || limit > 50 {
		return nil, errors.New("invalid list limit")
	}
	timeout, e := number(f, 0xa2b77e50, wire.Int64, 30)
	if e != nil || timeout > 120 {
		return nil, errors.New("invalid timeout")
	}
	wanted, e := number(f, 0xba6857e5, wire.Int64, 0)
	if e != nil {
		return nil, e
	}
	mask, e := number(f, maskID, wire.Int64, 0)
	if e != nil || wanted&^mask != 0 {
		return nil, errors.New("invalid filter")
	}
	d.expirePublic(live, now)
	if !live[key] {
		return nil, fail(401, "Unknown or expired local session")
	}
	excluded := map[string]int{}
	for _, s := range strings.Fields("own full capacity_missing attributes_missing filter length header owner marker name descriptor_missing") {
		excluded[s] = 0
	}
	examined, used := 0, 0
	blobs := [][]byte{}
	records := []wire.Field{}
	for _, p := range publicOrder(d) {
		examined++
		switch {
		case p.Session == key:
			excluded["own"]++
			continue
		case full(p):
			excluded["full"]++
			continue
		case p.Room.Capacity == nil:
			excluded["capacity_missing"]++
			continue
		case p.Room.Attributes == nil:
			excluded["attributes_missing"]++
			continue
		case mask != 0 && *p.Room.Attributes&mask != wanted:
			excluded["filter"]++
			continue
		}
		candidates := p.Room.Data
		if p.Descriptor != nil {
			candidates = [][]byte{p.Descriptor}
		}
		owner, _ := canonicalID(p.Metadata["spec_hostID"])
		reason := "descriptor_missing"
		for _, b := range candidates {
			reason = descriptorRejection(b, owner)
			if reason == "" {
				blobs = append(blobs, b)
				cap := *p.Room.Capacity
				records = append(records, wire.Num(matchID, wire.Int64, p.Room.ID), wire.Num(attributesID, wire.Int64, *p.Room.Attributes), wire.Num(0xba769d4f, wire.Int64, cap), wire.Num(0x3f8d6d18, wire.Int64, cap-uint64(participants(p.Room))))
				if p.Descriptor != nil {
					used++
				}
				break
			}
		}
		if reason != "" {
			excluded[reason]++
		}
		if uint64(len(blobs)) >= limit {
			break
		}
	}
	d.LastScan = map[string]any{"registered": len(d.Publications), "examined": examined, "returned": len(blobs), "published_descriptor_used": used, "excluded": excluded}
	records = append(records, wire.Num(wire.Result, wire.Int32, wire.Success), wire.Num(0xa25aa38a, wire.Int64, uint64(len(blobs))))
	if len(blobs) == 0 {
		blobs = [][]byte{{}}
	}
	for _, b := range blobs {
		records = append(records, wire.Binary(sessionData, b))
	}
	return wire.Encode(wire.Sorted(records))
}

type lobbyFilter struct {
	Key, Kind string
	Value     any
	Compare   int64
}

func compare(c int, op int64) bool {
	switch op {
	case -2:
		return c <= 0
	case -1:
		return c < 0
	case 0:
		return c == 0
	case 1:
		return c > 0
	case 2:
		return c >= 0
	case 3:
		return c != 0
	}
	return false
}
func (d *directory) listJSON(data map[string]any) (map[string]any, error) {
	if !fieldsAllowed(data, "filters", "result_count") {
		return nil, errors.New("invalid list fields")
	}
	count := int64(10)
	if v, ok := data["result_count"]; ok {
		var valid bool
		count, valid = jint(v)
		if !valid || count < 1 || count > 50 {
			return nil, errors.New("invalid result count")
		}
	}
	filters := []lobbyFilter{}
	if raw, has := data["filters"]; has {
		items, ok := raw.([]any)
		if !ok || len(items) > 32 {
			return nil, errors.New("invalid filters")
		}
		for _, v := range items {
			m, ok := v.(map[string]any)
			if !ok || len(m) != 4 || !fieldsAllowed(m, "key", "type", "value", "comparison") {
				return nil, errors.New("invalid filter")
			}
			key, ok := jstr(m["key"])
			kind, valid := jstr(m["type"])
			c, validC := jint(m["comparison"])
			allowed := metadataKeys[key] && key != "spec_hostID" && key != "spec_vc_matchid"
			if !ok || !valid || !validC || c < -2 || c > 3 || (!allowed && !isNumericKey(key)) {
				return nil, errors.New("unsupported filter")
			}
			if kind == "numeric" {
				n, ok := jint(m["value"])
				if !ok || n < math.MinInt32 || n > math.MaxInt32 || key == "spec_dev" || key == "build_no" {
					return nil, errors.New("invalid numeric filter")
				}
				filters = append(filters, lobbyFilter{key, kind, n, c})
			} else if kind == "string" {
				s, ok := jstr(m["value"])
				if !ok || utf8.RuneCountInString(s) > 256 || !noControls(s) {
					return nil, errors.New("invalid string filter")
				}
				filters = append(filters, lobbyFilter{key, kind, s, c})
			} else {
				return nil, errors.New("unsupported filter type")
			}
		}
	}
	entries := []any{}
	for _, p := range publicOrder(d) {
		if full(p) {
			continue
		}
		matched := true
		for _, f := range filters {
			actual, has := p.Metadata[f.Key]
			if !has {
				matched = false
				break
			}
			cmp := 0
			if f.Kind == "numeric" {
				n, ok := numeric32(actual)
				if !ok {
					matched = false
					break
				}
				v := f.Value.(int64)
				if n < v {
					cmp = -1
				} else if n > v {
					cmp = 1
				}
			} else {
				cmp = strings.Compare(actual, f.Value.(string))
			}
			if !compare(cmp, f.Compare) {
				matched = false
				break
			}
		}
		if matched {
			entries = append(entries, map[string]any{"lobby_id": decimal(p.Lobby), "metadata": p.Metadata, "visibility": "public", "joinable": true, "member_limit": p.Limit, "member_count": p.Count})
		}
	}
	total := len(entries)
	if len(entries) > int(count) {
		entries = entries[:count]
	}
	return map[string]any{"lobbies": entries, "total": total, "more": total > int(count)}, nil
}
