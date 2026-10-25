package backend

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"
	"wwe2k22-server/internal/wire"
)

const (
	matchID         uint32 = 0xfcdda3f4
	ownerID         uint32 = 0xfce760f3
	revisionID      uint32 = 0x40c9d476
	localGroup      uint32 = 0x4295a563
	groupIDs        uint32 = 0xd14f6868
	groupEndpoints  uint32 = 0x4853eb3c
	userCounts      uint32 = 0x8e33358a
	userIDs         uint32 = 0xa1559632
	operationID     uint32 = 0xc21260e8
	userData        uint32 = 0x1ba8f718
	sessionData     uint32 = 0x87ff9e19
	minParticipants uint32 = 0x73ef1bd8
	maxParticipants uint32 = 0x9908802a
	attributesID    uint32 = 0x34198061
	maskID          uint32 = 0x80483fef
)

type requestError struct {
	Code    int
	Message string
}

func (e *requestError) Error() string     { return e.Message }
func fail(code int, message string) error { return &requestError{code, message} }

type group struct {
	ID, Session, Room uint64
	Users             []uint64
	Token             []byte
	Data              []byte
	Operation         uint64
	Address           netip.AddrPort
	Closed            bool
	Active            time.Time
}
type room struct {
	ID, Owner, Revision uint64
	Groups              map[uint64]*group
	Data                [][]byte
	Attributes          *uint64
	Capacity            *uint64
}
type directory struct {
	mu           sync.Mutex
	Endpoint     wire.Endpoint
	Rooms        map[uint64]*room
	Groups       map[uint64]*group
	Sessions     map[uint64]*group
	Addresses    map[netip.AddrPort]*group
	Next         uint64
	Random       io.Reader
	Publications map[uint64]*publication
	LastScan     map[string]any
	UDP          map[string]uint64
}

func newDirectory(e wire.Endpoint) *directory {
	var seed [8]byte
	_, _ = io.ReadFull(rand.Reader, seed[:])
	return &directory{Endpoint: e, Rooms: map[uint64]*room{}, Groups: map[uint64]*group{}, Sessions: map[uint64]*group{}, Addresses: map[netip.AddrPort]*group{}, Next: binary.LittleEndian.Uint64(seed[:])&((1<<60)-1) | 1, Random: rand.Reader, Publications: map[uint64]*publication{}, UDP: map[string]uint64{"received": 0, "opens": 0, "forwarded": 0, "policy_dropped": 0, "invalid": 0, "send_errors": 0}}
}
func groupOrder(r *room) []*group {
	out := make([]*group, 0, len(r.Groups))
	for _, g := range r.Groups {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b *group) int { return cmp.Compare(a.ID, b.ID) })
	return out
}
func participants(r *room) int {
	n := 0
	for _, g := range r.Groups {
		n += len(g.Users)
	}
	return n
}
func sameUsers(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func overlaps(a, b []uint64) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
func sameBlobs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
func (d *directory) remove(g *group) {
	r := d.Rooms[g.Room]
	delete(r.Groups, g.ID)
	delete(d.Groups, g.ID)
	delete(d.Sessions, g.Session)
	if g.Address.IsValid() {
		delete(d.Addresses, g.Address)
		g.Address = netip.AddrPort{}
	}
	if len(r.Groups) == 0 {
		delete(d.Rooms, r.ID)
	} else {
		if r.Owner == g.ID {
			r.Owner = groupOrder(r)[0].ID
		}
		r.Revision++
	}
}
func (d *directory) summary() map[string]any {
	n := 0
	for _, g := range d.Groups {
		n += len(g.Users)
	}
	return map[string]any{"active": len(d.Rooms), "groups": len(d.Groups), "participants": n, "udp_bound": len(d.Addresses), "limits": map[string]int{"rooms": 128, "groups": 512}}
}
func number(f wire.Fields, id, kind uint32, def uint64) (uint64, error) {
	n, e := f.Scalar(id, kind, def)
	if e != nil {
		return 0, fail(400, "invalid scalar")
	}
	return n, nil
}
func blobs(f wire.Fields, id uint32, def [][]byte) ([][]byte, error) {
	v, ok := f[id]
	if !ok {
		return def, nil
	}
	n := 0
	out := make([][]byte, 0, len(v))
	for _, b := range v {
		if b.Kind != wire.Blob {
			return nil, fail(400, "invalid blob")
		}
		n += len(b.Data)
		out = append(out, b.Data)
	}
	if len(out) < 1 || len(out) > 100 || n > 65536 {
		return nil, fail(400, "invalid blob vector")
	}
	return out, nil
}

// Caller holds mu. Validate the projected snapshot before replacing membership.
func (d *directory) response(op string, key uint64, f wire.Fields, now time.Time) ([]byte, error) {
	if op != "create" && op != "search" && op != "update" && op != "interlocked_update" {
		return nil, fail(400, "unsupported operation")
	}
	source := d.Sessions[key]
	users := []uint64{}
	if source != nil {
		users = source.Users
	}
	if values, ok := f[userIDs]; ok {
		users = make([]uint64, 0, len(values))
		for _, v := range values {
			if v.Kind != wire.Int64 || v.N == 0 {
				return nil, fail(400, "invalid users")
			}
			users = append(users, v.N)
		}
	}
	if len(users) < 1 || len(users) > 100 {
		return nil, fail(400, "invalid users")
	}
	seen := map[uint64]bool{}
	for _, u := range users {
		if seen[u] {
			return nil, fail(400, "duplicate users")
		}
		seen[u] = true
	}
	requested, e := number(f, matchID, wire.Int64, 0)
	if e != nil {
		return nil, e
	}
	previousOp := uint64(0)
	data := []byte{}
	if source != nil {
		previousOp = source.Operation
		data = source.Data
	}
	command := previousOp
	if values, ok := f[operationID]; ok {
		if len(values) != 1 || (values[0].Kind != wire.Int32 && values[0].Kind != wire.Int64) {
			return nil, fail(400, "invalid operation")
		}
		command = values[0].N
	}
	if command != 0 && command != 0xf47eaf6b && command != 0x42343fd3 && command != 0x29dd7acf {
		return nil, fail(400, "unsupported operation")
	}
	if values, ok := f[userData]; ok {
		if len(values) != 1 || values[0].Kind != wire.Blob || len(values[0].Data) > 65536 {
			return nil, fail(400, "invalid user data")
		}
		data = values[0].Data
	}
	session, e := blobs(f, sessionData, nil)
	if e != nil {
		return nil, e
	}
	var attrs, capacity *uint64
	for _, id := range []uint32{attributesID, maskID, minParticipants, maxParticipants, revisionID} {
		if f.Has(id) {
			n, err := number(f, id, wire.Int64, 0)
			if err != nil {
				return nil, err
			}
			if (id == minParticipants || id == maxParticipants) && (n < 1 || n > 100) {
				return nil, fail(400, "invalid capacity")
			}
			if id == revisionID && n == 0 {
				return nil, fail(400, "invalid revision")
			}
			if id == attributesID {
				attrs = &n
			}
			if id == maxParticipants {
				capacity = &n
			}
		}
	}
	if f.Has(minParticipants) && capacity != nil && f[minParticipants][0].N > *capacity {
		return nil, fail(400, "invalid capacity pair")
	}
	var destination *room
	var replacement *group
	existing := false
	if source != nil {
		if !sameUsers(source.Users, users) {
			return nil, fail(400, "participant-change")
		}
		fresh := op == "create" && requested == 0
		if !fresh && (requested == 0 || requested == source.Room) {
			destination = d.Rooms[source.Room]
			existing = true
		} else if op != "create" && op != "search" {
			return nil, fail(400, "update-target-mismatch")
		}
	}
	if source == nil && op != "create" && op != "search" {
		if d.Rooms[requested] != nil {
			return nil, fail(400, "update-membership-required")
		}
		return nil, fail(404, "unknown-match")
	}
	if !existing {
		if requested != 0 {
			destination = d.Rooms[requested]
			if destination == nil {
				return nil, fail(404, "unknown-match")
			}
		}
		if destination != nil {
			count := 0
			for _, candidate := range destination.Groups {
				if overlaps(users, candidate.Users) {
					count++
					replacement = candidate
				}
			}
			if count > 0 && (source != nil || op != "search" || count != 1 || !sameUsers(replacement.Users, users) || replacement.ID == destination.Owner || (!replacement.Closed && now.Sub(replacement.Active) < 60*time.Second)) {
				return nil, fail(400, "participants-already-present")
			}
		}
		groups := len(d.Groups) + 1
		rooms := len(d.Rooms)
		if source != nil {
			groups--
			if len(d.Rooms[source.Room].Groups) == 1 {
				rooms--
			}
		}
		if replacement != nil {
			groups--
		}
		if destination == nil {
			rooms++
		}
		if groups > 512 || rooms > 128 {
			return nil, fail(400, "local-capacity")
		}
	}
	conflict := op == "interlocked_update" && f.Has(revisionID) && destination != nil && f[revisionID][0].N != destination.Revision
	outgoingSession := [][]byte{{}}
	if destination != nil {
		outgoingSession = destination.Data
	}
	if !conflict && session != nil {
		outgoingSession = session
	}
	outgoingData := data
	if conflict {
		outgoingData = source.Data
	}
	otherCount := 0
	n := len(users)
	size := 16
	if destination != nil {
		for _, g := range destination.Groups {
			if g != source && g != replacement {
				otherCount++
				n += len(g.Users)
				size += len(g.Users) * len(g.Data)
			}
		}
	}
	cap := (*uint64)(nil)
	owns := destination == nil || (source != nil && destination.Owner == source.ID)
	if destination != nil {
		cap = destination.Capacity
	}
	if !conflict && capacity != nil && owns {
		cap = capacity
	}
	if n > 100 || (cap != nil && uint64(n) > *cap) {
		return nil, fail(400, "participant-limit")
	}
	size += 16*(10+4*(otherCount+1)+3*n+len(outgoingSession)+1) + len(users)*len(outgoingData)
	for _, b := range outgoingSession {
		size += len(b)
	}
	if size > wire.MaxBody {
		return nil, fail(400, "local-response-size-limit")
	}
	g := source
	if !existing {
		var rid uint64
		if destination != nil {
			rid = destination.ID
		} else {
			for {
				var b [8]byte
				if _, e = io.ReadFull(d.Random, b[:]); e != nil {
					return nil, e
				}
				rid = binary.LittleEndian.Uint64(b[:])&math.MaxInt64 | 1
				if d.Rooms[rid] == nil && d.Groups[rid] == nil {
					break
				}
			}
		}
		var gid uint64
		for {
			if d.Next > math.MaxInt64 {
				return nil, fail(400, "local-group-id-exhausted")
			}
			gid = d.Next
			d.Next += 2
			if gid != rid && d.Rooms[gid] == nil && d.Groups[gid] == nil {
				break
			}
		}
		token := make([]byte, 16)
		if _, e = io.ReadFull(d.Random, token); e != nil {
			return nil, e
		}
		g = &group{ID: gid, Session: key, Room: rid, Users: append([]uint64(nil), users...), Token: token, Active: now}
		if source != nil {
			d.remove(source)
		}
		if replacement != nil {
			d.remove(replacement)
		}
		if destination == nil {
			destination = &room{ID: rid, Owner: gid, Revision: 1, Groups: map[uint64]*group{}, Data: [][]byte{{}}}
			d.Rooms[rid] = destination
		}
		destination.Groups[gid] = g
		d.Groups[gid] = g
		d.Sessions[key] = g
	}
	r := destination
	if !conflict {
		dataChanged := !bytes.Equal(g.Data, data)
		changed := g.Operation != command || dataChanged || (session != nil && !sameBlobs(r.Data, session))
		if r.Owner == g.ID {
			if attrs != nil && (r.Attributes == nil || *r.Attributes != *attrs) {
				r.Attributes = attrs
				changed = true
			}
			if capacity != nil && (r.Capacity == nil || *r.Capacity != *capacity) {
				r.Capacity = capacity
				changed = true
			}
		}
		if dataChanged {
			g.Data = bytes.Clone(data)
		}
		g.Operation = command
		if session != nil {
			r.Data = session
		}
		if changed || op == "create" || op == "search" {
			r.Revision++
		}
	}
	g.Active = now
	result := wire.Success
	if conflict {
		result = 0x48a161bd
	}
	records := []wire.Field{wire.Num(wire.Result, wire.Int32, result), wire.Num(matchID, wire.Int64, r.ID), wire.Num(ownerID, wire.Int64, r.Owner), wire.Num(revisionID, wire.Int64, r.Revision), wire.Num(localGroup, wire.Int64, g.ID), wire.Num(0xa8e0cebc, wire.Int32, 0x34f312d8), wire.Num(0x20f13d5a, wire.Int32, 0), wire.Num(operationID, wire.Int32, g.Operation), wire.Addr(0x432608dd, d.Endpoint), wire.Binary(0x6a9160cc, g.Token)}
	for _, item := range groupOrder(r) {
		records = append(records, wire.Num(groupIDs, wire.Int64, item.ID), wire.Addr(groupEndpoints, d.Endpoint), wire.Num(userCounts, wire.Int64, uint64(len(item.Users))), wire.Binary(0x3e3d9383, nil))
		for _, u := range item.Users {
			records = append(records, wire.Num(userIDs, wire.Int64, u), wire.Binary(userData, item.Data), wire.Num(0x802bdc33, wire.Int64, r.Revision))
		}
	}
	for _, b := range r.Data {
		records = append(records, wire.Binary(sessionData, b))
	}
	return wire.Encode(wire.Sorted(records))
}
func statusCode(err error, def int) int {
	var e *requestError
	if errors.As(err, &e) {
		return e.Code
	}
	return def
}
