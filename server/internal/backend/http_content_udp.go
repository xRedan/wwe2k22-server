package backend

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"wwe2k22-server/internal/wire"
)

func lobbyIDs(response map[string]any) ([]byte, error) {
	entries := response["lobbies"].([]any)
	out := make([]byte, 8+8*len(entries))
	copy(out, "W2L1")
	binary.LittleEndian.PutUint32(out[4:], uint32(len(entries)))
	for i, v := range entries {
		id, e := canonicalID(v.(map[string]any)["lobby_id"])
		if e != nil {
			return nil, e
		}
		binary.LittleEndian.PutUint64(out[8+8*i:], id)
	}
	return out, nil
}
func (s *Server) nativeContent(w http.ResponseWriter, r *http.Request) {
	if s.content == nil {
		s.reply(w, r, 501, errorJSON("Experimental custom content is disabled"))
		return
	}
	uid, e := s.restUser(r, false)
	if e != nil || uid == "" {
		s.reply(w, r, 401, errorJSON("A local REST session is required"))
		return
	}
	enc := r.Header.Values("Content-Encoding")
	if len(enc) > 1 || (len(enc) == 1 && strings.ToLower(strings.TrimSpace(enc[0])) != "identity") {
		s.reply(w, r, 415, errorJSON("Custom content requires identity encoding"))
		return
	}
	op := strings.TrimPrefix(r.URL.Path, "/api/")
	var data map[string]any
	var files map[string]binaryPart
	if op == "ContentUpload" {
		select {
		case s.uploads <- struct{}{}:
			defer func() { <-s.uploads }()
		default:
			s.reply(w, r, 503, errorJSON("A content transfer is already active; retry later"))
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(120 * time.Second))
		types := r.Header.Values("Content-Type")
		if len(types) != 1 {
			s.reply(w, r, 400, errorJSON("One native multipart content type is required"))
			return
		}
		var cleanup func()
		data, files, cleanup, e = parseMultipart(types[0], r.Body, r.ContentLength)
		defer cleanup()
	} else {
		data, e = requestJSON(r, 1, wire.MaxBody)
	}
	if e != nil {
		message := "Invalid native content request"
		if _, ok := e.(*requestError); ok {
			message = e.Error()
		}
		s.reply(w, r, statusCode(e, 400), errorJSON(message))
		return
	}
	uid, e = s.restUser(r, false)
	if e != nil || uid == "" {
		s.reply(w, r, 401, errorJSON("A local REST session is required"))
		return
	}
	response, e := s.nativeContentHandle(r, op, uid, data, files)
	if e != nil {
		code := statusCode(e, 503)
		msg := "Invalid native content request"
		if _, ok := e.(*requestError); ok {
			msg = e.Error()
		}
		s.reply(w, r, code, errorJSON(msg))
		return
	}
	_, _ = s.restUser(r, true)
	s.reply(w, r, 200, response)
}
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if s.content == nil {
		s.reply(w, r, 501, errorJSON("Experimental custom content is disabled"))
		return
	}
	id, e := cdnID(r.URL.Path)
	if e != nil {
		s.reply(w, r, 404, errorJSON("Unknown local content asset"))
		return
	}
	uid, e := s.restUser(r, false)
	if e != nil {
		s.reply(w, r, 401, errorJSON("A local REST session is required"))
		return
	}
	if len(r.Header.Values("X-Sessionid")) > 0 && uid == "" {
		s.reply(w, r, 401, errorJSON("A local REST session is required"))
		return
	}
	select {
	case s.downloads <- struct{}{}:
		defer func() { <-s.downloads }()
	default:
		s.reply(w, r, 503, errorJSON("A content transfer is already active; retry later"))
		return
	}
	snapshot, e := s.content.snapshot(id, uid)
	if e != nil {
		s.reply(w, r, statusCode(e, 503), errorJSON(e.Error()))
		return
	}
	defer snapshot.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(snapshot.size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(120 * time.Second))
	s.responses.Add(1)
	w.WriteHeader(200)
	_, _ = io.CopyBuffer(w, snapshot, make([]byte, 64*1024))
}

type udpReply struct {
	Data    []byte
	Address netip.AddrPort
}

// The caller holds d.mu. Replies borrow packet, and must be sent before reuse.
func (d *directory) udpReplies(raw []byte, from netip.AddrPort, now time.Time, packet []byte, out []udpReply) ([]udpReply, error) {
	out = out[:0]
	d.UDP["received"]++
	f, err := wire.DecodeUDP(raw)
	if err != nil {
		return out, err
	}
	if f.Namespace != d.Endpoint.Tag {
		return out, nil
	}
	if f.Kind == 0 {
		if f.Flags != 0 || len(f.Payload) != 24 {
			return out, wire.ErrUDP
		}
		g := d.Groups[binary.LittleEndian.Uint64(f.Payload[16:])]
		if g == nil || subtle.ConstantTimeCompare(f.Payload[:16], g.Token) != 1 {
			return out, nil
		}
		if old := d.Addresses[from]; old != nil && old != g {
			return out, nil
		}
		if g.Address.IsValid() {
			delete(d.Addresses, g.Address)
		}
		g.Address = from
		g.Closed = false
		g.Active = now
		d.Addresses[from] = g
		d.UDP["opens"]++
		var payload [12]byte
		binary.LittleEndian.PutUint64(payload[4:], g.ID)
		ack, err := wire.EncodeUDPInto(packet, wire.Datagram{Namespace: f.Namespace, Kind: 1, Payload: payload[:]})
		if err != nil {
			return out, err
		}
		return append(out, udpReply{ack, from}), nil
	}
	g := d.Addresses[from]
	if g == nil {
		return out, nil
	}
	if f.Kind == 2 {
		if f.Flags != 0 || len(f.Payload) != 8 {
			return out, wire.ErrUDP
		}
		if binary.LittleEndian.Uint64(f.Payload) == g.ID {
			delete(d.Addresses, from)
			g.Address = netip.AddrPort{}
			g.Closed = true
			g.Active = now
		}
		return out, nil
	}
	if f.Kind != 3 && f.Kind != 4 {
		return out, nil
	}
	room := d.Rooms[g.Room]
	if room == nil {
		return out, nil
	}
	payload := f.Payload
	var ids []byte
	switch f.Flags {
	case 0x800:
		ids, payload, err = wire.TargetedBytes(f)
		if err != nil {
			return out, err
		}
	case 0x1000, 0x1800:
	default:
		return out, nil
	}
	g.Active = now
	exclude := f.Flags == 0x1800 || wire.IsApplicationACK(f, g.ID)
	if f.Flags == 0x800 {
		for len(ids) > 0 {
			id := binary.LittleEndian.Uint64(ids)
			ids = ids[8:]
			item := d.Groups[id]
			if item == nil || item.Room != g.Room || !item.Address.IsValid() {
				continue
			}
			duplicate := false
			for _, reply := range out {
				if reply.Address == item.Address {
					duplicate = true
					break
				}
			}
			if !duplicate {
				out = append(out, udpReply{Address: item.Address})
			}
		}
	} else {
		for _, item := range room.Groups {
			if item.Address.IsValid() && (!exclude || item != g) {
				out = append(out, udpReply{Address: item.Address})
			}
		}
	}
	if len(out) == 0 {
		return out, nil
	}
	frame, err := wire.EncodeUDPInto(packet, wire.Datagram{Namespace: f.Namespace, Kind: f.Kind, Payload: payload})
	if err != nil {
		return out[:0], err
	}
	for i := range out {
		out[i].Data = frame
	}
	d.UDP["forwarded"] += uint64(len(out))
	return out, nil
}
func (s *Server) serveUDP() {
	raw := make([]byte, wire.MaxDatagram+1)
	packet := make([]byte, wire.MaxDatagram)
	replies := make([]udpReply, 0, 100)
	for {
		n, from, e := s.udp.ReadFromUDPAddrPort(raw)
		if e != nil {
			if s.ctx.Err() != nil || errors.Is(e, net.ErrClosed) {
				return
			}
			s.dir.mu.Lock()
			s.dir.UDP["read_errors"]++
			s.dir.mu.Unlock()
			// A persistent socket error must not turn into a busy loop. Partial
			// oversized datagrams are discarded without delaying the next valid one.
			if n > 0 && from.IsValid() {
				continue
			}
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-s.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		now := time.Now()
		if !s.policy.admit(from.Addr().Unmap(), "udp", now) {
			s.dir.mu.Lock()
			s.dir.UDP["policy_dropped"]++
			s.dir.mu.Unlock()
			continue
		}
		s.dir.mu.Lock()
		replies, e = s.dir.udpReplies(raw[:n], from, now, packet, replies)
		if e != nil {
			s.dir.UDP["invalid"]++
		}
		s.dir.mu.Unlock()
		if e != nil {
			continue
		}
		for _, reply := range replies {
			if _, e = s.udp.WriteToUDPAddrPort(reply.Data, reply.Address); e != nil {
				s.dir.mu.Lock()
				s.dir.UDP["send_errors"]++
				s.dir.mu.Unlock()
			}
		}
	}
}
