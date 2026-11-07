package backend

import (
	"fmt"
	"time"
)

// Relay diagnostics answer "why did the match drop?" without logging session
// keys, tokens, player identities or addresses. Players are labelled by their
// position in the room (ordered by local group ID) and rooms by a short prefix
// of the random local room ID.
const (
	relaySilentAfter = 3 * time.Second
	relayNoteEvery   = 10 * time.Second
)

type relayDiag struct {
	Created, LastUDP                   time.Time
	Packets                            uint64
	Silent                             bool
	Opens, Closes                      int
	UplinkWraps, DownWraps             int
	Blocked                            bool
	BlockedSince, ConflictAt, ReopenAt time.Time
	AckStalled                         bool
}

func (d *directory) note(event string, g *group, fields map[string]any) {
	if d.notify == nil {
		return
	}
	out := map[string]any{"event": event}
	if g != nil {
		out["room"] = fmt.Sprintf("%06x", g.Room&0xffffff)
		out["player"] = d.playerIndex(g)
		if !g.Diag.Created.IsZero() {
			out["member_s"] = int(time.Since(g.Diag.Created).Seconds())
		}
	}
	for k, v := range fields {
		out[k] = v
	}
	d.notify(out)
}
func (d *directory) playerIndex(g *group) int {
	r := d.Rooms[g.Room]
	if r == nil {
		return 0
	}
	for i, item := range groupOrder(r) {
		if item == g {
			return i + 1
		}
	}
	return 0
}
func (d *directory) relayWrap(g *group, direction string) {
	if direction == "uplink" {
		g.Diag.UplinkWraps++
	} else {
		g.Diag.DownWraps++
	}
	d.UDP["reliable_sequence_wraps"]++
	d.note("relay_sequence_wrap", g, map[string]any{"direction": direction, "uplink_wraps": g.Diag.UplinkWraps, "downlink_wraps": g.Diag.DownWraps})
}
func (d *directory) relayBlocked(source *group, groups map[uint64]*group, targets []uint64) {
	if source.Diag.Blocked {
		return
	}
	source.Diag.Blocked = true
	source.Diag.BlockedSince = time.Now()
	d.UDP["reliable_backpressure"]++
	by := 0
	for _, id := range targets {
		if t := groups[id]; t != nil && t.Reliable != nil && len(t.Reliable.outgoing) >= reliableQueue {
			by = d.playerIndex(t)
			break
		}
	}
	d.note("relay_backpressure", source, map[string]any{"blocked_by_player": by})
}
func (d *directory) relayUnblocked(source *group) {
	if !source.Diag.Blocked {
		return
	}
	source.Diag.Blocked = false
	d.note("relay_backpressure_cleared", source, map[string]any{"blocked_ms": time.Since(source.Diag.BlockedSince).Milliseconds()})
}
func (d *directory) relayConflict(g *group, seq uint16, now time.Time) {
	d.UDP["reliable_conflict"]++
	if now.Sub(g.Diag.ConflictAt) < relayNoteEvery {
		return
	}
	g.Diag.ConflictAt = now
	head := uint16(0)
	if g.Reliable != nil {
		head = g.Reliable.receiveHead
	}
	d.note("relay_sequence_conflict", g, map[string]any{"sequence": seq, "uplink_head": head})
}

// Caller holds mu. Every UDP datagram from a bound address proves liveness,
// whatever its kind or routing flags.
func (d *directory) relaySeen(g *group, now time.Time) {
	if g.Diag.Silent {
		g.Diag.Silent = false
		d.note("relay_resumed", g, map[string]any{"silent_ms": now.Sub(g.Diag.LastUDP).Milliseconds()})
	}
	g.Diag.LastUDP = now
	g.Diag.Packets++
}
func (d *directory) relayUnknownSource(now time.Time) {
	d.UDP["unknown_source"]++
	d.unknownQuiet++
	if now.Sub(d.unknownNoted) < relayNoteEvery {
		return
	}
	d.unknownNoted = now
	d.note("udp_unknown_source", nil, map[string]any{"packets": d.unknownQuiet})
	d.unknownQuiet = 0
}

// Caller holds mu. Runs about once per second.
func (d *directory) relayWatch(now time.Time) {
	for _, g := range d.Groups {
		if g.Closed || !g.Address.IsValid() || g.Diag.LastUDP.IsZero() {
			continue
		}
		p := g.Reliable
		if !g.Diag.Silent && now.Sub(g.Diag.LastUDP) >= relaySilentAfter {
			g.Diag.Silent = true
			fields := map[string]any{"silent_ms": now.Sub(g.Diag.LastUDP).Milliseconds()}
			if p != nil {
				fields["queue"] = len(p.outgoing)
				fields["unacked"] = uint16(p.next - p.acknowledged)
			}
			d.note("relay_silent", g, fields)
		}
		// The peer keeps sending but no longer acknowledges what we relay to it.
		stalled := p != nil && len(p.outgoing) > 0 && !g.Diag.Silent && !p.lastAck.IsZero() && now.Sub(p.lastAck) >= relaySilentAfter
		if stalled && !g.Diag.AckStalled {
			d.note("relay_ack_stalled", g, map[string]any{"queue": len(p.outgoing), "unacked": uint16(p.next - p.acknowledged), "since_ack_ms": now.Sub(p.lastAck).Milliseconds()})
		} else if !stalled && g.Diag.AckStalled {
			d.note("relay_ack_resumed", g, nil)
		}
		g.Diag.AckStalled = stalled
	}
}

// Caller holds mu. A compact per-player snapshot for the 30 s summary line.
func (d *directory) relaySnapshot(now time.Time) []map[string]any {
	out := []map[string]any{}
	for _, r := range d.Rooms {
		players := []map[string]any{}
		for i, g := range groupOrder(r) {
			item := map[string]any{"player": i + 1, "closed": g.Closed, "packets": g.Diag.Packets, "opens": g.Diag.Opens}
			if !g.Diag.LastUDP.IsZero() {
				item["udp_age_ms"] = now.Sub(g.Diag.LastUDP).Milliseconds()
			}
			if p := g.Reliable; p != nil {
				item["uplink_head"] = p.receiveHead
				item["downlink_next"] = p.next
				item["downlink_acked"] = p.acknowledged
				item["queue"] = len(p.outgoing)
				item["srtt_ms"] = p.srtt.Milliseconds()
				item["rto_ms"] = p.retryAfter(&reliableDelivery{}).Milliseconds()
				item["wraps"] = g.Diag.UplinkWraps + g.Diag.DownWraps
			}
			players = append(players, item)
		}
		out = append(out, map[string]any{"room": fmt.Sprintf("%06x", r.ID&0xffffff), "members": players})
	}
	return out
}
