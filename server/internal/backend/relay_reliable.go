package backend

import (
	"bytes"
	"encoding/binary"
	"time"
	"wwe2k22-server/internal/wire"
)

const (
	reliableData   = uint32(0x59a91251)
	reliableACK    = uint32(0x85912ac9)
	reliableWindow = 63
	reliableQueue  = 128
	reliableRetry  = 100 * time.Millisecond
)

// The native transport has a single receive window (0x141931d70) and ACK
// consumer (0x141931c60) per client. Forwarding independent sender sequences
// directly therefore loses the second remote peer's sequence zero. Terminate
// reliability here and assign one ordered sequence stream per destination.
// All fields are protected by directory.mu, including socket reply generation.
// State is allocated lazily and bounded per authenticated matchmaking group.
type reliablePeer struct {
	receiveHead              uint16
	incoming                 [64]*reliableInput
	next, acknowledged, sent uint16
	outgoing                 []reliableDelivery
	ackNeeded                bool
}
type reliableInput struct {
	record  []byte
	targets []uint64
}
type reliableDelivery struct {
	record   []byte
	sequence uint16
	sent     time.Time
}
type reliablePart struct {
	record  []byte
	command uint32
}

// Validate the entire compound envelope before changing any transport state.
// Unrecognized application traffic keeps its established transparent routing.
func reliableParts(payload []byte, sender uint64) ([]reliablePart, bool, error) {
	var parts []reliablePart
	recognized := false
	for len(payload) != 0 {
		if len(payload) < 16 {
			if recognized {
				return nil, true, wire.ErrUDP
			}
			return nil, false, nil
		}
		command := binary.LittleEndian.Uint32(payload[4:])
		known := command == reliableData || command == reliableACK
		size := int(binary.LittleEndian.Uint16(payload[2:]))
		if size < 16 || size > len(payload) {
			if known || recognized {
				return nil, true, wire.ErrUDP
			}
			return nil, false, nil
		}
		record := payload[:size]
		if known {
			recognized = true
			if binary.LittleEndian.Uint16(record) != 0 || binary.LittleEndian.Uint64(record[8:]) != sender {
				return nil, true, wire.ErrUDP
			}
			if command == reliableACK {
				if size != 22 {
					return nil, true, wire.ErrUDP
				}
			} else if size < 24 || int(binary.LittleEndian.Uint16(record[22:])) != size-24 {
				return nil, true, wire.ErrUDP
			}
		}
		parts = append(parts, reliablePart{record, command})
		payload = payload[size:]
	}
	return parts, recognized, nil
}
func relayState(g *group) *reliablePeer {
	if g.Reliable == nil {
		g.Reliable = &reliablePeer{}
	}
	return g.Reliable
}

// Snapshot membership at first receipt. A later join must start at sequence
// zero in its own stream, without inheriting another player's old history.
func (d *directory) reliableTargets(r *room, sender *group, flags uint16, ids []byte) []uint64 {
	targets := make([]uint64, 0, len(r.Groups))
	add := func(g *group) {
		if g == nil || g.Room != r.ID || g.Closed {
			return
		}
		for _, id := range targets {
			if id == g.ID {
				return
			}
		}
		targets = append(targets, g.ID)
	}
	if flags == 0x800 {
		for len(ids) >= 8 {
			add(d.Groups[binary.LittleEndian.Uint64(ids)])
			ids = ids[8:]
		}
	} else {
		for _, g := range r.Groups {
			if !g.Closed && (flags != 0x1800 || g != sender) {
				targets = append(targets, g.ID)
			}
		}
	}
	return targets
}

func acknowledgeReliable(p *reliablePeer, record []byte) {
	head := binary.LittleEndian.Uint16(record[16:])
	// Stale ACKs cannot rewind a stream; a future ACK cannot release data that
	// was never sent. Differences stay below half the uint16 sequence space.
	if int16(head-p.acknowledged) < 0 || int16(p.sent-head) < 0 {
		return
	}
	p.acknowledged = head
	mask := binary.LittleEndian.Uint16(record[18:])
	keep := p.outgoing[:0]
	for _, item := range p.outgoing {
		delta := int16(item.sequence - head)
		acked := delta < 0 || (delta < 16 && mask&(uint16(1)<<uint(delta)) != 0)
		if item.sent.IsZero() || !acked {
			keep = append(keep, item)
		}
	}
	clear(p.outgoing[len(keep):])
	p.outgoing = keep
}

// Queue a complete input atomically for all of its recipients. A slow peer
// applies bounded backpressure instead of making the server allocate forever.
func (d *directory) pumpReliable(r *room) {
	for _, source := range r.Groups {
		p := source.Reliable
		if p == nil {
			continue
		}
		for {
			index := p.receiveHead & 63
			input := p.incoming[index]
			if input == nil {
				break
			}
			blocked := false
			for _, id := range input.targets {
				target := r.Groups[id]
				if target != nil && !target.Closed && len(relayState(target).outgoing) >= reliableQueue {
					blocked = true
					break
				}
			}
			if blocked {
				break
			}
			for _, id := range input.targets {
				target := r.Groups[id]
				if target == nil || target.Closed {
					continue
				}
				q := relayState(target)
				q.outgoing = append(q.outgoing, reliableDelivery{record: input.record, sequence: q.next})
				q.next++
			}
			p.incoming[index] = nil
			p.receiveHead++
			p.ackNeeded = true
			d.UDP["reliable_accepted"]++
		}
	}
}

func reliableAcknowledgement(p *reliablePeer, id uint64) [22]byte {
	var record [22]byte
	binary.LittleEndian.PutUint16(record[2:], 22)
	binary.LittleEndian.PutUint32(record[4:], reliableACK)
	binary.LittleEndian.PutUint64(record[8:], id)
	binary.LittleEndian.PutUint16(record[16:], p.receiveHead)
	var mask uint16
	for i := uint16(0); i < 16; i++ {
		if p.incoming[(p.receiveHead+i)&63] != nil {
			mask |= 1 << i
		}
	}
	binary.LittleEndian.PutUint16(record[18:], mask)
	// This is the relay's downstream send head, not another client's uplink.
	binary.LittleEndian.PutUint16(record[20:], p.next)
	return record
}

func (d *directory) flushReliable(g *group, now time.Time, out []udpReply) []udpReply {
	p := g.Reliable
	if p == nil || g.Closed || !g.Address.IsValid() {
		return out
	}
	var frame []byte
	appendFrame := func() {
		if len(frame) <= 4 {
			return
		}
		binary.LittleEndian.PutUint32(frame, uint32(d.Endpoint.Tag)<<16|3<<13|uint32(len(frame)))
		out = append(out, udpReply{Data: frame, Address: g.Address})
		d.UDP["forwarded"]++
		frame = nil
	}
	if p.ackNeeded {
		frame = make([]byte, 4, 26)
		ack := reliableAcknowledgement(p, g.ID)
		frame = append(frame, ack[:]...)
		p.ackNeeded = false
	}
	emitted := 0
	for i := range p.outgoing {
		item := &p.outgoing[i]
		if uint16(item.sequence-p.acknowledged) >= reliableWindow {
			continue
		}
		if !item.sent.IsZero() && now.Sub(item.sent) < reliableRetry {
			continue
		}
		if emitted == 5 {
			break
		}
		if len(frame)+len(item.record) > wire.MaxDatagram {
			appendFrame()
		}
		if frame == nil {
			frame = make([]byte, 4, wire.MaxDatagram)
		}
		offset := len(frame)
		frame = append(frame, item.record...)
		binary.LittleEndian.PutUint16(frame[offset+20:], item.sequence)
		if item.sent.IsZero() {
			p.sent = item.sequence + 1
		} else {
			d.UDP["reliable_retransmitted"]++
		}
		item.sent = now
		emitted++
	}
	appendFrame()
	return out
}

func (d *directory) reliableReplies(g *group, r *room, parts []reliablePart, flags uint16, ids []byte, now time.Time, out []udpReply) ([]udpReply, error) {
	p := relayState(g)
	var targets []uint64
	var opaque []byte
	// ACKs release downstream capacity before new upstream records are queued.
	for _, part := range parts {
		if part.command == reliableACK {
			acknowledgeReliable(p, part.record)
		}
	}
	for _, part := range parts {
		switch part.command {
		case reliableACK:
			p.ackNeeded = true
		case reliableData:
			seq := binary.LittleEndian.Uint16(part.record[20:])
			p.ackNeeded = true
			if uint16(seq-p.receiveHead) >= reliableWindow {
				continue
			}
			old := p.incoming[seq&63]
			if old != nil {
				if !bytes.Equal(old.record, part.record) {
					return nil, wire.ErrUDP
				}
				continue
			}
			if targets == nil {
				targets = d.reliableTargets(r, g, flags, ids)
			}
			p.incoming[seq&63] = &reliableInput{record: bytes.Clone(part.record), targets: targets}
		default:
			opaque = append(opaque, part.record...)
		}
	}
	if len(opaque) != 0 {
		raw, err := wire.EncodeUDP(wire.Datagram{Namespace: d.Endpoint.Tag, Kind: 3, Payload: opaque})
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].Data = raw
		}
		d.UDP["forwarded"] += uint64(len(out))
	} else {
		out = out[:0]
	}
	d.pumpReliable(r)
	for _, peer := range r.Groups {
		out = d.flushReliable(peer, now, out)
	}
	return out, nil
}
