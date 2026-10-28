package backend

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"
	"wwe2k22-server/internal/wire"
)

// This envelope follows the native writer at 0x141930930. The native reader
// at 0x141931d70 has one receive window per client, not one per remote group.
func reliableTestRecord(origin uint64, sequence uint16, body []byte) []byte {
	p := make([]byte, 24+len(body))
	binary.LittleEndian.PutUint16(p[2:], uint16(len(p)))
	binary.LittleEndian.PutUint32(p[4:], 0x59a91251)
	binary.LittleEndian.PutUint64(p[8:], origin)
	binary.LittleEndian.PutUint32(p[16:], 1)
	binary.LittleEndian.PutUint16(p[20:], sequence)
	binary.LittleEndian.PutUint16(p[22:], uint16(len(body)))
	copy(p[24:], body)
	return p
}

func reliableTestRoom(t *testing.T, count int) (*directory, []*group, time.Time) {
	t.Helper()
	d := newDirectory(wire.Endpoint{IP: netip.MustParseAddr("127.0.0.1"), Port: 8788, Tag: 1})
	now := time.Unix(1234, 0)
	peers := make([]*group, 0, count)
	for i := 0; i < count; i++ {
		fields := wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, uint64(1001+i))}}
		op := "create"
		if i == 0 {
			fields[maxParticipants] = []wire.Field{wire.Num(maxParticipants, wire.Int64, uint64(count))}
		} else {
			op = "search"
			fields[matchID] = []wire.Field{wire.Num(matchID, wire.Int64, peers[0].Room)}
		}
		raw, err := d.response(op, uint64(i+1), fields, now)
		if err != nil {
			t.Fatalf("peer %d admission: %v", i+1, err)
		}
		decoded, err := wire.Decode(raw, true)
		if err != nil || len(decoded[groupIDs]) != i+1 {
			t.Fatalf("peer %d membership response: %v", i+1, err)
		}
		g := d.Sessions[uint64(i+1)]
		g.Address = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(11000+i))
		d.Addresses[g.Address] = g
		peers = append(peers, g)
	}
	return d, peers, now
}

func reliableTestSend(t *testing.T, d *directory, from *group, payload []byte, now time.Time) []udpReply {
	t.Helper()
	raw, err := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1800, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	replies, err := d.udpReplies(raw, from.Address, now, make([]byte, wire.MaxDatagram), nil)
	if err != nil {
		t.Fatal(err)
	}
	return replies
}

func TestReliableRelayDistinctReceiveSequences(t *testing.T) {
	for _, count := range []int{2, 3, 4, 6, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			d, peers, now := reliableTestRoom(t, count)
			seen := make(map[netip.AddrPort]map[uint16]uint64)
			for _, from := range peers {
				for _, reply := range reliableTestSend(t, d, from, reliableTestRecord(from.ID, 0, []byte("join")), now) {
					frame, err := wire.DecodeUDP(reply.Data)
					if err != nil {
						t.Fatal(err)
					}
					for p := frame.Payload; len(p) >= 16; {
						size := int(binary.LittleEndian.Uint16(p[2:]))
						if size < 16 || size > len(p) {
							t.Fatal("invalid application envelope")
						}
						record := p[:size]
						p = p[size:]
						if binary.LittleEndian.Uint32(record[4:]) != 0x59a91251 {
							continue
						}
						origin := binary.LittleEndian.Uint64(record[8:])
						seq := binary.LittleEndian.Uint16(record[20:])
						if seen[reply.Address] == nil {
							seen[reply.Address] = make(map[uint16]uint64)
						}
						if old, ok := seen[reply.Address][seq]; ok && old != origin {
							t.Fatalf("two senders share receive sequence %d: third-player join is discarded by the native window", seq)
						}
						seen[reply.Address][seq] = origin
					}
				}
			}
			for _, peer := range peers {
				if len(seen[peer.Address]) != count-1 {
					t.Fatalf("received %d distinct peer joins, want %d", len(seen[peer.Address]), count-1)
				}
			}
		})
	}
}

func reliableTestACK(id uint64, head, mask, sendHead uint16) []byte {
	p := make([]byte, 22)
	binary.LittleEndian.PutUint16(p[2:], 22)
	binary.LittleEndian.PutUint32(p[4:], 0x85912ac9)
	binary.LittleEndian.PutUint64(p[8:], id)
	binary.LittleEndian.PutUint16(p[16:], head)
	binary.LittleEndian.PutUint16(p[18:], mask)
	binary.LittleEndian.PutUint16(p[20:], sendHead)
	return p
}

func TestReliableLateJoinStartsFreshReceiveStream(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 2)
	for seq := uint16(0); seq < 40; seq++ {
		reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, seq, []byte("state")), now)
		reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, seq+1, 0, 0), now)
	}
	cap := uint64(3)
	d.Rooms[peers[0].Room].Capacity = &cap
	_, err := d.response("search", 3, wire.Fields{
		userIDs: {wire.Num(userIDs, wire.Int64, 1003)},
		matchID: {wire.Num(matchID, wire.Int64, peers[0].Room)},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	late := d.Sessions[3]
	// Queue the message before the new peer has completed its UDP open.
	reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 40, []byte("welcome")), now)
	if late.Reliable == nil || len(late.Reliable.outgoing) != 1 {
		t.Fatal("unbound new peer lost its initial message")
	}
	late.Address = netip.MustParseAddrPort("127.0.0.1:12003")
	d.Addresses[late.Address] = late
	replies := reliableTestSend(t, d, late, reliableTestACK(late.ID, 0, 0, 0), now)
	delivered := false
	for _, reply := range replies {
		if reply.Address != late.Address {
			continue
		}
		frame, _ := wire.DecodeUDP(reply.Data)
		for p := frame.Payload; len(p) >= 16; {
			n := int(binary.LittleEndian.Uint16(p[2:]))
			record := p[:n]
			p = p[n:]
			if binary.LittleEndian.Uint32(record[4:]) == 0x59a91251 {
				if binary.LittleEndian.Uint16(record[20:]) != 0 || string(record[24:]) != "welcome" {
					t.Fatal("late peer inherited an old receive sequence or payload")
				}
				delivered = true
			}
		}
	}
	if !delivered {
		t.Fatal("new peer never received its queued first message")
	}
}

func TestReliableBackpressureAndSequenceWrap(t *testing.T) {
	t.Run("bounded-backpressure", func(t *testing.T) {
		d, peers, now := reliableTestRoom(t, 3)
		slow := relayState(peers[2])
		record := reliableTestRecord(peers[0].ID, 0, []byte("old"))
		for i := 0; i < reliableQueue; i++ {
			slow.outgoing = append(slow.outgoing, reliableDelivery{record: record, sequence: uint16(i), sent: now})
		}
		slow.next, slow.sent = reliableQueue, reliableQueue
		reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 0, []byte("new")), now)
		source := peers[0].Reliable
		if source.receiveHead != 0 || source.incoming[0] == nil || len(slow.outgoing) != reliableQueue {
			t.Fatal("queue overflow or lost backpressure")
		}
		reliableTestSend(t, d, peers[2], reliableTestACK(peers[2].ID, reliableQueue, 0, 0), now)
		if source.receiveHead != 1 || source.incoming[0] != nil || len(slow.outgoing) != 1 {
			t.Fatal("ACK did not resume the blocked multicast")
		}
	})
	t.Run("uint16-wrap", func(t *testing.T) {
		d, peers, now := reliableTestRoom(t, 2)
		relayState(peers[0]).receiveHead = 65534
		q := relayState(peers[1])
		q.next, q.sent, q.acknowledged = 65534, 65534, 65534
		for _, seq := range []uint16{65534, 65535, 0} {
			reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, seq, []byte("wrap")), now)
		}
		if peers[0].Reliable.receiveHead != 1 || q.next != 1 || len(q.outgoing) != 3 {
			t.Fatal("sequence wrap broke the receive window")
		}
		reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, 1, 0, 0), now)
		if len(q.outgoing) != 0 {
			t.Fatal("wrapped ACK did not release delivery history")
		}
	})
}

func TestReliableEnvelopeValidationAndACKIsolation(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 3)
	reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 0, []byte("hello")), now)
	before := len(peers[1].Reliable.outgoing)
	// A receiver cannot acknowledge sequences that have not been sent.
	reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, 100, 0xffff, 0), now)
	if len(peers[1].Reliable.outgoing) != before {
		t.Fatal("future ACK deleted queued delivery")
	}
	for name, record := range map[string][]byte{
		"spoofed-origin":   reliableTestRecord(peers[1].ID, 1, []byte("bad")),
		"truncated-data":   reliableTestRecord(peers[0].ID, 1, []byte("bad"))[:25],
		"trailing-garbage": append(reliableTestRecord(peers[0].ID, 1, []byte("bad")), 0),
	} {
		t.Run(name, func(t *testing.T) {
			_, handled, err := reliableParts(record, peers[0].ID)
			if !handled || err == nil || peers[0].Reliable.receiveHead != 1 {
				t.Fatal("invalid envelope admitted or state changed")
			}
		})
	}
	replies := reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, 1, 0, 0), now)
	if len(peers[1].Reliable.outgoing) != 0 {
		t.Fatal("valid receiver ACK ignored")
	}
	for _, reply := range replies {
		frame, _ := wire.DecodeUDP(reply.Data)
		for p := frame.Payload; len(p) >= 16; {
			n := int(binary.LittleEndian.Uint16(p[2:]))
			if binary.LittleEndian.Uint32(p[4:]) == 0x85912ac9 && reply.Address != peers[1].Address {
				t.Fatal("one client's ACK changed another client's stream")
			}
			p = p[n:]
		}
	}
}

// A faithful model of the native receiver's single 63-packet window. Payload
// serials additionally prove per-sender ordering across the translated stream.
type reliableNativeModel struct {
	head     uint16
	pending  [64][]byte
	received map[uint64][]uint16
	uplink   []bool
}

func (c *reliableNativeModel) receive(t *testing.T, raw []byte) {
	t.Helper()
	frame, err := wire.DecodeUDP(raw)
	if err != nil {
		t.Fatal(err)
	}
	for p := frame.Payload; len(p) != 0; {
		if len(p) < 16 {
			t.Fatal("short native record")
		}
		n := int(binary.LittleEndian.Uint16(p[2:]))
		if n < 16 || n > len(p) {
			t.Fatal("invalid native record length")
		}
		record := p[:n]
		p = p[n:]
		switch binary.LittleEndian.Uint32(record[4:]) {
		case 0x85912ac9:
			head := binary.LittleEndian.Uint16(record[16:])
			mask := binary.LittleEndian.Uint16(record[18:])
			for i := range c.uplink {
				delta := int16(uint16(i) - head)
				if delta < 0 || (delta < 16 && mask&(1<<uint(delta)) != 0) {
					c.uplink[i] = true
				}
			}
		case 0x59a91251:
			seq := binary.LittleEndian.Uint16(record[20:])
			if int16(seq-c.head) < 0 || uint16(seq-c.head) >= 63 {
				continue
			}
			if c.pending[seq&63] == nil {
				c.pending[seq&63] = append([]byte(nil), record...)
			}
			for c.pending[c.head&63] != nil {
				item := c.pending[c.head&63]
				origin := binary.LittleEndian.Uint64(item[8:])
				serial := binary.LittleEndian.Uint16(item[24:])
				if int(serial) != len(c.received[origin]) {
					t.Fatalf("native receive order mismatch: got serial %d after %d records", serial, len(c.received[origin]))
				}
				c.received[origin] = append(c.received[origin], serial)
				c.pending[c.head&63] = nil
				c.head++
			}
		}
	}
}
func (c *reliableNativeModel) acknowledgement(id uint64) []byte {
	var mask uint16
	for i := uint16(0); i < 16; i++ {
		if c.pending[(c.head+i)&63] != nil {
			mask |= 1 << i
		}
	}
	return reliableTestACK(id, c.head, mask, uint16(len(c.uplink)))
}

func TestReliableRelayLossReorderingAndDuplicates(t *testing.T) {
	for _, count := range []int{2, 3, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			d, peers, start := reliableTestRoom(t, count)
			const messages = 80
			clients := make(map[netip.AddrPort]*reliableNativeModel)
			for _, g := range peers {
				clients[g.Address] = &reliableNativeModel{received: make(map[uint64][]uint16), uplink: make([]bool, messages)}
			}
			random := rand.New(rand.NewSource(1729))
			var network []udpReply
			for tick := 0; tick < 4000; tick++ {
				now := start.Add(time.Duration(tick) * 10 * time.Millisecond)
				for _, g := range peers {
					client := clients[g.Address]
					send := func(payload []byte) {
						if random.Intn(5) == 0 {
							return
						}
						for _, reply := range reliableTestSend(t, d, g, payload, now) {
							if random.Intn(5) == 0 {
								continue
							}
							network = append(network, reply)
							if random.Intn(10) == 0 {
								network = append(network, reply)
							}
						}
					}
					send(client.acknowledgement(g.ID))
					if tick%10 == 0 {
						emitted := 0
						for seq, acked := range client.uplink {
							if acked {
								continue
							}
							body := make([]byte, 300)
							binary.LittleEndian.PutUint16(body, uint16(seq))
							send(reliableTestRecord(g.ID, uint16(seq), body))
							emitted++
							if emitted == 5 {
								break
							}
						}
					}
				}
				random.Shuffle(len(network), func(i, j int) { network[i], network[j] = network[j], network[i] })
				for _, reply := range network {
					clients[reply.Address].receive(t, reply.Data)
				}
				network = network[:0]
				complete := true
				for _, g := range peers {
					client := clients[g.Address]
					for _, acked := range client.uplink {
						complete = complete && acked
					}
					for _, other := range peers {
						if other != g {
							complete = complete && len(client.received[other.ID]) == messages
						}
					}
					if len(g.Reliable.outgoing) > reliableQueue {
						t.Fatal("unbounded retransmission queue")
					}
				}
				if complete {
					if d.UDP["reliable_retransmitted"] == 0 {
						t.Fatal("loss simulation did not exercise retransmission")
					}
					return
				}
			}
			t.Fatal("reliable streams did not converge after packet loss, duplicates and reordering")
		})
	}
}

func TestHTTPThreePlayersAndReliableUDP(t *testing.T) {
	s := testServer(t, false)
	type connection struct {
		peer  *net.UDPConn
		id    uint64
		model reliableNativeModel
	}
	var connections []connection
	var roomID uint64
	for i := 0; i < 3; i++ {
		key := loginNative(t, s)
		fields := []wire.Field{wire.Num(userIDs, wire.Int64, uint64(76561198000000001+i))}
		op := "create"
		if i == 0 {
			fields = append(fields, wire.Num(maxParticipants, wire.Int64, 3))
		} else {
			op = "search"
			fields = append(fields, wire.Num(matchID, wire.Int64, roomID))
		}
		raw, _ := wire.Encode(wire.Sorted(fields))
		code, _, body := request(t, s, "/lab/vconline/match/"+op, raw, map[string]string{"S": key})
		if code != 200 {
			t.Fatalf("peer %d matchmaking returned %d", i+1, code)
		}
		response, err := wire.Decode(body, true)
		if err != nil || len(response[groupIDs]) != i+1 {
			t.Fatalf("peer %d membership: %v", i+1, err)
		}
		roomID = response[matchID][0].N
		id := response[localGroup][0].N
		peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { peer.Close() })
		peer.SetDeadline(time.Now().Add(2 * time.Second))
		open := make([]byte, 24)
		copy(open, response[0x6a9160cc][0].Data)
		binary.LittleEndian.PutUint64(open[16:], id)
		raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Payload: open})
		if _, err = peer.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, wire.MaxDatagram)
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := wire.DecodeUDP(buf[:n])
		if err != nil || ack.Kind != 1 {
			t.Fatalf("peer %d UDP open: %v", i+1, err)
		}
		connections = append(connections, connection{peer: peer, id: id, model: reliableNativeModel{received: make(map[uint64][]uint16), uplink: make([]bool, 1)}})
	}
	fourth := loginNative(t, s)
	raw, _ := wire.Encode(wire.Sorted([]wire.Field{wire.Num(userIDs, wire.Int64, 76561198000000004), wire.Num(matchID, wire.Int64, roomID)}))
	code, _, _ := request(t, s, "/lab/vconline/match/search", raw, map[string]string{"S": fourth})
	if code != 400 {
		t.Fatal("configured three-player capacity was bypassed")
	}
	for _, c := range connections {
		raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1800, Payload: reliableTestRecord(c.id, 0, []byte{0, 0})})
		if _, err := c.peer.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	for i := range connections {
		c := &connections[i]
		for !c.model.uplink[0] || len(c.model.received) < 2 {
			buf := make([]byte, wire.MaxDatagram)
			n, _, err := c.peer.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("peer %d did not receive both remote joins and its uplink ACK: %v", i+1, err)
			}
			c.model.receive(t, buf[:n])
		}
		if c.model.head != 2 {
			t.Fatalf("peer %d receive head = %d", i+1, c.model.head)
		}
		raw, _ = wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: c.model.acknowledgement(c.id)})
		if _, err := c.peer.WriteToUDP(raw, s.UDPAddress().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReliableTargetedCompoundAndRoomIsolation(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 3)
	_, err := d.response("create", 4, wire.Fields{userIDs: {wire.Num(userIDs, wire.Int64, 1004)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	foreign := d.Sessions[4]
	foreign.Address = netip.MustParseAddrPort("127.0.0.1:14004")
	d.Addresses[foreign.Address] = foreign
	targets := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(targets, 3)
	binary.LittleEndian.PutUint64(targets[4:], peers[1].ID)
	binary.LittleEndian.PutUint64(targets[12:], peers[1].ID)
	binary.LittleEndian.PutUint64(targets[20:], foreign.ID)
	for _, seq := range []uint16{1, 0} {
		targets = append(targets, reliableTestRecord(peers[0].ID, seq, []byte{byte(seq), 0})...)
	}
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x800, Payload: targets})
	replies, err := d.udpReplies(raw, peers[0].Address, now, make([]byte, wire.MaxDatagram), nil)
	if err != nil {
		t.Fatal(err)
	}
	model := reliableNativeModel{received: make(map[uint64][]uint16)}
	for _, reply := range replies {
		if reply.Address == peers[1].Address {
			model.receive(t, reply.Data)
		} else if reply.Address != peers[0].Address {
			t.Fatal("targeted record escaped its room or recipient set")
		}
	}
	if model.head != 2 || len(model.received[peers[0].ID]) != 2 {
		t.Fatal("compound records were not reordered and delivered exactly once")
	}
	if foreign.Reliable != nil || peers[2].Reliable != nil {
		t.Fatal("non-recipient acquired reliable delivery state")
	}
}

func FuzzReliableApplicationEnvelope(f *testing.F) {
	f.Add(reliableTestRecord(1, 0, []byte{0, 0}))
	f.Add(reliableTestACK(1, 0, 0, 0))
	f.Add([]byte("heartbeat"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > wire.MaxDatagram {
			return
		}
		parts, handled, err := reliableParts(raw, 1)
		if err != nil || !handled {
			return
		}
		total := 0
		for _, part := range parts {
			if len(part.record) < 16 || int(binary.LittleEndian.Uint16(part.record[2:])) != len(part.record) {
				t.Fatal("decoder admitted an invalid record length")
			}
			total += len(part.record)
		}
		if total != len(raw) {
			t.Fatal("decoder lost compound-envelope bytes")
		}
	})
}
