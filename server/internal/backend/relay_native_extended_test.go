package backend

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"wwe2k22-server/internal/wire"
)

// Historical native captures contain reliable join data in type 4 frames,
// while their acknowledgements arrive in type 3. Both share one sequence space.
func TestReliableNativeExtendedIngress(t *testing.T) {
	for _, count := range []int{2, 3, 4, 5, 6, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			d, peers, now := reliableTestRoom(t, count)
			delivered := make(map[uint64]int)
			received := make(map[netip.AddrPort]uint16)
			for _, source := range peers {
				raw, e := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 4, Flags: 0x1800, Payload: reliableTestRecord(source.ID, 0, []byte("native lobby join"))})
				if e != nil {
					t.Fatal(e)
				}
				replies, e := d.udpReplies(raw, source.Address, now, make([]byte, wire.MaxDatagram), nil)
				if e != nil {
					t.Fatal(e)
				}
				if d.UDP["reliable_accepted"] != uint64(len(delivered)+1) {
					t.Fatal("native type 4 join bypassed reliability and cannot share type 3 ACK state")
				}
				countData := 0
				for _, reply := range replies {
					frame, e := wire.DecodeUDP(reply.Data)
					if e != nil {
						t.Fatal(e)
					}
					parts, handled, e := reliableParts(frame.Payload, source.ID)
					if e != nil || !handled {
						t.Fatal("invalid relay envelope", e)
					}
					for _, part := range parts {
						if part.command == reliableData {
							if frame.Kind != 4 {
								t.Fatal("native extended data changed transport type", frame.Kind)
							}
							if binary.LittleEndian.Uint16(part.record[20:]) != received[reply.Address] {
								t.Fatal("destination sequence did not advance")
							}
							received[reply.Address]++
							countData++
						} else if frame.Kind != 3 {
							t.Fatal("ACK must retain its ordinary native transport type")
						}
					}
				}
				if countData != count-1 {
					t.Fatal("native join not delivered to all other peers", countData)
				}
				delivered[source.ID] = countData
			}
		})
	}
}

func TestReliableNativeMixedFrameRetransmission(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 2)
	for sequence := uint16(0); sequence < 5; sequence++ {
		raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3 + uint8(sequence%2), Flags: 0x1800, Payload: reliableTestRecord(peers[0].ID, sequence, []byte("mixed"))})
		if _, e := d.udpReplies(raw, peers[0].Address, now, make([]byte, wire.MaxDatagram), nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(peers[1].Reliable.outgoing) != 5 {
		t.Fatal("mixed data not queued")
	}
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1000, Payload: reliableTestACK(peers[0].ID, 0, 0, 5)})
	replies, e := d.udpReplies(raw, peers[0].Address, now.Add(2*reliableRetry), make([]byte, wire.MaxDatagram), nil)
	if e != nil {
		t.Fatal(e)
	}
	received := 0
	for _, reply := range replies {
		frame, e := wire.DecodeUDP(reply.Data)
		if e != nil {
			t.Fatal(e)
		}
		for payload := frame.Payload; len(payload) >= 16; {
			length := int(binary.LittleEndian.Uint16(payload[2:]))
			if length < 16 || length > len(payload) {
				t.Fatal("bad mixed envelope")
			}
			record := payload[:length]
			payload = payload[length:]
			if binary.LittleEndian.Uint32(record[4:]) == reliableData {
				sequence := binary.LittleEndian.Uint16(record[20:])
				if frame.Kind != 3+uint8(sequence%2) {
					t.Fatal("retransmission changed native frame kind", sequence, frame.Kind)
				}
				received++
			} else if frame.Kind != 3 {
				t.Fatal("ordinary ACK merged into extended frame")
			}
		}
	}
	if received != 5 {
		t.Fatal("mixed retransmission lost records", received)
	}
	// A normal type 3 ACK must release all extended downstream data too.
	reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, 5, 0, 0), now.Add(3*reliableRetry))
	if len(peers[1].Reliable.outgoing) != 0 {
		t.Fatal("ordinary ACK did not release mixed data")
	}
}
