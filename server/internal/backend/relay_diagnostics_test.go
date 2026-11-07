package backend

import (
	"net/netip"
	"testing"
	"time"
	"wwe2k22-server/internal/wire"
)

func TestReliableAdaptiveRetransmission(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 2)
	q := relayState(peers[1])
	// Ten round trips of 150 ms, each acknowledged exactly once.
	for i := 0; i < 10; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, uint16(i), []byte("rtt")), at)
		reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, uint16(i+1), 0, 0), at.Add(150*time.Millisecond))
	}
	if q.srtt < 140*time.Millisecond || q.srtt > 160*time.Millisecond || q.rto <= 150*time.Millisecond {
		t.Fatalf("RTT estimate srtt=%v rto=%v", q.srtt, q.rto)
	}
	start := now.Add(20 * time.Second)
	reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 10, []byte("late")), start)
	before := d.UDP["reliable_retransmitted"]
	// The fixed 100 ms timer resent here although the ACK could not arrive yet.
	reliableTestSend(t, d, peers[0], reliableTestACK(peers[0].ID, 0, 0, 0), start.Add(120*time.Millisecond))
	if d.UDP["reliable_retransmitted"] != before {
		t.Fatal("retransmitted before the measured round trip elapsed")
	}
	reliableTestSend(t, d, peers[0], reliableTestACK(peers[0].ID, 0, 0, 0), start.Add(q.rto+time.Millisecond))
	if d.UDP["reliable_retransmitted"] != before+1 {
		t.Fatal("lost record was not retransmitted after the adaptive timeout")
	}
	// Repeated loss backs off, bounded by reliableRetryMax.
	if wait := q.retryAfter(&reliableDelivery{retries: 200}); wait != reliableRetryMax {
		t.Fatalf("backoff cap %v", wait)
	}
	if wait := (&reliablePeer{}).retryAfter(&reliableDelivery{}); wait != reliableRetry {
		t.Fatalf("initial timeout %v", wait)
	}
}

func TestRelayDiagnosticsEvents(t *testing.T) {
	d, peers, now := reliableTestRoom(t, 2)
	var events []map[string]any
	d.notify = func(e map[string]any) { events = append(events, e) }
	has := func(name string) map[string]any {
		for _, e := range events {
			if e["event"] == name {
				return e
			}
		}
		return nil
	}
	reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 0, []byte("a")), now)
	reliableTestSend(t, d, peers[1], reliableTestACK(peers[1].ID, 0, 0, 0), now)
	d.relayWatch(now.Add(time.Second))
	if has("relay_silent") != nil {
		t.Fatal("silence reported too early")
	}
	d.relayWatch(now.Add(4 * time.Second))
	e := has("relay_silent")
	if e == nil || e["player"] == 0 || e["room"] == "" {
		t.Fatalf("missing labelled silence event: %v", events)
	}
	for _, key := range []string{"session", "token", "address", "user"} {
		if _, leaked := e[key]; leaked {
			t.Fatalf("diagnostic event leaks %s", key)
		}
	}
	reliableTestSend(t, d, peers[0], reliableTestACK(peers[0].ID, 0, 0, 0), now.Add(5*time.Second))
	if has("relay_resumed") == nil {
		t.Fatal("missing resume event")
	}
	q := relayState(peers[1])
	q.next, q.sent, q.acknowledged, q.outgoing = 65535, 65535, 65535, nil
	reliableTestSend(t, d, peers[0], reliableTestRecord(peers[0].ID, 1, []byte("w")), now.Add(6*time.Second))
	if e := has("relay_sequence_wrap"); e == nil || e["direction"] != "downlink" || d.UDP["reliable_sequence_wraps"] != 1 {
		t.Fatalf("missing wrap event: %v", events)
	}
	snapshot := d.relaySnapshot(now.Add(6 * time.Second))
	if len(snapshot) != 1 || len(snapshot[0]["members"].([]map[string]any)) != 2 {
		t.Fatalf("snapshot %v", snapshot)
	}
	// Datagrams from an unbound address are counted, not routed.
	raw, _ := wire.EncodeUDP(wire.Datagram{Namespace: 1, Kind: 3, Flags: 0x1800, Payload: []byte{1, 2, 3, 4}})
	moved := netip.AddrPortFrom(peers[0].Address.Addr(), 40000)
	if _, err := d.udpReplies(raw, moved, now, make([]byte, wire.MaxDatagram), nil); err != nil || d.UDP["unknown_source"] != 1 {
		t.Fatalf("unknown source err=%v count=%d", err, d.UDP["unknown_source"])
	}
}
