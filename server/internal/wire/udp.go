package wire

import (
	"encoding/binary"
	"errors"
)

const MaxDatagram = 0x5c0

var ErrUDP = errors.New("invalid UDP frame")

type Datagram struct {
	Namespace uint16
	Kind      uint8
	Flags     uint16
	Payload   []byte
}

func DecodeUDP(raw []byte) (Datagram, error) {
	if len(raw) < 4 || len(raw) > MaxDatagram {
		return Datagram{}, ErrUDP
	}
	h := binary.LittleEndian.Uint32(raw)
	if int(h&0x7ff) != len(raw) {
		return Datagram{}, ErrUDP
	}
	return Datagram{uint16(h >> 16), uint8((h >> 13) & 7), uint16(h & 0x1800), raw[4:]}, nil
}
func EncodeUDP(f Datagram) ([]byte, error) { return EncodeUDPInto(nil, f) }

// EncodeUDPInto reuses dst when it has enough capacity. The returned frame may
// share dst, and must be consumed before the next reuse. Payload may overlap dst.
func EncodeUDPInto(dst []byte, f Datagram) ([]byte, error) {
	if f.Kind > 7 || f.Flags&^uint16(0x1800) != 0 || len(f.Payload)+4 > MaxDatagram {
		return nil, ErrUDP
	}
	n := len(f.Payload) + 4
	var out []byte
	if cap(dst) >= n {
		out = dst[:n]
	} else {
		out = make([]byte, n)
	}
	copy(out[4:], f.Payload)
	binary.LittleEndian.PutUint32(out, uint32(f.Namespace)<<16|uint32(f.Kind)<<13|uint32(f.Flags)|uint32(len(out)))
	return out, nil
}

// TargetedBytes returns a validated, borrowed little-endian recipient vector.
func TargetedBytes(f Datagram) ([]byte, []byte, error) {
	if (f.Kind != 3 && f.Kind != 4) || f.Flags != 0x800 || len(f.Payload) < 4 {
		return nil, nil, ErrUDP
	}
	n := uint64(binary.LittleEndian.Uint32(f.Payload))
	end := 4 + 8*n
	if n == 0 || end > uint64(len(f.Payload)) {
		return nil, nil, ErrUDP
	}
	return f.Payload[4:end], f.Payload[end:], nil
}
func Targeted(f Datagram) ([]uint64, []byte, error) {
	raw, p, err := TargetedBytes(f)
	if err != nil {
		return nil, nil, err
	}
	ids := make([]uint64, len(raw)/8)
	for i := range ids {
		ids[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return ids, p, nil
}
func IsApplicationACK(f Datagram, id uint64) bool {
	p := f.Payload
	return f.Kind == 3 && f.Flags == 0x1000 && len(p) == 22 && binary.LittleEndian.Uint16(p) == 0 && binary.LittleEndian.Uint16(p[2:]) == 22 && binary.LittleEndian.Uint32(p[4:]) == 0x85912ac9 && binary.LittleEndian.Uint64(p[8:]) == id
}
