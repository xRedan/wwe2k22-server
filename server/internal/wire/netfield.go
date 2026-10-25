package wire

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"unicode/utf8"
)

const MaxBody = 1024 * 1024
const (
	Int32      uint32 = 0x46304ce1
	Int64      uint32 = 0x32c4f552
	Time64     uint32 = 0x1e4d318b
	String     uint32 = 0xcc05a5a8
	Boolean    uint32 = 0xc334f341
	Blob       uint32 = 0x7d06b391
	Address    uint32 = 0x75703480
	Result     uint32 = 0xbb258956
	Success    uint64 = 0x8a46d950
	SessionKey uint32 = 0xf046a214
)

var ErrFormat = errors.New("invalid binary fields")

type Endpoint struct {
	IP        netip.Addr
	Port, Tag uint16
}
type Field struct {
	ID, Kind uint32
	N        uint64
	Data     []byte
	Text     string
	Endpoint Endpoint
}
type Fields map[uint32][]Field

func Num(id, kind uint32, n uint64) Field { return Field{ID: id, Kind: kind, N: n} }
func Binary(id uint32, b []byte) Field    { return Field{ID: id, Kind: Blob, Data: b} }
func Str(id uint32, s string) Field       { return Field{ID: id, Kind: String, Text: s} }
func Addr(id uint32, e Endpoint) Field    { return Field{ID: id, Kind: Address, Endpoint: e} }
func (f Fields) Scalar(id, kind uint32, def uint64) (uint64, error) {
	v, ok := f[id]
	if !ok {
		return def, nil
	}
	if len(v) != 1 || v[0].Kind != kind {
		return 0, ErrFormat
	}
	return v[0].N, nil
}
func (f Fields) Has(id uint32) bool { _, ok := f[id]; return ok }
func Sorted(records []Field) []Field {
	slices.SortStableFunc(records, func(a, b Field) int { return cmp.Compare(a.ID, b.ID) })
	return records
}
func Encode(records []Field) ([]byte, error) {
	size := 16 * (len(records) + 1)
	for _, f := range records {
		if f.Kind == String {
			size += len(f.Text) + 1
		} else if f.Kind == Blob {
			size += len(f.Data)
		}
	}
	if size > MaxBody {
		return nil, ErrFormat
	}
	out := make([]byte, size)
	payload := 16 * (len(records) + 1)
	cursor := payload
	for i, f := range records {
		if f.ID == 0 {
			return nil, ErrFormat
		}
		p := out[i*16:]
		binary.BigEndian.PutUint32(p, f.ID)
		binary.BigEndian.PutUint32(p[4:], f.Kind)
		switch f.Kind {
		case Int32:
			binary.BigEndian.PutUint32(p[8:], uint32(f.N))
		case Int64, Time64:
			binary.BigEndian.PutUint64(p[8:], f.N)
		case Boolean:
			if f.N != 0 {
				p[11] = 1
			}
		case Address:
			if !f.Endpoint.IP.Is4() {
				return nil, ErrFormat
			}
			a := f.Endpoint.IP.As4()
			copy(p[8:12], a[:])
			binary.BigEndian.PutUint16(p[12:], f.Endpoint.Port)
			binary.BigEndian.PutUint16(p[14:], f.Endpoint.Tag)
		case String, Blob:
			n := len(f.Data)
			if f.Kind == String {
				n = len(f.Text) + 1
				copy(out[cursor:], f.Text)
			} else {
				copy(out[cursor:], f.Data)
			}
			binary.BigEndian.PutUint32(p[8:], uint32(cursor-payload))
			binary.BigEndian.PutUint32(p[12:], uint32(n))
			cursor += n
		default:
			return nil, ErrFormat
		}
	}
	return out, nil
}
func Decompress(raw []byte, encoding string, limit int) ([]byte, error) {
	var reader io.ReadCloser
	var err error
	b := bytes.NewReader(raw)
	switch encoding {
	case "identity":
		if len(raw) > limit {
			return nil, ErrFormat
		}
		return raw, nil
	case "gzip":
		var g *gzip.Reader
		g, err = gzip.NewReader(b)
		if err == nil {
			g.Multistream(false)
			reader = g
		}
	case "deflate":
		reader, err = zlib.NewReader(b)
	default:
		return nil, ErrFormat
	}
	if err != nil {
		return nil, ErrFormat
	}
	defer reader.Close()
	out, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil || len(out) > limit || b.Len() != 0 {
		return nil, ErrFormat
	}
	return out, nil
}
func Decode(raw []byte, repeated bool) (Fields, error) {
	if len(raw) > MaxBody {
		return nil, ErrFormat
	}
	if bytes.HasPrefix(raw, []byte{31, 139}) {
		var err error
		raw, err = Decompress(raw, "gzip", MaxBody)
		if err != nil {
			return nil, err
		}
	}
	if bytes.HasPrefix(raw, []byte("ZLIB")) {
		return nil, ErrFormat
	}
	end := 0
	for {
		if end+16 > len(raw) {
			return nil, ErrFormat
		}
		id := binary.BigEndian.Uint32(raw[end:])
		end += 16
		if id == 0 {
			break
		}
	}
	payload := raw[end:]
	fields := Fields{}
	// Offset aliases must not amplify a bounded request into unbounded copies.
	ownedBytes := uint64(0)
	for off := 0; off < end-16; off += 16 {
		p := raw[off : off+16]
		f := Field{ID: binary.BigEndian.Uint32(p), Kind: binary.BigEndian.Uint32(p[4:])}
		if old := fields[f.ID]; len(old) > 0 && (!repeated || old[0].Kind != f.Kind) {
			return nil, ErrFormat
		}
		switch f.Kind {
		case Int32:
			f.N = uint64(binary.BigEndian.Uint32(p[8:]))
		case Int64, Time64:
			f.N = binary.BigEndian.Uint64(p[8:])
		case Boolean:
			if p[11] != 0 {
				f.N = 1
			}
		case Address:
			var a [4]byte
			copy(a[:], p[8:12])
			f.Endpoint = Endpoint{netip.AddrFrom4(a), binary.BigEndian.Uint16(p[12:]), binary.BigEndian.Uint16(p[14:])}
		case String, Blob:
			a, n := uint64(binary.BigEndian.Uint32(p[8:])), uint64(binary.BigEndian.Uint32(p[12:]))
			if a > uint64(len(payload)) || n > uint64(len(payload))-a {
				return nil, ErrFormat
			}
			if n > MaxBody-ownedBytes {
				return nil, ErrFormat
			}
			ownedBytes += n
			data := payload[a : a+n]
			if f.Kind == String {
				zero := bytes.IndexByte(data, 0)
				if zero < 0 || !utf8.Valid(data[:zero]) {
					return nil, ErrFormat
				}
				f.Text = string(data[:zero])
			} else {
				f.Data = bytes.Clone(data)
			}
		default:
			f.Data = bytes.Clone(p[8:])
		}
		fields[f.ID] = append(fields[f.ID], f)
	}
	return fields, nil
}
