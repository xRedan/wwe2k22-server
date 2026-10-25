package wire

import (
	"hash/crc32"
	"time"
)

func Catalog() []byte {
	records := []Field{}
	for _, op := range []struct{ upper, lower string }{{"SEARCH", "search"}, {"CREATE", "create"}, {"UPDATE", "update"}, {"INTERLOCKED_UPDATE", "interlocked_update"}, {"LIST", "list"}} {
		fields := []Field{Num(0xe6e567b6, Int32, uint64(crc32.Checksum([]byte("MATCH_SESSION:"+op.upper), crc32.MakeTable(crc32.Castagnoli)))), Num(0xe9360420, Int32, 0x251a8fc8), Str(0x51211b00, "POST"), Num(0x85901811, Int32, 0x61d84089), Str(0x3262a956, "https://wwe2k22-ws.2ksports.com:22117/lab/vconline/match/"+op.lower)}
		records = append(records, Sorted(fields)...)
	}
	raw, _ := Encode(records)
	return raw
}
func Session(key uint64, catalog []byte, now time.Time) []byte {
	ms := uint64(now.UnixMilli())
	fields := []Field{Num(Result, Int32, Success), Num(SessionKey, Int64, key), Num(0x7e6f0a6e, Time64, ms), Num(0x428ed19c, Time64, ms+60000), Num(0xb015a903, Int32, 0)}
	if catalog != nil {
		fields = append(fields, Binary(0x0e78781e, catalog))
	}
	raw, _ := Encode(Sorted(fields))
	return raw
}
