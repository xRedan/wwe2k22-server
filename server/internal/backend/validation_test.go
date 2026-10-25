package backend

import (
	"encoding/json"
	"testing"
)

func TestNativeDependentCountsCannotBypassUnsupportedOperations(t *testing.T) {
	for _, v := range []any{json.Number("-1"), json.Number("18446744073709551615")} {
		if _, e := uploadMetadata(map[string]any{"ContentType": json.Number("1"), "Title": "test", "SubContentCount": v}); statusCode(e, 0) != 501 {
			t.Fatal("unreconstructed dependencies accepted")
		}
	}
	for _, v := range []any{0, int64(0), uint64(0), json.Number("0")} {
		if numericNonzero(v) {
			t.Fatal("zero treated as dependency")
		}
	}
}
func TestMalformedUTF16Rejected(t *testing.T) {
	if _, e := jsonEncoding([]byte{0xff, 0xfe, '"', 0, 0, 0xd8, '"', 0}); e == nil {
		t.Fatal("invalid surrogate accepted")
	}
}
