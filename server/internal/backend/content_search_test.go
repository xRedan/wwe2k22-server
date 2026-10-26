package backend

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSearchReusesMetadataBytesAcrossChangingRowSizes(t *testing.T) {
	s, e := newContentStore("", 8<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	// Vary the copied length both ways. A reused buffer must not expose the
	// previous row's suffix or retain references to its mutable bytes.
	for i, size := range []int{8192, 0, 65536, 1, 4096, 0} {
		meta := `{"ContentType":9223372036854775807,"Tag0":"Stra\u00dfe","FromWeb":true,"Title":"` + strings.Repeat("x", size) + `"}` + strings.Repeat(" \r\n\t", i)
		if e = s.exec("INSERT INTO content VALUES (?,?,?,?,?)", fmt.Sprintf("%032x", i+1), "owner", 0, int64(i), meta); e != nil {
			t.Fatal(e)
		}
	}
	typ, web := int64(9223372036854775807), true
	ids, total, e := s.search("owner", contentQuery{Type: &typ, FromWeb: &web, Tags: []string{"STRASSE"}, Offset: 1, Limit: 3})
	want := []string{fmt.Sprintf("%032x", 5), fmt.Sprintf("%032x", 4), fmt.Sprintf("%032x", 3)}
	if e != nil || total != 6 || !reflect.DeepEqual(ids, want) {
		t.Fatal(ids, total, e)
	}
}

func TestSearchMetadataCopyPreservesJSONValidation(t *testing.T) {
	for _, item := range []struct {
		name, meta string
		invalid    bool
	}{
		{"duplicate-last-value", `{"ContentType":1,"Tag0":"wrong","Tag0":"Stra\u00dfe"}`, false},
		{"trailing-whitespace", "{\"Tag0\":\"Straße\"}\r\n\t ", false},
		{"exact-field-case", `{"Tag0":"STRASSE","tag0":"wrong"}`, false},
		{"invalid-utf8", "{\"Tag0\":\"" + string([]byte{0xff}) + "\"}", true},
		{"trailing-value", `{"Tag0":"STRASSE"} {}`, true},
		{"truncated", `{"Tag0":"STRASSE"`, true},
		{"non-object", `["STRASSE"]`, true},
		{"depth", `{"Tag0":"STRASSE","unused":` + strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130) + "}", true},
	} {
		t.Run(item.name, func(t *testing.T) {
			s, e := newContentStore("", 8<<20)
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			if e = s.exec("INSERT INTO content VALUES (?,?,?,?,?)", strings.Repeat("1", 32), "owner", 0, 1, item.meta); e != nil {
				t.Fatal(e)
			}
			ids, total, e := s.search("owner", contentQuery{Tags: []string{"STRASSE"}, Limit: 64})
			if item.invalid {
				if e == nil {
					t.Fatal("invalid metadata accepted")
				}
			} else if e != nil || total != 1 || len(ids) != 1 {
				t.Fatal(ids, total, e)
			}
		})
	}
}
