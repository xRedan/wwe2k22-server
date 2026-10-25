package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

func jsonObject(raw []byte, unique bool) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	var e error
	if unique {
		v, e = readJSONValue(d, true, 0)
	} else {
		// Decode whole values without Token's per-token allocations. Preserve exact
		// numbers and the same nesting limit as the duplicate-checking path.
		e = d.Decode(&v)
		if e == nil {
			e = checkJSONDepth(v, 0)
		}
	}
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("expected object")
	}
	return m, nil
}
func checkJSONDepth(v any, depth int) error {
	if depth > 128 {
		return errors.New("JSON depth")
	}
	switch x := v.(type) {
	case map[string]any:
		for _, value := range x {
			if err := checkJSONDepth(value, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, value := range x {
			if err := checkJSONDepth(value, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
func readJSONValue(d *json.Decoder, unique bool, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("JSON depth")
	}
	v, e := d.Token()
	if e != nil {
		return nil, e
	}
	if delim, ok := v.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := key.(string)
				if !ok {
					return nil, errors.New("JSON key")
				}
				if _, has := m[s]; has && unique {
					return nil, errors.New("duplicate JSON key")
				}
				item, e := readJSONValue(d, unique, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = item
			}
			_, e = d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				item, e := readJSONValue(d, unique, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, item)
			}
			_, e = d.Token()
			return a, e
		}
		return nil, errors.New("invalid JSON delimiter")
	}
	return v, nil
}
func jstr(v any) (string, bool) { s, ok := v.(string); return s, ok }
func juint(v any) (uint64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, e := strconv.ParseUint(string(x), 10, 64)
		return n, e == nil
	case uint64:
		return x, true
	case uint32:
		return uint64(x), true
	case int:
		if x >= 0 {
			return uint64(x), true
		}
	case int64:
		if x >= 0 {
			return uint64(x), true
		}
	}
	return 0, false
}
func jint(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, e := strconv.ParseInt(string(x), 10, 64)
		return n, e == nil
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		if x < 1<<63 {
			return int64(x), true
		}
	}
	return 0, false
}
func jbool(v any) (bool, bool) { b, ok := v.(bool); return b, ok }
func str(v any) string         { s, _ := jstr(v); return s }
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func canonicalID(v any) (uint64, error) {
	s, ok := jstr(v)
	if !ok || len(s) > 20 || !digits(s) || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("invalid identifier")
	}
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || n == 0 {
		return 0, errors.New("invalid identifier")
	}
	return n, nil
}
func fieldsAllowed(m map[string]any, keys ...string) bool {
	set := map[string]bool{}
	for _, k := range keys {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			return false
		}
	}
	return true
}
func validText(s string, limit int) bool {
	return utf8.ValidString(s) && len(s) <= limit && !strings.ContainsRune(s, 0)
}
func noControls(s string) bool {
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func identity(m map[string]any) string {
	for _, k := range []string{"Login", "userid", "user_id", "UserID", "steamUserId", "username", "Username"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case json.Number:
			if _, ok := jint(x); !ok {
				if _, ok = juint(x); !ok {
					continue
				}
			}
			s = string(x)
		default:
			continue
		}
		sum := sha256.Sum256([]byte("wwe-local:" + s))
		return hex.EncodeToString(sum[:16])
	}
	sum := sha256.Sum256([]byte("wwe-local:fixture-player"))
	return hex.EncodeToString(sum[:16])
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, e := io.ReadFull(rand.Reader, b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func uuidID(v any, zero bool) (string, error) {
	s, ok := jstr(v)
	if !ok || (len(s) != 32 && len(s) != 36) {
		return "", fail(400, "Invalid native content identifier")
	}
	if len(s) == 36 {
		for _, p := range []int{8, 13, 18, 23} {
			if s[p] != '-' {
				return "", fail(400, "Invalid native content identifier")
			}
		}
		s = strings.ReplaceAll(s, "-", "")
	}
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 16 || (!zero && bytes.Equal(b, make([]byte, 16))) {
		return "", fail(400, "Invalid native content identifier")
	}
	return strings.ToLower(s), nil
}
func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return hex.EncodeToString(b), nil
}
func copyObject(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
func errorJSON(message string) map[string]any { return map[string]any{"error": message} }
func decimal(n uint64) string                 { return fmt.Sprint(n) }

// DecodeSettings rejects duplicate operator settings before applying any values.
func DecodeSettings(raw []byte) (map[string]any, error) {
	return jsonObject(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf}), true)
}
