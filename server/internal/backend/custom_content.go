package backend

import (
	"bytes"
	"io"
	"mime"
	"regexp"
	"strings"
)

const maxUpload = 64 * 1024 * 1024

var contentContext = []string{"Platform", "FirstParty", "FirstPartyEnv", "GameID", "PatchVersion", "RT"}

var nativeBoundaryPattern = regexp.MustCompile(`^[A-Za-z0-9'()+_,./:=?-]{1,70}$`)

type multipartInput struct {
	buffer  [64 * 1024]byte
	r       io.Reader
	pending []byte
}

func (m *multipartInput) read() error {
	b := m.buffer[:]
	n, e := m.r.Read(b)
	if n == 0 {
		if e != nil {
			return e
		}
		return io.ErrNoProgress
	}
	m.pending = append(m.pending, b[:n]...)
	return nil
}
func (m *multipartInput) line() (string, error) {
	for {
		if i := bytes.Index(m.pending, []byte("\r\n")); i >= 0 {
			if i > 8192 {
				return "", fail(413, "Multipart header is too large")
			}
			s := string(m.pending[:i])
			m.pending = m.pending[i+2:]
			return s, nil
		}
		if len(m.pending) > 8192 {
			return "", fail(413, "Multipart header is too large")
		}
		if e := m.read(); e != nil {
			return "", fail(400, "Incomplete multipart headers")
		}
	}
}
func (m *multipartInput) part(boundary []byte, target *spool, limit int64) (bool, error) {
	marker := append([]byte("\r\n--"), boundary...)
	for {
		start := bytes.Index(m.pending, marker)
		count := 0
		if start >= 0 && len(m.pending) >= start+len(marker)+2 {
			suffix := string(m.pending[start+len(marker) : start+len(marker)+2])
			if suffix == "--" || suffix == "\r\n" {
				if target.size+int64(start) > limit {
					return false, fail(413, "Native multipart part is too large")
				}
				if _, e := target.Write(m.pending[:start]); e != nil {
					return false, e
				}
				m.pending = m.pending[start+len(marker)+2:]
				return suffix == "--", nil
			}
			count = start + 2
		} else if start >= 0 {
			count = start
		} else {
			count = len(m.pending) - len(marker) - 2
			if count < 0 {
				count = 0
			}
		}
		if count > 0 {
			if target.size+int64(count) > limit {
				return false, fail(413, "Native multipart part is too large")
			}
			if _, e := target.Write(m.pending[:count]); e != nil {
				return false, e
			}
			m.pending = m.pending[count:]
			// Examine buffered bytes before reading again. False boundary
			// prefixes can consume only a few bytes while much more is pending.
			continue
		}
		if e := m.read(); e != nil {
			return false, fail(400, "Missing native multipart terminator")
		}
	}
}
func parseMultipart(contentType string, r io.Reader, length int64) (map[string]any, map[string]binaryPart, func(), error) {
	files := map[string]binaryPart{}
	spools := []*spool{}
	cleanup := func() {
		for _, s := range spools {
			s.Close()
		}
	}
	bad := func(e error) (map[string]any, map[string]binaryPart, func(), error) {
		cleanup()
		return nil, nil, func() {}, e
	}
	if length < 1 || length > maxUpload {
		return bad(fail(413, "Native upload is too large"))
	}
	media, params, e := mime.ParseMediaType(contentType)
	boundary := params["boundary"]
	if e != nil || media != "multipart/form-data" || len(boundary) < 1 || len(boundary) > 70 || !nativeBoundaryPattern.MatchString(boundary) {
		return bad(fail(400, "Expected native multipart upload"))
	}
	limited := &io.LimitedReader{R: r, N: length}
	reader := &multipartInput{r: limited}
	line, e := reader.line()
	if e != nil || line != "--"+boundary {
		return bad(fail(400, "Invalid native multipart opening"))
	}
	var data map[string]any
	for part := 0; part < 5; part++ {
		headers := map[string]string{}
		total := 0
		for {
			line, e = reader.line()
			if e != nil {
				return bad(e)
			}
			total += len(line) + 2
			if total > 16384 {
				return bad(fail(413, "Multipart headers are too large"))
			}
			if line == "" {
				break
			}
			k, v, ok := strings.Cut(line, ":")
			k = strings.ToLower(k)
			_, duplicate := headers[k]
			if !ok || duplicate {
				return bad(fail(400, "Invalid native multipart header"))
			}
			for _, c := range line {
				if c > 127 {
					return bad(fail(400, "Invalid native multipart header"))
				}
			}
			headers[k] = strings.TrimSpace(v)
		}
		disposition, params, e := mime.ParseMediaType(headers["content-disposition"])
		name := params["name"]
		if e != nil || disposition != "form-data" || (name != "Params" && name != "content" && name != "thumb1" && name != "thumb2" && name != "RstrParts") {
			return bad(fail(501, "Unsupported native multipart part"))
		}
		if _, has := files[name]; has || (name == "Params" && data != nil) {
			return bad(fail(400, "Duplicate native multipart part"))
		}
		if _, has := headers["content-transfer-encoding"]; has {
			return bad(fail(501, "Unsupported multipart transfer encoding"))
		}
		s := &spool{}
		spools = append(spools, s)
		limit := int64(maxAsset)
		if name == "Params" {
			limit = 1024 * 1024
		}
		final, e := reader.part([]byte(boundary), s, limit)
		if e != nil {
			return bad(e)
		}
		s.Seek(0, io.SeekStart)
		if name == "Params" {
			ct, _, e := mime.ParseMediaType(headers["content-type"])
			if e != nil || ct != "application/json" {
				return bad(fail(400, "Native Params must be JSON"))
			}
			raw, e := io.ReadAll(s)
			if e != nil {
				return bad(e)
			}
			data, e = jsonObject(raw, true)
			if e != nil {
				return bad(fail(400, "Invalid native multipart metadata"))
			}
		} else {
			if s.size == 0 {
				return bad(fail(400, "Empty native content part"))
			}
			files[name] = binaryPart{s, s.size}
		}
		if final {
			tail := reader.pending
			if len(tail) > 2 {
				return bad(fail(400, "Unexpected multipart trailing data"))
			}
			rest, e := io.ReadAll(io.LimitReader(limited, 3))
			if e != nil {
				return bad(e)
			}
			tail = append(tail, rest...)
			if limited.N != 0 || (!bytes.Equal(tail, []byte("\r\n")) && len(tail) != 0) {
				return bad(fail(400, "Unexpected multipart trailing data"))
			}
			if data == nil {
				return bad(fail(400, "Native Params and content parts are required"))
			}
			if _, ok := files["content"]; !ok {
				return bad(fail(400, "Native Params and content parts are required"))
			}
			return data, files, cleanup, nil
		}
	}
	return bad(fail(413, "Too many native multipart parts"))
}
func uploadMetadata(data map[string]any) (map[string]any, error) {
	stringsSet := map[string]bool{"Title": true, "Comment0": true, "Comment1": true, "Comment2": true}
	for i := 0; i < 10; i++ {
		stringsSet["Tag"+string(rune('0'+i))] = true
	}
	bools := map[string]bool{"Private": true, "FromWeb": true, "OtherUserEdit": true, "NotUploading": true}
	ints := map[string]bool{}
	for _, k := range strings.Fields("ContentType SubContentCount BuildVersion DataVersion PLCFlags DLCFlags DLCFlags1 DLCFlags2 VCCFlags PlayerSetSlot TexLogoW TexLogoH RstrPartsSize VCCFlags1 VCCFlags2 VCCFlags3 VCCFlags4 VCCFlags5 VCCFlags6 VCCFlags7 VCCFlags8 VCCFlags9") {
		ints[k] = true
	}
	context := map[string]bool{}
	for _, k := range contentContext {
		context[k] = true
	}
	if _, ok := data["ContentType"]; !ok || str(data["Title"]) == "" {
		return nil, fail(400, "Native ContentType and Title are required")
	}
	out := map[string]any{}
	for k, v := range data {
		if context[k] {
			continue
		}
		switch {
		case stringsSet[k]:
			s, ok := jstr(v)
			if !ok || !validText(s, 4096) {
				return nil, fail(400, "Invalid native content string")
			}
		case bools[k]:
			if _, ok := jbool(v); !ok {
				return nil, fail(400, "Invalid native content flag")
			}
		case ints[k]:
			n, ok := jint(v)
			if !ok || n < -2147483648 {
				if _, ok := juint(v); !ok {
					return nil, fail(400, "Invalid native content number")
				}
			}
		case k == "PrevContentID" || k == "SubContentID":
			id, e := uuidID(v, true)
			if e != nil {
				return nil, e
			}
			if id == strings.Repeat("0", 32) {
				continue
			}
			v = id
		default:
			return nil, fail(501, "Native content metadata field is not reconstructed")
		}
		out[k] = v
	}
	if numericNonzero(out["SubContentCount"]) || out["SubContentID"] != nil {
		return nil, fail(501, "Native dependent content upload is not reconstructed")
	}
	if out["PrevContentID"] != nil {
		return nil, fail(501, "Native content overwrite is not reconstructed")
	}
	return out, nil
}
func (s *contentStore) records(ids []string, owner string, data map[string]any, complete bool) ([]any, error) {
	names := []string{}
	flags := map[string]bool{}
	for _, key := range []string{"IncludeThumbnails", "IncludeThumbnails1", "IncludeThumbnails2"} {
		if v, has := data[key]; has {
			b, ok := jbool(v)
			if !ok {
				return nil, fail(400, "Invalid native thumbnail flag")
			}
			flags[key] = b
		}
	}
	if flags["IncludeThumbnails"] || flags["IncludeThumbnails1"] {
		names = append(names, "thumb1")
	}
	if flags["IncludeThumbnails"] || flags["IncludeThumbnails2"] {
		names = append(names, "thumb2")
	}
	out := []any{}
	size := 32
	for _, id := range ids {
		m, e := s.metadata(id, owner, names, (2*1024*1024-size)/2)
		if e != nil {
			if statusCode(e, 503) == 404 {
				if complete {
					return []any{}, nil
				}
				continue
			}
			return nil, e
		}
		raw, e := marshalJSON(m)
		if e != nil {
			return nil, e
		}
		size += len(raw) + 1
		if size > 2*1024*1024 {
			return nil, fail(413, "Native metadata response is too large")
		}
		out = append(out, m)
	}
	return out, nil
}
func (s *contentStore) handle(op, owner string, data map[string]any, files map[string]binaryPart) (map[string]any, error) {
	switch op {
	case "ContentUpload":
		meta, e := uploadMetadata(data)
		if e != nil {
			return nil, e
		}
		if numericNonzero(meta["RstrPartsSize"]) || files["RstrParts"].Stream != nil {
			return nil, fail(501, "Native restriction-part conversion is not reconstructed")
		}
		id, e := s.create(owner, meta, files)
		return map[string]any{"ID": id}, e
	case "ContentMetaGet":
		allowed := append(append([]string{}, contentContext...), "ContentIDs", "IncludeThumbnails", "IncludeThumbnails1", "IncludeThumbnails2")
		if !fieldsAllowed(data, allowed...) {
			return nil, fail(501, "Native metadata query field is not reconstructed")
		}
		a, ok := data["ContentIDs"].([]any)
		if !ok || len(a) < 1 || len(a) > 64 {
			return nil, fail(400, "Invalid native content identifier list")
		}
		ids := []string{}
		seen := map[string]bool{}
		for _, v := range a {
			id, e := uuidID(v, false)
			if e != nil {
				return nil, e
			}
			if seen[id] {
				return nil, fail(400, "Duplicate native content identifier")
			}
			seen[id] = true
			ids = append(ids, id)
		}
		records, e := s.records(ids, owner, data, true)
		return map[string]any{"Results": records}, e
	case "ContentSave":
		if !fieldsAllowed(data, append(append([]string{}, contentContext...), "ContentID")...) {
			return nil, fail(400, "Invalid native content save request")
		}
		id, e := uuidID(data["ContentID"], false)
		if e != nil {
			return nil, e
		}
		return map[string]any{}, s.save(owner, id)
	case "ContentSearch":
		q, e := parseSearch(data)
		if e != nil {
			return nil, e
		}
		ids, total, e := s.search(owner, q)
		if e != nil {
			return nil, e
		}
		records, e := s.records(ids, owner, data, false)
		return map[string]any{"TotalCount": total, "Results": records}, e
	}
	return nil, fail(501, "Native content operation is not reconstructed")
}
func parseSearch(data map[string]any) (contentQuery, error) {
	q := contentQuery{Limit: 15}
	allowed := append(append([]string{}, contentContext...), "FilterName", "SortName", "Params", "Filters", "Offset", "Limit", "IncludeThumbnails", "IncludeThumbnails1", "IncludeThumbnails2", "Private", "FromWeb", "SearchID", "PresetCIDs")
	if !fieldsAllowed(data, allowed...) {
		return q, fail(501, "Native search field is not reconstructed")
	}
	for _, k := range []string{"Filters", "PresetCIDs", "SearchID"} {
		if v, ok := data[k]; ok && truthy(v) {
			return q, fail(501, "Native compound or preset content search is not reconstructed")
		}
	}
	name := "SVR_UCC_FILTER_CONTENT_ALL"
	if v, ok := data["FilterName"]; ok {
		name = str(v)
	}
	tagCount := 0
	for i := 1; i <= 3; i++ {
		suffix := "_TAG" + string(rune('0'+i))
		if strings.HasSuffix(name, suffix) {
			tagCount = i
			name = strings.TrimSuffix(name, suffix)
		}
	}
	if name != "SVR_UCC_FILTER_CONTENT" && name != "SVR_UCC_FILTER_CONTENT_ALL" {
		return q, fail(501, "Native content filter is not reconstructed")
	}
	order := "SVR_UCC_SORT_DATECREATE"
	if v, ok := data["SortName"]; ok {
		order = str(v)
	}
	if order != "SVR_UCC_SORT_DATECREATE" && order != "SVR_UCC_SORT_SAVES" {
		return q, fail(501, "Native content ranking is not reconstructed")
	}
	q.Saves = order == "SVR_UCC_SORT_SAVES"
	params := []any{}
	if v, has := data["Params"]; has {
		var ok bool
		params, ok = v.([]any)
		if !ok || len(params) > 32 {
			return q, fail(400, "Invalid native positional search parameters")
		}
	}
	p := make([]string, len(params))
	for i, v := range params {
		s, ok := jstr(v)
		if !ok || len([]rune(s)) > 4096 || strings.ContainsRune(s, 0) {
			return q, fail(400, "Invalid native positional search parameters")
		}
		if i != 0 && (i < 4 || i > 6) && s != "" && s != "0" && s != "false" {
			return q, fail(501, "Native positional content filter is not reconstructed")
		}
		p[i] = s
	}
	if len(p) > 0 && p[0] != "" && p[0] != "-1" && p[0] != "4294967295" {
		if !digits(p[0]) || len(p[0]) > 10 {
			return q, fail(400, "Invalid native content type filter")
		}
		n, ok := juint(jsonNumber(p[0]))
		if !ok || n > 2147483647 {
			return q, fail(400, "Invalid native content type filter")
		}
		v := int64(n)
		q.Type = &v
	}
	for len(p) < 7 {
		p = append(p, "")
	}
	for i := 0; i < tagCount; i++ {
		if p[4+i] == "" {
			return q, fail(400, "Native tag search parameters do not match the filter")
		}
		q.Tags = append(q.Tags, p[4+i])
	}
	if tagCount == 0 && (p[4] != "" || p[5] != "" || p[6] != "") {
		return q, fail(400, "Native tag search parameters do not match the filter")
	}
	for _, k := range []string{"Offset", "Limit"} {
		if v, ok := data[k]; ok {
			n, valid := jint(v)
			if !valid || (k == "Offset" && (n < 0 || n > 4096)) || (k == "Limit" && (n < 1 || n > 64)) {
				return q, fail(400, "Invalid native content search page")
			}
			if k == "Offset" {
				q.Offset = int(n)
			} else {
				q.Limit = int(n)
			}
		}
	}
	for _, k := range []string{"Private", "FromWeb"} {
		if v, ok := data[k]; ok {
			b, valid := jbool(v)
			if !valid {
				return q, fail(400, "Invalid native content search flag")
			}
			if k == "Private" {
				q.Private = b
			} else {
				q.FromWeb = &b
			}
		}
	}
	return q, nil
}

func numericNonzero(v any) bool {
	if n, ok := jint(v); ok {
		return n != 0
	}
	n, ok := juint(v)
	return ok && n != 0
}
