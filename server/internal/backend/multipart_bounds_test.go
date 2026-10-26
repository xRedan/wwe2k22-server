package backend

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

type observedMultipartReader struct {
	raw         *bytes.Reader
	input       *multipartInput
	chunk, peak int
}

func TestMultipartBoundaryLookaheadAcrossChunkEdges(t *testing.T) {
	for _, boundary := range []string{"a", strings.Repeat("b", 70)} {
		for _, chunk := range []int{1, 2, 3, 5, 7, 17, 74, 75, 65535, 65536} {
			t.Run(fmt.Sprintf("boundary=%d/chunk=%d", len(boundary), chunk), func(t *testing.T) {
				payload := bytes.Repeat([]byte("\r\n--"+boundary+"NOTDELIMITER\x00\xff"), 8)
				for _, final := range []bool{false, true} {
					suffix := "\r\n"
					if final {
						suffix = "--"
					}
					raw := append(bytes.Clone(payload), []byte("\r\n--"+boundary+suffix+"\r\n")...)
					input, target := &multipartInput{}, &spool{}
					defer target.Close()
					reader := &observedMultipartReader{raw: bytes.NewReader(raw), input: input, chunk: chunk}
					input.r = reader
					closed, e := input.part([]byte(boundary), target, maxAsset)
					if e != nil || closed != final {
						t.Fatal(closed, final, e)
					}
					target.Seek(0, io.SeekStart)
					copied, e := io.ReadAll(target)
					if e != nil || !bytes.Equal(copied, payload) {
						t.Fatal("chunked payload differs", e)
					}
					if reader.peak > 2*len(input.buffer) {
						t.Fatal("unbounded pending bytes", reader.peak)
					}
				}
			})
		}
	}
}

func TestMultipartFalsePrefixesStillRejectMissingTerminatorAndLimit(t *testing.T) {
	payload := falseMultipartPayload()
	for _, truncated := range [][]byte{
		payload,
		append(bytes.Clone(payload), []byte("\r\n--a?")...),
		append(bytes.Clone(payload), []byte("\r\n--a-")...),
	} {
		input, target := &multipartInput{}, &spool{}
		defer target.Close()
		reader := &observedMultipartReader{raw: bytes.NewReader(truncated), input: input}
		input.r = reader
		_, e := input.part([]byte("a"), target, maxAsset)
		if statusCode(e, 0) != 400 {
			t.Fatal("missing terminator accepted", e)
		}
		if reader.peak > 2*len(input.buffer) || target.file == nil {
			t.Fatal("unterminated payload bypassed spool", reader.peak, target.file != nil)
		}
	}
	input, target := &multipartInput{r: bytes.NewReader(append(bytes.Clone(payload), []byte("\r\n--a--\r\n")...))}, &spool{}
	defer target.Close()
	if _, e := input.part([]byte("a"), target, int64(len(payload)-1)); statusCode(e, 0) != 413 {
		t.Fatal("part limit bypassed", e)
	}
}

func TestMultipartBoundaryAtReadBufferEdges(t *testing.T) {
	for _, boundary := range []string{"a", strings.Repeat("b", 70)} {
		marker := "\r\n--" + boundary
		for edge := 0; edge <= len(marker)+1; edge++ {
			for _, suffix := range []string{"--", "\r\n"} {
				// Place every byte of the marker and its two-byte lookahead on
				// either side of the parser's actual 64 KiB read boundary.
				payload := bytes.Repeat([]byte{'x'}, 64*1024-edge)
				raw := append(bytes.Clone(payload), []byte(marker+suffix+"\r\n")...)
				input, target := &multipartInput{}, &spool{}
				reader := &observedMultipartReader{raw: bytes.NewReader(raw), input: input}
				input.r = reader
				final, e := input.part([]byte(boundary), target, maxAsset)
				target.Seek(0, io.SeekStart)
				copied, readErr := io.ReadAll(target)
				target.Close()
				if e != nil || readErr != nil || final != (suffix == "--") || !bytes.Equal(copied, payload) {
					t.Fatal("read-boundary lookahead differs", len(boundary), edge, suffix, e, readErr)
				}
				if reader.peak > 2*len(input.buffer) {
					t.Fatal("read-boundary lookahead exceeded pending bound", reader.peak)
				}
			}
		}
	}
}

func ownedMultipartUpload(payload []byte) []byte {
	opening := "--a\r\nContent-Disposition: form-data; name=\"Params\"\r\nContent-Type: application/json\r\n\r\n{\"ContentType\":1,\"Title\":\"Synthetic multipart\"}\r\n--a\r\nContent-Disposition: form-data; name=\"content\"; filename=\"owned.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
	raw := append([]byte(opening), payload...)
	return append(raw, []byte("\r\n--a--\r\n")...)
}

func TestMultipartFalsePrefixesHTTPUploadAndCDNExactBytes(t *testing.T) {
	s := testServer(t, true)
	code, _, raw := request(t, s, "/api/Login", map[string]any{"Login": "owned-multipart-bounds"}, nil)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	headers := map[string]string{"X-Sessionid": str(object(t, raw)["SessionID"]), "Content-Type": "multipart/form-data; boundary=a"}
	payload := falseMultipartPayload()
	code, _, raw = request(t, s, "/api/ContentUpload", ownedMultipartUpload(payload), headers)
	if code != 200 {
		t.Fatal("valid upload rejected", code, string(raw))
	}
	id := str(object(t, raw)["ID"])
	delete(headers, "Content-Type")
	code, _, raw = request(t, s, "/api/ContentMetaGet", map[string]any{"ContentIDs": []any{id}}, headers)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	results := object(t, raw)["Results"].([]any)
	if len(results) != 1 {
		t.Fatal("uploaded metadata missing", string(raw))
	}
	meta := results[0].(map[string]any)
	fid := str(meta["FileID"])
	code, _, raw = request(t, s, cdnNamespace+fid[:3]+"/"+fid[3:6]+"/"+fid+".bin", nil, headers)
	if code != 200 || !bytes.Equal(raw, payload) {
		t.Fatal("CDN payload differs", code, len(raw))
	}
	// A malformed follow-up must not acknowledge or add another stored asset.
	malformed := ownedMultipartUpload(payload)
	malformed = malformed[:len(malformed)-9]
	headers["Content-Type"] = "multipart/form-data; boundary=a"
	if code, _, _ := request(t, s, "/api/ContentUpload", malformed, headers); code != 400 {
		t.Fatal("unterminated HTTP upload accepted", code)
	}
	summary, e := s.content.summary()
	if e != nil || summary["contents"] != int64(1) || summary["assets"] != int64(1) {
		t.Fatal("malformed upload changed storage", summary, e)
	}
}

func (r *observedMultipartReader) Read(p []byte) (int, error) {
	if r.chunk > 0 && len(p) > r.chunk {
		p = p[:r.chunk]
	}
	n, e := r.raw.Read(p)
	r.peak = max(r.peak, len(r.input.pending)+n)
	return n, e
}

func falseMultipartPayload() []byte {
	pattern := []byte("\r\n--aNOTDELIMITER")
	payload := bytes.Repeat(pattern, (2<<20)/len(pattern)+1)
	return append(payload, 0, 0xff, 0x80)
}

func TestMultipartFalseBoundaryPrefixesStayBounded(t *testing.T) {
	payload := falseMultipartPayload()
	raw := append(bytes.Clone(payload), []byte("\r\n--a--\r\n")...)
	input, target := &multipartInput{}, &spool{}
	defer target.Close()
	reader := &observedMultipartReader{raw: bytes.NewReader(raw), input: input}
	input.r = reader
	final, e := input.part([]byte("a"), target, maxAsset)
	t.Logf("payload=%d peak_pending=%d spooled=%d disk=%t", len(payload), reader.peak, target.size, target.file != nil)
	if e != nil || !final {
		t.Fatal("valid binary multipart failed", e)
	}
	if reader.peak > 2*len(input.buffer) || target.file == nil {
		t.Fatal("multipart bypassed bounded disk spool", reader.peak, target.file != nil)
	}
	if _, e = target.Seek(0, io.SeekStart); e != nil {
		t.Fatal(e)
	}
	copied, e := io.ReadAll(target)
	if e != nil || !bytes.Equal(copied, payload) {
		t.Fatal("binary multipart bytes differ", e)
	}
}

func FuzzNativeMultipartRoundTrip(f *testing.F) {
	f.Add([]byte("x"))
	f.Add([]byte("\x00\xff\r\n--aNOTDELIMITER\r\n--a?\r\n--a-"))
	f.Add(bytes.Repeat([]byte("\r\n--aNOTDELIMITER"), 3800))
	f.Add(append(bytes.Repeat([]byte{'x'}, 65536-6), []byte("\r\n--a?")...))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) < 1 || len(payload) > 64*1024 {
			t.Skip()
		}
		// The required encapsulation CRLF can finish an otherwise partial
		// delimiter at the payload's end. Only actual delimiter ambiguity is
		// excluded; arbitrary invalid suffixes remain binary content.
		framedPayload := append(bytes.Clone(payload), '\r', '\n')
		if bytes.Contains(framedPayload, []byte("\r\n--a\r\n")) || bytes.Contains(framedPayload, []byte("\r\n--a--")) {
			t.Skip()
		}
		raw := ownedMultipartUpload(payload)
		meta, files, cleanup, e := parseMultipart("multipart/form-data; boundary=a", bytes.NewReader(raw), int64(len(raw)))
		defer cleanup()
		if e != nil {
			t.Fatal("unambiguous native multipart rejected", e)
		}
		typ, ok := jint(meta["ContentType"])
		if !ok || typ != 1 || meta["Title"] != "Synthetic multipart" || len(meta) != 2 || len(files) != 1 {
			t.Fatal("multipart metadata differs", meta, len(files))
		}
		part, ok := files["content"]
		if !ok || part.Size != int64(len(payload)) {
			t.Fatal("multipart binary part differs", part.Size, len(payload))
		}
		copied, e := io.ReadAll(part.Stream)
		if e != nil || !bytes.Equal(copied, payload) {
			t.Fatal("multipart binary bytes differ", e)
		}
	})
}
