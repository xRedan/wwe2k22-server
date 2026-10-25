package backend

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const imageMax = 16 * 1024 * 1024

var imageTags = map[int]string{0: "LOGO\x00\x00\x00\x00", 31: "FAPH\x00\x00\x00\x00", 61: "CUPO\x00\x00\x00\x00"}

func contentHash(data []byte) uint64 {
	const m uint64 = 0xc6a4a7935bd1e995
	h := uint64(0xbd030ac0a7cb7e69) ^ uint64(len(data))*m
	end := len(data) / 8 * 8
	for i := 0; i < end; i += 8 {
		k := binary.LittleEndian.Uint64(data[i:])
		k *= m
		k ^= k >> 47
		k *= m
		h = (h ^ k) * m
	}
	if end < len(data) {
		var tail uint64
		for i, b := range data[end:] {
			tail |= uint64(b) << (8 * i)
		}
		h = (h ^ tail) * m
	}
	h ^= h >> 47
	h *= m
	h ^= h >> 47
	return h
}
func ddsDimensions(data []byte) (uint32, uint32, error) {
	if len(data) < 128 || len(data) > imageMax || string(data[:4]) != "DDS " || binary.LittleEndian.Uint32(data[4:]) != 124 || binary.LittleEndian.Uint32(data[76:]) != 32 {
		return 0, 0, errors.New("invalid DDS header")
	}
	height, width := binary.LittleEndian.Uint32(data[12:]), binary.LittleEndian.Uint32(data[16:])
	if width < 1 || height < 1 || width > 16384 || height > 16384 {
		return 0, 0, errors.New("invalid DDS dimensions")
	}
	return width, height, nil
}
func packImage(data []byte, kind int, nonce, stamp uint32) ([]byte, error) {
	width, height, e := ddsDimensions(data)
	if e != nil {
		return nil, e
	}
	tag, ok := imageTags[kind]
	if !ok {
		return nil, errors.New("unsupported image kind")
	}
	header := make([]byte, 128)
	put := binary.LittleEndian.PutUint32
	put(header, nonce)
	put(header[4:], 128)
	binary.LittleEndian.PutUint64(header[8:], contentHash(data))
	copy(header[16:], tag)
	put(header[88:], 5)
	put(header[92:], 0x12d)
	put(header[96:], stamp)
	put(header[104:], 1)
	put(header[108:], 0x250015)
	var compressed bytes.Buffer
	writer, e := zlib.NewWriterLevel(&compressed, 9)
	if e != nil {
		return nil, e
	}
	if _, e = writer.Write(data); e != nil {
		return nil, e
	}
	if e = writer.Close(); e != nil {
		return nil, e
	}
	body := make([]byte, 16+compressed.Len())
	copy(body, "ZLIB")
	put(body[4:], 0x2050)
	put(body[8:], uint32(compressed.Len()))
	put(body[12:], uint32(len(data)))
	copy(body[16:], compressed.Bytes())
	first := bytes.Clone(header)
	put(first[28:], uint32(len(body)))
	put(first[32:], width)
	put(first[36:], height)
	out := make([]byte, 0, 256+2*len(body))
	out = append(out, first...)
	out = append(out, body...)
	out = append(out, header...)
	out = append(out, body...)
	return out, nil
}

type imageInfo struct {
	Kind, Codec   int
	Width, Height uint32
	DDS           []byte
	SHA           string
}

func unpackImageBody(body []byte) ([]byte, error) {
	if len(body) < 16 || string(body[:4]) != "ZLIB" || binary.LittleEndian.Uint32(body[4:]) != 0x2050 || int(binary.LittleEndian.Uint32(body[8:])) != len(body)-16 {
		return nil, errors.New("invalid compressed image")
	}
	size := binary.LittleEndian.Uint32(body[12:])
	if size < 128 || size > imageMax {
		return nil, errors.New("invalid image size")
	}
	reader := bytes.NewReader(body[16:])
	z, e := zlib.NewReader(reader)
	if e != nil {
		return nil, e
	}
	out, e := io.ReadAll(io.LimitReader(z, int64(size)+1))
	ce := z.Close()
	if e != nil || ce != nil || len(out) != int(size) || reader.Len() != 0 {
		return nil, errors.New("invalid compressed image")
	}
	if _, _, e = ddsDimensions(out); e != nil {
		return nil, e
	}
	return out, nil
}
func inspectImage(packet []byte) (imageInfo, error) {
	bad := func() (imageInfo, error) { return imageInfo{}, errors.New("invalid original image package") }
	if len(packet) < 272 || len(packet) > 2*(imageMax+65536)+256 {
		return bad()
	}
	h := packet[:128]
	if binary.LittleEndian.Uint32(h[4:]) != 128 {
		return bad()
	}
	kind := -1
	for k, t := range imageTags {
		if string(h[16:24]) == t {
			kind = k
		}
	}
	if kind < 0 {
		return bad()
	}
	for _, span := range [][2]int{{24, 28}, {40, 88}, {100, 104}, {112, 128}} {
		for _, b := range h[span[0]:span[1]] {
			if b != 0 {
				return bad()
			}
		}
	}
	if binary.LittleEndian.Uint32(h[88:]) != 5 || binary.LittleEndian.Uint32(h[92:]) != 0x12d || binary.LittleEndian.Uint32(h[104:]) != 1 || binary.LittleEndian.Uint32(h[108:]) != 0x250015 {
		return bad()
	}
	preview := uint64(binary.LittleEndian.Uint32(h[28:]))
	second := 128 + preview
	if second+144 > uint64(len(packet)) {
		return bad()
	}
	canonical := bytes.Clone(h)
	clear(canonical[28:40])
	if !bytes.Equal(canonical, packet[second:second+128]) {
		return bad()
	}
	data, e := unpackImageBody(packet[second+128:])
	if e != nil || contentHash(data) != binary.LittleEndian.Uint64(h[8:]) {
		return bad()
	}
	width, height, e := ddsDimensions(data)
	if e != nil {
		return bad()
	}
	codec := 1
	if preview > 0 {
		p, e := unpackImageBody(packet[128:second])
		if e != nil || !bytes.Equal(p, data) || binary.LittleEndian.Uint32(h[32:]) != width || binary.LittleEndian.Uint32(h[36:]) != height {
			return bad()
		}
		codec = 2
	} else if binary.LittleEndian.Uint32(h[32:]) != 0 || binary.LittleEndian.Uint32(h[36:]) != 0 {
		return bad()
	}
	sum := sha256.Sum256(data)
	return imageInfo{kind, codec, width, height, data, hex.EncodeToString(sum[:])}, nil
}

type importedImage struct {
	ID     string
	Info   imageInfo
	Packet []byte
}

func loadImages(path string) ([]importedImage, error) {
	root, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return nil, e
	}
	raw, e := readLimitedFile(root, 128*1024)
	if e != nil {
		return nil, e
	}
	m, e := jsonObject(raw, true)
	if e != nil || m["target_sha256"] != TargetSHA || m["error"] != nil {
		return nil, errors.New("invalid original-image capture manifest")
	}
	if v, has := m["rejected"]; has {
		n, ok := jint(v)
		if !ok || n != 0 {
			return nil, errors.New("unclean capture")
		}
	}
	images, ok := m["images"].([]any)
	if !ok || len(images) < 1 || len(images) > 32 {
		return nil, errors.New("invalid image count")
	}
	out := []importedImage{}
	seen := map[string]bool{}
	var total int64
	var packageTotal int64
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, v := range images {
		item, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("invalid image metadata")
		}
		desc, digest := str(item["descriptor_hex"]), str(item["sha256"])
		kind, ok := jint(item["storage_kind"])
		if !ok || !hex64.MatchString(desc) || !hex64.MatchString(digest) {
			return nil, errors.New("invalid original image descriptor")
		}
		b, _ := hex.DecodeString(desc)
		if int64(binary.LittleEndian.Uint16(b[4:])) != kind {
			return nil, errors.New("mismatched image kind")
		}
		id, e := uuidID(hex.EncodeToString(b[16:32]), false)
		if e != nil || seen[id] {
			return nil, errors.New("invalid image identity")
		}
		seen[id] = true
		if str(item["file"]) != digest+".dds" {
			return nil, errors.New("invalid image filename")
		}
		asset, e := filepath.EvalSymlinks(filepath.Join(filepath.Dir(root), digest+".dds"))
		if e != nil || filepath.Dir(asset) != filepath.Dir(root) {
			return nil, errors.New("image escapes capture directory")
		}
		data, e := readLimitedFile(asset, imageMax)
		if e != nil {
			return nil, e
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, errors.New("image digest differs")
		}
		width, height, e := ddsDimensions(data)
		size, sizeOK := jint(item["size"])
		w, wOK := juint(item["width"])
		h, hOK := juint(item["height"])
		if e != nil || !sizeOK || size != int64(len(data)) || !wOK || !hOK || w != uint64(width) || h != uint64(height) {
			return nil, errors.New("image metadata differs")
		}
		total += size
		if total > 64*1024*1024 {
			return nil, errors.New("capture exceeds import budget")
		}
		info, e := os.Stat(asset)
		if e != nil || info.ModTime().Unix() < 0 || info.ModTime().Unix() > 0xffffffff {
			return nil, errors.New("invalid image time")
		}
		packet, e := packImage(data, int(kind), uint32(contentHash(data)), uint32(info.ModTime().Unix()))
		if e != nil {
			return nil, e
		}
		parsed, e := inspectImage(packet)
		if e != nil {
			return nil, e
		}
		packageTotal += int64(len(packet))
		if packageTotal > 64*1024*1024 {
			return nil, errors.New("image package batch exceeds import budget")
		}
		parsed.DDS = nil
		out = append(out, importedImage{id, parsed, packet})
	}
	expected, ok := jint(m["bytes"])
	if !ok || expected != total {
		return nil, errors.New("capture size differs")
	}
	return out, nil
}
func readLimitedFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return b, nil
}
func (s *contentStore) importImages(path, owner string, upgrade bool) (map[string]any, error) {
	owner, e := uuidID(owner, false)
	if e != nil {
		return nil, e
	}
	entries, e := loadImages(path)
	if e != nil {
		return nil, errors.New("invalid original-image capture manifest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	added, upgraded, unchanged := 0, 0, 0
	e = s.transaction(func() error {
		type pending struct {
			Image importedImage
			Meta  map[string]any
			Old   bool
		}
		list := []pending{}
		delta := int64(0)
		for _, item := range entries {
			kind := map[int]int{0: 2, 31: 6, 61: 7}[item.Info.Kind]
			meta := map[string]any{"ContentType": kind, "Title": "Immagine Superstar importata localmente", "Private": false, "TexLogoW": item.Info.Width, "TexLogoH": item.Info.Height, "_NativeDependency": true, "_NativeSourceSHA256": item.Info.SHA, "_NativeImageCodec": 2}
			rows, e := s.rows("SELECT owner,metadata FROM content WHERE id=?", item.ID)
			if e != nil {
				return e
			}
			old := false
			if len(rows) > 0 {
				stored, e := jsonObject([]byte(rows[0][1].(string)), false)
				n, ok := jint(stored["ContentType"])
				codec, _ := jint(stored["_NativeImageCodec"])
				if e != nil || rows[0][0] != owner || stored["_NativeDependency"] != true || !ok || n != int64(kind) || stored["_NativeSourceSHA256"] != item.Info.SHA {
					return fail(409, "Original-image identity already belongs to different content")
				}
				if codec == 2 {
					unchanged++
					continue
				}
				if !upgrade || codec != 1 {
					return fail(409, "Original image codec differs; explicit upgrade required")
				}
				rows, e = s.rows("SELECT rowid,size FROM assets WHERE content_id=? AND name=?", item.ID, "content")
				if e != nil || len(rows) != 1 {
					return fail(409, "Legacy image cannot be safely upgraded")
				}
				size := rows[0][1].(int64)
				if size < 272 || size > 2*(imageMax+65536)+256 {
					return fail(409, "Legacy image cannot be safely upgraded")
				}
				blob, e := s.conn.OpenBlob("main", "assets", "payload", rows[0][0].(int64), false)
				if e != nil {
					return e
				}
				packet, e := io.ReadAll(io.LimitReader(blob, size+1))
				ce := blob.Close()
				original, pe := inspectImage(packet)
				if e != nil || ce != nil || pe != nil || original.Codec != 1 || original.SHA != item.Info.SHA || int64(len(packet)) != size {
					return fail(409, "Legacy image cannot be safely upgraded")
				}
				delta -= size
				old = true
				upgraded++
			} else {
				added++
			}
			delta += int64(len(item.Packet))
			list = append(list, pending{item, meta, old})
		}
		if e := s.quotaCheck(delta, added); e != nil {
			return e
		}
		for _, p := range list {
			raw, e := marshalJSON(p.Meta)
			if e != nil {
				return e
			}
			if p.Old {
				if e = s.exec("UPDATE content SET metadata=? WHERE id=?", string(raw), p.Image.ID); e != nil {
					return e
				}
				if e = s.exec("DELETE FROM assets WHERE content_id=? AND name=?", p.Image.ID, "content"); e != nil {
					return e
				}
			} else {
				if e = s.exec("INSERT INTO content VALUES (?,?,?,?,?)", p.Image.ID, owner, 0, time.Now().Unix(), string(raw)); e != nil {
					return e
				}
			}
			if e = s.insertAsset(p.Image.ID, "content", binaryPart{bytes.NewReader(p.Image.Packet), int64(len(p.Image.Packet))}); e != nil {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return nil, storageError(e)
	}
	return map[string]any{"imported": added, "upgraded": upgraded, "unchanged": unchanged, "codec_client_verified": false}, nil
}
