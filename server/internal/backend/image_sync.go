package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

// Native dependency queries opt in explicitly, so ordinary metadata misses keep
// their established immediate response. The bounded wait also covers slow WAN
// uploads; notifications never extend the original per-request deadline.
const nativeImageWait = 20 * time.Second
const maxImageWaiters = 32

func (s *Server) imageNotification() <-chan struct{} {
	s.imageMu.Lock()
	defer s.imageMu.Unlock()
	if s.imageChanged == nil {
		s.imageChanged = make(chan struct{})
	}
	return s.imageChanged
}

func (s *Server) notifyImageSync() {
	s.imageMu.Lock()
	defer s.imageMu.Unlock()
	if s.imageChanged != nil {
		close(s.imageChanged)
		s.imageChanged = nil
	}
}

func (s *Server) nativeContentHandle(r *http.Request, op, uid string, data map[string]any, files map[string]binaryPart) (map[string]any, error) {
	values := r.Header.Values("X-WWE-Native-Images")
	if op != "ContentMetaGet" || len(values) != 1 || values[0] != "1" {
		return s.content.handle(op, uid, data, files)
	}
	return s.waitNativeImages(r, uid, data, files, nativeImageWait)
}

func (s *Server) waitNativeImages(r *http.Request, uid string, data map[string]any, files map[string]binaryPart, budget time.Duration) (map[string]any, error) {
	const op = "ContentMetaGet"
	changed := s.imageNotification()
	response, e := s.content.handle(op, uid, data, files)
	if e != nil || len(response["Results"].([]any)) != 0 {
		return response, e
	}
	s.imageMu.Lock()
	limit := maxImageWaiters
	if s.Config.MaxConnections > 0 {
		limit = min(limit, s.Config.MaxConnections/2)
	}
	if s.imageWaiters >= limit {
		s.imageWaitCapacity.Add(1)
		s.imageMu.Unlock()
		return response, nil
	}
	s.imageWaiters++
	s.imageMu.Unlock()
	defer func() { s.imageMu.Lock(); s.imageWaiters--; s.imageMu.Unlock() }()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	for {
		select {
		case <-r.Context().Done():
			return nil, fail(408, "Native image query canceled")
		case <-s.ctx.Done():
			return nil, fail(503, "Server is shutting down")
		case <-timer.C:
			// Other native content writers need not emit image notifications.
			// Re-read once so a commit near the deadline is still observable.
			response, e = s.content.handle(op, uid, data, files)
			if e == nil && len(response["Results"].([]any)) == 0 {
				s.imageWaitTimeouts.Add(1)
			}
			return response, e
		case <-changed:
			// Subscribe before reading to avoid missing a commit during the query.
			changed = s.imageNotification()
			response, e = s.content.handle(op, uid, data, files)
			if e != nil || len(response["Results"].([]any)) != 0 {
				return response, e
			}
		}
	}
}

// The descriptor is opaque except for its storage kind and native image UUID.
// Keeping that UUID is essential: CAW payloads refer to it directly.
func parseImageSync(raw []byte) (string, int, []byte, error) {
	if len(raw) < 44 || string(raw[:8]) != "W2IMG001" {
		return "", 0, nil, fail(400, "Invalid native image frame")
	}
	kind := int(binary.LittleEndian.Uint16(raw[12:14]))
	if _, ok := imageTags[kind]; !ok {
		return "", 0, nil, fail(400, "Unsupported native image kind")
	}
	id, e := uuidID(hex.EncodeToString(raw[24:40]), false)
	if e != nil {
		return "", 0, nil, e
	}
	size := uint64(binary.LittleEndian.Uint32(raw[40:44]))
	if size > imageMax {
		return "", 0, nil, fail(413, "Native image is too large")
	}
	if size != uint64(len(raw)-44) {
		return "", 0, nil, fail(400, "Native image length differs")
	}
	if _, _, e = ddsDimensions(raw[44:]); e != nil {
		return "", 0, nil, fail(400, "Invalid native DDS image")
	}
	return id, kind, raw[44:], nil
}

type imageSyncPlan struct {
	Status, FileID string
	PreviousSize   int64
}

// Caller holds s.mu. Both the preflight and the committing transaction use this
// decision so concurrent uploads cannot bypass identity or ownership checks.
func (s *contentStore) planImageSync(owner, id string, contentType int, digest string) (imageSyncPlan, error) {
	plan := imageSyncPlan{Status: "created"}
	rows, e := s.rows("SELECT owner,private,metadata FROM content WHERE id=?", id)
	if e != nil || len(rows) == 0 {
		return plan, e
	}
	stored, e := jsonObject([]byte(rows[0][2].(string)), false)
	typ, ok := jint(stored["ContentType"])
	codec, _ := jint(stored["_NativeImageCodec"])
	if e != nil || stored["_NativeDependency"] != true || !ok || typ != int64(contentType) || (codec != 1 && codec != 2) {
		return plan, fail(409, "Native image identity belongs to different content")
	}
	assets, e := s.rows("SELECT file_id,size FROM assets WHERE content_id=? AND name=?", id, "content")
	if e != nil {
		return plan, e
	}
	if len(assets) != 1 {
		return plan, fail(409, "Native image has no original asset")
	}
	// Identical public dependencies can be shared across authenticated owners.
	if codec == 2 && stored["_NativeSourceSHA256"] == digest && rows[0][1].(int64) == 0 {
		plan.Status, plan.FileID = "unchanged", assets[0][0].(string)
		return plan, nil
	}
	if rows[0][0] != owner {
		return plan, fail(409, "Native image identity belongs to another owner")
	}
	plan.Status, plan.PreviousSize = "updated", assets[0][1].(int64)
	return plan, nil
}

func (s *contentStore) syncImage(owner, id string, kind int, dds []byte) (map[string]any, error) {
	width, height, e := ddsDimensions(dds)
	contentType, supported := map[int]int{0: 2, 31: 6, 61: 7}[kind]
	if e != nil || !supported {
		return nil, fail(400, "Invalid native DDS image")
	}
	sum := sha256.Sum256(dds)
	digest := hex.EncodeToString(sum[:])
	s.mu.Lock()
	plan, e := s.planImageSync(owner, id, contentType, digest)
	s.mu.Unlock()
	if e != nil {
		return nil, storageError(e)
	}
	if plan.Status == "unchanged" {
		return map[string]any{"ID": id, "FileID": plan.FileID, "status": plan.Status, "codec": 2}, nil
	}
	// Compression stays outside the storage lock; only genuinely new/changed
	// pixels pay its CPU and temporary memory cost.
	packet, e := packImage(dds, kind, uint32(contentHash(dds)), uint32(time.Now().Unix()))
	if e != nil {
		return nil, fail(400, "Invalid native DDS image")
	}
	meta := map[string]any{"ContentType": contentType, "Title": "Native Superstar image", "Private": false, "TexLogoW": width, "TexLogoH": height, "_NativeDependency": true, "_NativeSourceSHA256": digest, "_NativeImageCodec": 2}
	encoded, e := marshalJSON(meta)
	if e != nil {
		return nil, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e = s.transaction(func() error {
		plan, e = s.planImageSync(owner, id, contentType, digest)
		if e != nil || plan.Status == "unchanged" {
			return e
		}
		delta, count := int64(len(packet))-plan.PreviousSize, 1
		if plan.Status == "updated" {
			count = 0
		}
		if e = s.quotaCheck(delta, count); e != nil {
			return e
		}
		if plan.Status == "updated" {
			if e = s.exec("UPDATE content SET metadata=?,private=0 WHERE id=?", string(encoded), id); e != nil {
				return e
			}
			if e = s.exec("DELETE FROM assets WHERE content_id=? AND name=?", id, "content"); e != nil {
				return e
			}
		} else if e = s.exec("INSERT INTO content VALUES (?,?,?,?,?)", id, owner, 0, time.Now().Unix(), string(encoded)); e != nil {
			return e
		}
		if e = s.insertAsset(id, "content", binaryPart{bytes.NewReader(packet), int64(len(packet))}); e != nil {
			return e
		}
		assets, e := s.rows("SELECT file_id FROM assets WHERE content_id=? AND name=?", id, "content")
		if e != nil || len(assets) != 1 {
			return fail(503, "Native image storage unavailable")
		}
		plan.FileID = assets[0][0].(string)
		return nil
	})
	if e != nil {
		return nil, storageError(e)
	}
	return map[string]any{"ID": id, "FileID": plan.FileID, "status": plan.Status, "codec": 2}, nil
}

func (s *Server) imageSync(w http.ResponseWriter, r *http.Request) {
	if s.content == nil {
		s.reply(w, r, 501, errorJSON("Experimental custom content is disabled"))
		return
	}
	uid, e := s.restUser(r, false)
	if e != nil || uid == "" {
		s.reply(w, r, 401, errorJSON("A local REST session is required"))
		return
	}
	enc := r.Header.Values("Content-Encoding")
	if len(enc) > 1 || (len(enc) == 1 && strings.ToLower(strings.TrimSpace(enc[0])) != "identity") {
		s.reply(w, r, 415, errorJSON("Native images require identity encoding"))
		return
	}
	if e := s.acquireContentTransfer(r, s.uploads); e != nil {
		s.reply(w, r, statusCode(e, 503), errorJSON(e.Error()))
		return
	}
	defer func() { <-s.uploads }()
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(120 * time.Second))
	raw, e := body(r, 44, imageMax+44)
	var response map[string]any
	if e == nil {
		var id string
		var kind int
		var dds []byte
		id, kind, dds, e = parseImageSync(raw)
		if e == nil {
			uid, e = s.restUser(r, false)
			if e != nil || uid == "" {
				e = fail(401, "A local REST session is required")
			} else {
				response, e = s.content.syncImage(uid, id, kind, dds)
			}
		}
	}
	if e != nil {
		message := "Native image synchronization unavailable"
		if _, ok := e.(*requestError); ok {
			message = e.Error()
		}
		s.reply(w, r, statusCode(e, 503), errorJSON(message))
		return
	}
	s.notifyImageSync()
	switch response["status"] {
	case "created":
		s.imageCreated.Add(1)
	case "updated":
		s.imageUpdated.Add(1)
	case "unchanged":
		s.imageUnchanged.Add(1)
	}
	_, _ = s.restUser(r, true)
	s.reply(w, r, 200, response)
}
