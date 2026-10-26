package backend

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Entirely synthetic pixels; no locally captured images enter source fixtures.
func syncDDS(seed byte) []byte {
	b := make([]byte, 128+64)
	copy(b, "DDS ")
	binary.LittleEndian.PutUint32(b[4:], 124)
	binary.LittleEndian.PutUint32(b[12:], 4)
	binary.LittleEndian.PutUint32(b[16:], 4)
	binary.LittleEndian.PutUint32(b[76:], 32)
	for i := 128; i < len(b); i++ {
		b[i] = seed + byte(i)
	}
	return b
}

func syncFrame(id string, kind int, dds []byte) []byte {
	b := make([]byte, 44+len(dds))
	copy(b, "W2IMG001")
	binary.LittleEndian.PutUint16(b[12:], uint16(kind))
	uuid, _ := hex.DecodeString(id)
	copy(b[24:40], uuid)
	binary.LittleEndian.PutUint32(b[40:], uint32(len(dds)))
	copy(b[44:], dds)
	return b
}

func newSyncStore(t *testing.T) *contentStore {
	t.Helper()
	s, e := newContentStore("", 8*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.close)
	return s
}

func TestImageSyncFrameAndAuthentication(t *testing.T) {
	s := testServer(t, true)
	s.key = strings.Repeat("a9", 32)
	id := strings.Repeat("a1", 16)
	valid := syncFrame(id, 31, syncDDS(1))
	if code, _, _ := request(t, s, "/lab/images/sync", valid, nil); code != 401 {
		t.Fatal(code)
	}
	key := map[string]string{"X-WWE-Lab-Key": s.key}
	if code, _, _ := request(t, s, "/lab/images/sync", valid, key); code != 401 {
		t.Fatal(code)
	}
	code, _, raw := request(t, s, "/api/Login", map[string]any{"Login": "image-sync-test"}, key)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	key["X-Sessionid"] = str(object(t, raw)["SessionID"])
	bad := []struct {
		name string
		raw  []byte
		code int
	}{
		{"short", valid[:40], 413},
		{"magic", append([]byte("W2IMG000"), valid[8:]...), 400},
		{"trailing", append(bytes.Clone(valid), 1), 400},
		{"short-body", valid[:len(valid)-1], 400},
		{"zero-id", syncFrame(strings.Repeat("00", 16), 31, syncDDS(1)), 400},
		{"kind", syncFrame(id, 30, syncDDS(1)), 400},
		{"dds", syncFrame(id, 31, []byte("DDS ")), 400},
	}
	oversized := bytes.Clone(valid)
	binary.LittleEndian.PutUint32(oversized[40:], imageMax+1)
	bad = append(bad, struct {
		name string
		raw  []byte
		code int
	}{"oversized-dds", oversized, 413})
	for _, item := range bad {
		t.Run(item.name, func(t *testing.T) {
			if code, _, raw := request(t, s, "/lab/images/sync", item.raw, key); code != item.code {
				t.Fatal(code, string(raw))
			}
		})
	}
	key["Content-Encoding"] = "gzip"
	if code, _, _ := request(t, s, "/lab/images/sync", valid, key); code != 415 {
		t.Fatal(code)
	}
	delete(key, "Content-Encoding")
	s.uploads <- struct{}{}
	code, _, _ = request(t, s, "/lab/images/sync", valid, key)
	<-s.uploads
	if code != 503 {
		t.Fatal(code)
	}
	code, _, raw = request(t, s, "/lab/images/sync", valid, key)
	if code != 200 || object(t, raw)["status"] != "created" {
		t.Fatal(code, string(raw))
	}
	// Fetch metadata and the actual CDN bytes under a distinct REST identity.
	_, _, login := request(t, s, "/api/Login", map[string]any{"Login": "image-sync-reader"}, map[string]string{"X-WWE-Lab-Key": s.key})
	reader := map[string]string{"X-WWE-Lab-Key": s.key, "X-Sessionid": str(object(t, login)["SessionID"])}
	code, _, raw = request(t, s, "/api/ContentMetaGet", map[string]any{"ContentIDs": []any{id}}, reader)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	meta := object(t, raw)["Results"].([]any)[0].(map[string]any)
	fid := str(meta["FileID"])
	code, _, raw = request(t, s, cdnNamespace+fid[:3]+"/"+fid[3:6]+"/"+fid+".bin", nil, reader)
	info, e := inspectImage(raw)
	if code != 200 || e != nil || info.Codec != 2 || info.Kind != 31 || !bytes.Equal(info.DDS, syncDDS(1)) {
		t.Fatal(code, e)
	}
	code, _, raw = request(t, s, "/lab/images/sync", valid, reader)
	if code != 200 || object(t, raw)["status"] != "unchanged" {
		t.Fatal("shared HTTP dependency", code, string(raw))
	}
	status, e := s.status()
	stats := status["native_image_sync"].(map[string]uint64)
	if e != nil || status["capabilities"].(map[string]any)["native_image_sync"] != true || stats["created"] != 1 || stats["unchanged"] != 1 {
		t.Fatal("synchronization status", stats, e)
	}
	s.mu.Lock()
	session := s.rest[reader["X-Sessionid"]]
	session.Expires = time.Now().Add(-time.Second)
	s.rest[reader["X-Sessionid"]] = session
	s.mu.Unlock()
	if code, _, _ := request(t, s, "/lab/images/sync", valid, reader); code != 401 {
		t.Fatal("expired REST session", code)
	}
}

func TestImageSyncOwnershipUpdatesQuotaAndSnapshots(t *testing.T) {
	s := newSyncStore(t)
	owner, other := strings.Repeat("11", 16), strings.Repeat("22", 16)
	for i, kind := range []int{0, 31, 61} {
		id := fmt.Sprintf("%032x", i+1)
		first, e := s.syncImage(owner, id, kind, syncDDS(1))
		if e != nil || first["status"] != "created" {
			t.Fatal(first, e)
		}
		shared, e := s.syncImage(other, id, kind, syncDDS(1))
		if e != nil || shared["status"] != "unchanged" || shared["FileID"] != first["FileID"] {
			t.Fatal(shared, e)
		}
		if _, e = s.syncImage(other, id, kind, syncDDS(2)); statusCode(e, 0) != 409 {
			t.Fatal("cross-owner replacement", e)
		}
		if _, e = s.syncImage(owner, id, []int{31, 61, 0}[i], syncDDS(1)); statusCode(e, 0) != 409 {
			t.Fatal("kind collision", e)
		}
		before, e := s.snapshot(str(first["FileID"]), other)
		if e != nil {
			t.Fatal(e)
		}
		updated, e := s.syncImage(owner, id, kind, syncDDS(2))
		if e != nil || updated["status"] != "updated" || updated["FileID"] == first["FileID"] {
			t.Fatal(updated, e)
		}
		old, e := io.ReadAll(before)
		before.Close()
		oldInfo, pe := inspectImage(old)
		if e != nil || pe != nil || oldInfo.Kind != kind || oldInfo.Codec != 2 || !bytes.Equal(oldInfo.DDS, syncDDS(1)) {
			t.Fatal("snapshot changed", e, pe)
		}
		latest, e := s.snapshot(str(updated["FileID"]), other)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(latest)
		latest.Close()
		info, e := inspectImage(raw)
		if e != nil || info.Codec != 2 || info.Kind != kind || !bytes.Equal(info.DDS, syncDDS(2)) {
			t.Fatal("updated original pixels", e)
		}
		// A failed quota check must preserve the old asset and its FileID.
		s.quota = 1
		if _, e = s.syncImage(owner, id, kind, syncDDS(3)); statusCode(e, 0) != 507 {
			t.Fatal("quota", e)
		}
		meta, e := s.metadata(id, other, nil, 0)
		if e != nil || meta["FileID"] != updated["FileID"] {
			t.Fatal("quota rotated asset", e)
		}
		s.quota = 8 * 1024 * 1024
	}
	ordinary, e := s.create(owner, map[string]any{"ContentType": 2}, map[string]binaryPart{"content": {bytes.NewReader([]byte("ordinary")), 8}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.syncImage(owner, ordinary, 0, syncDDS(1)); statusCode(e, 0) != 409 {
		t.Fatal("ordinary asset replaced", e)
	}
}

func TestImageSyncConcurrentMetadataAndDownloads(t *testing.T) {
	s := newSyncStore(t)
	owner, id := strings.Repeat("11", 16), strings.Repeat("33", 16)
	if _, e := s.syncImage(owner, id, 31, syncDDS(1)); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				meta, e := s.metadata(id, owner, nil, 0)
				if e != nil {
					t.Error(e)
					return
				}
				asset, e := s.snapshot(str(meta["FileID"]), owner)
				if statusCode(e, 0) == 404 {
					continue
				} // Atomic FileID rotation may retire this metadata's asset.
				if e != nil {
					t.Error(e)
					return
				}
				raw, e := io.ReadAll(asset)
				asset.Close()
				info, pe := inspectImage(raw)
				if e != nil || pe != nil || info.Codec != 2 || (!bytes.Equal(info.DDS, syncDDS(1)) && !bytes.Equal(info.DDS, syncDDS(2))) {
					t.Error("torn image", e, pe)
					return
				}
			}
		}()
	}
	for j := 0; j < 20; j++ {
		if _, e := s.syncImage(owner, id, 31, syncDDS(byte(1+j%2))); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
}

func TestImageMetadataWaitNotificationCancellationAndBound(t *testing.T) {
	store := newSyncStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{content: store, ctx: ctx}
	id, owner := strings.Repeat("44", 16), strings.Repeat("55", 16)
	data := map[string]any{"ContentIDs": []any{id}}
	r := httptest.NewRequest(http.MethodPost, "/api/ContentMetaGet", nil)
	start := time.Now()
	if _, e := s.nativeContentHandle(r, "ContentMetaGet", owner, data, nil); e != nil || time.Since(start) > time.Second {
		t.Fatal("ordinary miss delayed", e)
	}
	r.Header.Set("X-WWE-Native-Images", "1")
	done := make(chan error, 1)
	go func() {
		response, e := s.nativeContentHandle(r, "ContentMetaGet", owner, data, nil)
		if e == nil && len(response["Results"].([]any)) != 1 {
			e = fmt.Errorf("missing image after notification")
		}
		done <- e
	}()
	waitSyncWaiters(t, s, 1)
	if _, e := store.syncImage(owner, id, 31, syncDDS(1)); e != nil {
		t.Fatal(e)
	}
	s.notifyImageSync()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	missing := map[string]any{"ContentIDs": []any{strings.Repeat("66", 16)}}
	requestCtx, requestCancel := context.WithCancel(context.Background())
	r = r.WithContext(requestCtx)
	go func() { _, e := s.nativeContentHandle(r, "ContentMetaGet", owner, missing, nil); done <- e }()
	waitSyncWaiters(t, s, 1)
	requestCancel()
	if e := <-done; statusCode(e, 0) != 408 {
		t.Fatal("request cancellation", e)
	}
	s.imageMu.Lock()
	s.imageWaiters = 16
	s.imageMu.Unlock()
	start = time.Now()
	if _, e := s.nativeContentHandle(r.Clone(context.Background()), "ContentMetaGet", owner, missing, nil); e != nil || time.Since(start) > time.Second {
		t.Fatal("waiter capacity", e)
	}
	s.imageMu.Lock()
	s.imageWaiters = 0
	s.imageMu.Unlock()
	go func() {
		_, e := s.nativeContentHandle(r.Clone(context.Background()), "ContentMetaGet", owner, missing, nil)
		done <- e
	}()
	waitSyncWaiters(t, s, 1)
	cancel()
	if e := <-done; statusCode(e, 0) != 503 {
		t.Fatal("shutdown cancellation", e)
	}
	// Exercise the real deadline without relying on notifications or shutdown.
	s.ctx = context.Background()
	start = time.Now()
	response, e := s.nativeContentHandle(r.Clone(context.Background()), "ContentMetaGet", owner, missing, nil)
	if e != nil || len(response["Results"].([]any)) != 0 || time.Since(start) < 2800*time.Millisecond || time.Since(start) > 4*time.Second {
		t.Fatal("deadline", e, time.Since(start))
	}
}

func waitSyncWaiters(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.imageMu.Lock()
		n := s.imageWaiters
		s.imageMu.Unlock()
		if n == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("metadata waiter did not register")
}
