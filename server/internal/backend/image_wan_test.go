package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWANImageMetadataWaitsForDelayedOwner(t *testing.T) {
	s := testServer(t, true)
	owner, id := strings.Repeat("11", 16), strings.Repeat("77", 16)
	r := httptest.NewRequest(http.MethodPost, "/api/ContentMetaGet", nil)
	r.Header.Set("X-WWE-Native-Images", "1")
	type result struct {
		value map[string]any
		err   error
	}
	done := make(chan result, 1)
	go func() {
		v, e := s.nativeContentHandle(r, "ContentMetaGet", owner, map[string]any{"ContentIDs": []any{id}}, nil)
		done <- result{v, e}
	}()
	waitSyncWaiters(t, s, 1)
	select {
	case got := <-done:
		t.Fatalf("metadata returned before the owner's WAN upload: %v %v", got.value, got.err)
	case <-time.After(3250 * time.Millisecond):
	}
	if _, err := s.content.syncImage(owner, id, 31, syncDDS(3)); err != nil {
		t.Fatal(err)
	}
	s.notifyImageSync()
	select {
	case got := <-done:
		if got.err != nil || len(got.value["Results"].([]any)) != 1 {
			t.Fatal("late face image missing", got.value, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late upload did not release metadata query")
	}
}

func TestWANImageDownloadWaitsForTransferSlot(t *testing.T) {
	s := testServer(t, true)
	original := syncDDS(5)
	stored, err := s.content.syncImage(strings.Repeat("11", 16), strings.Repeat("78", 16), 31, original)
	if err != nil {
		t.Fatal(err)
	}
	fid := str(stored["FileID"])
	for i := 0; i < cap(s.downloads); i++ {
		s.downloads <- struct{}{}
	}
	r := httptest.NewRequest(http.MethodGet, cdnNamespace+fid[:3]+"/"+fid[3:6]+"/"+fid+".bin", nil)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.asset(w, r); close(done) }()
	select {
	case <-done:
		t.Fatalf("simultaneous texture download was discarded: HTTP %d", w.Code)
	case <-time.After(50 * time.Millisecond):
	}
	<-s.downloads
	select {
	case <-done:
		info, e := inspectImage(w.Body.Bytes())
		if w.Code != 200 || e != nil || !bytes.Equal(info.DDS, original) {
			t.Fatal("queued texture differs", w.Code, e)
		}
	case <-time.After(time.Second):
		t.Fatal("queued download did not resume")
	}
}

func TestWANImageUploadWaitsForTransferSlot(t *testing.T) {
	s := testServer(t, true)
	_, _, raw := request(t, s, "/api/Login", map[string]any{"Login": "wan-upload-test"}, nil)
	session := str(object(t, raw)["SessionID"])
	s.uploads <- struct{}{}
	r := httptest.NewRequest(http.MethodPost, "/lab/images/sync", bytes.NewReader(syncFrame(strings.Repeat("79", 16), 31, syncDDS(7))))
	r.Header.Set("X-Sessionid", session)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.imageSync(w, r); close(done) }()
	select {
	case <-done:
		t.Fatalf("simultaneous image upload was discarded: HTTP %d", w.Code)
	case <-time.After(50 * time.Millisecond):
	}
	<-s.uploads
	select {
	case <-done:
		if w.Code != 200 {
			t.Fatal("queued upload failed", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("queued upload did not resume")
	}
}

func TestWANContentQueueCancellationAndBound(t *testing.T) {
	t.Run("request-cancel", func(t *testing.T) {
		s := testServer(t, true)
		s.uploads <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		r := httptest.NewRequest(http.MethodPost, "/lab/images/sync", nil).WithContext(ctx)
		done := make(chan error, 1)
		go func() { done <- s.acquireContentTransfer(r, s.uploads) }()
		deadline := time.Now().Add(time.Second)
		for len(s.contentWaiters) != 1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		cancel()
		if e := <-done; statusCode(e, 0) != 408 || len(s.contentWaiters) != 0 || len(s.uploads) != 1 {
			t.Fatal("canceled queue leaked a permit", e)
		}
		<-s.uploads
	})
	t.Run("server-stop", func(t *testing.T) {
		s := testServer(t, true)
		s.uploads <- struct{}{}
		done := make(chan error, 1)
		go func() {
			done <- s.acquireContentTransfer(httptest.NewRequest(http.MethodPost, "/lab/images/sync", nil), s.uploads)
		}()
		deadline := time.Now().Add(time.Second)
		for len(s.contentWaiters) != 1 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		s.cancel()
		if e := <-done; statusCode(e, 0) != 503 || len(s.contentWaiters) != 0 {
			t.Fatal("shutdown did not release queued request", e)
		}
		<-s.uploads
	})
	t.Run("small-http-budget", func(t *testing.T) {
		c := DefaultConfig()
		c.HTTPPort = 0
		c.UDPPort = 0
		c.MaxConnections = 3
		c.CustomContent = true
		s, e := NewServer(c)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		if cap(s.contentWaiters) != 0 {
			t.Fatal("small HTTP budget can be exhausted by transfer waiters")
		}
		s.uploads <- struct{}{}
		if e = s.acquireContentTransfer(httptest.NewRequest(http.MethodPost, "/lab/images/sync", nil), s.uploads); statusCode(e, 0) != 503 {
			t.Fatal("unbounded queue for a small HTTP budget", e)
		}
		<-s.uploads
	})
}

func TestWANSixOwnersDelayedImagesReachAllReaders(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("TLS=%v", secure), func(t *testing.T) { testWANSixOwnersDelayedImages(t, secure) })
	}
}

func testWANSixOwnersDelayedImages(t *testing.T, secure bool) {
	s := testServer(t, true)
	const players = 6
	client := &http.Client{Timeout: 12 * time.Second}
	endpoint := s.Origin()
	if secure {
		frontend := httptest.NewTLSServer(s)
		t.Cleanup(frontend.Close)
		client = frontend.Client()
		client.Timeout = 12 * time.Second
		endpoint = frontend.URL
	}
	call := func(path string, payload []byte, headers map[string]string) (int, []byte, error) {
		method := http.MethodPost
		if payload == nil {
			method = http.MethodGet
		}
		r, e := http.NewRequest(method, endpoint+path, bytes.NewReader(payload))
		if e != nil {
			return 0, nil, e
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		response, e := client.Do(r)
		if e != nil {
			return 0, nil, e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(response.Body)
		return response.StatusCode, body, e
	}
	ids := make([]any, players)
	sessions := make([]string, players)
	pixels := make([][]byte, players)
	for i := 0; i < players; i++ {
		_, _, raw := request(t, s, "/api/Login", map[string]any{"Login": fmt.Sprintf("wan-owner-%d", i)}, nil)
		sessions[i] = str(object(t, raw)["SessionID"])
		ids[i] = fmt.Sprintf("%032x", i+100)
		pixels[i] = syncDDS(byte(i + 1))
	}
	// Keep the upload lane busy beyond the former three-second deadline.
	s.uploads <- struct{}{}
	var releaseUpload sync.Once
	defer releaseUpload.Do(func() { <-s.uploads })
	type result struct {
		code int
		body []byte
		err  error
	}
	uploaded := make(chan result, players)
	for i := 0; i < players; i++ {
		go func(i int) {
			code, body, e := call("/lab/images/sync", syncFrame(ids[i].(string), []int{0, 31, 61}[i%3], pixels[i]), map[string]string{"X-Sessionid": sessions[i]})
			uploaded <- result{code, body, e}
		}(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.contentWaiters) != players && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.contentWaiters) != players {
		t.Fatal("uploads were not queued")
	}
	metadata := make(chan result, players)
	query, _ := marshalJSON(map[string]any{"ContentIDs": ids})
	for i := 0; i < players; i++ {
		go func(i int) {
			code, body, e := call("/api/ContentMetaGet", query, map[string]string{"X-Sessionid": sessions[i], "X-WWE-Native-Images": "1"})
			metadata <- result{code, body, e}
		}(i)
	}
	waitSyncWaiters(t, s, players)
	select {
	case got := <-metadata:
		t.Fatal("incomplete images reached a reader", got.code, got.err)
	case <-time.After(3250 * time.Millisecond):
	}
	if code, _, e := call("/health", nil, nil); e != nil || code != 200 {
		t.Fatal("image waiters starved control traffic", code, e)
	}
	releaseUpload.Do(func() { <-s.uploads })
	for i := 0; i < players; i++ {
		got := <-uploaded
		if got.err != nil || got.code != 200 {
			t.Fatal("queued source upload failed", got.code, got.err, string(got.body))
		}
	}
	var records []any
	for i := 0; i < players; i++ {
		got := <-metadata
		if got.err != nil || got.code != 200 {
			t.Fatal("remote image metadata failed", got.code, got.err)
		}
		records = object(t, got.body)["Results"].([]any)
		if len(records) != players {
			t.Fatal("partial image batch returned to a reader")
		}
	}
	// Six receivers exceed the four active download lanes; queued reads must
	// return the original pixels rather than a transient 503/fallback image.
	for i := 0; i < cap(s.downloads); i++ {
		s.downloads <- struct{}{}
	}
	var releaseDownloads sync.Once
	defer releaseDownloads.Do(func() {
		for i := 0; i < cap(s.downloads); i++ {
			<-s.downloads
		}
	})
	downloaded := make(chan result, players)
	for batch, value := range records {
		meta := value.(map[string]any)
		fid := str(meta["FileID"])
		for i := 0; i < players; i++ {
			go func(i int) {
				code, body, e := call(cdnNamespace+fid[:3]+"/"+fid[3:6]+"/"+fid+".bin", nil, map[string]string{"X-Sessionid": sessions[i]})
				downloaded <- result{code, body, e}
			}(i)
		}
		if batch == 0 { // The first batch must actually contend for all four lanes.
			deadline = time.Now().Add(2 * time.Second)
			for len(s.contentWaiters) != players && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(s.contentWaiters) != players {
				t.Fatal("downloads did not enter the bounded queue")
			}
		}
		releaseDownloads.Do(func() {
			for i := 0; i < cap(s.downloads); i++ {
				<-s.downloads
			}
		})
		var expected []byte
		for i, id := range ids {
			if id == meta["ID"] {
				expected = pixels[i]
			}
		}
		for i := 0; i < players; i++ {
			got := <-downloaded
			if got.err != nil || got.code != 200 {
				t.Fatal("queued remote texture download failed", got.code, got.err)
			}
			image, e := inspectImage(got.body)
			if e != nil || !bytes.Equal(image.DDS, expected) {
				t.Fatal("remote pixels differ", e)
			}
		}
	}
	status, e := s.status()
	if e != nil {
		t.Fatal(e)
	}
	imageStats := status["native_image_sync"].(map[string]uint64)
	transfers := status["content_transfers"].(map[string]uint64)
	stored := status["custom_content"].(map[string]any)
	if imageStats["created"] != players || imageStats["metadata_timeouts"] != 0 || transfers["completed_downloads"] != players*players || stored["native_images"] != int64(players) {
		t.Fatal("incomplete WAN pipeline", imageStats, transfers, stored)
	}
}

func TestWANQueuedDownloadRechecksExpiredSession(t *testing.T) {
	s := testServer(t, true)
	_, _, body := request(t, s, "/api/Login", map[string]any{"Login": "expiring-image-reader"}, nil)
	sid := str(object(t, body)["SessionID"])
	stored, e := s.content.syncImage(strings.Repeat("11", 16), strings.Repeat("7a", 16), 31, syncDDS(1))
	if e != nil {
		t.Fatal(e)
	}
	fid := str(stored["FileID"])
	for i := 0; i < cap(s.downloads); i++ {
		s.downloads <- struct{}{}
	}
	r := httptest.NewRequest(http.MethodGet, cdnNamespace+fid[:3]+"/"+fid[3:6]+"/"+fid+".bin", nil)
	r.Header.Set("X-Sessionid", sid)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.asset(w, r); close(done) }()
	deadline := time.Now().Add(time.Second)
	for len(s.contentWaiters) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.contentWaiters) != 1 {
		t.Fatal("download did not enter the transfer queue")
	}
	s.mu.Lock()
	session := s.rest[sid]
	session.Expires = time.Now().Add(-time.Second)
	s.rest[sid] = session
	s.mu.Unlock()
	<-s.downloads
	select {
	case <-done:
		if w.Code != 401 {
			t.Fatal("expired queued session downloaded an asset", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("queued download failed to resume")
	}
}
