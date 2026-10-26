package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestImageMetadataWaitRequiresEntireMixedBatch(t *testing.T) {
	store := newSyncStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{content: store, ctx: ctx}
	owner := strings.Repeat("11", 16)
	ids := []string{strings.Repeat("21", 16), strings.Repeat("22", 16), strings.Repeat("23", 16)}
	if _, e := store.syncImage(owner, ids[0], 0, syncDDS(1)); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/ContentMetaGet", nil)
	r.Header.Set("X-WWE-Native-Images", "1")
	data := map[string]any{"ContentIDs": []any{ids[0], ids[1], ids[2]}}
	type result struct {
		response map[string]any
		err      error
	}
	done := make(chan result, 1)
	go func() {
		response, e := s.nativeContentHandle(r, "ContentMetaGet", owner, data, nil)
		done <- result{response, e}
	}()
	waitSyncWaiters(t, s, 1)
	if _, e := store.syncImage(owner, ids[1], 31, syncDDS(2)); e != nil {
		t.Fatal(e)
	}
	s.notifyImageSync()
	// The existing logo and the new face photo are insufficient while the
	// portrait is missing. ContentMetaGet intentionally returns complete batches.
	select {
	case result := <-done:
		t.Fatal("partial dependency batch ended wait", result.response, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	if _, e := store.syncImage(owner, ids[2], 61, syncDDS(3)); e != nil {
		t.Fatal(e)
	}
	s.notifyImageSync()
	select {
	case result := <-done:
		if result.err != nil || len(result.response["Results"].([]any)) != len(ids) {
			t.Fatal(result.response, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("complete dependency batch did not wake")
	}
	for _, invalid := range [][]any{{ids[0], ids[0]}, {ids[0], "invalid"}, {}} {
		_, e := s.nativeContentHandle(r, "ContentMetaGet", owner, map[string]any{"ContentIDs": invalid}, nil)
		if statusCode(e, 0) != 400 {
			t.Fatal("invalid dependency batch waited or was accepted", invalid, e)
		}
	}
}
