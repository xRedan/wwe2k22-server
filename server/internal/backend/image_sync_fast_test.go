package backend

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestImageSyncFastPathRespectsPrivateContentAndValidation(t *testing.T) {
	s := newSyncStore(t)
	owner, other, id := strings.Repeat("11", 16), strings.Repeat("22", 16), strings.Repeat("33", 16)
	dds := syncDDS(1)
	first, e := s.syncImage(owner, id, 31, dds)
	if e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	e = s.exec("UPDATE content SET private=1 WHERE id=?", id)
	s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.syncImage(other, id, 31, dds); statusCode(e, 0) != 409 {
		t.Fatal("private dependency shared across owners", e)
	}
	if _, e = s.snapshot(str(first["FileID"]), other); statusCode(e, 0) != 404 {
		t.Fatal("private dependency download exposed", e)
	}
	updated, e := s.syncImage(owner, id, 31, dds)
	if e != nil || updated["status"] != "updated" || updated["FileID"] == first["FileID"] {
		t.Fatal("owner could not republish private dependency", updated, e)
	}
	// A shared duplicate uses no additional storage, even after an operator
	// lowers the quota below current usage.
	s.quota = 1
	shared, e := s.syncImage(other, id, 31, dds)
	if e != nil || shared["status"] != "unchanged" || shared["FileID"] != updated["FileID"] {
		t.Fatal("duplicate charged quota or rotated asset", shared, e)
	}
	invalid := bytes.Clone(dds)
	binary.LittleEndian.PutUint32(invalid[16:], 0)
	if _, e = s.syncImage(owner, id, 31, invalid); statusCode(e, 0) != 400 {
		t.Fatal("invalid DDS reached duplicate lookup", e)
	}
	if _, e = s.syncImage(owner, id, 32, dds); statusCode(e, 0) != 400 {
		t.Fatal("unsupported kind reached duplicate lookup", e)
	}
}

func TestImageSyncConcurrentFirstUploadRechecksIdentity(t *testing.T) {
	for _, conflicting := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflicting=%t", conflicting), func(t *testing.T) {
			s := newSyncStore(t)
			id := strings.Repeat("aa", 16)
			base := benchmarkSyncDDS(256)
			count := 8
			if conflicting {
				count = 2
			}
			type upload struct {
				owner    string
				dds      []byte
				response map[string]any
				err      error
			}
			start, done := make(chan struct{}), make(chan upload, count)
			for i := 0; i < count; i++ {
				go func(i int) {
					dds := base
					if conflicting && i == 1 {
						dds = bytes.Clone(base)
						dds[len(dds)-1] ^= 1
					}
					owner := fmt.Sprintf("%032x", i+1)
					<-start
					response, e := s.syncImage(owner, id, 31, dds)
					done <- upload{owner, dds, response, e}
				}(i)
			}
			close(start)
			created, unchanged, rejected := 0, 0, 0
			var winner upload
			var fileIDs []string
			for i := 0; i < count; i++ {
				result := <-done
				if statusCode(result.err, 0) == 409 {
					rejected++
					continue
				}
				if result.err != nil {
					t.Fatal(result.err)
				}
				fileIDs = append(fileIDs, str(result.response["FileID"]))
				switch result.response["status"] {
				case "created":
					created++
					winner = result
				case "unchanged":
					unchanged++
				default:
					t.Fatal("concurrent initial upload overwrote an owner", result.response)
				}
			}
			if created != 1 || (conflicting && (rejected != 1 || unchanged != 0)) || (!conflicting && (rejected != 0 || unchanged != count-1)) {
				t.Fatal(created, unchanged, rejected)
			}
			for _, fid := range fileIDs {
				if fid != winner.response["FileID"] {
					t.Fatal("duplicate initial upload rotated FileID")
				}
			}
			meta, e := s.metadata(id, winner.owner, nil, 0)
			if e != nil || meta["PID"] != winner.owner {
				t.Fatal("concurrent owner changed", meta, e)
			}
			asset, e := s.snapshot(str(meta["FileID"]), winner.owner)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := io.ReadAll(asset)
			asset.Close()
			image, pe := inspectImage(raw)
			if e != nil || pe != nil || image.Codec != 2 || !bytes.Equal(image.DDS, winner.dds) {
				t.Fatal("concurrent pixels differ", e, pe)
			}
			summary, e := s.summary()
			if e != nil || summary["contents"] != int64(1) || summary["assets"] != int64(1) {
				t.Fatal("concurrent upload created extra assets", summary, e)
			}
		})
	}
}
