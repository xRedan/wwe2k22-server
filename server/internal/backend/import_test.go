package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalImageImportUpgradeAndIdempotence(t *testing.T) {
	raw, e := os.ReadFile("testdata/python_images.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		DDS     string `json:"dds_hex"`
		Packets []struct {
			Kind    int
			Preview bool
			Hex     string
		}
	}
	if e = json.Unmarshal(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	dds, _ := hex.DecodeString(fixture.DDS)
	sum := sha256.Sum256(dds)
	digest := hex.EncodeToString(sum[:])
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, digest+".dds"), dds, 0600)
	descriptor := make([]byte, 32)
	for i := 16; i < 32; i++ {
		descriptor[i] = 0x22
	}
	id, owner := strings.Repeat("22", 16), strings.Repeat("33", 16)
	manifest := map[string]any{"target_sha256": TargetSHA, "error": nil, "rejected": 0, "bytes": len(dds), "images": []any{map[string]any{"descriptor_hex": hex.EncodeToString(descriptor), "sha256": digest, "storage_kind": 0, "file": digest + ".dds", "size": len(dds), "width": 64, "height": 32}}}
	encoded, _ := marshalJSON(manifest)
	path := filepath.Join(root, "manifest.json")
	os.WriteFile(path, encoded, 0600)
	store, e := newContentStore("", 8*1024*1024)
	if e != nil {
		t.Fatal(e)
	}
	defer store.close()
	legacy, _ := hex.DecodeString(fixture.Packets[0].Hex)
	meta := map[string]any{"ContentType": 2, "Private": false, "_NativeDependency": true, "_NativeImageCodec": 1, "_NativeSourceSHA256": digest}
	encoded, _ = marshalJSON(meta)
	store.mu.Lock()
	e = store.transaction(func() error {
		if e := store.exec("INSERT INTO content VALUES (?,?,?,?,?)", id, owner, 0, 1, string(encoded)); e != nil {
			return e
		}
		return store.insertAsset(id, "content", binaryPart{bytes.NewReader(legacy), int64(len(legacy))})
	})
	store.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	before, e := store.metadata(id, owner, nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.importImages(path, owner, false); statusCode(e, 0) != 409 {
		t.Fatal("legacy package overwritten without explicit upgrade")
	}
	result, e := store.importImages(path, owner, true)
	if e != nil || result["upgraded"] != 1 {
		t.Fatal("explicit upgrade failed", e)
	}
	after, e := store.metadata(id, owner, nil, 0)
	if e != nil || before["FileID"] == after["FileID"] {
		t.Fatal("upgraded FileID not rotated")
	}
	snapshot, e := store.snapshot(str(after["FileID"]), owner)
	if e != nil {
		t.Fatal(e)
	}
	packet := make([]byte, snapshot.size)
	n, e := snapshot.Read(packet)
	snapshot.Close()
	if e != nil || int64(n) != int64(len(packet)) {
		t.Fatal(e)
	}
	image, e := inspectImage(packet)
	if e != nil || image.Codec != 2 || !bytes.Equal(image.DDS, dds) {
		t.Fatal("upgraded image differs", e)
	}
	result, e = store.importImages(path, owner, false)
	if e != nil || result["unchanged"] != 1 {
		t.Fatal("import not idempotent", e)
	}
	again, _ := store.metadata(id, owner, nil, 0)
	if again["FileID"] != after["FileID"] {
		t.Fatal("idempotent import changed FileID")
	}
	if _, e = store.importImages(path, strings.Repeat("44", 16), true); statusCode(e, 0) != 409 {
		t.Fatal("other owner overwrote imported image")
	}
}
