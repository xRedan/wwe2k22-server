package backend

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const maxAsset = 64 * 1024 * 1024
const cdnNamespace = "/ae70420fb2e24ec6a145023e0fa111f8/"

type contentStore struct {
	mu    sync.Mutex
	conn  *sqlite.Conn
	lease *os.File
	quota int64
}
type binaryPart struct {
	Stream io.ReadSeeker
	Size   int64
}

func newContentStore(path string, quota int64) (*contentStore, error) {
	lease, err := acquireDatabaseLease(path)
	if err != nil {
		return nil, err
	}
	if path == "" {
		path = ":memory:"
	}
	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		releaseDatabaseLease(lease)
		return nil, err
	}
	s := &contentStore{conn: conn, lease: lease, quota: quota}
	conn.SetBusyTimeout(5 * time.Second)
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA synchronous=FULL"} {
		if err = s.exec(q); err != nil {
			s.close()
			return nil, err
		}
	}
	version, err := s.rows("PRAGMA user_version")
	if err != nil || len(version) != 1 || version[0][0].(int64) < 0 || version[0][0].(int64) > 1 {
		s.close()
		return nil, errors.New("unsupported database schema; preserve the existing file")
	}
	err = s.transaction(func() error {
		for _, q := range []string{
			"CREATE TABLE IF NOT EXISTS content (id TEXT PRIMARY KEY, owner TEXT NOT NULL, private INTEGER NOT NULL, created INTEGER NOT NULL, metadata TEXT NOT NULL)",
			"CREATE TABLE IF NOT EXISTS assets (file_id TEXT UNIQUE NOT NULL, content_id TEXT NOT NULL REFERENCES content(id) ON DELETE CASCADE, name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, payload BLOB NOT NULL, UNIQUE(content_id,name))",
			"CREATE TABLE IF NOT EXISTS saved (owner TEXT NOT NULL, content_id TEXT NOT NULL REFERENCES content(id) ON DELETE CASCADE, PRIMARY KEY(owner,content_id))",
			"CREATE INDEX IF NOT EXISTS saved_content_lookup ON saved(content_id)",
			"PRAGMA user_version=1",
		} {
			if err := s.exec(q); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *contentStore) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	releaseDatabaseLease(s.lease)
	s.lease = nil
}
func (s *contentStore) exec(q string, args ...any) error {
	if s.conn == nil {
		return fail(503, "Local content storage is closed")
	}
	return sqlitex.Execute(s.conn, q, &sqlitex.ExecOptions{Args: args})
}
func (s *contentStore) rows(q string, args ...any) ([][]any, error) {
	if s.conn == nil {
		return nil, fail(503, "Local content storage is closed")
	}
	out := [][]any{}
	e := sqlitex.Execute(s.conn, q, &sqlitex.ExecOptions{Args: args, ResultFunc: func(stmt *sqlite.Stmt) error {
		row := make([]any, stmt.ColumnCount())
		for i := range row {
			switch stmt.ColumnType(i) {
			case sqlite.TypeInteger:
				row[i] = stmt.ColumnInt64(i)
			case sqlite.TypeText:
				row[i] = stmt.ColumnText(i)
			case sqlite.TypeBlob:
				b := make([]byte, stmt.ColumnLen(i))
				stmt.ColumnBytes(i, b)
				row[i] = b
			case sqlite.TypeFloat:
				row[i] = stmt.ColumnFloat(i)
			}
		}
		out = append(out, row)
		return nil
	}})
	return out, e
}
func (s *contentStore) transaction(fn func() error) (err error) {
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		// Also roll back when fn panics; the HTTP boundary handles the panic.
		if !committed {
			_ = s.exec("ROLLBACK")
		}
	}()
	if err = fn(); err != nil {
		return err
	}
	err = s.exec("COMMIT")
	committed = err == nil
	return err
}
func (s *contentStore) summary() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, e := s.rows("SELECT COUNT(*) FROM content")
	if e != nil {
		return nil, storageError(e)
	}
	b, e := s.rows("SELECT COUNT(*),COALESCE(SUM(size),0) FROM assets")
	if e != nil {
		return nil, storageError(e)
	}
	return map[string]any{"contents": a[0][0], "assets": b[0][0], "bytes": b[0][1], "quota_bytes": s.quota, "max_asset_bytes": maxAsset}, nil
}
func (s *contentStore) quotaCheck(added int64, count int) error {
	a, e := s.rows("SELECT COALESCE(SUM(size),0) FROM assets")
	if e != nil {
		return e
	}
	b, e := s.rows("SELECT COUNT(*) FROM content")
	if e != nil {
		return e
	}
	if a[0][0].(int64)+added > s.quota || b[0][0].(int64)+int64(count) > 4096 {
		return fail(507, "Local content storage quota exceeded")
	}
	return nil
}
func (s *contentStore) insertAsset(cid, name string, part binaryPart) error {
	fid, e := randomUUID()
	if e != nil {
		return e
	}
	if e = s.exec("INSERT INTO assets VALUES (?,?,?,?,?,zeroblob(?))", fid, cid, name, part.Size, "", part.Size); e != nil {
		return e
	}
	row := s.conn.LastInsertRowID()
	blob, e := s.conn.OpenBlob("main", "assets", "payload", row, true)
	if e != nil {
		return e
	}
	if _, e = part.Stream.Seek(0, io.SeekStart); e != nil {
		blob.Close()
		return e
	}
	digest := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(blob, digest), io.LimitReader(part.Stream, part.Size), make([]byte, 64*1024))
	ce := blob.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	extra := make([]byte, 1)
	k, readErr := part.Stream.Read(extra)
	if n != part.Size || k != 0 || (readErr != nil && readErr != io.EOF) {
		return fail(400, "Native content size mismatch")
	}
	return s.exec("UPDATE assets SET sha256=? WHERE file_id=?", hex.EncodeToString(digest.Sum(nil)), fid)
}
func (s *contentStore) create(owner string, meta map[string]any, files map[string]binaryPart) (string, error) {
	raw, e := json.Marshal(meta)
	if e != nil {
		return "", fail(400, "Invalid content metadata")
	}
	if len(raw) > 1024*1024 {
		return "", fail(413, "Content metadata is too large")
	}
	if _, ok := files["content"]; !ok {
		return "", fail(400, "Native main content part is required")
	}
	total := int64(0)
	for name, p := range files {
		if (name != "content" && name != "thumb1" && name != "thumb2" && name != "RstrParts") || p.Size < 1 || p.Size > maxAsset {
			return "", fail(413, "Invalid native content asset")
		}
		total += p.Size
	}
	if total > maxAsset {
		return "", fail(413, "Native content package is too large")
	}
	cid, e := randomUUID()
	if e != nil {
		return "", e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e = s.transaction(func() error {
		if e := s.quotaCheck(total, 1); e != nil {
			return e
		}
		private := 0
		if meta["Private"] == true {
			private = 1
		}
		if e := s.exec("INSERT INTO content VALUES (?,?,?,?,?)", cid, owner, private, time.Now().Unix(), string(raw)); e != nil {
			return e
		}
		names := make([]string, 0, len(files))
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if e := s.insertAsset(cid, name, files[name]); e != nil {
				return e
			}
		}
		return nil
	})
	return cid, storageError(e)
}
func (s *contentStore) record(cid, owner string) ([]any, error) {
	rows, e := s.rows("SELECT owner,private,created,metadata FROM content WHERE id=?", cid)
	if e != nil {
		return nil, e
	}
	if len(rows) == 0 || (rows[0][1].(int64) != 0 && rows[0][0].(string) != owner) {
		return nil, fail(404, "Unknown local content")
	}
	return rows[0], nil
}
func (s *contentStore) metadata(cid, owner string, names []string, budget int) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, e := s.record(cid, owner)
	if e != nil {
		return nil, storageError(e)
	}
	meta, e := jsonObject([]byte(row[3].(string)), false)
	if e != nil {
		return nil, storageError(e)
	}
	for k := range meta {
		if strings.HasPrefix(k, "_Native") {
			delete(meta, k)
		}
	}
	main, e := s.rows("SELECT file_id,size FROM assets WHERE content_id=? AND name=?", cid, "content")
	if e != nil || len(main) != 1 {
		return nil, fail(503, "Local content storage is unavailable")
	}
	saves, e := s.rows("SELECT COUNT(*) FROM saved WHERE content_id=?", cid)
	if e != nil {
		return nil, storageError(e)
	}
	meta["ID"] = cid
	meta["PID"] = row[0]
	meta["FileID"] = main[0][0]
	meta["FileSize"] = main[0][1]
	meta["CreatedAt"] = (row[2].(int64) + 2208988800) * 1000000
	meta["Saves"] = saves[0][0]
	rows, e := s.rows("SELECT rowid,name,size FROM assets WHERE content_id=? AND name != ?", cid, "content")
	if e != nil {
		return nil, storageError(e)
	}
	used := int64(0)
	for _, r := range rows {
		include := false
		for _, n := range names {
			if n == r[1].(string) {
				include = true
			}
		}
		if !include {
			continue
		}
		n := r[2].(int64)
		used += n
		if used > int64(budget) {
			return nil, fail(413, "Native metadata response is too large")
		}
	}
	for _, r := range rows {
		include := false
		for _, n := range names {
			if n == r[1].(string) {
				include = true
			}
		}
		if !include {
			continue
		}
		blob, e := s.conn.OpenBlob("main", "assets", "payload", r[0].(int64), false)
		if e != nil {
			return nil, storageError(e)
		}
		b, e := io.ReadAll(io.LimitReader(blob, r[2].(int64)+1))
		ce := blob.Close()
		if e != nil || ce != nil || int64(len(b)) != r[2].(int64) {
			return nil, fail(503, "Local content storage is unavailable")
		}
		key := "Thumbnail1"
		if r[1] == "thumb2" {
			key = "Thumbnail2"
		}
		meta[key] = hex.EncodeToString(b)
	}
	return meta, nil
}
func (s *contentStore) snapshot(fid, owner string) (*spool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, e := s.rows("SELECT a.rowid,a.size,c.owner,c.private FROM assets a JOIN content c ON c.id=a.content_id WHERE a.file_id=?", fid)
	if e != nil {
		return nil, storageError(e)
	}
	if len(rows) == 0 || (rows[0][3].(int64) != 0 && rows[0][2].(string) != owner) {
		return nil, fail(404, "Unknown local content asset")
	}
	row := rows[0]
	size := row[1].(int64)
	if size < 0 || size > maxAsset {
		return nil, fail(503, "Invalid stored asset length")
	}
	blob, e := s.conn.OpenBlob("main", "assets", "payload", row[0].(int64), false)
	if e != nil {
		return nil, storageError(e)
	}
	out := &spool{}
	n, e := io.CopyBuffer(out, io.LimitReader(blob, size+1), make([]byte, 64*1024))
	ce := blob.Close()
	if e != nil || ce != nil || n != size {
		out.Close()
		return nil, fail(503, "Local content snapshot is unavailable")
	}
	out.Seek(0, io.SeekStart)
	return out, nil
}
func (s *contentStore) save(owner, cid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e := s.record(cid, owner); e != nil {
		return storageError(e)
	}
	return storageError(s.exec("INSERT OR IGNORE INTO saved VALUES (?,?)", owner, cid))
}

type contentQuery struct {
	Type          *int64
	Tags          []string
	Private       bool
	FromWeb       *bool
	Offset, Limit int
	Saves         bool
}

func (s *contentStore) search(owner string, q contentQuery) ([]string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, 0, fail(503, "Local content storage is closed")
	}
	type match struct {
		ID             string
		Created, Saves int64
	}
	matches := []match{}
	fold := cases.Fold()
	tags := make([]string, len(q.Tags))
	for i, tag := range q.Tags {
		tags[i] = fold.String(tag)
	}
	// Reuse the SQLite copy for this search. ColumnText followed by []byte
	// allocated two complete metadata copies for every candidate row.
	var metadataBytes []byte
	// Stream each row: do not retain every opaque metadata document in memory.
	err := sqlitex.Execute(s.conn, "SELECT c.id,c.owner,c.private,c.created,c.metadata,COUNT(s.owner) FROM content c LEFT JOIN saved s ON s.content_id=c.id WHERE c.private=0 OR c.owner=? GROUP BY c.id", &sqlitex.ExecOptions{Args: []any{owner}, ResultFunc: func(stmt *sqlite.Stmt) error {
		if (stmt.ColumnInt64(2) != 0) != q.Private {
			return nil
		}
		size := stmt.ColumnLen(4)
		if size > cap(metadataBytes) {
			metadataBytes = make([]byte, size)
		} else {
			metadataBytes = metadataBytes[:size]
		}
		stmt.ColumnBytes(4, metadataBytes)
		meta, err := jsonObject(metadataBytes, false)
		if err != nil {
			return err
		}
		if meta["_NativeDependency"] == true {
			return nil
		}
		n, ok := jint(meta["ContentType"])
		if q.Type != nil && (!ok || n != *q.Type) {
			return nil
		}
		web, _ := jbool(meta["FromWeb"])
		if q.FromWeb != nil && web != *q.FromWeb {
			return nil
		}
		if len(tags) > 0 {
			var candidateTags [10]string
			var folded uint16
			for _, tag := range tags {
				found := false
				for i := range candidateTags {
					if folded&(1<<i) == 0 {
						candidateTags[i] = fold.String(str(meta["Tag"+string(rune('0'+i))]))
						folded |= 1 << i
					}
					if tag == candidateTags[i] {
						found = true
						break
					}
				}
				if !found {
					return nil
				}
			}
		}
		matches = append(matches, match{stmt.ColumnText(0), stmt.ColumnInt64(3), stmt.ColumnInt64(5)})
		return nil
	}})
	if err != nil {
		return nil, 0, storageError(err)
	}
	slices.SortFunc(matches, func(a, b match) int {
		if q.Saves && a.Saves != b.Saves {
			return cmp.Compare(b.Saves, a.Saves)
		}
		if a.Created != b.Created {
			return cmp.Compare(b.Created, a.Created)
		}
		return cmp.Compare(b.ID, a.ID)
	})
	total := len(matches)
	ids := []string{}
	for i := q.Offset; i < total && i < q.Offset+q.Limit; i++ {
		ids = append(ids, matches[i].ID)
	}
	return ids, total, nil
}
func cdnID(path string) (string, error) {
	if !strings.HasPrefix(path, cdnNamespace) {
		return "", fail(404, "Unknown local content asset")
	}
	parts := strings.Split(strings.TrimPrefix(path, cdnNamespace), "/")
	if len(parts) != 3 || !strings.HasSuffix(parts[2], ".bin") {
		return "", fail(404, "Unknown local content asset")
	}
	id := strings.TrimSuffix(parts[2], ".bin")
	if len(id) != 32 || id != strings.ToLower(id) || parts[0] != id[:3] || parts[1] != id[3:6] {
		return "", fail(404, "Unknown local content asset")
	}
	v, e := uuidID(id, false)
	if e != nil {
		return "", fail(404, "Unknown local content asset")
	}
	return v, nil
}
