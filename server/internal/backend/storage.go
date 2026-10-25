package backend

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type database struct {
	DB    *sql.DB
	Lease *os.File
}

// Content and profile stores share the lease, not a redundant SQL connection.
func acquireDatabaseLease(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if info.Size() == 0 {
		if _, e = f.WriteAt([]byte{'0'}, 0); e != nil {
			f.Close()
			return nil, e
		}
	}
	if e = lockLease(f); e != nil {
		f.Close()
		return nil, errors.New("database already in use; stop its owning server first")
	}
	return f, nil
}
func releaseDatabaseLease(f *os.File) {
	if f != nil {
		unlockLease(f)
		_ = f.Close()
	}
}

func openDatabase(path string) (*database, error) {
	lease, err := acquireDatabaseLease(path)
	if err != nil {
		return nil, err
	}
	d := &database{Lease: lease}
	if path == "" {
		path = ":memory:"
	}
	var e error
	d.DB, e = sql.Open("sqlite", path)
	if e != nil {
		d.close()
		return nil, e
	}
	d.DB.SetMaxOpenConns(1)
	d.DB.SetMaxIdleConns(1)
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON"} {
		if _, e = d.DB.Exec(q); e != nil {
			d.close()
			return nil, e
		}
	}
	var version int
	if e = d.DB.QueryRow("PRAGMA user_version").Scan(&version); e != nil || version < 0 || version > 1 {
		d.close()
		return nil, errors.New("unsupported database schema; preserve the existing file")
	}
	if _, e = d.DB.Exec("PRAGMA journal_mode=WAL"); e != nil {
		d.close()
		return nil, e
	}
	schema := []string{"CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, data TEXT NOT NULL)", "CREATE TABLE IF NOT EXISTS notices (id TEXT NOT NULL, document TEXT NOT NULL, version INTEGER NOT NULL, PRIMARY KEY(id, document))", "CREATE TABLE IF NOT EXISTS counters (id TEXT NOT NULL, board TEXT NOT NULL, rank_key TEXT NOT NULL, value INTEGER NOT NULL, PRIMARY KEY(id, board, rank_key))"}
	tx, e := d.DB.Begin()
	if e != nil {
		d.close()
		return nil, e
	}
	defer tx.Rollback()
	for _, q := range append(schema, "PRAGMA user_version=1") {
		if _, e = tx.Exec(q); e != nil {
			_ = tx.Rollback()
			d.close()
			return nil, e
		}
	}
	if e = tx.Commit(); e != nil {
		d.close()
		return nil, e
	}
	return d, nil
}
func (d *database) close() {
	if d == nil {
		return
	}
	if d.DB != nil {
		d.DB.Close()
		d.DB = nil
	}
	if d.Lease != nil {
		releaseDatabaseLease(d.Lease)
		d.Lease = nil
	}
}

type counterKey struct{ User, Board, Rank string }
type stateStore struct {
	Database   *database
	Persistent bool
}

func newState(path string) (*stateStore, error) {
	s := &stateStore{Persistent: path != ""}
	if path != "" {
		d, e := openDatabase(path)
		if e != nil {
			return nil, e
		}
		s.Database = d
	}
	return s, nil
}
func (s *stateStore) load() (map[string]map[string]any, map[string]map[string]int64, map[counterKey]int64, error) {
	profiles := map[string]map[string]any{}
	notices := map[string]map[string]int64{}
	counters := map[counterKey]int64{}
	if s.Database == nil {
		return profiles, notices, counters, nil
	}
	db := s.Database.DB
	rows, e := db.Query("SELECT id,data FROM profiles")
	if e != nil {
		return nil, nil, nil, e
	}
	for rows.Next() {
		var id, raw string
		if e = rows.Scan(&id, &raw); e != nil {
			rows.Close()
			return nil, nil, nil, e
		}
		m, err := jsonObject([]byte(raw), false)
		if err != nil || m["ID"] != id {
			rows.Close()
			return nil, nil, nil, errors.New("invalid stored profile")
		}
		profiles[id] = m
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, nil, e
	}
	rows, e = db.Query("SELECT id,document,version FROM notices")
	if e != nil {
		return nil, nil, nil, e
	}
	for rows.Next() {
		var id, doc string
		var v int64
		if e = rows.Scan(&id, &doc, &v); e != nil {
			rows.Close()
			return nil, nil, nil, e
		}
		if notices[id] == nil {
			notices[id] = map[string]int64{}
		}
		notices[id][doc] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, nil, nil, e
	}
	rows, e = db.Query("SELECT id,board,rank_key,value FROM counters")
	if e != nil {
		return nil, nil, nil, e
	}
	for rows.Next() {
		var k counterKey
		var v int64
		if e = rows.Scan(&k.User, &k.Board, &k.Rank, &v); e != nil {
			rows.Close()
			return nil, nil, nil, e
		}
		counters[k] = v
	}
	e = rows.Err()
	rows.Close()
	return profiles, notices, counters, e
}
func (s *stateStore) profile(id string, m map[string]any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxProfileBytes {
		return fail(413, "Local profile is too large")
	}
	if s.Database == nil {
		return nil
	}
	_, err = s.Database.DB.Exec("INSERT INTO profiles VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", id, string(b))
	return err
}

func (s *stateStore) notice(id, doc string, v int64) error {
	if s.Database == nil {
		return nil
	}
	_, e := s.Database.DB.Exec("INSERT INTO notices VALUES (?,?,?) ON CONFLICT(id,document) DO UPDATE SET version=excluded.version", id, doc, v)
	return e
}
func (s *stateStore) counters(changes map[counterKey]int64) error {
	if s.Database == nil {
		return nil
	}
	tx, e := s.Database.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for k, v := range changes {
		if _, e = tx.Exec("INSERT INTO counters VALUES (?,?,?,?) ON CONFLICT(id,board,rank_key) DO UPDATE SET value=excluded.value", k.User, k.Board, k.Rank, v); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func contentDBPath(path string) string {
	if path == "" {
		return ""
	}
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".content.sqlite3"
}
func storageError(e error) error {
	if e == nil {
		return nil
	}
	var re *requestError
	if errors.As(e, &re) {
		return e
	}
	return fail(503, "Local content storage is unavailable")
}
