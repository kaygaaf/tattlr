package openclaw

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite" // pure Go, no cgo
)

// dbName is the per-agent database OpenClaw 2026.10+ writes under
// agents/<agent>/agent/.
const dbName = "openclaw-agent.sqlite"

// sep joins a database path and a session id into one Discover path.
const sep = "#"

func splitDBPath(p string) (db, session string, ok bool) {
	i := strings.LastIndex(p, sep)
	if i < 0 || !strings.HasSuffix(p[:i], dbName) {
		return "", "", false
	}
	return p[:i], p[i+1:], true
}

// openDB opens the database read only, so tattlr never changes a row and
// OpenClaw can keep running while we read. (SQLite may still touch the
// -shm index next to it; that's how WAL readers work.)
func openDB(path string) (*sql.DB, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// file:///C:/x on Windows, file:///home/x elsewhere.
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: "mode=ro&_pragma=busy_timeout(3000)&_pragma=query_only(1)"}
	return sql.Open("sqlite", u.String())
}

// dbSessions lists one "<db>#<session id>" path per session with events.
// A database tattlr can't read is skipped here; nothing else depends on it.
func dbSessions(path string) []string {
	db, err := openDB(path)
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.Query(`SELECT session_id FROM transcript_events GROUP BY session_id ORDER BY MIN(created_at)`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && id != "" {
			out = append(out, path+sep+id)
		}
	}
	return out
}

// dbEvents calls fn for each transcript line of one session, in order.
// Big lines are stored zstd compressed in event_zstd instead of event_json.
func dbEvents(path, session string, fn func(map[string]any)) error {
	db, err := openDB(path)
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT event_json, event_zstd FROM transcript_events WHERE session_id = ? ORDER BY seq`, session)
	if err != nil {
		return err
	}
	defer rows.Close()
	var dec *zstd.Decoder
	defer func() {
		if dec != nil {
			dec.Close()
		}
	}()
	bad := 0
	for rows.Next() {
		var js sql.NullString
		var z []byte
		if err := rows.Scan(&js, &z); err != nil {
			return err
		}
		raw := []byte(js.String)
		if !js.Valid {
			if len(z) == 0 {
				continue
			}
			if dec == nil {
				if dec, err = zstd.NewReader(nil, zstd.WithDecoderMaxMemory(64<<20)); err != nil {
					return err
				}
			}
			if raw, err = dec.DecodeAll(z, nil); err != nil {
				bad++
				continue
			}
		}
		// Same as jsonl.EachLine: a row that isn't a JSON object is skipped.
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil && m != nil {
			fn(m)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if bad > 0 {
		return fmt.Errorf("skipped %d compressed transcript rows that would not decode", bad)
	}
	return nil
}
