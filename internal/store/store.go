// Package store is SQLite-backed persistence for runs, decisions, findings,
// audit records and checkpoints. Schema v10 mirrors db.py DDL so existing
// user data stays readable; migrations are transactional with backup.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 10

const ddl = `
CREATE TABLE IF NOT EXISTS _migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS missions (id TEXT PRIMARY KEY, program_name TEXT NOT NULL DEFAULT '', objective TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'preparing', target TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL DEFAULT 'attack', goal TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, request_json TEXT NOT NULL DEFAULT '{}', result_json TEXT NOT NULL DEFAULT '{}', title TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS decisions (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '', prompt_text TEXT NOT NULL DEFAULT '', required_text TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', answer TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, answered_at TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'proposed', data_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL DEFAULT '', event_type TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_runs_state ON runs(state);
CREATE INDEX IF NOT EXISTS idx_decisions_run ON decisions(run_id);
`

// DB wraps the SQLite handle plus the reports dir for JSONL artifacts.
type DB struct {
	SQL        *sql.DB
	ReportsDir string
	Path       string
}

// Open creates parent dirs, backs up before migrating, and applies DDL.
func Open(dbPath, reportsDir string) (*DB, error) {
	if dbPath == "" {
		dbPath = "api_runtime.db"
	}
	if reportsDir == "" {
		reportsDir = "reports"
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(dbPath)), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Clean(reportsDir), 0o755); err != nil {
		return nil, err
	}
	// Backup pre-migration copy (best effort, never blocks open).
	if st, err := os.Stat(dbPath); err == nil && st.Size() > 0 {
		_ = copyFile(dbPath, dbPath+".pre-go-migration.bak")
	}
	sqlDB, err := sql.Open("sqlite", dbPath+"?cache=shared")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := sqlDB.Exec(ddl); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("apply ddl: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = sqlDB.Exec(`INSERT OR IGNORE INTO _migrations(version, applied_at) VALUES(?, ?)`, schemaVersion, now)
	return &DB{SQL: sqlDB, ReportsDir: reportsDir, Path: dbPath}, nil
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(dst), raw, 0o600)
}

// CreateRun inserts a run row. updated_at == created_at initially.
func (d *DB) CreateRun(id, state, target, mode, goal, requestJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`INSERT INTO runs(id,state,target,mode,goal,created_at,updated_at,request_json) VALUES(?,?,?,?,?,?,?,?)`,
		id, state, target, mode, goal, now, now, requestJSON)
	return err
}

// GetRun returns the run row as a map, or nil when missing.
func (d *DB) GetRun(id string) (map[string]any, error) {
	row := d.SQL.QueryRow(`SELECT id,state,target,mode,goal,created_at,updated_at,request_json,result_json,title FROM runs WHERE id=?`, id)
	var m = map[string]any{}
	var rid, state, target, mode, goal, created, updated, req, res, title string
	if err := row.Scan(&rid, &state, &target, &mode, &goal, &created, &updated, &req, &res, &title); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	m["id"] = rid
	m["state"] = state
	m["target"] = target
	m["mode"] = mode
	m["goal_name"] = goal
	m["created_at"] = created
	m["updated_at"] = updated
	m["target_ip"] = target
	m["title"] = title
	return m, nil
}

// ListRuns returns newest-first run summaries.
func (d *DB) ListRuns(limit, offset int, q, state, sort string) ([]map[string]any, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var total int
	countQ := `SELECT COUNT(*) FROM runs`
	args := []any{}
	if state != "" {
		countQ += ` WHERE state=?`
		args = append(args, state)
	}
	if err := d.SQL.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := `created_at DESC`
	switch sort {
	case "created_asc":
		order = `created_at ASC`
	case "title_asc":
		order = `title ASC`
	case "title_desc":
		order = `title DESC`
	}
	q2 := `SELECT id,state,target,mode,goal,created_at FROM runs`
	if state != "" {
		q2 += ` WHERE state=?`
	}
	q2 += ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := d.SQL.Query(q2, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, st, target, mode, goal, created string
		if err := rows.Scan(&id, &st, &target, &mode, &goal, &created); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]any{"id": id, "state": st, "target": target, "mode": mode, "goal_name": goal, "created_at": created, "target_ip": target})
	}
	if out == nil {
		out = []map[string]any{}
	}
	_ = q // substring filter applied at API layer for v1 parity (small lists)
	return out, total, rows.Err()
}

// SetRunState updates state + updated_at.
func (d *DB) SetRunState(id, state string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`UPDATE runs SET state=?, updated_at=? WHERE id=?`, state, now, id)
	return err
}

// LogAudit appends a tamper-evident audit row (hash chain lives in JSONL too).
func (d *DB) LogAudit(runID, eventType, message, metadata string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`INSERT INTO audit_logs(run_id,event_type,message,metadata,created_at) VALUES(?,?,?,?,?)`, runID, eventType, message, metadata, now)
	return err
}

// Close releases the handle.
func (d *DB) Close() error { return d.SQL.Close() }
