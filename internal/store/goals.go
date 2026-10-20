package store

import (
	"fmt"
	"strings"
	"time"
)

// CustomGoal mirrors the custom_goals table (persistence_schema v5).
type CustomGoal struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Objective string `json:"objective"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

const goalsDDL = `
CREATE TABLE IF NOT EXISTS custom_goals (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL COLLATE NOCASE,
	objective TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE(name)
);
CREATE INDEX IF NOT EXISTS idx_custom_goals_name ON custom_goals(name COLLATE NOCASE);
`

func ensureGoals(db *DB) error {
	_, err := db.SQL.Exec(goalsDDL)
	return err
}

// ListCustomGoals returns all custom goals ordered by name.
func (d *DB) ListCustomGoals() ([]CustomGoal, error) {
	if err := ensureGoals(d); err != nil {
		return nil, err
	}
	rows, err := d.SQL.Query(`SELECT id,name,objective,created_at,updated_at FROM custom_goals ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomGoal
	for rows.Next() {
		var g CustomGoal
		if err := rows.Scan(&g.ID, &g.Name, &g.Objective, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if out == nil {
		out = []CustomGoal{}
	}
	return out, rows.Err()
}

// GoalNameTaken reports whether name collides (case-insensitive) with a
// custom goal or one of the preset names.
func GoalNameTaken(existing []CustomGoal, presets []string, name string) bool {
	for _, g := range existing {
		if strings.EqualFold(g.Name, name) {
			return true
		}
	}
	for _, p := range presets {
		if strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}

// CreateCustomGoal inserts a goal; name collisions (incl. presets, checked by
// the caller via GoalNameTaken or enforced here for customs) fail.
func (d *DB) CreateCustomGoal(id, name, objective string) (CustomGoal, error) {
	if err := ensureGoals(d); err != nil {
		return CustomGoal{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`INSERT INTO custom_goals(id,name,objective,created_at,updated_at) VALUES(?,?,?,?,?)`,
		id, name, objective, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return CustomGoal{}, fmt.Errorf("duplicate_goal: %w", err)
		}
		return CustomGoal{}, err
	}
	return CustomGoal{ID: id, Name: name, Objective: objective, CreatedAt: now, UpdatedAt: now}, nil
}

// GetCustomGoal fetches by id or nil.
func (d *DB) GetCustomGoal(id string) (*CustomGoal, error) {
	if err := ensureGoals(d); err != nil {
		return nil, err
	}
	var g CustomGoal
	err := d.SQL.QueryRow(`SELECT id,name,objective,created_at,updated_at FROM custom_goals WHERE id=?`, id).
		Scan(&g.ID, &g.Name, &g.Objective, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, nil //nolint:nilerr // missing row is not an error
	}
	return &g, nil
}

// UpdateCustomGoal changes name/objective; empty fields keep current values.
func (d *DB) UpdateCustomGoal(id, name, objective string) (*CustomGoal, error) {
	g, err := d.GetCustomGoal(id)
	if err != nil || g == nil {
		return nil, err
	}
	if name == "" {
		name = g.Name
	}
	if objective == "" {
		objective = g.Objective
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := d.SQL.Exec(`UPDATE custom_goals SET name=?, objective=?, updated_at=? WHERE id=?`,
		name, objective, now, id); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, fmt.Errorf("duplicate_goal: %w", err)
		}
		return nil, err
	}
	g.Name, g.Objective, g.UpdatedAt = name, objective, now
	return g, nil
}

// DeleteCustomGoal removes by id, reporting whether a row existed.
func (d *DB) DeleteCustomGoal(id string) (bool, error) {
	if err := ensureGoals(d); err != nil {
		return false, err
	}
	res, err := d.SQL.Exec(`DELETE FROM custom_goals WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
