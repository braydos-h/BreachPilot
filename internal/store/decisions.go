package store

import (
	"time"
)

// Decision mirrors the decisions table: start_confirm / goal_select /
// tool_approval kinds with pending -> answered | cancelled lifecycle.
type Decision struct {
	ID           string `json:"id"`
	RunID        string `json:"run_id"`
	Kind         string `json:"kind"`
	PromptText   string `json:"prompt_text"`
	RequiredText string `json:"required_text"`
	Status       string `json:"status"`
	Answer       string `json:"answer"`
	CreatedAt    string `json:"created_at"`
	AnsweredAt   string `json:"answered_at"`
}

// CreateDecision inserts a pending decision.
func (d *DB) CreateDecision(id, runID, kind, promptText, requiredText string) (Decision, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	dec := Decision{ID: id, RunID: runID, Kind: kind, PromptText: promptText,
		RequiredText: requiredText, Status: "pending", CreatedAt: now}
	_, err := d.SQL.Exec(`INSERT INTO decisions(id,run_id,kind,prompt_text,required_text,status,answer,created_at,answered_at) VALUES(?,?,?,?,?,'pending','',?,?)`,
		id, runID, kind, promptText, requiredText, now, "")
	if err != nil {
		return Decision{}, err
	}
	return dec, nil
}

// ListDecisions returns a run's decisions oldest-first.
func (d *DB) ListDecisions(runID string) ([]Decision, error) {
	rows, err := d.SQL.Query(`SELECT id,run_id,kind,prompt_text,required_text,status,answer,created_at,answered_at FROM decisions WHERE run_id=? ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var dec Decision
		if err := rows.Scan(&dec.ID, &dec.RunID, &dec.Kind, &dec.PromptText, &dec.RequiredText, &dec.Status, &dec.Answer, &dec.CreatedAt, &dec.AnsweredAt); err != nil {
			return nil, err
		}
		out = append(out, dec)
	}
	if out == nil {
		out = []Decision{}
	}
	return out, rows.Err()
}

// GetDecision fetches one decision, ensuring it belongs to runID.
func (d *DB) GetDecision(runID, id string) (*Decision, error) {
	var dec Decision
	err := d.SQL.QueryRow(`SELECT id,run_id,kind,prompt_text,required_text,status,answer,created_at,answered_at FROM decisions WHERE id=? AND run_id=?`, id, runID).
		Scan(&dec.ID, &dec.RunID, &dec.Kind, &dec.PromptText, &dec.RequiredText, &dec.Status, &dec.Answer, &dec.CreatedAt, &dec.AnsweredAt)
	if err != nil {
		return nil, nil //nolint:nilerr // missing row is not an error
	}
	return &dec, nil
}

// AnswerDecision marks answered with the given answer.
func (d *DB) AnswerDecision(id, answer string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`UPDATE decisions SET status='answered', answer=?, answered_at=? WHERE id=?`, answer, now, id)
	return err
}

// CancelDecisions marks all pending decisions of a run cancelled.
func (d *DB) CancelDecisions(runID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := d.SQL.Exec(`UPDATE decisions SET status='cancelled', answered_at=? WHERE run_id=? AND status='pending'`, now, runID)
	return err
}
