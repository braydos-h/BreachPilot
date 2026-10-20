// Package audit implements hash-chained per-run audit rows
// (reports/<run_id>/exploit_audit.jsonl). Each row links prev_hash -> hash
// (SHA-256 over run_id|sequence|tool|status|command|prev), so tampering
// breaks verification. Mirrors tools/exploit_agent/policy.py record chain
// and the bp-evidence Rust crate (same algorithm).
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Record is one audit row.
type Record struct {
	Sequence  int    `json:"sequence"`
	Timestamp string `json:"timestamp"`
	RunID     string `json:"run_id"`
	Tool      string `json:"tool"`
	Target    string `json:"target"`
	Status    string `json:"status"`
	Command   string `json:"command"`
	AttemptID string `json:"attempt_id"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

func hashOf(runID string, seq int, tool, status, command, prev string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%s|%s|%s", runID, seq, tool, status, command, prev)
	return hex.EncodeToString(h.Sum(nil))
}

func pathOf(runDir string) string { return filepath.Join(runDir, "exploit_audit.jsonl") }

// Append adds a chained row. dir is reports/<run_id>.
func Append(runDir, runID, tool, target, status, command, attemptID string) (Record, error) {
	prev, seq := tail(runDir)
	rec := Record{
		Sequence: seq + 1, Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RunID: runID, Tool: tool, Target: target, Status: status,
		Command: command, AttemptID: attemptID, PrevHash: prev,
	}
	rec.Hash = hashOf(runID, rec.Sequence, tool, status, command, prev)
	f, err := os.OpenFile(filepath.Clean(pathOf(runDir)), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	raw, _ := json.Marshal(rec)
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// List returns all rows (nil when the file is absent).
func List(runDir string) ([]Record, error) {
	f, err := os.Open(filepath.Clean(pathOf(runDir)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Verify replays the chain. Returns (valid, reason, badIndex).
func Verify(runDir string) (bool, string, int) {
	rows, err := List(runDir)
	if err != nil {
		return false, "unreadable", -1
	}
	prev := "GENESIS"
	for i, r := range rows {
		if r.PrevHash != prev {
			return false, "broken link", i
		}
		if r.Hash != hashOf(r.RunID, r.Sequence, r.Tool, r.Status, r.Command, r.PrevHash) {
			return false, "hash mismatch", i
		}
		prev = r.Hash
	}
	return true, "go-native-chain", -1
}

func tail(runDir string) (string, int) {
	rows, err := List(runDir)
	if err != nil || len(rows) == 0 {
		return "GENESIS", 0
	}
	last := rows[len(rows)-1]
	return last.Hash, last.Sequence
}
