// Package memory implements persistent episodic, working, target, hypothesis,
// dead_end, finding_note, and semantic memory backed by SQLite, plus
// cross-mission similarity retrieval and lessons learned.
// Mirrors legacy/memory.py and tools/semantic_memory.py without Python.
package memory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/braydos-h/BreachPilot/internal/store"
)

var validMemoryTypes = map[string]bool{
	"working":      true,
	"episodic":     true,
	"semantic":     true,
	"target":       true,
	"hypothesis":   true,
	"dead_end":     true,
	"finding_note": true,
}

var memoryTypeAliases = map[string]string{
	"recon":                  "target",
	"service_recon":          "target",
	"service_enumeration":    "target",
	"vuln":                   "hypothesis",
	"vuln_research":          "hypothesis",
	"vulnerability_research": "hypothesis",
	"exploit":                "episodic",
	"exploitation":           "episodic",
	"exploit_success":        "episodic",
	"post_exploit":           "episodic",
	"post_exploitation":      "episodic",
	"reflection":             "semantic",
	"learning":               "semantic",
	"critic":                 "working",
	"exploit_failure":        "dead_end",
	"failure":                "dead_end",
}

var memSeq atomic.Uint64

func newID(prefix string) string {
	n := memSeq.Add(1)
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

// NormalizeMemoryType resolves aliases and defaults unknown types to "target".
func NormalizeMemoryType(raw string) string {
	k := strings.ToLower(strings.TrimSpace(raw))
	if k == "" {
		return "target"
	}
	if validMemoryTypes[k] {
		return k
	}
	if aliased, ok := memoryTypeAliases[k]; ok {
		return aliased
	}
	return "target"
}

// Record represents one persisted memory row.
type Record struct {
	ID         string         `json:"id"`
	MissionID  string         `json:"mission_id"`
	MemoryType string         `json:"memory_type"`
	Target     string         `json:"target"`
	Fact       string         `json:"fact"`
	Tags       []string       `json:"tags"`
	Confidence float64        `json:"confidence"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  string         `json:"created_at"`
}

// Lesson represents a reusable cross-mission semantic lesson.
type Lesson struct {
	ID        string   `json:"id"`
	MissionID string   `json:"mission_id"`
	Target    string   `json:"target"`
	Phase     string   `json:"phase"`
	Summary   string   `json:"summary"`
	Tags      []string `json:"tags"`
	CreatedAt string   `json:"created_at"`
}

// Manager provides CRUD and similarity retrieval over SQLite memories.
type Manager struct {
	DB        *store.DB
	MissionID string
}

// New constructs a memory Manager for a mission (or global when missionID is empty).
func New(db *store.DB, missionID string) *Manager {
	if missionID == "" {
		missionID = "default"
	}
	return &Manager{DB: db, MissionID: missionID}
}

// Remember persists a memory record, preserving original_memory_type when aliased.
func (m *Manager) Remember(target, fact, memoryType string, tags []string, confidence float64, metadata map[string]any) (Record, error) {
	orig := strings.TrimSpace(memoryType)
	if orig == "" {
		orig = "target"
	}
	norm := NormalizeMemoryType(orig)
	meta := map[string]any{}
	for k, v := range metadata {
		meta[k] = v
	}
	normTags := make([]string, 0, len(tags)+1)
	seenTag := map[string]bool{}
	for _, t := range tags {
		if t != "" && !seenTag[t] {
			normTags = append(normTags, t)
			seenTag[t] = true
		}
	}
	if norm != orig {
		if _, exists := meta["original_memory_type"]; !exists {
			meta["original_memory_type"] = orig
		}
		if !seenTag[orig] {
			normTags = append(normTags, orig)
		}
	}
	if confidence <= 0 {
		confidence = 1.0
	}
	id := newID("MEM")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tagsRaw, _ := json.Marshal(normTags)
	metaRaw, _ := json.Marshal(meta)

	_, err := m.DB.SQL.Exec(
		`INSERT INTO memories(id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		id, m.MissionID, norm, target, fact, string(tagsRaw), confidence, string(metaRaw), now,
	)
	if err != nil {
		return Record{}, err
	}
	return Record{
		ID:         id,
		MissionID:  m.MissionID,
		MemoryType: norm,
		Target:     target,
		Fact:       fact,
		Tags:       normTags,
		Confidence: confidence,
		Metadata:   meta,
		CreatedAt:  now,
	}, nil
}

// MarkDeadEnd records a dead_end memory for a target.
func (m *Manager) MarkDeadEnd(target, reason string, metadata map[string]any) (Record, error) {
	return m.Remember(target, reason, "dead_end", []string{"dead_end"}, 1.0, metadata)
}

// Retrieve queries memories for the current mission with optional target, type, and tag filters.
func (m *Manager) Retrieve(target, memoryType string, tags []string, limit int) ([]Record, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	q := `SELECT id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at FROM memories WHERE mission_id=?`
	args := []any{m.MissionID}
	if target != "" {
		q += ` AND target=?`
		args = append(args, target)
	}
	if memoryType != "" {
		q += ` AND memory_type=?`
		args = append(args, NormalizeMemoryType(memoryType))
	}
	for _, tag := range tags {
		esc := strings.ReplaceAll(tag, `\`, `\\`)
		esc = strings.ReplaceAll(esc, `%`, `\%`)
		esc = strings.ReplaceAll(esc, `_`, `\_`)
		q += ` AND tags_json LIKE ? ESCAPE '\'`
		args = append(args, `%"`+esc+`"%`)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := m.DB.SQL.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// RetrieveRelevant returns exact target matches for the current mission, falling
// back to cross-mission lexical/token similarity over contextText when exact
// matches are fewer than limit/2.
func (m *Manager) RetrieveRelevant(target, contextText string, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = 10
	}
	exact, err := m.Retrieve(target, "", nil, limit)
	if err != nil {
		return nil, err
	}
	if len(exact) >= limit/2 && limit > 1 {
		return exact, nil
	}
	queryText := strings.TrimSpace(contextText)
	if queryText == "" {
		queryText = target
	}
	queryTokens := tokenize(queryText)
	if len(queryTokens) == 0 {
		return exact, nil
	}

	rows, err := m.DB.SQL.Query(
		`SELECT id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at FROM memories ORDER BY created_at DESC LIMIT 200`,
	)
	if err != nil {
		return exact, nil
	}
	defer rows.Close()
	candidates, err := scanRecords(rows)
	if err != nil {
		return exact, nil
	}

	seen := map[string]bool{}
	for _, r := range exact {
		seen[r.ID] = true
	}
	type scored struct {
		rec   Record
		score float64
	}
	var matches []scored
	for _, c := range candidates {
		if seen[c.ID] {
			continue
		}
		sc := jaccardSimilarity(queryTokens, tokenize(c.Fact+" "+strings.Join(c.Tags, " ")))
		if sc > 0 {
			matches = append(matches, scored{rec: c, score: sc})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].score > matches[j].score })

	merged := append([]Record{}, exact...)
	for _, sm := range matches {
		if len(merged) >= limit {
			break
		}
		merged = append(merged, sm.rec)
	}
	return merged, nil
}

// StoreLesson persists a reusable cross-mission lesson in the lessons table.
func (m *Manager) StoreLesson(target, phase, summary string, tags []string) (Lesson, error) {
	id := newID("LES")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if tags == nil {
		tags = []string{}
	}
	tagsRaw, _ := json.Marshal(tags)
	_, err := m.DB.SQL.Exec(
		`INSERT INTO lessons(id, mission_id, target, phase, summary, tags_json, created_at) VALUES(?,?,?,?,?,?,?)`,
		id, m.MissionID, target, phase, summary, string(tagsRaw), now,
	)
	if err != nil {
		return Lesson{}, err
	}
	return Lesson{
		ID:        id,
		MissionID: m.MissionID,
		Target:    target,
		Phase:     phase,
		Summary:   summary,
		Tags:      tags,
		CreatedAt: now,
	}, nil
}

// ListLessons returns recent semantic lessons across missions.
func (m *Manager) ListLessons(limit int) ([]Lesson, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := m.DB.SQL.Query(
		`SELECT id, mission_id, target, phase, summary, tags_json, created_at FROM lessons ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Lesson
	for rows.Next() {
		var l Lesson
		var tagsStr string
		if err := rows.Scan(&l.ID, &l.MissionID, &l.Target, &l.Phase, &l.Summary, &tagsStr, &l.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsStr), &l.Tags)
		if l.Tags == nil {
			l.Tags = []string{}
		}
		out = append(out, l)
	}
	if out == nil {
		out = []Lesson{}
	}
	return out, rows.Err()
}

// ListAllEpisodes returns recent episodic/working/target memories across all missions for the API view.
func (m *Manager) ListAllEpisodes(limit int) ([]Record, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := m.DB.SQL.Query(
		`SELECT id, mission_id, memory_type, target, fact, tags_json, confidence, metadata_json, created_at FROM memories ORDER BY created_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

type rowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func scanRecords(rows rowScanner) ([]Record, error) {
	var out []Record
	for rows.Next() {
		var r Record
		var tagsStr, metaStr string
		if err := rows.Scan(&r.ID, &r.MissionID, &r.MemoryType, &r.Target, &r.Fact, &tagsStr, &r.Confidence, &metaStr, &r.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tagsStr), &r.Tags)
		if r.Tags == nil {
			r.Tags = []string{}
		}
		_ = json.Unmarshal([]byte(metaStr), &r.Metadata)
		if r.Metadata == nil {
			r.Metadata = map[string]any{}
		}
		out = append(out, r)
	}
	if out == nil {
		out = []Record{}
	}
	return out, rows.Err()
}

func tokenize(s string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if len(f) >= 2 {
			out[f] = true
		}
	}
	return out
}

func jaccardSimilarity(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	union := len(a)
	for k := range b {
		if a[k] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}
