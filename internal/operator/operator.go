// Package operator is the native operator-connection registry: persisted
// operator-box → victim persistence channels (post-RCE implants). Records
// live in <workspace>/operator_connections.json with per-target shards,
// mirroring tools/operator_connection/manager.py. Creation validates the
// target (format + allowlist when required); health checks degrade honestly
// when no native listener backend is attached.
package operator

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

// Statuses for a connection record.
const (
	StatusActive  = "active"
	StatusStale   = "stale"
	StatusRemoved = "removed"
	StatusError   = "error"
)

var validStatuses = map[string]bool{
	StatusActive: true, StatusStale: true, StatusRemoved: true, StatusError: true,
}

// ValidStatus reports whether s is a known connection status.
func ValidStatus(s string) bool { return validStatuses[strings.ToLower(strings.TrimSpace(s))] }

var connIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidConnectionID mirrors the Python route guard: no path traversal,
// bounded length, safe charset.
func ValidConnectionID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	if strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return false
	}
	return connIDRe.MatchString(id)
}

// Record is one operator-connection row.
type Record struct {
	ConnectionID   string  `json:"connection_id"`
	TargetIP       string  `json:"target_ip"`
	Method         string  `json:"method"`
	CallbackHost   string  `json:"callback_host"`
	CallbackPort   int     `json:"callback_port"`
	ListenerName   string  `json:"listener_name"`
	Status         string  `json:"status"`
	CreatedAt      float64 `json:"created_at"`
	LastBeacon     float64 `json:"last_beacon,omitempty"`
	LastCheck      float64 `json:"last_check,omitempty"`
	CheckOutput    string  `json:"check_output"`
	ImplantPath    string  `json:"implant_path"`
	MitreTechnique string  `json:"mitre_technique"`
	OSFamily       string  `json:"os_family"`
	Notes          string  `json:"notes"`
	CreatedAtISO   string  `json:"created_at_iso,omitempty"`
	LastBeaconISO  string  `json:"last_beacon_iso,omitempty"`
	LastCheckISO   string  `json:"last_check_iso,omitempty"`
}

func iso(ts float64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(int64(ts), int64((ts-float64(int64(ts)))*1e9)).UTC().Format(time.RFC3339Nano)
}

func withISOs(r Record) Record {
	r.CreatedAtISO = iso(r.CreatedAt)
	r.LastBeaconISO = iso(r.LastBeacon)
	r.LastCheckISO = iso(r.LastCheck)
	return r
}

// CreateArgs carries record creation fields.
type CreateArgs struct {
	TargetIP       string
	Method         string
	CallbackHost   string
	CallbackPort   int
	ListenerName   string
	ImplantPath    string
	MitreTechnique string
	OSFamily       string
	Notes          string
}

// Manager is the JSON-file-backed record store.
type Manager struct {
	dir      string
	entries  []string
	required bool
	records  map[string]Record
}

// Open loads (or creates) the registry in dir.
func Open(dir string, allowedTargets []string, requireAllowlist bool) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "connections"), 0o755); err != nil {
		return nil, err
	}
	m := &Manager{dir: dir, entries: allowedTargets, required: requireAllowlist, records: map[string]Record{}}
	raw, err := os.ReadFile(filepath.Join(dir, "operator_connections.json"))
	if err != nil {
		return m, nil
	}
	var payload struct {
		Connections []Record `json:"connections"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return m, nil
	}
	for _, r := range payload.Connections {
		if r.ConnectionID != "" {
			m.records[r.ConnectionID] = r
		}
	}
	return m, nil
}

func (m *Manager) save() {
	payload := map[string]any{
		"saved_at":    time.Now().UTC().Format(time.RFC3339Nano),
		"connections": m.all(),
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	tmp := filepath.Join(m.dir, "operator_connections.json.tmp")
	if os.WriteFile(tmp, append(raw, '\n'), 0o644) == nil {
		_ = os.Rename(tmp, filepath.Join(m.dir, "operator_connections.json"))
	}
	byTarget := map[string][]Record{}
	for _, r := range m.records {
		byTarget[r.TargetIP] = append(byTarget[r.TargetIP], r)
	}
	for target, lst := range byTarget {
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(target)
		raw, _ := json.MarshalIndent(map[string]any{"target_ip": target, "connections": lst}, "", "  ")
		_ = os.WriteFile(filepath.Join(m.dir, "connections", safe+".json"), append(raw, '\n'), 0o644)
	}
}

func (m *Manager) all() []Record {
	out := make([]Record, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	return out
}

func connID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "conn-" + hex.EncodeToString(b[:])
}

// Create validates the target and stores a new active record.
func (m *Manager) Create(a CreateArgs) (Record, error) {
	target := strings.TrimSpace(a.TargetIP)
	if target == "" {
		return Record{}, fmt.Errorf("invalid target_ip")
	}
	if _, _, err := recon.ParseTarget(target); err != nil {
		return Record{}, fmt.Errorf("invalid target_ip: %v", err)
	}
	if !allowlist.Check(target, allowlist.ApprovalEntries(m.entries, nil), m.required) {
		return Record{}, fmt.Errorf("target %q is not in allowlist", target)
	}
	if a.CallbackPort < 1 || a.CallbackPort > 65535 {
		return Record{}, fmt.Errorf("invalid callback_port")
	}
	listener := a.ListenerName
	if listener == "" {
		safe := strings.NewReplacer(".", "-", ":", "-", "/", "-").Replace(target)
		listener = "persist-" + safe + "-" + a.Method
		if len(listener) > 64 {
			listener = listener[:64]
		}
	}
	now := float64(time.Now().UnixNano()) / 1e9
	rec := withISOs(Record{
		ConnectionID: connID(), TargetIP: target, Method: a.Method,
		CallbackHost: a.CallbackHost, CallbackPort: a.CallbackPort,
		ListenerName: listener, Status: StatusActive, CreatedAt: now,
		ImplantPath: a.ImplantPath, MitreTechnique: a.MitreTechnique,
		OSFamily: a.OSFamily, Notes: a.Notes,
	})
	m.records[rec.ConnectionID] = rec
	m.save()
	return rec, nil
}

// Get returns one record or nil.
func (m *Manager) Get(id string) *Record {
	if r, ok := m.records[id]; ok {
		cp := withISOs(r)
		return &cp
	}
	return nil
}

// List returns records filtered by target and/or status (empty = all).
func (m *Manager) List(target, status string) []Record {
	var out []Record
	for _, r := range m.records {
		if target != "" && r.TargetIP != target {
			continue
		}
		if status != "" && r.Status != status {
			continue
		}
		out = append(out, withISOs(r))
	}
	if out == nil {
		out = []Record{}
	}
	return out
}

// Counts mirrors the list-response counters.
func Counts(recs []Record) map[string]int {
	c := map[string]int{"total": len(recs)}
	for _, r := range recs {
		c[r.Status]++
	}
	for _, k := range []string{"active", "stale", "removed", "error"} {
		if _, ok := c[k]; !ok {
			c[k] = 0
		}
	}
	return c
}

// MarkBeacon stamps a beacon and reactivates the record.
func (m *Manager) MarkBeacon(id string) {
	if r, ok := m.records[id]; ok {
		r.LastBeacon = float64(time.Now().UnixNano()) / 1e9
		r.Status = StatusActive
		m.records[id] = r
		m.save()
	}
}

// MarkCheck records a health check; unhealthy flips to stale.
func (m *Manager) MarkCheck(id, output string, healthy bool) {
	if r, ok := m.records[id]; ok {
		r.LastCheck = float64(time.Now().UnixNano()) / 1e9
		if len(output) > 2000 {
			output = output[:2000]
		}
		r.CheckOutput = output
		if healthy {
			r.Status = StatusActive
		} else {
			r.Status = StatusStale
		}
		m.records[id] = r
		m.save()
	}
}

// MarkRemoved preserves the record for audit with removed status.
func (m *Manager) MarkRemoved(id string) bool {
	if r, ok := m.records[id]; ok {
		r.Status = StatusRemoved
		m.records[id] = r
		m.save()
		return true
	}
	return false
}

// Remove deletes the record.
func (m *Manager) Remove(id string) bool {
	if _, ok := m.records[id]; !ok {
		return false
	}
	delete(m.records, id)
	m.save()
	return true
}
