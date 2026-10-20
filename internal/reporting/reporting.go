// Package reporting builds the native enhanced run report
// (enhanced_report.json/.md/.html) from on-disk run artifacts: run.json,
// recon_assessment.json, proposed.json, and activity.jsonl.
//
// HITL gate (mirrors tools/reporting/models.apply_hitl_filter): only
// findings whose lifecycle status is APPROVED, VERIFIED, or STILL_OPEN
// reach technical_findings. PROPOSED, REJECTED, and undecided candidates
// stay in proposed_findings, clearly labeled unvetted — never promoted,
// never given vetted titles.
package reporting

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Finding is one evidence-backed result, vetted or proposed.
type Finding struct {
	ID         string  `json:"id"`
	Title      string  `json:"title"`
	Asset      string  `json:"asset"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Status     string  `json:"status"`
	Summary    string  `json:"summary"`
	Evidence   string  `json:"evidence"`
}

// TimelineEntry is one attack-timeline row derived from activity phases.
type TimelineEntry struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	Target      string `json:"target"`
	Module      string `json:"module"`
	Result      string `json:"result"`
}

// Report is the assembled enhanced report.
type Report struct {
	GeneratedAt string          `json:"generated_at"`
	RunID       string          `json:"run_id"`
	Target      string          `json:"target"`
	Mode        string          `json:"mode"`
	Goal        string          `json:"goal"`
	Summary     string          `json:"executive_summary"`
	Services    []any           `json:"services"`
	OpenPorts   []int           `json:"open_ports"`
	OSVerdict   string          `json:"os_verdict"`
	Technical   []Finding       `json:"technical_findings"`
	Proposed    []Finding       `json:"proposed_findings"`
	Timeline    []TimelineEntry `json:"attack_timeline"`
}

// Vetted reports whether a finding lifecycle status passes the HITL gate
// into technical_findings.
func Vetted(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "approved", "verified", "still_open":
		return true
	}
	return false
}

// Build assembles a Report from a finished run directory. Missing optional
// artifacts degrade to empty sections; a missing run.json is an error.
func Build(runDir string) (Report, error) {
	var rep Report
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	runRaw, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err != nil {
		return rep, fmt.Errorf("reporting: %w", err)
	}
	var run struct {
		RunID     string         `json:"run_id"`
		Target    string         `json:"target"`
		Mode      string         `json:"mode"`
		Goal      string         `json:"goal"`
		Outcome   map[string]any `json:"outcome"`
		Completed string         `json:"completed_at"`
	}
	if err := json.Unmarshal(runRaw, &run); err != nil {
		return rep, fmt.Errorf("reporting: bad run.json: %w", err)
	}
	rep.RunID, rep.Target, rep.Mode, rep.Goal = run.RunID, run.Target, run.Mode, run.Goal

	if raw, err := os.ReadFile(filepath.Join(runDir, "recon_assessment.json")); err == nil {
		var assess struct {
			OpenPorts []int  `json:"open_ports"`
			Services  []any  `json:"services"`
			OSVerdict string `json:"os_verdict"`
		}
		if json.Unmarshal(raw, &assess) == nil {
			rep.OpenPorts, rep.Services, rep.OSVerdict = assess.OpenPorts, assess.Services, assess.OSVerdict
		}
	}
	if raw, err := os.ReadFile(filepath.Join(runDir, "proposed.json")); err == nil {
		var items []struct {
			ID       string `json:"id"`
			Service  string `json:"service"`
			Port     int    `json:"port"`
			Summary  string `json:"summary"`
			Evidence string `json:"evidence"`
			Status   string `json:"status"`
		}
		if json.Unmarshal(raw, &items) == nil {
			for _, it := range items {
				f := Finding{
					ID: it.ID, Title: it.Summary, Asset: rep.Target,
					Status: it.Status, Summary: it.Summary, Evidence: it.Evidence,
				}
				if f.Title == "" {
					f.Title = fmt.Sprintf("%s on port %d", it.Service, it.Port)
				}
				if Vetted(it.Status) {
					rep.Technical = append(rep.Technical, f)
				} else {
					rep.Proposed = append(rep.Proposed, f)
				}
			}
		}
	}
	if rep.Technical == nil {
		rep.Technical = []Finding{}
	}
	if rep.Proposed == nil {
		rep.Proposed = []Finding{}
	}
	if raw, err := os.ReadFile(filepath.Join(runDir, "activity.jsonl")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			phase, _ := row["phase"].(string)
			at, _ := row["at"].(string)
			mod, _ := row["module"].(string)
			entry := TimelineEntry{Timestamp: at, EventType: phase, Description: phase, Target: rep.Target, Module: mod}
			if outcome, ok := row["outcome"]; ok {
				rawOut, _ := json.Marshal(outcome)
				entry.Result = string(rawOut)
			}
			rep.Timeline = append(rep.Timeline, entry)
		}
	}
	sort.Slice(rep.Timeline, func(i, j int) bool { return rep.Timeline[i].Timestamp < rep.Timeline[j].Timestamp })
	rep.Summary = summarize(rep)
	return rep, nil
}

func summarize(rep Report) string {
	return fmt.Sprintf("Run %s against %s (%s mode): %d open ports observed, %d vetted findings, %d proposed candidates awaiting human review.",
		rep.RunID, rep.Target, rep.Mode, len(rep.OpenPorts), len(rep.Technical), len(rep.Proposed))
}

// Markdown renders a human-readable report. Proposed findings appear only
// under an explicitly unvetted heading.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# BreachPilot run %s\n\n", r.RunID)
	fmt.Fprintf(&b, "- target: %s\n- mode: %s\n- goal: %s\n- generated: %s\n\n", r.Target, r.Mode, r.Goal, r.GeneratedAt)
	fmt.Fprintf(&b, "## Executive summary\n\n%s\n\n", r.Summary)
	fmt.Fprintf(&b, "## Vetted findings (%d)\n\n", len(r.Technical))
	if len(r.Technical) == 0 {
		b.WriteString("No vetted findings. Only human-approved, verified, or still-open findings appear here.\n\n")
	}
	for _, f := range r.Technical {
		fmt.Fprintf(&b, "### %s\n\n- id: %s\n- status: %s\n- evidence: %s\n\n%s\n\n", f.Title, f.ID, f.Status, f.Evidence, f.Summary)
	}
	fmt.Fprintf(&b, "## Proposed findings, unvetted (%d)\n\n", len(r.Proposed))
	fmt.Fprintf(&b, "Candidates below are NOT vetted: they have not passed human review and must not be treated as confirmed.\n\n")
	for _, f := range r.Proposed {
		fmt.Fprintf(&b, "### %s\n\n- id: %s\n- status: %s\n- evidence: %s\n\n%s\n\n", f.Title, f.ID, f.Status, f.Evidence, f.Summary)
	}
	fmt.Fprintf(&b, "## Timeline (%d events)\n\n", len(r.Timeline))
	for _, e := range r.Timeline {
		fmt.Fprintf(&b, "- %s %s %s\n", e.Timestamp, e.EventType, e.Result)
	}
	return b.String()
}

// HTML renders a minimal valid document with escaped content.
func (r Report) HTML() string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	fmt.Fprintf(&b, "<title>BreachPilot run %s</title>\n</head>\n<body>\n", html.EscapeString(r.RunID))
	fmt.Fprintf(&b, "<h1>BreachPilot run %s</h1>\n", html.EscapeString(r.RunID))
	fmt.Fprintf(&b, "<p>%s</p>\n", html.EscapeString(r.Summary))
	b.WriteString("<h2>Vetted findings</h2>\n<ul>\n")
	for _, f := range r.Technical {
		fmt.Fprintf(&b, "<li><strong>%s</strong> (%s): %s</li>\n", html.EscapeString(f.Title), html.EscapeString(f.Status), html.EscapeString(f.Evidence))
	}
	b.WriteString("</ul>\n<h2>Proposed findings (unvetted)</h2>\n<ul>\n")
	for _, f := range r.Proposed {
		fmt.Fprintf(&b, "<li><strong>%s</strong> (%s): %s</li>\n", html.EscapeString(f.Title), html.EscapeString(f.Status), html.EscapeString(f.Evidence))
	}
	b.WriteString("</ul>\n</body>\n</html>\n")
	return b.String()
}

// Write stores enhanced_report.json/.md/.html in runDir. Filenames join the
// API artifact whitelist so the WebUI Artifacts page serves them.
func Write(runDir string, r Report) ([]string, error) {
	payloads := map[string]string{}
	raw, err := json.MarshalIndent(map[string]any{
		"report_metadata":    map[string]any{"generated_at": r.GeneratedAt, "run_id": r.RunID},
		"executive_summary":  r.Summary,
		"target":             r.Target,
		"mode":               r.Mode,
		"open_ports":         r.OpenPorts,
		"os_verdict":         r.OSVerdict,
		"technical_findings": r.Technical,
		"proposed_findings":  r.Proposed,
		"attack_timeline":    r.Timeline,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	payloads["enhanced_report.json"] = string(append(raw, '\n'))
	payloads["enhanced_report.md"] = r.Markdown()
	payloads["enhanced_report.html"] = r.HTML()
	payloads["enhanced_report.pdf"] = string(r.PDF())
	var paths []string
	for name, body := range payloads {
		if err := os.WriteFile(filepath.Join(runDir, name), []byte(body), 0o644); err != nil {
			return paths, err
		}
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths, nil
}

// Regenerate rebuilds the report files for an existing finished run directory.
func Regenerate(runDir string) ([]string, error) {
	rep, err := Build(runDir)
	if err != nil {
		return nil, err
	}
	return Write(runDir, rep)
}
