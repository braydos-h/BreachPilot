package reporting_test

// Slice 4 RED: HITL-gated native reporting must exist — vetted findings in
// technical_findings, proposed ones labeled unvetted and never promoted,
// timeline from activity, markdown + html renderers, disk round-trip.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/reporting"
)

func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("run.json", `{"run_id":"run-r1","target":"127.0.0.1","mode":"attack","goal":"","outcome":{"target":"127.0.0.1","mode":"attack","recon_complete":true},"completed_at":"2026-10-20T00:00:00Z"}`)
	write("recon_assessment.json", `{"target_ip":"127.0.0.1","open_ports":[80],"services":[{"port":80,"service":"http"}],"os_verdict":"Linux"}`)
	write("proposed.json", `[{"id":"finding-web-80","service":"http","port":80,"summary":"Web server exposes version banner","evidence":"status=200 server=nginx","status":"proposed"},{"id":"finding-vet-1","service":"http","port":80,"summary":"Confirmed info disclosure","evidence":"body contains version","status":"verified"}]`)
	write("activity.jsonl", "{\"phase\":\"recon_start\",\"at\":\"2026-10-20T00:00:01Z\"}\n{\"phase\":\"completed\",\"at\":\"2026-10-20T00:00:02Z\"}\n")
	return dir
}

func TestVettedGate(t *testing.T) {
	for _, s := range []string{"approved", "APPROVED", "verified", "still_open"} {
		if !reporting.Vetted(s) {
			t.Fatalf("Vetted(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"proposed", "rejected", "", "pending"} {
		if reporting.Vetted(s) {
			t.Fatalf("Vetted(%q) = true, want false", s)
		}
	}
}

func TestBuildFiltersUnvetted(t *testing.T) {
	rep, err := reporting.Build(fixtureDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Technical) != 1 || rep.Technical[0].ID != "finding-vet-1" {
		raw, _ := json.Marshal(rep.Technical)
		t.Fatalf("technical must hold only the verified finding, got %s", raw)
	}
	if len(rep.Proposed) != 1 || rep.Proposed[0].ID != "finding-web-80" {
		raw, _ := json.Marshal(rep.Proposed)
		t.Fatalf("proposed must hold the unvetted finding, got %s", raw)
	}
	if len(rep.Timeline) != 2 {
		t.Fatalf("timeline should have 2 entries, got %d", len(rep.Timeline))
	}
	md := rep.Markdown()
	if !strings.Contains(md, "Confirmed info disclosure") {
		t.Fatalf("markdown must include vetted finding:\n%s", md)
	}
	if !strings.Contains(md, "unvetted") {
		t.Fatalf("markdown must label proposed findings unvetted:\n%s", md)
	}
	html := rep.HTML()
	if !strings.Contains(html, "<html") || !strings.Contains(html, "Confirmed info disclosure") {
		t.Fatalf("html must be a valid doc with the vetted finding:\n%s", html)
	}
}

func TestWriteRoundTrip(t *testing.T) {
	dir := fixtureDir(t)
	rep, err := reporting.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := reporting.Write(dir, rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("Write should return 3 paths, got %v", paths)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "enhanced_report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v["technical_findings"]; !ok {
		t.Fatalf("json report needs technical_findings key: %s", raw)
	}
	if _, ok := v["proposed_findings"]; !ok {
		t.Fatalf("json report needs proposed_findings key: %s", raw)
	}
}
