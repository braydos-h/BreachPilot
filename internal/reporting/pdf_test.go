package reporting_test

// Slice 19 RED: native pure-Go PDF report generation (no Python, no external
// binary) with HITL gating and valid PDF 1.4 structure.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/reporting"
)

func TestPDFGenerationAndWrite(t *testing.T) {
	dir := fixtureDir(t)
	rep, err := reporting.Build(dir)
	if err != nil {
		t.Fatal(err)
	}
	pdf := rep.PDF()
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4\n")) {
		t.Fatalf("PDF missing header: %q", string(pdf[:min(32, len(pdf))]))
	}
	text := string(pdf)
	if !strings.Contains(text, "xref") || !strings.Contains(text, "%%EOF") {
		t.Fatalf("PDF missing xref/EOF structure")
	}
	if !strings.Contains(text, "Confirmed info disclosure") {
		t.Fatalf("PDF missing vetted finding title")
	}
	paths, err := reporting.Write(dir, rep)
	if err != nil {
		t.Fatal(err)
	}
	foundPDF := false
	for _, p := range paths {
		if p == "enhanced_report.pdf" {
			foundPDF = true
		}
	}
	if !foundPDF {
		t.Fatalf("Write did not emit enhanced_report.pdf: %v", paths)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "enhanced_report.pdf"))
	if err != nil || len(raw) < 200 {
		t.Fatalf("enhanced_report.pdf missing or too small: len=%d err=%v", len(raw), err)
	}
}
