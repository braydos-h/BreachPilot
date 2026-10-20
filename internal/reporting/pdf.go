package reporting

import (
	"bytes"
	"fmt"
	"strings"
)

func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r > 126 {
			continue
		}
		if r == '\\' || r == '(' || r == ')' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PDF renders a self-contained PDF 1.4 document with zero external dependencies.
// Vetted findings appear in the Technical Findings section; proposed candidates
// are explicitly separated under an unvetted warning section.
func (r Report) PDF() []byte {
	var lines []string
	lines = append(lines, "BreachPilot Assessment Report - "+r.RunID)
	lines = append(lines, fmt.Sprintf("Target: %s | Mode: %s | Goal: %s | Generated: %s", r.Target, r.Mode, r.Goal, r.GeneratedAt))
	lines = append(lines, "")
	lines = append(lines, "Executive Summary:")
	lines = append(lines, r.Summary)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Vetted Technical Findings (%d):", len(r.Technical)))
	if len(r.Technical) == 0 {
		lines = append(lines, "  No vetted findings (only APPROVED/VERIFIED/STILL_OPEN appear here).")
	}
	for _, f := range r.Technical {
		lines = append(lines, fmt.Sprintf("  - [%s] %s (%s): %s", f.ID, f.Title, f.Status, f.Evidence))
	}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Proposed Candidates - UNVETTED (%d):", len(r.Proposed)))
	for _, f := range r.Proposed {
		lines = append(lines, fmt.Sprintf("  - [UNVETTED %s] %s: %s", f.ID, f.Title, f.Evidence))
	}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Attack Timeline (%d events):", len(r.Timeline)))
	for _, e := range r.Timeline {
		lines = append(lines, fmt.Sprintf("  - %s %s", e.Timestamp, e.EventType))
	}

	var stream bytes.Buffer
	stream.WriteString("BT\n/F1 10 Tf\n50 750 Td\n14 TL\n")
	maxLines := 48
	for i, ln := range lines {
		if i >= maxLines {
			break
		}
		if len(ln) > 95 {
			ln = ln[:95] + "..."
		}
		fmt.Fprintf(&stream, "(%s) Tj T*\n", pdfEscape(ln))
	}
	stream.WriteString("ET\n")
	streamBytes := stream.Bytes()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, 6)

	writeObj := func(id int, body string) {
		offsets[id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	writeObj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	writeObj(5, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(streamBytes), string(streamBytes)))

	xrefOffset := buf.Len()
	buf.WriteString("xref\n0 6\n0000000000 65535 f \n")
	for id := 1; id <= 5; id++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[id])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset)
	return buf.Bytes()
}
