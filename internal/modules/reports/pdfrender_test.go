package reports

import (
	"strings"
	"testing"
)

func TestMarkdownToPDFCarriesTheReport(t *testing.T) {
	md := "# Daily Digest\n\nGenerated now\n\n## Contents\n\n- [Traffic](#Traffic)\n\n## Traffic by device\n\n*Who moved what*\n\n| Device | Bytes |\n|---|---|\n| mac | 1.2 GB |\n| tv | 300 MB |\n\nA closing paragraph with **bold** words.\n"
	pdf := string(markdownToPDF("Daily Digest", md))
	for _, want := range []string{"Traffic by device", "Who moved what", "Device", "1.2 GB", "closing paragraph with bold words"} {
		if !strings.Contains(pdf, want) {
			t.Fatalf("pdf lacks %q", want)
		}
	}
	if strings.Count(pdf, "Daily Digest") != 1 {
		t.Fatalf("title should appear once, got %d", strings.Count(pdf, "Daily Digest"))
	}
	if len(pdf) < 1000 {
		t.Fatalf("pdf suspiciously small: %d bytes", len(pdf))
	}
}
