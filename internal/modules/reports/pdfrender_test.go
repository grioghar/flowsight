package reports

import (
	"fmt"
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

func TestPDFManyPagesIsWellFormed(t *testing.T) {
	var b strings.Builder
	b.WriteString("# Big\n\n")
	for i := 0; i < 400; i++ {
		b.WriteString("| Row | Value |\n|---|---|\n| a very long cell that goes on and on to force wrapping of the line so it does not run off the right edge of the page at all | 1 |\n\n")
	}
	pdf := string(markdownToPDF("Big", b.String()))
	pages := strings.Count(pdf, "/Type /Page ")
	if pages < 5 {
		t.Fatalf("expected many pages, got %d", pages)
	}
	if strings.Count(pdf, "endstream") != pages || !strings.Contains(pdf, "startxref") {
		t.Fatalf("streams %d for %d pages", strings.Count(pdf, "endstream"), pages)
	}
	// Every object the xref announces has an entry.
	var size int
	if _, err := fmt.Sscanf(pdf[strings.LastIndex(pdf, "/Size "):], "/Size %d", &size); err != nil || size != 3+2*pages {
		t.Fatalf("xref size %d for %d pages (%v)", size, pages, err)
	}
	if strings.Count(pdf, " 00000 n \n") != size-1 {
		t.Fatalf("xref entries %d, want %d", strings.Count(pdf, " 00000 n \n"), size-1)
	}
}

func TestRenderPDFDrawsChartsForTrafficSections(t *testing.T) {
	charts := sectionCharts("traffic_by_device", TrafficByDevice{Rows: []TrafficByDeviceRow{
		{DeviceName: "MacBookPro", BytesIn: 5000, BytesOut: 1000}, {DeviceName: "roku", BytesIn: 100, BytesOut: 50}}})
	if len(charts) != 1 || len(charts[0].Items) != 2 || charts[0].Items[0].Label != "MacBookPro" {
		t.Fatalf("device chart: %+v", charts)
	}
	pdf := NewSimplePDF()
	pdf.AddHeading("Test")
	pdf.AddBarChart(charts[0])
	out := string(pdf.Bytes())
	if !strings.Contains(out, " re\n") || !strings.Contains(out, "MacBookPro") {
		t.Fatalf("bar chart operators or labels missing")
	}
	if len(sectionCharts("dns_summary", DNSSummary{TotalQueries: 100, TotalBlocked: 20})) != 1 {
		t.Fatal("dns chart")
	}
	if sectionCharts("alerts", nil) != nil {
		t.Fatal("no chart for sections without one")
	}
}
