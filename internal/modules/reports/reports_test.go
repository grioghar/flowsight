package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func TestReportHTMLGeneration(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create mock module with minimal context
	m := &Module{ctx: &core.Context{Store: store}}

	// Add test data to database
	now := time.Now().Unix()

	// Add hosts
	_ = store.Exec(`INSERT INTO hosts(ip, first_seen, last_seen, is_local, bytes_in, bytes_out)
		VALUES(?, ?, ?, 1, 1000000, 2000000)`, "10.0.0.1", now-3600, now)

	// Add flows
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, dst_ip, app, domain, bytes_in, bytes_out, verdict)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, now-1800, "10.0.0.1", "8.8.8.8", "HTTP", "example.com", 10000, 20000, "observed")
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, dst_ip, app, domain, bytes_in, bytes_out, verdict)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, now-1800, "10.0.0.2", "8.8.8.8", "HTTPS", "google.com", 5000, 15000, "blocked")

	// Add DNS records
	_ = store.Exec(`INSERT INTO dns(ts, client, domain, qtype, action, list)
		VALUES(?, ?, ?, ?, ?, ?)`, now-900, "10.0.0.1", "example.com", "A", "pass", "")
	_ = store.Exec(`INSERT INTO dns(ts, client, domain, qtype, action, list)
		VALUES(?, ?, ?, ?, ?, ?)`, now-600, "10.0.0.2", "blocked.com", "A", "block", "policy1")

	// Add alerts
	_ = store.Exec(`INSERT INTO alerts(ts, source, severity, signature, src_ip, dst_ip)
		VALUES(?, ?, ?, ?, ?, ?)`, now-1200, "suricata", "high", "Test Alert", "10.0.0.1", "8.8.8.8")

	// Add findings
	_ = store.Exec(`INSERT INTO findings(ts, module, kind, severity, subject, title)
		VALUES(?, ?, ?, ?, ?, ?)`, now-600, "tls", "cert", "high", "bad-cert", "Expired Certificate")

	// Generate report
	html := m.buildReport(24)

	// Verify report content
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("report should be valid HTML")
	}
	if !strings.Contains(html, "<h1>Flowsight Report</h1>") {
		t.Errorf("report should have title")
	}
	if !strings.Contains(html, "Executive Summary") {
		t.Errorf("report should have executive summary section")
	}
	if !strings.Contains(html, "<style>") {
		t.Errorf("report should have CSS styles")
	}

	// Check for data in report
	if !strings.Contains(html, "example.com") {
		t.Errorf("report should contain domain data")
	}

	// Verify no XSS vectors
	if strings.Contains(html, "<script") {
		t.Errorf("report should not contain script tags")
	}
}

func TestScheduleCreation(t *testing.T) {
	sched := Schedule{
		Name:       "daily-report",
		Enabled:    true,
		Cadence:    "daily",
		Hour:       9,
		Recipients: []string{"admin@example.com", "ops@example.com"},
		Window:     24,
	}

	if sched.Name != "daily-report" {
		t.Errorf("schedule name mismatch")
	}
	if sched.Cadence != "daily" {
		t.Errorf("schedule cadence mismatch")
	}
	if len(sched.Recipients) != 2 {
		t.Errorf("schedule should have 2 recipients")
	}
	if sched.Hour < 0 || sched.Hour > 23 {
		t.Errorf("schedule hour should be 0-23")
	}
}

func TestCSVExport(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	m := &Module{ctx: &core.Context{Store: store}}

	now := time.Now().Unix()

	// Add test flow data
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, src_port, dst_ip, dst_port, proto, app, verdict)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, now-1800, "10.0.0.1", 12345, "8.8.8.8", 443, "tcp", "HTTPS", "observed")

	// Generate CSV
	csv, err := m.exportCSV("flows", 24)
	if err != nil {
		t.Fatalf("exportCSV failed: %v", err)
	}

	// Verify CSV structure
	csvStr := string(csv)
	if !strings.Contains(csvStr, "time,src_ip,src_port") {
		t.Errorf("CSV should have header row")
	}
	if !strings.Contains(csvStr, "10.0.0.1") {
		t.Errorf("CSV should contain test data")
	}
	if !strings.Contains(csvStr, "8.8.8.8") {
		t.Errorf("CSV should contain destination IP")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		contains string
	}{
		{512, "B"},
		{1024, "KB"},
		{1024 * 1024, "MB"},
		{1024 * 1024 * 1024, "GB"},
	}

	for _, test := range tests {
		result := formatBytes(test.bytes)
		if !strings.Contains(result, test.contains) {
			t.Errorf("formatBytes(%d) should contain %s, got %s", test.bytes, test.contains, result)
		}
	}
}

func TestSeverityClass(t *testing.T) {
	tests := []struct {
		sev      string
		expected string
	}{
		{"critical", "bad"},
		{"high", "bad"},
		{"medium", "warn"},
		{"low", "ok"},
		{"info", "ok"},
	}

	for _, test := range tests {
		result := sevClass(test.sev)
		if result != test.expected {
			t.Errorf("sevClass(%q) = %q, want %q", test.sev, result, test.expected)
		}
	}
}

func TestHTMLEscaping(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"example & test", "example &amp; test"},
		{"quote\"test", "quote&quot;test"},
	}

	for _, test := range tests {
		result := escapeHTML(test.input)
		if result != test.expected {
			t.Errorf("escapeHTML(%q) = %q, want %q", test.input, result, test.expected)
		}
	}
}

func TestScheduleStorage(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create schedules
	schedules := []Schedule{
		{
			Name:       "daily",
			Enabled:    true,
			Cadence:    "daily",
			Hour:       9,
			Recipients: []string{"admin@example.com"},
			Window:     24,
		},
		{
			Name:       "weekly",
			Enabled:    true,
			Cadence:    "weekly",
			Hour:       0,
			Recipients: []string{"team@example.com"},
			Window:     168,
		},
	}

	// Store in KV
	if err := store.KVSet("reports.schedules", schedules); err != nil {
		t.Fatalf("KVSet failed: %v", err)
	}

	// Retrieve from KV
	var retrieved []Schedule
	found := store.KVGet("reports.schedules", &retrieved)
	if !found {
		t.Errorf("failed to retrieve schedules from KV")
	}

	if len(retrieved) != 2 {
		t.Errorf("expected 2 schedules, got %d", len(retrieved))
	}

	if retrieved[0].Name != "daily" {
		t.Errorf("first schedule name mismatch")
	}

	if retrieved[1].Cadence != "weekly" {
		t.Errorf("second schedule cadence mismatch")
	}
}

func TestReportWithNoData(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	m := &Module{ctx: &core.Context{Store: store}}

	// Generate report with empty database
	html := m.buildReport(24)

	// Should still produce valid HTML
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("report should be valid HTML even with no data")
	}
	if !strings.Contains(html, "<h1>Flowsight Report</h1>") {
		t.Errorf("report should have title")
	}
}
