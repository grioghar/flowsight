package reports

import (
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func TestEngineExecute(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{
		Store: store,
		Name:  "reports",

		Platform: &core.Platform{DataDir: t.TempDir()},
	}

	engine := NewEngine(ctx)

	now := time.Now().Unix()

	// Add test data
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, src_device_mac, src_zone, app, domain, bytes_in, bytes_out, verdict)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		now-1800, "10.0.0.1", "aa:bb:cc:dd:ee:01", "home", "HTTP", "example.com", 10000, 20000, "allowed")

	def := &Definition{
		ID:       "test",
		Name:     "Test Report",
		Sections: []string{"executive_summary", "traffic_by_device"},
		Filters:  &Filters{},
		Formats:  []string{"html", "json"},
	}

	window := &TimeWindow{
		From: now - 3600,
		To:   now,
	}

	run, err := engine.Execute(def, window)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if run.Status != "done" {
		t.Errorf("run status should be 'done', got %q (error: %s)", run.Status, run.Error)
	}

	if len(run.SectionData) == 0 {
		t.Errorf("run should have section data")
	}
}

func TestRenderHTML(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{
		Store: store,
		Name:  "reports",

		Platform: &core.Platform{DataDir: t.TempDir()},
	}

	engine := NewEngine(ctx)

	now := time.Now().Unix()

	def := &Definition{
		ID:       "test",
		Name:     "Test Report",
		Sections: []string{"executive_summary"},
		Filters:  &Filters{},
	}

	window := &TimeWindow{
		From: now - 3600,
		To:   now,
	}

	run, err := engine.Execute(def, window)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	html, err := engine.RenderHTML(def, run)
	if err != nil {
		t.Fatalf("RenderHTML failed: %v", err)
	}

	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Errorf("report should be valid HTML")
	}
	if !strings.Contains(html, "Test Report") {
		t.Errorf("report should contain report name")
	}
}

func TestRenderJSON(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{
		Store: store,
		Name:  "reports",

		Platform: &core.Platform{DataDir: t.TempDir()},
	}

	engine := NewEngine(ctx)

	now := time.Now().Unix()

	def := &Definition{
		ID:       "test",
		Name:     "Test",
		Sections: []string{"executive_summary"},
		Filters:  &Filters{},
	}

	window := &TimeWindow{
		From: now - 3600,
		To:   now,
	}

	run, _ := engine.Execute(def, window)
	data, err := engine.RenderJSON(def, run)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	if !strings.Contains(string(data), "definition") {
		t.Errorf("JSON should contain definition key")
	}
	if !strings.Contains(string(data), "run") {
		t.Errorf("JSON should contain run key")
	}
}

func TestFiltersApply(t *testing.T) {
	f := &Filters{
		IPs:  []string{"10.0.0.1"},
		Apps: []string{"HTTP"},
		TopN: 10,
	}

	if len(f.ipArgs()) != 1 {
		t.Errorf("ipArgs should have 1 argument")
	}
	if len(f.appArgs()) != 1 {
		t.Errorf("appArgs should have 1 argument")
	}

	where := f.whereClause()
	if !strings.Contains(where, "src_ip IN") {
		t.Errorf("whereClause should contain IP filter")
	}
}

func TestListBuiltIns(t *testing.T) {
	defs := ListBuiltIns()
	if len(defs) == 0 {
		t.Errorf("should have built-in definitions")
	}

	// Check for expected definitions
	hasDaily := false
	for _, def := range defs {
		if def.ID == "daily_digest" {
			hasDaily = true
			if def.ReadOnly != true {
				t.Errorf("daily_digest should be read-only")
			}
		}
	}

	if !hasDaily {
		t.Errorf("should have daily_digest definition")
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

func TestTimeWindowCalculations(t *testing.T) {
	now := time.Now().Unix()
	tw := &TimeWindow{
		From: now - 3600,
		To:   now,
	}

	hours := tw.Hours()
	if hours < 0.99 || hours > 1.01 {
		t.Errorf("TimeWindow.Hours() should be ~1, got %f", hours)
	}

	str := tw.String()
	if !strings.Contains(str, "to") {
		t.Errorf("TimeWindow.String() should contain 'to'")
	}
}
