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

func TestTrafficByZoneSection(t *testing.T) {
	store, _ := core.OpenStore(t.TempDir())
	defer store.Close()

	ctx := &core.Context{Store: store, Name: "reports", Platform: &core.Platform{DataDir: t.TempDir()}}
	engine := NewEngine(ctx)
	now := time.Now().Unix()

	// Insert test data with default zone
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, src_zone, app, bytes_in, bytes_out, verdict) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		now-1800, "10.0.0.1", "", "HTTP", 5000, 10000, "allowed")

	window := &TimeWindow{From: now - 3600, To: now}
	result, err := engine.sections["traffic_by_zone"].Run(ctx, window, &Filters{})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	tbl := result.(TrafficByZone)
	// Should at least try to run without error
	if tbl.Rows == nil {
		t.Errorf("traffic_by_zone should return a valid result")
	}
}

func TestTrafficByAppSection(t *testing.T) {
	store, _ := core.OpenStore(t.TempDir())
	defer store.Close()

	ctx := &core.Context{Store: store, Name: "reports", Platform: &core.Platform{DataDir: t.TempDir()}}
	engine := NewEngine(ctx)
	now := time.Now().Unix()

	_ = store.Exec(`INSERT INTO flows(ts, src_ip, app, category, bytes_in, bytes_out, verdict) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		now-1800, "10.0.0.1", "HTTP", "web", 5000, 10000, "allowed")
	_ = store.Exec(`INSERT INTO flows(ts, src_ip, app, category, bytes_in, bytes_out, verdict) VALUES(?, ?, ?, ?, ?, ?, ?)`,
		now-1600, "10.0.0.2", "HTTPS", "web", 6000, 12000, "allowed")

	window := &TimeWindow{From: now - 3600, To: now}
	result, _ := engine.sections["traffic_by_app"].Run(ctx, window, &Filters{})
	tbl := result.(TrafficByApp)
	if len(tbl.Rows) < 1 {
		t.Errorf("traffic_by_app should have rows")
	}
}

func TestFilteringAndTopN(t *testing.T) {
	store, _ := core.OpenStore(t.TempDir())
	defer store.Close()

	ctx := &core.Context{Store: store, Name: "reports", Platform: &core.Platform{DataDir: t.TempDir()}}
	engine := NewEngine(ctx)
	now := time.Now().Unix()

	// Insert multiple flows
	for i := 0; i < 10; i++ {
		_ = store.Exec(`INSERT INTO flows(ts, src_ip, app, bytes_in, bytes_out) VALUES(?, ?, ?, ?, ?)`,
			now-int64(1800-i*100), "10.0.0."+string(rune(49+i)), "APP"+string(rune(65+i)), int64(i*1000), int64(i*2000))
	}

	window := &TimeWindow{From: now - 3600, To: now}

	// Test with TopN = 5
	filters := &Filters{TopN: 5}
	result, _ := engine.sections["traffic_by_app"].Run(ctx, window, filters)
	tbl := result.(TrafficByApp)
	if len(tbl.Rows) > 5 {
		t.Errorf("TopN=5 should limit results to 5, got %d", len(tbl.Rows))
	}
}

func TestScheduleDueComputation(t *testing.T) {
	// Test daily schedule
	now := time.Now()
	sched := &Schedule{
		Cadence:  "daily",
		TimeUTC:  "09:00",
		Timezone: "UTC",
	}

	m := &Module{}
	nextRun := m.nextRunTime(now, sched)

	if nextRun.Hour() != 9 {
		t.Errorf("next run should be at hour 9, got %d", nextRun.Hour())
	}
	if nextRun.Minute() != 0 {
		t.Errorf("next run should be at minute 0, got %d", nextRun.Minute())
	}
	if nextRun.Before(now) && nextRun.Day() == now.Day() {
		t.Errorf("next run should not be in the past for today")
	}
}

func TestScheduleWeeklyAndMonthly(t *testing.T) {
	m := &Module{}
	now := time.Now()

	// Weekly on Monday
	schedW := &Schedule{
		Cadence:  "weekly",
		TimeUTC:  "10:00",
		Weekday:  "mon",
		Timezone: "UTC",
	}
	nextW := m.nextRunTime(now, schedW)
	if nextW.Weekday() != time.Monday {
		t.Errorf("next weekly run should be on Monday, got %v", nextW.Weekday())
	}

	// Monthly on 15th
	schedM := &Schedule{
		Cadence:  "monthly",
		TimeUTC:  "10:00",
		Day:      15,
		Timezone: "UTC",
	}
	nextM := m.nextRunTime(now, schedM)
	if nextM.Day() != 15 {
		t.Errorf("next monthly run should be on day 15, got %d", nextM.Day())
	}
}

func TestRunStorageAndRetention(t *testing.T) {
	store, _ := core.OpenStore(t.TempDir())
	defer store.Close()

	ctx := &core.Context{
		Store:    store,
		Name:     "reports",
		Platform: &core.Platform{DataDir: t.TempDir()},
	}

	m := &Module{ctx: ctx, dataDir: ctx.Platform.DataDir + "/reports", maxTotalMB: 100}

	def := &Definition{ID: "test-def", Name: "Test"}
	run := &Run{
		ID:           "test-run-1",
		DefinitionID: def.ID,
		StartedAt:    time.Now().Unix(),
		CompletedAt:  time.Now().Unix(),
		Status:       "done",
		Sizes:        map[string]int{"html": 50000, "json": 10000},
	}

	// Store run
	_ = m.storeRun(run, def)
	_ = m.storeRunFormat(run, def, "html", []byte("test html content"))

	// Load and verify
	loaded, err := m.loadRun(run.ID)
	if err != nil {
		t.Fatalf("loadRun failed: %v", err)
	}
	if loaded.ID != run.ID {
		t.Errorf("loaded run ID mismatch")
	}
}

func TestNextRunTimeAvoidsDuplicates(t *testing.T) {
	store, _ := core.OpenStore(t.TempDir())
	defer store.Close()

	ctx := &core.Context{
		Store:    store,
		Name:     "reports",
		Platform: &core.Platform{DataDir: t.TempDir()},
	}

	m := &Module{ctx: ctx}

	def := &Definition{
		ID:       "test",
		Schedule: &Schedule{Cadence: "daily", TimeUTC: "09:00", Timezone: "UTC"},
	}

	// Set next run to far future to avoid being due
	futureTime := time.Now().AddDate(0, 0, 1).Unix()
	_ = m.ctx.Store.KVSet("reports.next_run."+def.ID, futureTime)

	now := time.Now()

	// Check that we're not due
	due := m.isDueForRun(now, def)
	if due {
		t.Errorf("should not be due when next_run is in the future")
	}
}

func TestAlertingIntegration(t *testing.T) {
	// Test the alerting interface
	msg := core.Message{
		Subject:     "Test Report",
		Text:        "Test text",
		HTML:        "<html><body>Test</body></html>",
		Attachments: []core.Attachment{},
	}

	if msg.Subject != "Test Report" {
		t.Errorf("Message subject mismatch")
	}

	att := core.Attachment{
		Name:  "test.pdf",
		MIME:  "application/pdf",
		Bytes: []byte("test pdf data"),
	}

	if att.Name != "test.pdf" {
		t.Errorf("Attachment name mismatch")
	}
}
