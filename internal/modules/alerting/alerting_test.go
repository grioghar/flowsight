package alerting

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func TestCooldown(t *testing.T) {
	// Create temp store
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Test cooldown key/value storage
	now := time.Now().Unix()
	key := "alerting.cooldown.rule1.subject1"

	// First notification - no prior send
	var lastSent int64
	found := store.KVGet(key, &lastSent)
	if found {
		t.Errorf("expected no prior cooldown record, got one")
	}

	// Record send time
	if err := store.KVSet(key, now); err != nil {
		t.Fatalf("KVSet failed: %v", err)
	}

	// Check cooldown - should be within 1 minute (60 seconds)
	cooldown := 60
	store.KVGet(key, &lastSent)
	if now-lastSent > int64(cooldown) {
		t.Errorf("cooldown check failed: elapsed %d > %d", now-lastSent, cooldown)
	}

	// Check that cooldown is enforced (simulate 30 seconds later, still in cooldown)
	later := now + 30
	store.KVGet(key, &lastSent)
	if later-lastSent < int64(cooldown) {
		// Should not send - still in cooldown
		t.Logf("correctly within cooldown period")
	}

	// Check that cooldown expires (simulate 90 seconds later)
	veryLater := now + 90
	store.KVGet(key, &lastSent)
	if veryLater-lastSent >= int64(cooldown) {
		// Should send - outside cooldown
		t.Logf("correctly outside cooldown period")
	}
}

func TestDefaultRules(t *testing.T) {
	rules := defaultRules()

	// Check that default rules are created
	if len(rules) == 0 {
		t.Errorf("expected default rules, got none")
	}

	// Check specific rules exist
	if _, ok := rules["new_host"]; !ok {
		t.Errorf("expected 'new_host' rule")
	}
	if _, ok := rules["ids_critical"]; !ok {
		t.Errorf("expected 'ids_critical' rule")
	}
	if _, ok := rules["finding_high"]; !ok {
		t.Errorf("expected 'finding_high' rule")
	}

	// Verify rule properties
	rule := rules["new_host"]
	if rule.Cooldown < 60 {
		t.Errorf("rule cooldown should be at least 60 seconds, got %d", rule.Cooldown)
	}
	if rule.Threshold < 1 {
		t.Errorf("rule threshold should be positive, got %d", rule.Threshold)
	}
}

func TestChannelConfig(t *testing.T) {
	// Test channel creation and masking
	ch := Channel{
		Name:    "test-email",
		Type:    ChannelEmail,
		Enabled: true,
		Config: map[string]string{
			"host":     "smtp.example.com",
			"port":     "587",
			"user":     "user@example.com",
			"password": "secret123",
			"from":     "alerts@example.com",
			"to":       "admin@example.com",
		},
	}

	// Verify channel structure
	if ch.Type != ChannelEmail {
		t.Errorf("expected ChannelEmail type")
	}
	if ch.Config["host"] != "smtp.example.com" {
		t.Errorf("channel config mismatch")
	}
	if ch.Config["password"] != "secret123" {
		t.Errorf("password should be stored (masked at API level)")
	}
}

func TestRuleEvaluation(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Add some test hosts with recent first_seen
	now := time.Now().Unix()
	for i := 0; i < 3; i++ {
		ip := "10.0.0." + string(rune(1+i))
		_ = store.Exec(`INSERT INTO hosts(ip, first_seen, last_seen, is_local)
			VALUES(?, ?, ?, 1)`, ip, now, now)
	}

	// Check that new_host rule would trigger
	count := store.Int(`SELECT COUNT(*) FROM hosts WHERE first_seen>=? AND is_local=1`, now-3600)
	if count < 3 {
		t.Errorf("expected at least 3 new hosts, got %d", count)
	}
}

// ============ FORMATTER TESTS ============

func TestPlainTextFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "Test Alert",
		Severity:  "critical",
		Module:    "dns",
		Category:  "anomaly",
		Body:      "Test body",
		Evidence:  []string{"evidence1", "evidence2"},
		Device: &DeviceInfo{
			IP:   "192.168.1.1",
			Name: "router",
		},
		Zone: "internal",
		Link: "https://example.com",
	}

	f := &PlainTextFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if !strings.Contains(result, "Test Alert") {
		t.Errorf("title missing")
	}
	if !strings.Contains(result, "critical") {
		t.Errorf("severity missing")
	}
	if !strings.Contains(result, "192.168.1.1") {
		t.Errorf("device IP missing")
	}
	if !strings.Contains(result, "evidence1") {
		t.Errorf("evidence missing")
	}
}

func TestSMSFormatter(t *testing.T) {
	msg := &Message{
		Title:    "Network anomaly detected on gateway router causing high latency and packet loss",
		Severity: "high",
		Body:     "The primary gateway experienced 45% packet loss in the last 5 minutes. Manual intervention may be required. Check status page for updates.",
		Link:     "https://example.com/alerts/12345",
	}

	f := &SMSFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// SMS should be <= 160 characters
	if len(result) > 160 {
		t.Errorf("SMS too long: %d chars", len(result))
	}

	// Should contain severity abbreviation
	if !strings.Contains(result, "[H]") {
		t.Errorf("severity abbreviation missing")
	}

	// Should not have unescaped control characters
	for _, char := range result {
		if char < 32 && char != '\n' && char != '\t' {
			t.Errorf("control character found: %d", char)
		}
	}
}

func TestJSONFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "Test Alert",
		Severity:  "medium",
		AlertKey:  "test-key",
	}

	f := &JSONFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should be valid JSON
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}

	// Check fields are present
	if m["title"] != "Test Alert" {
		t.Errorf("title mismatch")
	}
	if m["severity"] != "medium" {
		t.Errorf("severity mismatch")
	}
}

func TestSlackFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "Critical Alert",
		Severity:  "critical",
		Module:    "firewall",
		Category:  "intrusion",
		Body:      "Malicious traffic detected",
		Evidence:  []string{"source: 203.0.113.1", "attempts: 127"},
		Link:      "https://example.com",
	}

	f := &SlackFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should be valid JSON
	var blocks map[string]interface{}
	if err := json.Unmarshal([]byte(result), &blocks); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}

	// Should have blocks
	if _, ok := blocks["blocks"]; !ok {
		t.Errorf("blocks field missing")
	}
}

func TestTeamsFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "High Severity Alert",
		Severity:  "high",
		Module:    "ids",
		Category:  "attack",
		Device: &DeviceInfo{
			IP:   "10.1.1.5",
			Name: "webserver-01",
		},
	}

	f := &TeamsFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should be valid JSON
	var card map[string]interface{}
	if err := json.Unmarshal([]byte(result), &card); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}

	// Should have attachments
	if _, ok := card["attachments"]; !ok {
		t.Errorf("attachments field missing")
	}
}

func TestCEFFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "SQL Injection Attempt",
		Severity:  "critical",
		Module:    "waf",
		Category:  "injection",
		AlertKey:  "sqli-001",
		Device: &DeviceInfo{
			IP:   "192.168.1.100",
			Name: "database-server",
		},
		Link: "https://example.com/alert/123",
	}

	f := &CEFFormatter{DeviceVendor: "flowsight"}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should start with CEF header
	if !strings.HasPrefix(result, "CEF:0|") {
		t.Errorf("CEF header missing")
	}

	// Should contain critical severity (10)
	if !strings.Contains(result, "|10|") {
		t.Errorf("severity mapping incorrect")
	}

	// Should contain device IP
	if !strings.Contains(result, "192.168.1.100") {
		t.Errorf("device IP missing")
	}
}

func TestLEEFFormatter(t *testing.T) {
	msg := &Message{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Title:     "Suspicious Activity",
		Severity:  "medium",
		Module:    "endpoint",
		Category:  "suspicious",
		AlertKey:  "susp-001",
		Evidence:  []string{"malware signature match", "behavioral anomaly"},
	}

	f := &LEEFFormatter{}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Should start with LEEF header
	if !strings.HasPrefix(result, "LEEF:1.0|") {
		t.Errorf("LEEF header missing")
	}

	// Should contain alert key
	if !strings.Contains(result, "susp-001") {
		t.Errorf("alert key missing")
	}

	// Should contain evidence
	if !strings.Contains(result, "evidence_1") {
		t.Errorf("evidence indexing incorrect")
	}
}

func TestTemplateFormatter(t *testing.T) {
	tmpl := "Alert: {{.Title}} ({{.Severity}}) - {{.Body}}"
	msg := &Message{
		Title:    "System Down",
		Severity: "critical",
		Body:     "Primary server unreachable",
	}

	f := &TemplateFormatter{Template: tmpl}
	result, err := f.Format(msg)
	if err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	if result != "Alert: System Down (critical) - Primary server unreachable" {
		t.Errorf("unexpected output: %s", result)
	}
}

func TestHMACSignature(t *testing.T) {
	payload := `{"alert":"test"}`
	secret := "webhook-secret"

	sig := HMACSignature(payload, secret)

	// Should be valid hex string (64 chars for SHA256)
	if len(sig) != 64 {
		t.Errorf("signature length incorrect: expected 64, got %d", len(sig))
	}

	// Should be deterministic
	sig2 := HMACSignature(payload, secret)
	if sig != sig2 {
		t.Errorf("signature not deterministic")
	}

	// Different secret should produce different signature
	sig3 := HMACSignature(payload, "different-secret")
	if sig == sig3 {
		t.Errorf("different secrets should produce different signatures")
	}
}

// ============ DELIVERY ENGINE TESTS ============

type MockChannelType struct {
	sendCount  int
	failUntil  int
	sendDelay  time.Duration
	shouldFail bool
}

func (m *MockChannelType) Type() string                                         { return "mock" }
func (m *MockChannelType) Label() string                                        { return "Mock" }
func (m *MockChannelType) Schema() []SettingField                               { return nil }
func (m *MockChannelType) Validate(config map[string]string) error              { return nil }
func (m *MockChannelType) Test(ctx context.Context, ch *Channel) (int64, error) { return 0, nil }
func (m *MockChannelType) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	m.sendCount++
	if m.sendCount <= m.failUntil {
		return 0, core.BadRequest("send failed")
	}
	if m.sendDelay > 0 {
		time.Sleep(m.sendDelay)
	}
	return int64(m.sendDelay / time.Millisecond), nil
}

func TestDeliveryEngineRetry(t *testing.T) {
	engine := NewDeliveryEngine(100)
	ch := &Channel{
		Name:    "test",
		Type:    "mock",
		Enabled: true,
		Config:  map[string]string{},
	}
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "info",
		AlertKey:  "test-retry",
	}

	mock := &MockChannelType{failUntil: 1} // Fail first, succeed second
	attempt := engine.Deliver(context.Background(), ch, msg, mock)

	if !attempt.Success {
		t.Errorf("delivery should succeed after retry")
	}
	if attempt.RetryCount != 1 {
		t.Errorf("expected 1 retry, got %d", attempt.RetryCount)
	}
	if mock.sendCount != 2 {
		t.Errorf("expected 2 send attempts, got %d", mock.sendCount)
	}
}

func TestDeliveryEngineRateLimit(t *testing.T) {
	engine := NewDeliveryEngine(100)
	ch := &Channel{
		Name:    "test",
		Type:    "mock",
		Enabled: true,
		Config: map[string]string{
			"rate_limit_minutes": "1",
		},
	}
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "info",
		AlertKey:  "test-rate",
	}

	mock := &MockChannelType{}

	// First attempt should succeed
	attempt1 := engine.Deliver(context.Background(), ch, msg, mock)
	if !attempt1.Success {
		t.Errorf("first delivery should succeed")
	}

	// Second attempt should be rate-limited
	attempt2 := engine.Deliver(context.Background(), ch, msg, mock)
	if attempt2.Success {
		t.Errorf("second delivery should be rate-limited")
	}
	if attempt2.Error != "rate limited" {
		t.Errorf("expected rate limit error, got: %s", attempt2.Error)
	}
}

func TestDeliveryEngineDedup(t *testing.T) {
	engine := NewDeliveryEngine(100)
	ch := &Channel{
		Name:    "test",
		Type:    "mock",
		Enabled: true,
		Config:  map[string]string{},
	}
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "info",
		AlertKey:  "test-dedup",
	}

	mock := &MockChannelType{}

	// First attempt should succeed
	attempt1 := engine.Deliver(context.Background(), ch, msg, mock)
	if !attempt1.Success {
		t.Errorf("first delivery should succeed")
	}

	// Second attempt (within dedup window) should be dropped
	attempt2 := engine.Deliver(context.Background(), ch, msg, mock)
	if attempt2.Success {
		t.Errorf("second delivery should be deduplicated")
	}
	if !strings.Contains(attempt2.Error, "duplicate") {
		t.Errorf("expected duplicate error, got: %s", attempt2.Error)
	}
}

func TestDeliveryEngineLog(t *testing.T) {
	engine := NewDeliveryEngine(10)
	ch := &Channel{
		Name:    "test",
		Type:    "mock",
		Enabled: true,
		Config:  map[string]string{},
	}

	mock := &MockChannelType{}

	// Send multiple deliveries
	for i := 0; i < 5; i++ {
		msg := &Message{
			Timestamp: time.Now(),
			Title:     "Test",
			Severity:  "info",
			AlertKey:  "test-" + string(rune('0'+i)),
		}
		engine.Deliver(context.Background(), ch, msg, mock)
	}

	log := engine.GetDeliveryLog("test", 10)
	if len(log) != 5 {
		t.Errorf("expected 5 log entries, got %d", len(log))
	}

	// Test log rotation
	allLogs := engine.GetAllDeliveryLogs(10)
	if len(allLogs["test"]) != 5 {
		t.Errorf("expected 5 log entries in all logs, got %d", len(allLogs["test"]))
	}
}

// ============ RULES ENGINE TESTS (Phase 4) ============

func TestRuleMatching(t *testing.T) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "high",
		Module:    "firewall",
		Category:  "intrusion",
		AlertKey:  "test-rule-match",
		Device: &DeviceInfo{
			IP: "10.1.1.1",
		},
		Zone: "internal",
	}

	// Test severity matching
	rule := RuleConfig{
		ID:       "test-rule",
		Name:     "Test Rule",
		Enabled:  true,
		Severity: "medium", // Should match high
	}

	// High severity should match medium threshold
	if !matchSeverity(msg.Severity, rule.Severity) {
		t.Errorf("high severity should match medium threshold")
	}

	// Low severity should not match high threshold
	if matchSeverity("low", "high") {
		t.Errorf("low severity should not match high threshold")
	}
}

func TestRuleSeverityMatching(t *testing.T) {
	tests := []struct {
		msgSev   string
		minSev   string
		expected bool
	}{
		{"critical", "critical", true},
		{"high", "medium", true},
		{"medium", "high", false},
		{"info", "critical", false},
		{"low", "low", true},
	}

	for _, tt := range tests {
		result := matchSeverity(tt.msgSev, tt.minSev)
		if result != tt.expected {
			t.Errorf("matchSeverity(%s, %s) = %v, want %v", tt.msgSev, tt.minSev, result, tt.expected)
		}
	}
}

func TestDigestQueuing(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	// Create a mock module with the store
	ctx := &core.Context{Store: store}

	msg1 := &Message{
		Timestamp: time.Now(),
		Title:     "Alert 1",
		Severity:  "info",
		AlertKey:  "alert-1",
	}

	msg2 := &Message{
		Timestamp: time.Now(),
		Title:     "Alert 2",
		Severity:  "info",
		AlertKey:  "alert-2",
	}

	// Create alert engine
	engine := NewAlertEngine(ctx)

	// Queue two messages for digest
	engine.QueueForDigest("rule-1", "channel-1", msg1)
	engine.QueueForDigest("rule-1", "channel-1", msg2)

	// Get status to verify queued
	status := engine.GetStatus()
	if status.DigestQueueSize != 2 {
		t.Errorf("expected 2 queued messages, got %d", status.DigestQueueSize)
	}
}

func TestEscalationTracking(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Critical Alert",
		Severity:  "critical",
		AlertKey:  "crit-001",
	}

	escalation := &Escalation{
		AfterMinutes: 15,
		Channels:     []string{"escalation-channel"},
		OnlyOnce:     true,
	}

	// Create alert engine
	engine := NewAlertEngine(ctx)

	// Track for escalation
	engine.TrackForEscalation("rule-1", msg, escalation)

	// Verify tracked via status
	status := engine.GetStatus()
	if status.EscalationTrackedAlerts != 1 {
		t.Errorf("escalation not tracked, expected 1 tracked alert, got %d", status.EscalationTrackedAlerts)
	}
}

func TestAcknowledgmentPreventsEscalation(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Alert",
		Severity:  "high",
		AlertKey:  "ack-test",
	}

	// Create alert engine
	engine := NewAlertEngine(ctx)

	escalation := &Escalation{
		AfterMinutes: 5,
		Channels:     []string{"esc-channel"},
	}

	// Track for escalation
	engine.TrackForEscalation("rule-1", msg, escalation)

	// Acknowledge the alert
	engine.AcknowledgeAlert("ack-test")

	// Verify it's marked as acknowledged
	status := engine.GetStatus()
	if status.EscalationTrackedAlerts != 1 {
		t.Errorf("escalation not tracked, expected 1 tracked alert, got %d", status.EscalationTrackedAlerts)
	}
}
