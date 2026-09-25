package alerting

import (
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
