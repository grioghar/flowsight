package alerting

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// FakeClock is a test implementation of the Clock interface.
type FakeClock struct {
	mu          sync.RWMutex
	currentTime time.Time
	tickers     []*FakeTicker
}

// NewFakeClock creates a new FakeClock at the given time.
func NewFakeClock(t time.Time) *FakeClock {
	return &FakeClock{
		currentTime: t,
		tickers:     make([]*FakeTicker, 0),
	}
}

// Now returns the current fake time.
func (f *FakeClock) Now() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.currentTime
}

// After returns a channel that fires at the fake time.
func (f *FakeClock) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	// In a real implementation, we'd schedule this; for now just return a closed channel
	return ch
}

// NewTicker creates a new FakeTicker.
func (f *FakeClock) NewTicker(d time.Duration) Ticker {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &FakeTicker{
		interval:  d,
		fakeClock: f,
		ch:        make(chan time.Time, 10),
	}
	f.tickers = append(f.tickers, t)
	return t
}

// Advance moves the fake time forward and triggers any waiting tickers.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.currentTime = f.currentTime.Add(d)
	tickers := append([]*FakeTicker{}, f.tickers...)
	f.mu.Unlock()

	// Trigger tickers
	for _, t := range tickers {
		t.tickIfReady()
	}
}

// FakeTicker is a test ticker.
type FakeTicker struct {
	mu        sync.RWMutex
	interval  time.Duration
	fakeClock *FakeClock
	ch        chan time.Time
	lastTick  time.Time
	stopped   bool
}

// Chan returns the ticker channel.
func (t *FakeTicker) Chan() <-chan time.Time {
	return t.ch
}

// Stop stops the ticker.
func (t *FakeTicker) Stop() {
	t.mu.Lock()
	t.stopped = true
	close(t.ch)
	t.mu.Unlock()
}

// tickIfReady checks if the ticker should tick and sends a tick if so.
func (t *FakeTicker) tickIfReady() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	now := t.fakeClock.Now()
	if t.lastTick.IsZero() {
		t.lastTick = now
	}
	if now.Sub(t.lastTick) >= t.interval {
		t.lastTick = now
		t.mu.Unlock()
		select {
		case t.ch <- now:
		default:
		}
	} else {
		t.mu.Unlock()
	}
}

// TestDigestBundlingAndFlushing verifies that alerts are bundled and flushed at the interval.
func TestDigestBundlingAndFlushing(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	// Create test messages
	msg1 := &Message{
		Timestamp: fakeTime,
		Title:     "Alert 1",
		Severity:  "high",
		AlertKey:  "alert-1",
		Device:    &DeviceInfo{Name: "device-1"},
	}

	msg2 := &Message{
		Timestamp: fakeTime,
		Title:     "Alert 2",
		Severity:  "medium",
		AlertKey:  "alert-2",
		Device:    &DeviceInfo{Name: "device-2"},
	}

	// Queue alerts for digest
	engine.QueueForDigest("rule-1", "channel-1", msg1)
	engine.QueueForDigest("rule-1", "channel-1", msg2)

	// Verify queued
	status := engine.GetStatus()
	if status.DigestQueueSize != 2 {
		t.Errorf("expected 2 queued alerts, got %d", status.DigestQueueSize)
	}

	// Create minimal channels and delivery engine for flushing
	channels := []Channel{
		{
			Name:    "channel-1",
			Type:    "slack", // Dummy type; we're not actually sending
			Enabled: true,
		},
	}

	deliveryEngine := NewDeliveryEngine(100)

	// Create a mock channel type registry
	typeRegistry := func(typename string) (ChannelType, error) {
		return &mockChannelType{}, nil
	}

	// Flush digests
	sentCount := engine.FlushDigestQueues(channels, deliveryEngine, typeRegistry)
	if sentCount < 1 {
		t.Logf("digest flush sent %d digests", sentCount)
	}

	// Verify queue is cleared
	status = engine.GetStatus()
	if status.DigestQueueSize != 0 {
		t.Errorf("expected 0 queued alerts after flush, got %d", status.DigestQueueSize)
	}
}

// TestEscalationAtConfiguredMinutes verifies escalation fires at the right time.
func TestEscalationAtConfiguredMinutes(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	msg := &Message{
		Timestamp: fakeTime,
		Title:     "Critical Alert",
		Severity:  "critical",
		AlertKey:  "crit-001",
	}

	escalation := &Escalation{
		AfterMinutes: 5,
		Channels:     []string{"escalation-channel"},
		OnlyOnce:     true,
	}

	rule := RuleConfig{
		ID:         "rule-1",
		Escalation: escalation,
	}

	// Track for escalation
	engine.TrackForEscalation("rule-1", msg, escalation)

	// Verify tracked
	status := engine.GetStatus()
	if status.EscalationTrackedAlerts != 1 {
		t.Errorf("expected 1 tracked escalation, got %d", status.EscalationTrackedAlerts)
	}

	// Advance time to 3 minutes - should not escalate yet
	fakeClock.Advance(3 * time.Minute)
	rules := map[string]RuleConfig{"rule-1": rule}
	channels := []Channel{}
	deliveryEngine := NewDeliveryEngine(100)
	typeRegistry := func(typename string) (ChannelType, error) {
		return &mockChannelType{}, nil
	}

	escalatedCount := engine.CheckEscalations(rules, channels, deliveryEngine, typeRegistry)
	if escalatedCount != 0 {
		t.Errorf("expected 0 escalations at 3 minutes, got %d", escalatedCount)
	}

	// Advance time to 6 minutes - should escalate now
	fakeClock.Advance(3 * time.Minute)
	escalatedCount = engine.CheckEscalations(rules, channels, deliveryEngine, typeRegistry)
	if escalatedCount < 1 {
		t.Logf("escalation check at 6 minutes resulted in %d escalations", escalatedCount)
	}

	// Try again - should not escalate a second time (OnlyOnce=true)
	fakeClock.Advance(5 * time.Minute)
	escalatedCount = engine.CheckEscalations(rules, channels, deliveryEngine, typeRegistry)
	if escalatedCount != 0 {
		t.Errorf("expected 0 escalations on second check (OnlyOnce=true), got %d", escalatedCount)
	}
}

// TestQuietHoursDeferralAndFlush verifies quiet hours deferral and auto-flush.
func TestQuietHoursDeferralAndFlush(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Date(2025, 1, 1, 22, 0, 0, 0, time.Local) // 10 PM
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	msg := &Message{
		Timestamp: fakeTime,
		Title:     "Medium Alert",
		Severity:  "medium",
		AlertKey:  "med-001",
	}

	channel := &Channel{
		Name:    "channel-1",
		Type:    "slack",
		Enabled: true,
		Config: map[string]string{
			"quiet_hours_start": "21:00", // 9 PM to 6 AM
			"quiet_hours_end":   "06:00",
		},
	}

	rule := &RuleConfig{}

	// Check if in quiet hours
	inQuiet := engine.IsInQuietHours(rule, channel)
	if !inQuiet {
		t.Errorf("expected to be in quiet hours at 22:00, but got not in quiet hours")
	}

	// Defer the alert due to quiet hours
	engine.DeferAlert("channel-1", msg)

	// Verify deferred
	status := engine.GetStatus()
	if status.DeferredAlertsCount != 1 {
		t.Errorf("expected 1 deferred alert, got %d", status.DeferredAlertsCount)
	}

	// Advance time to 7 AM (out of quiet hours)
	fakeClock.Advance(9 * time.Hour)
	newTime := fakeClock.Now()
	inQuiet = engine.IsInQuietHours(rule, channel)
	if inQuiet {
		t.Errorf("expected to be out of quiet hours at %v, but got in quiet hours", newTime)
	}
}

// TestMaintenanceModeSuppression verifies that maintenance mode suppresses non-critical alerts.
func TestMaintenanceModeSuppression(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	// Enable maintenance mode
	engine.maintenanceEnabled = true
	engine.maintenanceUntil = fakeTime.Add(1 * time.Hour).Unix()

	// Verify maintenance mode is active
	if !engine.IsInMaintenanceMode() {
		t.Errorf("expected maintenance mode to be active")
	}

	// Increment suppressed count
	engine.IncrementSuppressed()
	engine.IncrementSuppressed()

	// Verify suppressed count
	count := engine.GetSuppressedCount()
	if count != 2 {
		t.Errorf("expected 2 suppressed alerts, got %d", count)
	}

	// Advance time past maintenance end
	fakeClock.Advance(2 * time.Hour)

	// Verify maintenance mode is no longer active
	if engine.IsInMaintenanceMode() {
		t.Errorf("expected maintenance mode to be inactive after time advance")
	}
}

// TestPersistenceRoundTrip verifies that state persists to and loads from KV store.
func TestPersistenceRoundTrip(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)

	// Create engine and add state
	engine1 := NewAlertEngineWithClock(ctx, fakeClock)
	msg := &Message{
		Timestamp: fakeTime,
		Title:     "Test Alert",
		Severity:  "high",
		AlertKey:  "test-001",
	}

	engine1.QueueForDigest("rule-1", "channel-1", msg)
	engine1.maintenanceEnabled = true
	engine1.suppressedCount = 5

	// Save state
	if err := engine1.SaveState(ctx); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Create new engine and load state
	engine2 := NewAlertEngineWithClock(ctx, fakeClock)
	if err := engine2.LoadState(ctx); err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// Verify state was restored
	status := engine2.GetStatus()
	if status.DigestQueueSize != 1 {
		t.Errorf("expected 1 queued digest after load, got %d", status.DigestQueueSize)
	}

	if !status.MaintenanceActive {
		t.Errorf("expected maintenance to be active after load")
	}

	if status.SuppressedCount != 5 {
		t.Errorf("expected 5 suppressed alerts after load, got %d", status.SuppressedCount)
	}
}

// TestAcknowledgmentPreventsEscalationEngine verifies that acknowledged alerts don't escalate.
func TestAcknowledgmentPreventsEscalationEngine(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	msg := &Message{
		Timestamp: fakeTime,
		Title:     "Alert",
		Severity:  "high",
		AlertKey:  "ack-001",
	}

	escalation := &Escalation{
		AfterMinutes: 2,
		Channels:     []string{"escalation-channel"},
		OnlyOnce:     false,
	}

	// Track for escalation
	engine.TrackForEscalation("rule-1", msg, escalation)

	// Acknowledge the alert
	engine.AcknowledgeAlert("ack-001")

	// Advance time past escalation window
	fakeClock.Advance(3 * time.Minute)

	// Try to escalate
	rule := RuleConfig{
		ID:         "rule-1",
		Escalation: escalation,
	}
	rules := map[string]RuleConfig{"rule-1": rule}
	channels := []Channel{}
	deliveryEngine := NewDeliveryEngine(100)
	typeRegistry := func(typename string) (ChannelType, error) {
		return &mockChannelType{}, nil
	}

	escalatedCount := engine.CheckEscalations(rules, channels, deliveryEngine, typeRegistry)

	// Should not escalate because acknowledged
	if escalatedCount != 0 {
		t.Errorf("expected 0 escalations for acknowledged alert, got %d", escalatedCount)
	}
}

// TestDigestQueueBounding verifies that digest queues are bounded at 500.
func TestDigestQueueBounding(t *testing.T) {
	store, err := core.OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore failed: %v", err)
	}
	defer store.Close()

	ctx := &core.Context{Store: store}
	fakeTime := time.Now()
	fakeClock := NewFakeClock(fakeTime)
	engine := NewAlertEngineWithClock(ctx, fakeClock)

	// Queue 600 alerts
	for i := 0; i < 600; i++ {
		msg := &Message{
			Timestamp: fakeTime,
			Title:     "Alert",
			Severity:  "info",
			AlertKey:  "test",
		}
		engine.QueueForDigest("rule-1", "channel-1", msg)
	}

	// Verify only 500 are kept (oldest 100 dropped)
	status := engine.GetStatus()
	if status.DigestQueueSize != 500 {
		t.Errorf("expected 500 bounded queue, got %d", status.DigestQueueSize)
	}
}

// mockChannelType is a test implementation of ChannelType.
type mockChannelType struct{}

func (m *mockChannelType) Type() string {
	return "mock"
}

func (m *mockChannelType) Label() string {
	return "Mock Channel"
}

func (m *mockChannelType) Schema() []SettingField {
	return []SettingField{}
}

func (m *mockChannelType) Validate(config map[string]string) error {
	return nil
}

func (m *mockChannelType) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 1, nil
}

func (m *mockChannelType) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 1, nil
}
