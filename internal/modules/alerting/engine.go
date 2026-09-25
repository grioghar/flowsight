package alerting

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Clock provides a testable interface for time operations.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker is a testable interface for time tickers.
type Ticker interface {
	Chan() <-chan time.Time
	Stop()
}

// RealClock implements Clock using actual system time.
type RealClock struct{}

func (c *RealClock) Now() time.Time {
	return time.Now()
}

func (c *RealClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func (c *RealClock) NewTicker(d time.Duration) Ticker {
	return &realTicker{time.NewTicker(d)}
}

type realTicker struct {
	t *time.Ticker
}

func (r *realTicker) Chan() <-chan time.Time {
	return r.t.C
}

func (r *realTicker) Stop() {
	r.t.Stop()
}

// DigestItem holds an alert queued for digest delivery.
type DigestItem struct {
	Message  *Message `json:"message"`
	QueuedAt int64    `json:"queued_at"`
	Severity string   `json:"severity"` // For determining highest in digest
}

// EscalationState tracks an alert's escalation progress.
type EscalationState struct {
	AlertKey         string                   `json:"alert_key"`
	RuleID           string                   `json:"rule_id"`
	FirstSentAt      int64                    `json:"first_sent_at"`
	LastSeenAt       int64                    `json:"last_seen_at"`
	Acknowledged     bool                     `json:"acknowledged"`
	AcknowledgedAt   int64                    `json:"acknowledged_at"`
	Resolved         bool                     `json:"resolved"`
	ResolvedAt       int64                    `json:"resolved_at"`
	EscalationLevels map[int]*EscalationLevel `json:"escalation_levels"` // minutes -> level info
}

// EscalationLevel tracks when an escalation level was sent.
type EscalationLevel struct {
	Minutes int   `json:"minutes"`
	SentAt  int64 `json:"sent_at"`
}

// AlertEngine manages digest bundling, escalation, quiet hours, and maintenance mode.
type AlertEngine struct {
	clock Clock
	mu    sync.RWMutex
	ctx   *core.Context // Assuming core.Context is imported (will be added)

	// State caches
	digestQueues       map[string]map[string][]DigestItem // ruleID -> channelID -> items
	escalationState    map[string]*EscalationState        // alertKey -> state
	quietHoursDeferred map[string][]DigestItem            // channelID -> items

	// Tickers for background jobs
	digestTicker     Ticker
	escalationTicker Ticker

	// Maintenance mode
	maintenanceEnabled bool
	maintenanceUntil   int64
	suppressedCount    int64
}

// NewAlertEngine creates a new AlertEngine with a real clock.
func NewAlertEngine(ctx *core.Context) *AlertEngine {
	return NewAlertEngineWithClock(ctx, &RealClock{})
}

// NewAlertEngineWithClock creates a new AlertEngine with a custom clock (for testing).
func NewAlertEngineWithClock(ctx *core.Context, clock Clock) *AlertEngine {
	return &AlertEngine{
		clock:              clock,
		ctx:                ctx,
		digestQueues:       make(map[string]map[string][]DigestItem),
		escalationState:    make(map[string]*EscalationState),
		quietHoursDeferred: make(map[string][]DigestItem),
		maintenanceEnabled: false,
		maintenanceUntil:   0,
		suppressedCount:    0,
	}
}

// LoadState loads digest queues, escalation state, and deferred alerts from KV store.
func (e *AlertEngine) LoadState(ctx *core.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Load digest queues
	digestData := make(map[string]map[string][]DigestItem)
	ctx.Store.KVGet("alerting.engine.digests", &digestData)
	e.digestQueues = digestData

	// Load escalation state
	escalationData := make(map[string]*EscalationState)
	ctx.Store.KVGet("alerting.engine.escalations", &escalationData)
	e.escalationState = escalationData

	// Load deferred alerts
	deferredData := make(map[string][]DigestItem)
	ctx.Store.KVGet("alerting.engine.deferred", &deferredData)
	e.quietHoursDeferred = deferredData

	// Load maintenance mode
	var maintenance struct {
		Enabled    bool  `json:"enabled"`
		Until      int64 `json:"until"`
		Suppressed int64 `json:"suppressed_count"`
	}
	ctx.Store.KVGet("alerting.maintenance", &maintenance)
	e.maintenanceEnabled = maintenance.Enabled
	e.maintenanceUntil = maintenance.Until
	e.suppressedCount = maintenance.Suppressed

	return nil
}

// SaveState persists digest queues, escalation state, and deferred alerts to KV store.
func (e *AlertEngine) SaveState(ctx *core.Context) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if err := ctx.Store.KVSet("alerting.engine.digests", e.digestQueues); err != nil {
		return err
	}
	if err := ctx.Store.KVSet("alerting.engine.escalations", e.escalationState); err != nil {
		return err
	}
	if err := ctx.Store.KVSet("alerting.engine.deferred", e.quietHoursDeferred); err != nil {
		return err
	}

	maintenance := map[string]any{
		"enabled":          e.maintenanceEnabled,
		"until":            e.maintenanceUntil,
		"suppressed_count": e.suppressedCount,
	}
	return ctx.Store.KVSet("alerting.maintenance", maintenance)
}

// QueueForDigest queues an alert for digest delivery.
func (e *AlertEngine) QueueForDigest(ruleID, channelID string, msg *Message) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.digestQueues[ruleID]; !ok {
		e.digestQueues[ruleID] = make(map[string][]DigestItem)
	}

	item := DigestItem{
		Message:  msg,
		QueuedAt: e.clock.Now().Unix(),
		Severity: msg.Severity,
	}

	queue := e.digestQueues[ruleID][channelID]
	queue = append(queue, item)

	// Enforce bounded queue: drop oldest if exceeds 500
	if len(queue) > 500 {
		queue = queue[len(queue)-500:]
	}

	e.digestQueues[ruleID][channelID] = queue
}

// DeferAlert defers an alert due to quiet hours.
func (e *AlertEngine) DeferAlert(channelID string, msg *Message) {
	e.mu.Lock()
	defer e.mu.Unlock()

	item := DigestItem{
		Message:  msg,
		QueuedAt: e.clock.Now().Unix(),
		Severity: msg.Severity,
	}

	queue := e.quietHoursDeferred[channelID]
	queue = append(queue, item)
	e.quietHoursDeferred[channelID] = queue
}

// TrackForEscalation records an alert for escalation tracking.
func (e *AlertEngine) TrackForEscalation(ruleID string, msg *Message, escalation *Escalation) {
	e.mu.Lock()
	defer e.mu.Unlock()

	state, ok := e.escalationState[msg.AlertKey]
	if !ok {
		state = &EscalationState{
			AlertKey:         msg.AlertKey,
			RuleID:           ruleID,
			FirstSentAt:      e.clock.Now().Unix(),
			EscalationLevels: make(map[int]*EscalationLevel),
		}
		e.escalationState[msg.AlertKey] = state
	}

	state.LastSeenAt = e.clock.Now().Unix()
}

// AcknowledgeAlert marks an alert as acknowledged, preventing further escalation.
func (e *AlertEngine) AcknowledgeAlert(alertKey string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if state, ok := e.escalationState[alertKey]; ok {
		state.Acknowledged = true
		state.AcknowledgedAt = e.clock.Now().Unix()
	}
}

// ResolveAlert marks an alert as resolved.
func (e *AlertEngine) ResolveAlert(alertKey string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if state, ok := e.escalationState[alertKey]; ok {
		state.Resolved = true
		state.ResolvedAt = e.clock.Now().Unix()
	}
}

// IsInMaintenanceMode returns true if maintenance mode is active.
func (e *AlertEngine) IsInMaintenanceMode() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.maintenanceEnabled {
		return false
	}
	if e.maintenanceUntil == 0 {
		return true // Indefinite maintenance
	}
	return e.clock.Now().Unix() < e.maintenanceUntil
}

// IncrementSuppressed increments the maintenance mode suppression counter.
func (e *AlertEngine) IncrementSuppressed() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressedCount++
}

// GetSuppressedCount returns the count of suppressed alerts during maintenance.
func (e *AlertEngine) GetSuppressedCount() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.suppressedCount
}

// IsInQuietHours checks if the current time is within quiet hours for a channel/rule.
func (e *AlertEngine) IsInQuietHours(rule *RuleConfig, channel *Channel) bool {
	if rule == nil || channel == nil {
		return false
	}

	// Check quiet hours in rule config or channel config
	// For now, parse from channel config if present
	quietStart := channel.Config["quiet_hours_start"] // HH:MM
	quietEnd := channel.Config["quiet_hours_end"]     // HH:MM
	quietDays := channel.Config["quiet_hours_days"]   // Optional: "0,1,2,3,4,5,6"

	if quietStart == "" || quietEnd == "" {
		return false
	}

	return e.isTimeInWindow(quietStart, quietEnd, quietDays)
}

// isTimeInWindow checks if current time is within the given window.
func (e *AlertEngine) isTimeInWindow(startHHMM, endHHMM, daysStr string) bool {
	now := e.clock.Now()
	localTime := now.Local()
	currentHour := localTime.Hour()
	currentMin := localTime.Minute()

	// Parse start time
	var startHour, startMin int
	fmt.Sscanf(startHHMM, "%d:%d", &startHour, &startMin)

	// Parse end time
	var endHour, endMin int
	fmt.Sscanf(endHHMM, "%d:%d", &endHour, &endMin)

	// Check days if specified
	if daysStr != "" {
		// Parse comma-separated days
		// For simplicity, just check if current weekday is in the list
		// (This is a simplified version; a full implementation would parse the CSV)
		// TODO: Implement day-of-week parsing for quiet hours
		// For now, skip day validation
	}

	// Check if current time is within the window
	currentMinOfDay := currentHour*60 + currentMin
	startMinOfDay := startHour*60 + startMin
	endMinOfDay := endHour*60 + endMin

	if startMinOfDay <= endMinOfDay {
		// Normal window (e.g., 09:00-17:00)
		return currentMinOfDay >= startMinOfDay && currentMinOfDay < endMinOfDay
	} else {
		// Wrap-around window (e.g., 22:00-06:00)
		return currentMinOfDay >= startMinOfDay || currentMinOfDay < endMinOfDay
	}
}

// FlushDigestQueues sends bundled digest messages for all queued alerts.
// Returns the number of digests sent.
func (e *AlertEngine) FlushDigestQueues(channels []Channel, deliveryEngine *DeliveryEngine, channelTypeRegistry func(string) (ChannelType, error)) int {
	e.mu.Lock()
	digests := make(map[string]map[string][]DigestItem)
	for rid, rules := range e.digestQueues {
		for channelID, items := range rules {
			if len(items) > 0 {
				if _, ok := digests[rid]; !ok {
					digests[rid] = make(map[string][]DigestItem)
				}
				digests[rid][channelID] = append([]DigestItem{}, items...)
			}
		}
	}
	e.digestQueues = make(map[string]map[string][]DigestItem) // Clear queues
	e.mu.Unlock()

	sentCount := 0

	// Send digests
	for _, rules := range digests {
		for channelID, items := range rules {
			if len(items) == 0 {
				continue
			}

			// Find channel
			var ch *Channel
			for i := range channels {
				if channels[i].Name == channelID {
					ch = &channels[i]
					break
				}
			}
			if ch == nil || !ch.Enabled {
				continue
			}

			// Create digest message
			digestMsg := e.createDigestMessage(items)

			// Get channel type
			ct, err := channelTypeRegistry(ch.Type)
			if err != nil {
				continue
			}

			// Deliver
			attempt := deliveryEngine.Deliver(context.Background(), ch, digestMsg, ct)
			if attempt.Success {
				sentCount++
			}
		}
	}

	// Save updated state
	e.mu.RLock()
	_ = e.SaveState(e.ctx)
	e.mu.RUnlock()

	return sentCount
}

// createDigestMessage creates a bundled digest message from queued items.
func (e *AlertEngine) createDigestMessage(items []DigestItem) *Message {
	if len(items) == 0 {
		return &Message{}
	}

	// Determine time span
	var oldestTime int64 = items[0].QueuedAt
	var newestTime int64 = items[0].QueuedAt
	for _, item := range items {
		if item.QueuedAt < oldestTime {
			oldestTime = item.QueuedAt
		}
		if item.QueuedAt > newestTime {
			newestTime = item.QueuedAt
		}
	}

	minutes := (newestTime - oldestTime) / 60
	if minutes == 0 {
		minutes = 1
	}

	// Find highest severity
	severityOrder := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	highestSevIdx := 0
	highestSev := "info"
	for _, item := range items {
		if severityOrder[item.Severity] > highestSevIdx {
			highestSevIdx = severityOrder[item.Severity]
			highestSev = item.Severity
		}
	}

	// Build compact list
	evidence := make([]string, 0)
	for _, item := range items {
		evidence = append(evidence, fmt.Sprintf("[%s] %s (%s)", item.Severity, item.Message.Title, item.Message.Device.Name))
	}

	return &Message{
		Timestamp: e.clock.Now(),
		Title:     fmt.Sprintf("%d alerts in the last %d minutes", len(items), minutes),
		Severity:  highestSev,
		Evidence:  evidence,
		AlertKey:  fmt.Sprintf("digest-%d", e.clock.Now().UnixNano()),
		Module:    "alerting",
		Category:  "digest",
	}
}

// CheckEscalations checks for alerts that need escalation and reschedules them.
func (e *AlertEngine) CheckEscalations(rules map[string]RuleConfig, channels []Channel, deliveryEngine *DeliveryEngine, channelTypeRegistry func(string) (ChannelType, error)) int {
	e.mu.Lock()
	stateCopy := make(map[string]*EscalationState)
	for k, v := range e.escalationState {
		// Deep copy
		newState := &EscalationState{
			AlertKey:         v.AlertKey,
			RuleID:           v.RuleID,
			FirstSentAt:      v.FirstSentAt,
			LastSeenAt:       v.LastSeenAt,
			Acknowledged:     v.Acknowledged,
			AcknowledgedAt:   v.AcknowledgedAt,
			Resolved:         v.Resolved,
			ResolvedAt:       v.ResolvedAt,
			EscalationLevels: make(map[int]*EscalationLevel),
		}
		for minutes, level := range v.EscalationLevels {
			newState.EscalationLevels[minutes] = &EscalationLevel{Minutes: level.Minutes, SentAt: level.SentAt}
		}
		stateCopy[k] = newState
	}
	e.mu.Unlock()

	escalatedCount := 0
	now := e.clock.Now().Unix()

	for alertKey, state := range stateCopy {
		// Skip if resolved or acknowledged
		if state.Resolved || state.Acknowledged {
			continue
		}

		rule, ok := rules[state.RuleID]
		if !ok || rule.Escalation == nil {
			continue
		}

		esc := rule.Escalation

		// Check if we should escalate at the configured interval
		minutesPassed := (now - state.FirstSentAt) / 60
		if minutesPassed < int64(esc.AfterMinutes) {
			continue
		}

		// Check if we've already escalated this level
		if _, alreadyEscalated := state.EscalationLevels[esc.AfterMinutes]; alreadyEscalated {
			if esc.OnlyOnce {
				continue
			}
		}

		// Escalate
		for _, chID := range esc.Channels {
			var ch *Channel
			for i := range channels {
				if channels[i].Name == chID {
					ch = &channels[i]
					break
				}
			}
			if ch == nil || !ch.Enabled {
				continue
			}

			// Create escalation message
			escMsg := &Message{
				Timestamp: e.clock.Now(),
				Title:     fmt.Sprintf("[ESCALATION] Unacknowledged alert after %d minutes", esc.AfterMinutes),
				Severity:  "critical", // Escalations are always critical
				AlertKey:  alertKey + "-escalation",
				Module:    "alerting",
				Category:  "escalation",
			}

			ct, err := channelTypeRegistry(ch.Type)
			if err != nil {
				continue
			}

			attempt := deliveryEngine.Deliver(context.Background(), ch, escMsg, ct)
			if attempt.Success {
				escalatedCount++
				// Mark this level as escalated
				e.mu.Lock()
				if state, ok := e.escalationState[alertKey]; ok {
					state.EscalationLevels[esc.AfterMinutes] = &EscalationLevel{
						Minutes: esc.AfterMinutes,
						SentAt:  now,
					}
				}
				e.mu.Unlock()
			}
		}
	}

	return escalatedCount
}

// Engine status for monitoring.
type EngineStatus struct {
	MaintenanceActive       bool  `json:"maintenance_active"`
	MaintenanceUntil        int64 `json:"maintenance_until"`
	SuppressedCount         int64 `json:"suppressed_count"`
	DigestQueueSize         int   `json:"digest_queue_size"`
	EscalationTrackedAlerts int   `json:"escalation_tracked_alerts"`
	DeferredAlertsCount     int   `json:"deferred_alerts_count"`
}

// GetStatus returns the current engine status.
func (e *AlertEngine) GetStatus() EngineStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	digestCount := 0
	for _, rules := range e.digestQueues {
		for _, items := range rules {
			digestCount += len(items)
		}
	}

	deferredCount := 0
	for _, items := range e.quietHoursDeferred {
		deferredCount += len(items)
	}

	return EngineStatus{
		MaintenanceActive:       e.maintenanceEnabled && (e.maintenanceUntil == 0 || e.clock.Now().Unix() < e.maintenanceUntil),
		MaintenanceUntil:        e.maintenanceUntil,
		SuppressedCount:         e.suppressedCount,
		DigestQueueSize:         digestCount,
		EscalationTrackedAlerts: len(e.escalationState),
		DeferredAlertsCount:     deferredCount,
	}
}
