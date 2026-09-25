package alerting

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DeliveryEngine manages alert delivery with retries, rate-limiting, and deduplication.
type DeliveryEngine struct {
	mu              sync.RWMutex
	rateLimits      map[string]int64              // key -> last send timestamp
	deliveryLog     map[string][]*DeliveryAttempt // channel_name -> attempts
	deliveryLogSize int                           // max entries per channel
}

// DeliveryAttempt records a single delivery attempt.
type DeliveryAttempt struct {
	Timestamp  int64  `json:"timestamp"`
	ChannelID  string `json:"channel_id"`
	AlertKey   string `json:"alert_key"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Success    bool   `json:"success"`
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error"`
	RetryCount int    `json:"retry_count"`
}

// NewDeliveryEngine creates a new delivery engine.
func NewDeliveryEngine(logSize int) *DeliveryEngine {
	if logSize <= 0 {
		logSize = 200
	}
	return &DeliveryEngine{
		rateLimits:      make(map[string]int64),
		deliveryLog:     make(map[string][]*DeliveryAttempt),
		deliveryLogSize: logSize,
	}
}

// Deliver sends an alert through a channel with retry logic.
// Returns the delivery attempt record.
func (e *DeliveryEngine) Deliver(ctx context.Context, ch *Channel, msg *Message, ct ChannelType) *DeliveryAttempt {
	attempt := &DeliveryAttempt{
		Timestamp:  time.Now().Unix(),
		ChannelID:  ch.Name,
		AlertKey:   msg.AlertKey,
		Severity:   msg.Severity,
		Title:      msg.Title,
		RetryCount: 0,
	}

	// Check rate limit
	if !e.CheckRateLimit(ch.Name, msg.AlertKey, ch.Config["rate_limit_minutes"]) {
		attempt.Success = false
		attempt.Error = "rate limited"
		e.logAttempt(ch.Name, attempt)
		return attempt
	}

	// Check dedup
	if e.IsDuplicate(ch.Name, msg.AlertKey) {
		attempt.Success = false
		attempt.Error = "duplicate (same alert within dedup window)"
		e.logAttempt(ch.Name, attempt)
		return attempt
	}

	// Retry loop with exponential backoff
	backoff := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}
	for attempt.RetryCount = 0; attempt.RetryCount < 3; attempt.RetryCount++ {
		select {
		case <-ctx.Done():
			attempt.Success = false
			attempt.Error = "context cancelled"
			e.logAttempt(ch.Name, attempt)
			return attempt
		default:
		}

		latencyMs, err := ct.Send(ctx, ch, msg)
		attempt.LatencyMs = latencyMs

		if err == nil {
			attempt.Success = true
			attempt.Error = ""
			e.logAttempt(ch.Name, attempt)
			e.RecordSend(ch.Name, msg.AlertKey)
			return attempt
		}

		// Retry with backoff
		if attempt.RetryCount < 2 {
			attempt.Error = err.Error()
			select {
			case <-time.After(backoff[attempt.RetryCount]):
			case <-ctx.Done():
				attempt.Success = false
				attempt.Error = "context cancelled on retry"
				e.logAttempt(ch.Name, attempt)
				return attempt
			}
		}
	}

	// All retries exhausted
	attempt.Success = false
	if attempt.Error == "" {
		attempt.Error = "all retries failed"
	}
	e.logAttempt(ch.Name, attempt)
	return attempt
}

// CheckRateLimit returns true if the alert can be sent (not rate-limited).
func (e *DeliveryEngine) CheckRateLimit(channelName, alertKey, minutesStr string) bool {
	if minutesStr == "" {
		return true // No rate limit
	}

	minutes := 0
	fmt.Sscanf(minutesStr, "%d", &minutes)
	if minutes <= 0 {
		return true
	}

	e.mu.RLock()
	key := fmt.Sprintf("%s:%s", channelName, alertKey)
	lastSend := e.rateLimits[key]
	e.mu.RUnlock()

	now := time.Now().Unix()
	return (now - lastSend) >= int64(minutes*60)
}

// IsDuplicate returns true if the alert was recently sent (within dedup window).
func (e *DeliveryEngine) IsDuplicate(channelName, alertKey string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", channelName, alertKey)
	lastSend := e.rateLimits[key]

	// Check if sent within last 10 minutes (default dedup window)
	now := time.Now().Unix()
	return (now - lastSend) < 600 // 10 minutes
}

// RecordSend updates the rate limit timestamp for an alert.
func (e *DeliveryEngine) RecordSend(channelName, alertKey string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := fmt.Sprintf("%s:%s", channelName, alertKey)
	e.rateLimits[key] = time.Now().Unix()
}

// logAttempt appends an attempt to the delivery log.
func (e *DeliveryEngine) logAttempt(channelName string, attempt *DeliveryAttempt) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.deliveryLog[channelName]; !exists {
		e.deliveryLog[channelName] = []*DeliveryAttempt{}
	}

	e.deliveryLog[channelName] = append(e.deliveryLog[channelName], attempt)

	// Rotate: keep only last N entries
	if len(e.deliveryLog[channelName]) > e.deliveryLogSize {
		e.deliveryLog[channelName] = e.deliveryLog[channelName][len(e.deliveryLog[channelName])-e.deliveryLogSize:]
	}
}

// GetDeliveryLog returns the delivery log for a channel.
func (e *DeliveryEngine) GetDeliveryLog(channelName string, limit int) []*DeliveryAttempt {
	e.mu.RLock()
	defer e.mu.RUnlock()

	log := e.deliveryLog[channelName]
	if log == nil {
		return []*DeliveryAttempt{}
	}

	if limit <= 0 || limit > len(log) {
		limit = len(log)
	}

	// Return most recent N entries
	result := make([]*DeliveryAttempt, limit)
	copy(result, log[len(log)-limit:])
	return result
}

// GetAllDeliveryLogs returns delivery logs for all channels.
func (e *DeliveryEngine) GetAllDeliveryLogs(limit int) map[string][]*DeliveryAttempt {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string][]*DeliveryAttempt)
	for ch, attempts := range e.deliveryLog {
		if limit <= 0 || limit > len(attempts) {
			result[ch] = attempts
		} else {
			result[ch] = attempts[len(attempts)-limit:]
		}
	}
	return result
}

// CleanupExpired removes old rate limit entries (older than 24 hours).
func (e *DeliveryEngine) CleanupExpired() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Unix()
	expiryThreshold := int64(24 * 60 * 60) // 24 hours

	for key, timestamp := range e.rateLimits {
		if now-timestamp > expiryThreshold {
			delete(e.rateLimits, key)
		}
	}
}

// ClearDeliveryLog removes old delivery log entries (older than 7 days).
func (e *DeliveryEngine) ClearDeliveryLog() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now().Unix()
	expiryThreshold := int64(7 * 24 * 60 * 60) // 7 days

	for ch, attempts := range e.deliveryLog {
		filtered := make([]*DeliveryAttempt, 0)
		for _, attempt := range attempts {
			if now-attempt.Timestamp <= expiryThreshold {
				filtered = append(filtered, attempt)
			}
		}
		e.deliveryLog[ch] = filtered
	}
}
