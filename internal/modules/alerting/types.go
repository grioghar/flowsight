package alerting

import (
	"context"
	"time"
)

// ChannelType defines the interface all notification channels must implement.
type ChannelType interface {
	// Type returns the channel type identifier (e.g., "slack", "pagerduty")
	Type() string

	// Label returns a human-readable label for the channel type.
	Label() string

	// Schema returns the configuration fields for this channel type.
	Schema() []SettingField

	// Validate checks if the channel config is valid.
	Validate(config map[string]string) error

	// Send delivers a message via this channel. ctx may be cancelled; respect it.
	// Returns latency in milliseconds if successful, or an error.
	Send(ctx context.Context, ch *Channel, msg *Message) (latencyMs int64, err error)

	// Test sends a test message. Used for the "Send test" action.
	Test(ctx context.Context, ch *Channel) (latencyMs int64, err error)
}

// SettingField describes a configuration field for a channel type.
type SettingField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // "text", "password", "url", "number", "select"
	Help     string   `json:"help"`
	Secret   bool     `json:"secret"`  // If true, don't return in API responses
	Options  []string `json:"options"` // For "select" type
	Required bool     `json:"required"`
}

// Note: Channel is defined in alerting.go (keep existing structure for backwards compatibility)

// QuietHours defines when a channel should not send notifications.
type QuietHours struct {
	StartHour int   // 0-23
	EndHour   int   // 0-23
	Weekdays  []int // 0-6 (Sunday-Saturday); empty = all days
}

// Message is the standard alert message structure passed to channels.
type Message struct {
	Timestamp time.Time   `json:"ts"`
	Title     string      `json:"title"`
	Severity  string      `json:"severity"`  // "critical", "high", "medium", "low", "info"
	Module    string      `json:"module"`    // Source module name
	Category  string      `json:"category"`  // Alert category
	Evidence  []string    `json:"evidence"`  // Key details
	Device    *DeviceInfo `json:"device"`    // Optional device context
	Zone      string      `json:"zone"`      // Optional zone
	AlertKey  string      `json:"alert_key"` // For dedup (rule + subject + params)
	Body      string      `json:"body"`      // Detailed description
	Link      string      `json:"link"`      // Link to relevant page (with base_url prepended)
	RuleID    string      `json:"rule_id"`   // Source rule ID
}

// DeviceInfo provides context about a device in an alert.
type DeviceInfo struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Name string `json:"name"`
	Zone string `json:"zone"`
}

// DeliveryLog records a single delivery attempt.
type DeliveryLog struct {
	ID          int64  `json:"id"`
	Timestamp   int64  `json:"ts"`
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	MessageKey  string `json:"message_key"` // For grouping related deliveries
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Success     bool   `json:"success"`
	LatencyMs   int64  `json:"latency_ms"`
	Error       string `json:"error"` // Error message if not successful
}

// RuleConfig defines how to route and deliver an alert.
type RuleConfig struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Enabled       bool        `json:"enabled"`
	Severity      string      `json:"severity"`       // Trigger on this severity or higher
	SeverityOnly  []string    `json:"severity_only"`  // If set, only these severities (overrides above)
	Module        string      `json:"module"`         // Empty = all; "dns", "web", etc.
	Category      string      `json:"category"`       // Empty = all
	Device        string      `json:"device"`         // Empty = all; IP or MAC
	Zone          string      `json:"zone"`           // Empty = all
	Channels      []string    `json:"channels"`       // Channel IDs to send to
	Cooldown      int         `json:"cooldown"`       // Seconds before same alert can re-fire
	DigestMinutes int         `json:"digest_minutes"` // If >0, bundle low-severity alerts
	Escalation    *Escalation `json:"escalation"`     // Optional escalation to additional channels
}

// Escalation defines what happens if an alert isn't acknowledged.
type Escalation struct {
	AfterMinutes int      `json:"after_minutes"`
	Channels     []string `json:"channels"`  // Additional channel IDs to escalate to
	OnlyOnce     bool     `json:"only_once"` // Don't escalate again if already escalated
}
