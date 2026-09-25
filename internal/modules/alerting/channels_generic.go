package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"
)

// WebhookChannel sends JSON POST to a custom HTTP endpoint with optional HMAC signing.
type WebhookChannel struct{}

func (w *WebhookChannel) Type() string  { return "webhook" }
func (w *WebhookChannel) Label() string { return "Webhook (Generic)" }

func (w *WebhookChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "url", Label: "Webhook URL", Type: "url", Required: true, Help: "POST endpoint for alerts"},
		{Key: "method", Label: "HTTP Method", Type: "select", Options: []string{"POST", "PUT", "PATCH"}, Help: "Default: POST"},
		{Key: "signing_key", Label: "Signing Key", Type: "password", Secret: true, Help: "For HMAC-SHA256; X-Signature header"},
		{Key: "headers_json", Label: "Extra Headers (JSON)", Type: "text", Help: `{"X-Custom": "value"}`},
		{Key: "body_template", Label: "Body Template", Type: "text", Help: "Go template; vars: .Title .Severity .Module etc; default: JSON"},
	}
}

func (w *WebhookChannel) Validate(config map[string]string) error {
	if config["url"] == "" {
		return fmt.Errorf("url required")
	}
	_, err := url.Parse(config["url"])
	return err
}

func (w *WebhookChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	var body string
	if ch.Config["body_template"] != "" {
		// Use template
		t, err := template.New("alert").Parse(ch.Config["body_template"])
		if err != nil {
			return 0, fmt.Errorf("template parse failed: %w", err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, msg); err != nil {
			return 0, fmt.Errorf("template execute failed: %w", err)
		}
		body = buf.String()
	} else {
		// Use JSON
		formatter := &JSONFormatter{}
		var err error
		body, err = formatter.Format(msg)
		if err != nil {
			return 0, err
		}
	}

	method := ch.Config["method"]
	if method == "" {
		method = "POST"
	}

	req, _ := http.NewRequestWithContext(ctx, method, ch.Config["url"], bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	// Parse extra headers if provided
	if ch.Config["headers_json"] != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(ch.Config["headers_json"]), &headers); err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	// Add HMAC signature if configured
	if ch.Config["signing_key"] != "" {
		h := hmac.New(sha256.New, []byte(ch.Config["signing_key"]))
		h.Write([]byte(body))
		signature := hex.EncodeToString(h.Sum(nil))
		req.Header.Set("X-Signature", signature)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (w *WebhookChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test webhook from FlowSight.",
		AlertKey:  "test-" + fmt.Sprint(time.Now().Unix()),
	}
	return w.Send(ctx, ch, msg)
}

// MQTTChannel publishes alerts to an MQTT broker (MQTT 3.1.1).
type MQTTChannel struct{}

func (m *MQTTChannel) Type() string  { return "mqtt" }
func (m *MQTTChannel) Label() string { return "MQTT" }

func (m *MQTTChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "broker_host", Label: "Broker Host", Type: "text", Required: true},
		{Key: "broker_port", Label: "Broker Port", Type: "number", Required: true, Help: "Typical: 1883 (plain) or 8883 (TLS)"},
		{Key: "topic", Label: "Topic", Type: "text", Required: true, Help: "E.g., flowsight/alerts/{severity}"},
		{Key: "username", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
		{Key: "qos", Label: "QoS", Type: "select", Options: []string{"0", "1", "2"}, Help: "Quality of Service; default: 0"},
		{Key: "use_tls", Label: "Use TLS", Type: "text", Help: "true/false"},
		{Key: "tls_skip_verify", Label: "Skip TLS Verification", Type: "text", Help: "true/false for self-signed certs"},
	}
}

func (m *MQTTChannel) Validate(config map[string]string) error {
	if config["broker_host"] == "" || config["broker_port"] == "" || config["topic"] == "" {
		return fmt.Errorf("broker_host, broker_port, and topic required")
	}
	return nil
}

func (m *MQTTChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	// TODO: Implement MQTT client in separate senders/mqtt/client.go
	// For now, return placeholder
	_ = payload

	return time.Since(start).Milliseconds(), fmt.Errorf("mqtt channel not yet implemented")
}

func (m *MQTTChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test MQTT message from FlowSight.",
	}
	return m.Send(ctx, ch, msg)
}

// RSSFeedChannel publishes alerts as an RSS feed (stored in-memory, token-authenticated).
type RSSFeedChannel struct{}

func (r *RSSFeedChannel) Type() string  { return "rss_feed" }
func (r *RSSFeedChannel) Label() string { return "RSS/Atom Feed" }

func (r *RSSFeedChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "feed_title", Label: "Feed Title", Type: "text", Required: true, Help: "E.g., 'FlowSight Alerts'"},
		{Key: "max_items", Label: "Max Items", Type: "number", Help: "Default: 100"},
		{Key: "token", Label: "Access Token", Type: "password", Secret: true, Help: "For feed URL auth"},
	}
}

func (r *RSSFeedChannel) Validate(config map[string]string) error {
	if config["feed_title"] == "" {
		return fmt.Errorf("feed_title required")
	}
	return nil
}

func (r *RSSFeedChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// RSS feed is read-only on this side; alerts are added to an in-memory store
	// that's served by GET /api/alerting/feed.xml
	// This is a no-op from the send perspective; the module handles storing

	return time.Since(start).Milliseconds(), nil
}

func (r *RSSFeedChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	// Test just returns ok; feed population is tested elsewhere
	return 0, nil
}

// AppriseLinkChannel parses Apprise-style URLs and routes to appropriate channels.
// Format: apprise://url1,url2,url3 (or individual apprise:// URLs)
type AppriseLinkChannel struct{}

func (a *AppriseLinkChannel) Type() string  { return "apprise" }
func (a *AppriseLinkChannel) Label() string { return "Apprise URL Import" }

func (a *AppriseLinkChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "apprise_urls", Label: "Apprise URLs", Type: "text", Required: true, Help: "Comma-separated apprise:// URLs"},
	}
}

func (a *AppriseLinkChannel) Validate(config map[string]string) error {
	if config["apprise_urls"] == "" {
		return fmt.Errorf("apprise_urls required")
	}

	// Validate that at least one valid apprise URL is provided
	urls := strings.Split(config["apprise_urls"], ",")
	validCount := 0
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if strings.HasPrefix(u, "apprise://") || strings.HasPrefix(u, "slack://") || strings.HasPrefix(u, "discord://") {
			validCount++
		}
	}

	if validCount == 0 {
		return fmt.Errorf("no valid apprise URLs found")
	}

	return nil
}

func (a *AppriseLinkChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	// Apprise URL parsing and delegation would happen here
	// For now, this is a placeholder showing the URL structure

	// Example mapping:
	// slack://webhook_id:token@token_c/token_b/token_a
	// discord://webhook_id:webhook_token
	// telegram://bot_token/chat_id
	// etc.

	// In a real implementation, we'd parse these and delegate to appropriate senders
	return 0, fmt.Errorf("apprise channel not yet implemented")
}

func (a *AppriseLinkChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test from FlowSight via Apprise.",
	}
	return a.Send(ctx, ch, msg)
}

// SMTPChannel (already defined in channels_email_sms_incident.go, included here for completeness)
// This is a reminder that SMTP is in that file
