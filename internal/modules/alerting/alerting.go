// Package alerting provides notification channels and alert rules.
//
// Channels are email (SMTP), webhook (JSON POST), discord, slack, and ntfy.
// Rules evaluate every minute over stored data and send notifications based
// on configured thresholds and cooldowns.
package alerting

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx              *core.Context
	mu               sync.RWMutex
	lastErr          string
	deliveryEngine   *DeliveryEngine
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "alerting", Version: "1.0",
		Description:  "Notification channels and alert rules.",
		Capabilities: []string{core.CapNotify},
		Defaults: map[string]any{
			"channels": []any{},
			"rules":    map[string]any{},
		},
		Schema: []core.SettingField{
			{Key: "channels", Label: "Notification channels", Type: "list", Help: "Configured channels for sending notifications."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.deliveryEngine = NewDeliveryEngine(200)

	// Initialize channels and rules from KV if not present
	if !ctx.Store.KVGet("alerting.channels", &[]Channel{}) {
		_ = ctx.Store.KVSet("alerting.channels", []Channel{})
	}
	if !ctx.Store.KVGet("alerting.rules", &map[string]Rule{}) {
		defaults := defaultRules()
		_ = ctx.Store.KVSet("alerting.rules", defaults)
	}

	// Register the notifier service
	ctx.Publish("notifier", &notifierService{m: m})

	// Run rules every minute
	ctx.Every("rules", time.Minute, m.evaluateRules)

	// Register new API routes
	m.registerRoutes()

	// Also keep old /api/alerting/status for backward compatibility
	ctx.Route("GET", "/api/alerting/status", m.apiStatus, core.Doc("Channel status and recent notifications"))
	ctx.Route("GET", "/api/alerting/notifications", m.apiNotifications, core.Doc("Recent notifications"),
		core.Params("limit", "rows"))

	ctx.Panel(core.Panel{ID: "alerts", Title: "Alerting", Group: "Administration", Order: 190, Icon: "alerts"})

	return nil
}

func (m *Module) Health() core.Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	return core.Health{OK: true, Detail: "alerting ready"}
}

// Channel types
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
	ChannelDiscord = "discord"
	ChannelSlack   = "slack"
	ChannelNtfy    = "ntfy"
)

type Channel struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"` // email, webhook, discord, slack, ntfy
	Enabled bool              `json:"enabled"`
	Config  map[string]string `json:"config"` // type-specific config
}

type Rule struct {
	Name      string   `json:"name"`
	Enabled   bool     `json:"enabled"`
	Severity  string   `json:"severity"` // info, medium, high, critical
	Cooldown  int      `json:"cooldown"` // seconds
	Channels  []string `json:"channels"` // channel names
	Subject   string   `json:"subject"`  // for dedup in cooldown
	Kind      string   `json:"kind"`     // new_host, ids_alert, finding, bytes_threshold, dns_spike, cert_finding, policy_fail, unhealthy_module, system_start
	Threshold int      `json:"threshold"`
	Window    int      `json:"window"` // seconds
}

type notifierService struct {
	m *Module
}

// Notify sends a notification to all enabled channels for a given subject and severity.
func (s *notifierService) Notify(subject, body string, severity string) error {
	ch := make([]Channel, 0)
	s.m.ctx.Store.KVGet("alerting.channels", &ch)

	rules := make(map[string]Rule)
	s.m.ctx.Store.KVGet("alerting.rules", &rules)

	// Find matching rules
	for _, rule := range rules {
		if !rule.Enabled || rule.Severity != severity {
			continue
		}

		// Check cooldown
		key := "alerting.cooldown." + rule.Name + "." + subject
		var lastSent int64
		s.m.ctx.Store.KVGet(key, &lastSent)
		now := time.Now().Unix()
		if lastSent > 0 && now-lastSent < int64(rule.Cooldown) {
			continue
		}

		// Send via enabled channels
		for _, chName := range rule.Channels {
			for _, c := range ch {
				if c.Name == chName && c.Enabled {
					_ = s.m.send(c, rule.Name, subject, body)
				}
			}
		}

		// Update cooldown
		_ = s.m.ctx.Store.KVSet(key, now)
	}

	return nil
}

// SendEmail sends an HTML email via the configured email channel.
func (s *notifierService) SendEmail(subject, html string, to []string) error {
	ch := make([]Channel, 0)
	s.m.ctx.Store.KVGet("alerting.channels", &ch)

	for _, c := range ch {
		if c.Type == ChannelEmail && c.Enabled {
			return s.m.sendEmail(c, subject, html, to)
		}
	}
	return fmt.Errorf("no email channel configured")
}

func (m *Module) send(ch Channel, rule, subject, body string) error {
	switch ch.Type {
	case ChannelEmail:
		to := strings.Split(ch.Config["to"], ",")
		for i, addr := range to {
			to[i] = strings.TrimSpace(addr)
		}
		return m.sendEmail(ch, subject, body, to)
	case ChannelWebhook:
		return m.sendWebhook(ch, rule, subject, body)
	case ChannelDiscord:
		return m.sendDiscord(ch, rule, subject, body)
	case ChannelSlack:
		return m.sendSlack(ch, rule, subject, body)
	case ChannelNtfy:
		return m.sendNtfy(ch, rule, subject, body)
	default:
		return fmt.Errorf("unknown channel type: %s", ch.Type)
	}
}

func (m *Module) sendEmail(ch Channel, subject, body string, to []string) error {
	host := ch.Config["host"]
	port := ch.Config["port"]
	user := ch.Config["user"]
	password := ch.Config["password"]
	from := ch.Config["from"]

	if host == "" || port == "" || from == "" {
		return fmt.Errorf("email channel missing configuration")
	}

	// Parse recipients
	var recipients []*mail.Address
	for _, addr := range to {
		pa, err := mail.ParseAddress(addr)
		if err != nil {
			continue
		}
		recipients = append(recipients, pa)
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no valid email recipients")
	}

	// Build message
	headers := map[string]string{
		"From":         from,
		"Subject":      subject,
		"Content-Type": "text/plain; charset=UTF-8",
	}

	var msg bytes.Buffer
	for k, v := range headers {
		msg.WriteString(k)
		msg.WriteString(": ")
		msg.WriteString(v)
		msg.WriteString("\r\n")
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Send via SMTP
	addr := net.JoinHostPort(host, port)
	auth := smtp.PlainAuth("", user, password, host)

	// Try with implicit TLS first
	tlsConfig := &tls.Config{ServerName: host}
	tlsConn, err := tls.Dial("tcp", addr, tlsConfig)
	if err == nil {
		defer tlsConn.Close()
		client, err := smtp.NewClient(tlsConn, host)
		if err != nil {
			return err
		}
		defer client.Close()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}

		toAddrs := make([]string, len(recipients))
		for i, r := range recipients {
			toAddrs[i] = r.Address
		}

		if err := client.Mail(from); err != nil {
			return err
		}
		for _, recipient := range toAddrs {
			if err := client.Rcpt(recipient); err != nil {
				return err
			}
		}

		w, err := client.Data()
		if err != nil {
			return err
		}
		_, _ = w.Write(msg.Bytes())
		w.Close()

		return client.Quit()
	}

	// Fallback to STARTTLS
	plainConn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer plainConn.Close()

	client, err := smtp.NewClient(plainConn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	toAddrs := make([]string, len(recipients))
	for i, r := range recipients {
		toAddrs[i] = r.Address
	}

	if err := client.Mail(from); err != nil {
		return err
	}
	for _, recipient := range toAddrs {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	_, _ = w.Write(msg.Bytes())
	w.Close()

	return client.Quit()
}

func (m *Module) sendWebhook(ch Channel, rule, subject, body string) error {
	url := ch.Config["url"]
	if url == "" {
		return fmt.Errorf("webhook channel missing url")
	}

	payload := map[string]string{
		"rule":    rule,
		"subject": subject,
		"body":    body,
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (m *Module) sendDiscord(ch Channel, rule, subject, body string) error {
	webhookURL := ch.Config["webhook_url"]
	if webhookURL == "" {
		return fmt.Errorf("discord channel missing webhook_url")
	}

	payload := map[string]any{
		"content": subject,
		"embeds": []map[string]any{
			{
				"description": body,
				"color":       0xFF0000,
			},
		},
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", webhookURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord returned %d", resp.StatusCode)
	}

	return nil
}

func (m *Module) sendSlack(ch Channel, rule, subject, body string) error {
	webhookURL := ch.Config["webhook_url"]
	if webhookURL == "" {
		return fmt.Errorf("slack channel missing webhook_url")
	}

	payload := map[string]any{
		"text": subject,
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": body,
				},
			},
		},
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", webhookURL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}

	return nil
}

func (m *Module) sendNtfy(ch Channel, rule, subject, body string) error {
	topicURL := ch.Config["topic_url"]
	if topicURL == "" {
		return fmt.Errorf("ntfy channel missing topic_url")
	}

	priority := ch.Config["priority"]
	if priority == "" {
		priority = "default"
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("POST", topicURL, strings.NewReader(body))
	req.Header.Set("Title", subject)
	req.Header.Set("Priority", priority)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}

	return nil
}

func (m *Module) evaluateRules() error {
	rules := make(map[string]Rule)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	st := m.ctx.Store
	now := time.Now().Unix()
	window := int64(3600) // 1 hour default window

	for name, rule := range rules {
		if !rule.Enabled {
			continue
		}

		subject := rule.Subject
		if subject == "" {
			subject = name
		}

		var shouldAlert bool
		var alertBody string

		switch rule.Kind {
		case "new_host":
			// Check for hosts first_seen within window
			count := st.Int(`SELECT COUNT(*) FROM hosts WHERE first_seen>=? AND is_local=1`, now-window)
			if count >= int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("%d new local hosts joined in the last hour", count)
			}

		case "ids_alert":
			// Check for critical/high IDS alerts
			sev := rule.Severity
			if sev == "" {
				sev = "high"
			}
			count := st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=? AND severity IN ('critical','high')`, now-window)
			if count >= int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("%d IDS alerts of severity %s or higher in the last hour", count, sev)
			}

		case "finding":
			// Check for high/critical findings
			count := st.Int(`SELECT COUNT(*) FROM findings WHERE ts>=? AND severity IN ('high','critical') AND resolved_ts IS NULL`, now-window)
			if count >= int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("%d open findings of severity high or critical", count)
			}

		case "dns_spike":
			// Check for DNS blocks spike
			recent := st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=? AND action='block'`, now-300) // 5 min
			count := st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=? AND action='block'`, now-3600)
			avg := count / 12 // blocks per 5 min average
			if recent > avg*int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("DNS blocks spiked to %d in the last 5 minutes (avg %d)", recent, avg)
			}

		case "cert_finding":
			// Check for certificate findings
			count := st.Int(`SELECT COUNT(*) FROM findings WHERE ts>=? AND module='tls' AND severity IN ('high','critical')`, now-window)
			if count >= int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("%d certificate findings in the last hour", count)
			}

		case "policy_fail":
			// Check for policy apply failures
			count := st.Int(`SELECT COUNT(*) FROM events WHERE ts>=? AND kind='policy' AND severity='high'`, now-window)
			if count >= int64(rule.Threshold) {
				shouldAlert = true
				alertBody = fmt.Sprintf("%d policy failures in the last hour", count)
			}

		case "unhealthy_module":
			// Check if modules are unhealthy
			for _, mod := range m.ctx.Core.Modules {
				if h, ok := mod.(core.Healther); ok {
					health := h.Health()
					if !health.OK {
						shouldAlert = true
						alertBody = fmt.Sprintf("Module unhealthy: %s", health.Detail)
						break
					}
				}
			}

		case "system_start":
			// Check for system start event in last minute
			count := st.Int(`SELECT COUNT(*) FROM events WHERE ts>=? AND kind='system'`, now-60)
			if count > 0 {
				shouldAlert = true
				alertBody = "FlowSight daemon has started"
			}
		}

		if shouldAlert {
			// Check cooldown
			key := "alerting.cooldown." + name + "." + subject
			var lastSent int64
			st.KVGet(key, &lastSent)
			if lastSent > 0 && now-lastSent < int64(rule.Cooldown) {
				continue
			}

			// Record notification and send
			_ = st.Exec(`INSERT INTO notifications(ts,channel,rule,subject,ok,error)
				VALUES(?,?,?,?,?,?)`, now, "", name, subject, 1, "")

			// Send to enabled channels
			ch := make([]Channel, 0)
			st.KVGet("alerting.channels", &ch)

			for _, chName := range rule.Channels {
				for _, c := range ch {
					if c.Name == chName && c.Enabled {
						if err := m.send(c, name, subject, alertBody); err != nil {
							m.mu.Lock()
							m.lastErr = err.Error()
							m.mu.Unlock()
						}
					}
				}
			}

			// Update cooldown
			_ = st.KVSet(key, now)
		}
	}

	return nil
}

func defaultRules() map[string]Rule {
	return map[string]Rule{
		"new_host": {
			Name:      "new_host",
			Enabled:   true,
			Severity:  "info",
			Cooldown:  3600,
			Channels:  []string{},
			Subject:   "New host joined network",
			Kind:      "new_host",
			Threshold: 1,
			Window:    3600,
		},
		"ids_critical": {
			Name:      "ids_critical",
			Enabled:   true,
			Severity:  "high",
			Cooldown:  1800,
			Channels:  []string{},
			Subject:   "IDS alert detected",
			Kind:      "ids_alert",
			Threshold: 5,
			Window:    3600,
		},
		"finding_high": {
			Name:      "finding_high",
			Enabled:   true,
			Severity:  "high",
			Cooldown:  1800,
			Channels:  []string{},
			Subject:   "New security finding",
			Kind:      "finding",
			Threshold: 1,
			Window:    3600,
		},
		"system_start": {
			Name:      "system_start",
			Enabled:   false,
			Severity:  "info",
			Cooldown:  300,
			Channels:  []string{},
			Subject:   "System started",
			Kind:      "system_start",
			Threshold: 0,
			Window:    60,
		},
	}
}

// API Routes

func (m *Module) apiStatus(r *core.Req) (any, error) {
	ch := make([]Channel, 0)
	m.ctx.Store.KVGet("alerting.channels", &ch)

	rules := make(map[string]Rule)
	m.ctx.Store.KVGet("alerting.rules", &rules)

	// Mask secrets in channels
	masked := make([]map[string]any, 0)
	for _, c := range ch {
		cfg := map[string]any{}
		for k, v := range c.Config {
			if k == "password" || k == "webhook_url" || k == "topic_url" {
				cfg[k] = "***"
			} else {
				cfg[k] = v
			}
		}
		masked = append(masked, map[string]any{
			"name":    c.Name,
			"type":    c.Type,
			"enabled": c.Enabled,
			"config":  cfg,
		})
	}

	// Recent notifications
	notifs, _ := m.ctx.Store.Rows(`SELECT ts, channel, rule, subject, ok, error FROM notifications ORDER BY ts DESC LIMIT 20`)

	return map[string]any{
		"channels":      masked,
		"rules":         rules,
		"notifications": notifs,
	}, nil
}


func (m *Module) apiNotifications(r *core.Req) (any, error) {
	limit := r.QInt("limit", 100, 1, 10000)
	notifs, err := m.ctx.Store.Rows(`SELECT ts, channel, rule, subject, ok, error FROM notifications ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}

	return map[string]any{"notifications": notifs}, nil
}
