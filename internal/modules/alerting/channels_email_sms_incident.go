package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// ==================== EMAIL CHANNELS ====================

// SMTPChannel sends via SMTP (STARTTLS or implicit TLS).
type SMTPChannel struct{}

func (s *SMTPChannel) Type() string  { return "smtp" }
func (s *SMTPChannel) Label() string { return "Email (SMTP)" }

func (s *SMTPChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "SMTP Host", Type: "text", Required: true, Help: "e.g., smtp.gmail.com"},
		{Key: "port", Label: "Port", Type: "number", Required: true, Help: "587 (STARTTLS) or 465 (implicit TLS)"},
		{Key: "user", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
		{Key: "tls_mode", Label: "TLS Mode", Type: "select", Options: []string{"starttls", "implicit", "none"}, Required: true},
	}
}

func (s *SMTPChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("host, port, from, and to required")
	}
	return nil
}

func (s *SMTPChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	// Parse recipients
	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []*mail.Address
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		pa, err := mail.ParseAddress(addr)
		if err != nil {
			continue
		}
		recipients = append(recipients, pa)
	}
	if len(recipients) == 0 {
		return 0, fmt.Errorf("no valid recipients")
	}

	// Build message
	var msgBuf bytes.Buffer
	msgBuf.WriteString("From: " + ch.Config["from"] + "\r\n")
	msgBuf.WriteString("To: ")
	for i, r := range recipients {
		if i > 0 {
			msgBuf.WriteString(", ")
		}
		msgBuf.WriteString(r.String())
	}
	msgBuf.WriteString("\r\n")
	msgBuf.WriteString("Subject: [" + strings.ToUpper(msg.Severity[:1]) + "] " + msg.Title + "\r\n")
	msgBuf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msgBuf.WriteString("\r\n")
	msgBuf.WriteString(body)

	// Send via SMTP
	addr := net.JoinHostPort(ch.Config["host"], ch.Config["port"])
	tlsMode := ch.Config["tls_mode"]
	tlsConfig := &tls.Config{ServerName: ch.Config["host"]}

	var client *smtp.Client
	var err error

	if tlsMode == "implicit" {
		// Implicit TLS
		tlsConn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return 0, fmt.Errorf("dial failed: %w", err)
		}
		defer tlsConn.Close()

		client, err = smtp.NewClient(tlsConn, ch.Config["host"])
		if err != nil {
			return 0, fmt.Errorf("client failed: %w", err)
		}
	} else {
		// Plain or STARTTLS
		plainConn, err := net.Dial("tcp", addr)
		if err != nil {
			return 0, fmt.Errorf("dial failed: %w", err)
		}
		defer plainConn.Close()

		client, err = smtp.NewClient(plainConn, ch.Config["host"])
		if err != nil {
			return 0, fmt.Errorf("client failed: %w", err)
		}

		if tlsMode == "starttls" {
			if ok, _ := client.Extension("STARTTLS"); ok {
				if err := client.StartTLS(tlsConfig); err != nil {
					client.Close()
					return 0, fmt.Errorf("starttls failed: %w", err)
				}
			}
		}
	}
	defer client.Close()

	// Authenticate
	if ch.Config["user"] != "" && ch.Config["password"] != "" {
		auth := smtp.PlainAuth("", ch.Config["user"], ch.Config["password"], ch.Config["host"])
		if err := client.Auth(auth); err != nil {
			return 0, fmt.Errorf("auth failed: %w", err)
		}
	}

	// Send message
	if err := client.Mail(ch.Config["from"]); err != nil {
		return 0, err
	}

	toAddrsStr := make([]string, len(recipients))
	for i, r := range recipients {
		toAddrsStr[i] = r.Address
	}

	for _, recipient := range toAddrsStr {
		if err := client.Rcpt(recipient); err != nil {
			return 0, err
		}
	}

	w, err := client.Data()
	if err != nil {
		return 0, err
	}
	_, _ = w.Write(msgBuf.Bytes())
	w.Close()

	if err := client.Quit(); err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SMTPChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Email",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test email from your FlowSight alerting system.",
	}
	return s.Send(ctx, ch, msg)
}

// SendGridChannel sends via SendGrid API.
type SendGridChannel struct{}

func (s *SendGridChannel) Type() string  { return "sendgrid" }
func (s *SendGridChannel) Label() string { return "SendGrid" }

func (s *SendGridChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients (comma-separated)", Type: "text", Required: true},
	}
}

func (s *SendGridChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, from, and to required")
	}
	return nil
}

func (s *SendGridChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	toAddrs := strings.Split(ch.Config["to"], ",")
	var recipients []map[string]string
	for _, addr := range toAddrs {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			recipients = append(recipients, map[string]string{"email": addr})
		}
	}

	payload := map[string]interface{}{
		"personalizations": []map[string]interface{}{
			{
				"to": recipients,
			},
		},
		"from": map[string]string{
			"email": ch.Config["from"],
		},
		"subject": "[" + msg.Severity + "] " + msg.Title,
		"content": []map[string]string{
			{
				"type":  "text/plain",
				"value": body,
			},
		},
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("sendgrid returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SendGridChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test email from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

// Placeholder implementations for other email channels
type MailgunChannel struct{}

func (m *MailgunChannel) Type() string  { return "mailgun" }
func (m *MailgunChannel) Label() string { return "Mailgun" }
func (m *MailgunChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "domain", Label: "Domain", Type: "text", Required: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients", Type: "text", Required: true},
	}
}
func (m *MailgunChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["domain"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, domain, from, and to required")
	}
	return nil
}
func (m *MailgunChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("mailgun channel not yet implemented")
}
func (m *MailgunChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("mailgun channel not yet implemented")
}

type AMAZONSESChannel struct{}

func (a *AMAZONSESChannel) Type() string  { return "amazon_ses" }
func (a *AMAZONSESChannel) Label() string { return "Amazon SES" }
func (a *AMAZONSESChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "access_key", Label: "Access Key", Type: "password", Secret: true, Required: true},
		{Key: "secret_key", Label: "Secret Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "text", Required: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients", Type: "text", Required: true},
	}
}
func (a *AMAZONSESChannel) Validate(config map[string]string) error {
	if config["access_key"] == "" || config["secret_key"] == "" || config["region"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (a *AMAZONSESChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("amazon_ses channel not yet implemented")
}
func (a *AMAZONSESChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("amazon_ses channel not yet implemented")
}

type PostmarkChannel struct{}

func (p *PostmarkChannel) Type() string  { return "postmark" }
func (p *PostmarkChannel) Label() string { return "Postmark" }
func (p *PostmarkChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from", Label: "From Address", Type: "text", Required: true},
		{Key: "to", Label: "Recipients", Type: "text", Required: true},
	}
}
func (p *PostmarkChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from"] == "" || config["to"] == "" {
		return fmt.Errorf("api_key, from, and to required")
	}
	return nil
}
func (p *PostmarkChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("postmark channel not yet implemented")
}
func (p *PostmarkChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("postmark channel not yet implemented")
}

// ==================== SMS/VOICE CHANNELS ====================

// TwilioChannel sends SMS and voice calls via Twilio.
type TwilioChannel struct{}

func (t *TwilioChannel) Type() string  { return "twilio" }
func (t *TwilioChannel) Label() string { return "Twilio" }

func (t *TwilioChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "account_sid", Label: "Account SID", Type: "text", Secret: true, Required: true},
		{Key: "auth_token", Label: "Auth Token", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true, Help: "E.164 format: +1234567890"},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true, Help: "E.164 format: +1234567890"},
		{Key: "mode", Label: "Mode", Type: "select", Options: []string{"sms", "voice"}, Required: true},
	}
}

func (t *TwilioChannel) Validate(config map[string]string) error {
	if config["account_sid"] == "" || config["auth_token"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}

func (t *TwilioChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SMSFormatter{}
	body, _ := formatter.Format(msg)

	params := url.Values{
		"From": {ch.Config["from_number"]},
		"To":   {ch.Config["to_number"]},
		"Body": {body},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", ch.Config["account_sid"])
	req, _ := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(params.Encode()))
	req.SetBasicAuth(ch.Config["account_sid"], ch.Config["auth_token"])
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("twilio returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TwilioChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS from FlowSight alerting.",
	}
	return t.Send(ctx, ch, msg)
}

// Placeholder SMS implementations
type VonageChannel struct{}

func (v *VonageChannel) Type() string  { return "vonage" }
func (v *VonageChannel) Label() string { return "Vonage/Nexmo" }
func (v *VonageChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "text", Required: true},
		{Key: "api_secret", Label: "API Secret", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (v *VonageChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["api_secret"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (v *VonageChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("vonage channel not yet implemented")
}
func (v *VonageChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("vonage channel not yet implemented")
}

type TelnyxChannel struct{}

func (t *TelnyxChannel) Type() string  { return "telnyx" }
func (t *TelnyxChannel) Label() string { return "Telnyx" }
func (t *TelnyxChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (t *TelnyxChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (t *TelnyxChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("telnyx channel not yet implemented")
}
func (t *TelnyxChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("telnyx channel not yet implemented")
}

type AWSSNSChannel struct{}

func (a *AWSSNSChannel) Type() string  { return "aws_sns" }
func (a *AWSSNSChannel) Label() string { return "AWS SNS" }
func (a *AWSSNSChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "access_key", Label: "Access Key", Type: "password", Secret: true, Required: true},
		{Key: "secret_key", Label: "Secret Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "text", Required: true},
		{Key: "topic_arn", Label: "Topic ARN", Type: "text", Required: true},
	}
}
func (a *AWSSNSChannel) Validate(config map[string]string) error {
	if config["access_key"] == "" || config["secret_key"] == "" || config["region"] == "" || config["topic_arn"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (a *AWSSNSChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("aws_sns channel not yet implemented")
}
func (a *AWSSNSChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("aws_sns channel not yet implemented")
}

type PlivoChannel struct{}

func (p *PlivoChannel) Type() string  { return "plivo" }
func (p *PlivoChannel) Label() string { return "Plivo" }
func (p *PlivoChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "auth_id", Label: "Auth ID", Type: "text", Required: true},
		{Key: "auth_token", Label: "Auth Token", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (p *PlivoChannel) Validate(config map[string]string) error {
	if config["auth_id"] == "" || config["auth_token"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (p *PlivoChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("plivo channel not yet implemented")
}
func (p *PlivoChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("plivo channel not yet implemented")
}

type MessageBirdChannel struct{}

func (m *MessageBirdChannel) Type() string  { return "messagebird" }
func (m *MessageBirdChannel) Label() string { return "MessageBird" }
func (m *MessageBirdChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (m *MessageBirdChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (m *MessageBirdChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("messagebird channel not yet implemented")
}
func (m *MessageBirdChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("messagebird channel not yet implemented")
}

type ClickSendChannel struct{}

func (c *ClickSendChannel) Type() string  { return "clicksend" }
func (c *ClickSendChannel) Label() string { return "ClickSend" }
func (c *ClickSendChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "username", Label: "Username", Type: "text", Required: true},
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (c *ClickSendChannel) Validate(config map[string]string) error {
	if config["username"] == "" || config["api_key"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (c *ClickSendChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("clicksend channel not yet implemented")
}
func (c *ClickSendChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("clicksend channel not yet implemented")
}

// ==================== INCIDENT/ON-CALL CHANNELS ====================

// PagerDutyChannel sends via PagerDuty Events v2 API.
type PagerDutyChannel struct{}

func (p *PagerDutyChannel) Type() string  { return "pagerduty" }
func (p *PagerDutyChannel) Label() string { return "PagerDuty" }

func (p *PagerDutyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "routing_key", Label: "Routing Key", Type: "password", Secret: true, Required: true, Help: "From Integration > PagerDuty Events Integration"},
	}
}

func (p *PagerDutyChannel) Validate(config map[string]string) error {
	if config["routing_key"] == "" {
		return fmt.Errorf("routing_key required")
	}
	return nil
}

func (p *PagerDutyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	severity := "error"
	if msg.Severity == "critical" {
		severity = "critical"
	} else if msg.Severity == "info" {
		severity = "info"
	}

	payload := map[string]interface{}{
		"routing_key":  ch.Config["routing_key"],
		"event_action": "trigger",
		"dedup_key":    msg.AlertKey,
		"payload": map[string]interface{}{
			"summary":   msg.Title,
			"severity":  severity,
			"source":    msg.Module,
			"timestamp": msg.Timestamp.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"category": msg.Category,
				"evidence": msg.Evidence,
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		payload["payload"].(map[string]interface{})["custom_details"].(map[string]interface{})["device"] = msg.Device.IP
	}

	b, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("pagerduty returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (p *PagerDutyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		AlertKey:  "test-alert-" + fmt.Sprint(time.Now().Unix()),
		Body:      "Test incident from FlowSight.",
	}
	return p.Send(ctx, ch, msg)
}

// Placeholder incident channel implementations
type OpsgenieChannel struct{}

func (o *OpsgenieChannel) Type() string  { return "opsgenie" }
func (o *OpsgenieChannel) Label() string { return "Opsgenie" }
func (o *OpsgenieChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
	}
}
func (o *OpsgenieChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" {
		return fmt.Errorf("api_key required")
	}
	return nil
}
func (o *OpsgenieChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("opsgenie channel not yet implemented")
}
func (o *OpsgenieChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("opsgenie channel not yet implemented")
}

type SplunkOnCallChannel struct{}

func (s *SplunkOnCallChannel) Type() string  { return "splunk_oncall" }
func (s *SplunkOnCallChannel) Label() string { return "Splunk On-Call" }
func (s *SplunkOnCallChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "routing_key", Label: "Routing Key", Type: "password", Secret: true, Required: true},
	}
}
func (s *SplunkOnCallChannel) Validate(config map[string]string) error {
	if config["routing_key"] == "" {
		return fmt.Errorf("routing_key required")
	}
	return nil
}
func (s *SplunkOnCallChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("splunk_oncall channel not yet implemented")
}
func (s *SplunkOnCallChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("splunk_oncall channel not yet implemented")
}

type SquadcastChannel struct{}

func (s *SquadcastChannel) Type() string  { return "squadcast" }
func (s *SquadcastChannel) Label() string { return "Squadcast" }
func (s *SquadcastChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (s *SquadcastChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (s *SquadcastChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("squadcast channel not yet implemented")
}
func (s *SquadcastChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("squadcast channel not yet implemented")
}

type IncidentIOChannel struct{}

func (i *IncidentIOChannel) Type() string  { return "incident_io" }
func (i *IncidentIOChannel) Label() string { return "incident.io" }
func (i *IncidentIOChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (i *IncidentIOChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (i *IncidentIOChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("incident_io channel not yet implemented")
}
func (i *IncidentIOChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("incident_io channel not yet implemented")
}

type XMattersChannel struct{}

func (x *XMattersChannel) Type() string  { return "xmatters" }
func (x *XMattersChannel) Label() string { return "xMatters" }
func (x *XMattersChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (x *XMattersChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (x *XMattersChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("xmatters channel not yet implemented")
}
func (x *XMattersChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("xmatters channel not yet implemented")
}

type ZendutySChannel struct{}

func (z *ZendutySChannel) Type() string  { return "zenduty" }
func (z *ZendutySChannel) Label() string { return "Zenduty" }
func (z *ZendutySChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (z *ZendutySChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (z *ZendutySChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("zenduty channel not yet implemented")
}
func (z *ZendutySChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("zenduty channel not yet implemented")
}

type BetterStackChannel struct{}

func (b *BetterStackChannel) Type() string  { return "betterstack" }
func (b *BetterStackChannel) Label() string { return "Better Stack" }
func (b *BetterStackChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (b *BetterStackChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (b *BetterStackChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("betterstack channel not yet implemented")
}
func (b *BetterStackChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("betterstack channel not yet implemented")
}
