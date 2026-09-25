package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
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

	// Expand topic template: {severity}, {module}, {category}
	topic := ch.Config["topic"]
	topic = strings.ReplaceAll(topic, "{severity}", msg.Severity)
	topic = strings.ReplaceAll(topic, "{module}", msg.Module)
	topic = strings.ReplaceAll(topic, "{category}", msg.Category)

	qos := 0
	if ch.Config["qos"] != "" {
		fmt.Sscanf(ch.Config["qos"], "%d", &qos)
	}

	// Create minimal MQTT 3.1.1 client
	client := &mqttClient{
		host:       ch.Config["broker_host"],
		port:       ch.Config["broker_port"],
		username:   ch.Config["username"],
		password:   ch.Config["password"],
		useTLS:     ch.Config["use_tls"] == "true",
		skipVerify: ch.Config["tls_skip_verify"] == "true",
	}

	err = client.connect(ctx)
	if err != nil {
		return 0, err
	}
	defer client.close()

	err = client.publish(ctx, topic, []byte(payload), byte(qos))
	if err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
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
	start := time.Now()

	// Parse Apprise URLs and send to each
	apprisesURLs := strings.Split(ch.Config["apprise_urls"], ",")
	lastErr := error(nil)

	for _, rawURL := range apprisesURLs {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		_, parsed, err := ParseAppriseURL(rawURL)
		if err != nil {
			lastErr = err
			continue
		}

		// For now, we just store the parsed config. In a real implementation,
		// we would delegate to the appropriate channel type handler.
		_ = parsed
	}

	return time.Since(start).Milliseconds(), lastErr
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

// ParseAppriseURL parses an Apprise-style URL and returns the channel type and config.
// Supported formats:
//   - slack://token_a/token_b/token_c
//   - discord://webhook_id/webhook_token
//   - tgram://bottoken/chatid (Telegram)
//   - pover://user@token (Pushover)
//   - ntfy://host/topic
//   - mailto://user:pass@host/recipient
//   - json://host/path
func ParseAppriseURL(u string) (typ string, cfg map[string]any, err error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return "", nil, err
	}

	cfg = make(map[string]any)

	switch parsed.Scheme {
	case "slack":
		// slack://TokenA/TokenB/TokenC
		// Host will be TokenA, Path will be /TokenB/TokenC
		cfg["token_a"] = parsed.Host
		pathParts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(pathParts) >= 2 {
			cfg["token_b"] = pathParts[0]
			cfg["token_c"] = pathParts[1]
		}
		return "slack", cfg, nil

	case "discord":
		// discord://webhook_id/webhook_token
		// Host will be webhook_id, Path will be /webhook_token
		cfg["webhook_id"] = parsed.Host
		pathParts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(pathParts) >= 1 {
			cfg["webhook_token"] = pathParts[0]
		}
		return "discord", cfg, nil

	case "tgram":
		// tgram://bottoken/chatid
		// Host will be bottoken, Path will be /chatid
		cfg["bot_token"] = parsed.Host
		pathParts := strings.Split(strings.TrimPrefix(parsed.Path, "/"), "/")
		if len(pathParts) >= 1 {
			cfg["chat_id"] = pathParts[0]
		}
		return "telegram", cfg, nil

	case "pover":
		// pover://user@token
		if parsed.User != nil {
			cfg["user"] = parsed.User.Username()
		}
		cfg["token"] = parsed.Host
		return "pushover", cfg, nil

	case "ntfy":
		// ntfy://host/topic
		cfg["host"] = parsed.Host
		cfg["topic"] = strings.TrimPrefix(parsed.Path, "/")
		return "ntfy", cfg, nil

	case "mailto":
		// mailto://user:pass@host/recipient
		cfg["host"] = parsed.Host
		if parsed.User != nil {
			cfg["username"] = parsed.User.Username()
			if pwd, ok := parsed.User.Password(); ok {
				cfg["password"] = pwd
			}
		}
		cfg["to"] = strings.TrimPrefix(parsed.Path, "/")
		return "smtp", cfg, nil

	case "json":
		// json://host/path
		cfg["host"] = parsed.Host
		cfg["path"] = parsed.Path
		return "webhook", cfg, nil

	default:
		return "", nil, fmt.Errorf("unsupported apprise scheme: %s", parsed.Scheme)
	}
}

// RenderRSS renders the alert feed as RSS 2.0 XML.
func RenderRSS(alerts []*Message, baseURL string) string {
	type RSSItem struct {
		Title       string `xml:"title"`
		Description string `xml:"description"`
		PubDate     string `xml:"pubDate"`
		Link        string `xml:"link"`
		Category    string `xml:"category"`
		GUID        string `xml:"guid"`
	}

	type RSS struct {
		XMLName xml.Name `xml:"rss"`
		Version string   `xml:"version,attr"`
		Channel struct {
			Title       string    `xml:"title"`
			Link        string    `xml:"link"`
			Description string    `xml:"description"`
			Items       []RSSItem `xml:"item"`
		} `xml:"channel"`
	}

	items := make([]RSSItem, 0)
	for _, alert := range alerts {
		item := RSSItem{
			Title:       alert.Title,
			Description: alert.Body,
			PubDate:     alert.Timestamp.Format(time.RFC1123Z),
			Link:        alert.Link,
			Category:    alert.Category,
			GUID:        alert.AlertKey,
		}
		items = append(items, item)
	}

	rss := RSS{Version: "2.0"}
	rss.Channel.Title = "FlowSight Alerts"
	rss.Channel.Link = baseURL
	rss.Channel.Description = "Real-time alerts from FlowSight"
	rss.Channel.Items = items

	b, _ := xml.MarshalIndent(rss, "", "  ")
	return fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s", string(b))
}

// mqttClient is a minimal MQTT 3.1.1 client.
type mqttClient struct {
	host       string
	port       string
	username   string
	password   string
	useTLS     bool
	skipVerify bool
	conn       net.Conn
	packetID   uint16
}

func (m *mqttClient) connect(ctx context.Context) error {
	addr := m.host + ":" + m.port

	var dialer net.Dialer
	dialer.Timeout = 5 * time.Second

	var err error
	if m.useTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: m.skipVerify,
		}
		m.conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		m.conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return err
	}

	// Send CONNECT packet
	packet := m.buildConnectPacket()
	_, err = m.conn.Write(packet)
	if err != nil {
		m.conn.Close()
		return err
	}

	// Read CONNACK
	buf := make([]byte, 4)
	m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = m.conn.Read(buf)
	if err != nil {
		m.conn.Close()
		return err
	}

	// Check CONNACK: buf[0] should be 0x20, buf[3] should be 0 (success)
	if buf[0] != 0x20 || buf[3] != 0 {
		m.conn.Close()
		return fmt.Errorf("mqtt connect failed: %d", buf[3])
	}

	return nil
}

func (m *mqttClient) publish(ctx context.Context, topic string, payload []byte, qos byte) error {
	packet := m.buildPublishPacket(topic, payload, qos)
	m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := m.conn.Write(packet)
	if err != nil {
		return err
	}

	// For QoS 1, wait for PUBACK
	if qos == 1 {
		m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		_, err = m.conn.Read(buf)
		if err != nil {
			return err
		}
		if buf[0] != 0x40 { // PUBACK type
			return fmt.Errorf("mqtt expected PUBACK, got %d", buf[0])
		}
	}

	return nil
}

func (m *mqttClient) close() error {
	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}

func (m *mqttClient) buildConnectPacket() []byte {
	var buf bytes.Buffer

	// Fixed header: MQTT Control Packet type = 1 (CONNECT)
	// Flags: bit 7 = User Name Flag, bit 6 = Password Flag, bit 5 = Will Retain,
	//        bit 4-2 = Will QoS, bit 1 = Will Flag, bit 0 = Clean Session
	connectFlags := byte(0x02) // Clean Session = 1

	if m.username != "" {
		connectFlags |= 0x80 // Username flag
	}
	if m.password != "" {
		connectFlags |= 0x40 // Password flag
	}

	// Variable header
	buf.WriteString("MQTT")     // Protocol name
	buf.WriteByte(0x04)         // Protocol level = 4
	buf.WriteByte(connectFlags) // Connect flags
	buf.WriteByte(0x00)         // Keep alive (high)
	buf.WriteByte(0x3c)         // Keep alive (low) = 60 seconds

	// Payload
	// Client ID
	clientID := "flowsight-" + fmt.Sprint(time.Now().UnixNano())
	buf.WriteByte(byte(len(clientID) >> 8))
	buf.WriteByte(byte(len(clientID)))
	buf.WriteString(clientID)

	// Username
	if m.username != "" {
		buf.WriteByte(byte(len(m.username) >> 8))
		buf.WriteByte(byte(len(m.username)))
		buf.WriteString(m.username)
	}

	// Password
	if m.password != "" {
		buf.WriteByte(byte(len(m.password) >> 8))
		buf.WriteByte(byte(len(m.password)))
		buf.WriteString(m.password)
	}

	payload := buf.Bytes()

	// Build fixed header
	var fixed bytes.Buffer
	fixed.WriteByte(0x10) // CONNECT type
	m.encodeRemainingLength(&fixed, len(payload))
	fixed.Write(payload)

	return fixed.Bytes()
}

func (m *mqttClient) buildPublishPacket(topic string, payload []byte, qos byte) []byte {
	var buf bytes.Buffer

	// Topic name
	buf.WriteByte(byte(len(topic) >> 8))
	buf.WriteByte(byte(len(topic)))
	buf.WriteString(topic)

	// Packet ID (for QoS > 0)
	if qos > 0 {
		m.packetID++
		buf.WriteByte(byte(m.packetID >> 8))
		buf.WriteByte(byte(m.packetID))
	}

	// Payload
	buf.Write(payload)

	varHeader := buf.Bytes()

	// Fixed header
	var fixed bytes.Buffer
	fixedHeaderByte := byte(0x30) // PUBLISH type
	fixedHeaderByte |= (qos << 1) // QoS
	fixed.WriteByte(fixedHeaderByte)

	m.encodeRemainingLength(&fixed, len(varHeader))
	fixed.Write(varHeader)

	return fixed.Bytes()
}

func (m *mqttClient) encodeRemainingLength(buf *bytes.Buffer, length int) {
	for {
		encodedByte := byte(length % 128)
		length /= 128
		if length > 0 {
			encodedByte |= 0x80
		}
		buf.WriteByte(encodedByte)
		if length == 0 {
			break
		}
	}
}
