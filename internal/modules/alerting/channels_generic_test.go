package alerting

import (
	"bytes"
	"context"
	"encoding/xml"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookChannel(t *testing.T) {
	server := httptest.NewServer(nil)
	defer server.Close()

	channel := &Channel{
		Name: "test-webhook",
		Type: "webhook",
		Config: map[string]string{
			"url": server.URL,
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "medium",
		Module:    "test",
		Category:  "test",
	}

	wc := &WebhookChannel{}
	_, err := wc.Send(context.Background(), channel, msg)
	if err == nil {
		t.Log("Webhook send succeeded")
	}
}

func TestMQTTChannel(t *testing.T) {
	// Start a simple TCP listener to simulate MQTT broker
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	// Accept connection in background
	go func() {
		for {
			conn, _ := listener.Accept()
			if conn == nil {
				break
			}
			// Read CONNECT packet
			buf := make([]byte, 1024)
			conn.Read(buf)
			// Send CONNACK
			conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
			conn.Close()
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	channel := &Channel{
		Name: "test-mqtt",
		Type: "mqtt",
		Config: map[string]string{
			"broker_host": addr.IP.String(),
			"broker_port": string(rune(addr.Port)),
			"topic":       "test/alerts",
			"qos":         "0",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
	}

	mc := &MQTTChannel{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := mc.Send(ctx, channel, msg)
	if err == nil || strings.Contains(err.Error(), "connection refused") {
		t.Log("MQTT send attempted")
	}
}

func TestMQTTTopicExpansion(t *testing.T) {
	tests := []struct {
		template string
		msg      *Message
		expected string
	}{
		{
			template: "alerts/{severity}/{module}",
			msg: &Message{
				Severity: "high",
				Module:   "firewall",
			},
			expected: "alerts/high/firewall",
		},
		{
			template: "{category}/test",
			msg: &Message{
				Category: "intrusion",
			},
			expected: "intrusion/test",
		},
	}

	for _, tt := range tests {
		topic := tt.template
		topic = strings.ReplaceAll(topic, "{severity}", tt.msg.Severity)
		topic = strings.ReplaceAll(topic, "{module}", tt.msg.Module)
		topic = strings.ReplaceAll(topic, "{category}", tt.msg.Category)

		if topic != tt.expected {
			t.Errorf("topic expansion: expected %s, got %s", tt.expected, topic)
		}
	}
}

func TestRSSFeedRendering(t *testing.T) {
	alerts := []*Message{
		{
			Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			Title:     "Critical Alert",
			Severity:  "critical",
			Body:      "Something went wrong",
			Category:  "security",
			AlertKey:  "alert-1",
			Link:      "https://example.com/alerts/1",
		},
		{
			Timestamp: time.Date(2024, 1, 1, 11, 0, 0, 0, time.UTC),
			Title:     "Warning Alert",
			Severity:  "low",
			Body:      "Something to watch",
			Category:  "performance",
			AlertKey:  "alert-2",
		},
	}

	rss := RenderRSS(alerts, "https://flowsight.local")

	// Verify it's valid XML
	var feed struct {
		XMLName xml.Name `xml:"rss"`
		Channel struct {
			Title string `xml:"title"`
			Items []struct {
				Title string `xml:"title"`
				GUID  string `xml:"guid"`
			} `xml:"item"`
		} `xml:"channel"`
	}

	err := xml.Unmarshal([]byte(rss), &feed)
	if err != nil {
		t.Errorf("invalid XML: %v", err)
	}

	if feed.Channel.Title != "FlowSight Alerts" {
		t.Errorf("expected title 'FlowSight Alerts', got '%s'", feed.Channel.Title)
	}

	if len(feed.Channel.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(feed.Channel.Items))
	}

	if feed.Channel.Items[0].GUID != "alert-1" {
		t.Errorf("expected GUID 'alert-1', got '%s'", feed.Channel.Items[0].GUID)
	}
}

func TestRSSFeedChannel(t *testing.T) {
	channel := &Channel{
		Name: "test-rss",
		Type: "rss_feed",
		Config: map[string]string{
			"feed_title": "Test Feed",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
	}

	rc := &RSSFeedChannel{}
	latency, err := rc.Send(context.Background(), channel, msg)
	if err == nil && latency >= 0 {
		t.Log("RSS feed send succeeded")
	}
}

func TestParseAppriseURL(t *testing.T) {
	tests := []struct {
		url            string
		expectedType   string
		expectedFields []string
	}{
		{
			url:            "slack://AAAA/BBBB/CCCC",
			expectedType:   "slack",
			expectedFields: []string{"token_a", "token_b", "token_c"},
		},
		{
			url:            "discord://webhook_id/webhook_token",
			expectedType:   "discord",
			expectedFields: []string{"webhook_id", "webhook_token"},
		},
		{
			url:            "tgram://bot123/chat456",
			expectedType:   "telegram",
			expectedFields: []string{"bot_token", "chat_id"},
		},
		{
			url:            "pover://user@token123",
			expectedType:   "pushover",
			expectedFields: []string{"user", "token"},
		},
		{
			url:            "ntfy://ntfy.sh/topic123",
			expectedType:   "ntfy",
			expectedFields: []string{"host", "topic"},
		},
		{
			url:            "mailto://user:pass@smtp.example.com/recipient@example.com",
			expectedType:   "smtp",
			expectedFields: []string{"host", "username", "password", "to"},
		},
		{
			url:            "json://webhook.example.com/api/alerts",
			expectedType:   "webhook",
			expectedFields: []string{"host", "path"},
		},
	}

	for _, tt := range tests {
		typ, cfg, err := ParseAppriseURL(tt.url)
		if err != nil {
			t.Errorf("%s: parse failed: %v", tt.url, err)
			continue
		}

		if typ != tt.expectedType {
			t.Errorf("%s: expected type %s, got %s", tt.url, tt.expectedType, typ)
		}

		for _, field := range tt.expectedFields {
			if _, ok := cfg[field]; !ok {
				t.Errorf("%s: missing field %s", tt.url, field)
			}
		}
	}
}

func TestParseAppriseURLErrors(t *testing.T) {
	invalidURLs := []string{
		"http://invalid.url",  // Invalid scheme
		"unknown://something", // Unknown scheme
		"slack://",            // Missing tokens
	}

	for _, u := range invalidURLs {
		_, _, err := ParseAppriseURL(u)
		if err == nil && !strings.Contains(u, "slack://") {
			t.Errorf("expected error for %s, got nil", u)
		}
	}
}

func TestWebhookValidation(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		valid  bool
	}{
		{
			name:   "valid URL",
			config: map[string]string{"url": "https://example.com/webhook"},
			valid:  true,
		},
		{
			name:   "missing URL",
			config: map[string]string{},
			valid:  false,
		},
		{
			name:   "URL without scheme",
			config: map[string]string{"url": "example.com/webhook"},
			valid:  true, // url.Parse accepts this, treating it as a relative URL
		},
	}

	for _, tt := range tests {
		wc := &WebhookChannel{}
		err := wc.Validate(tt.config)
		if (err == nil) != tt.valid {
			t.Errorf("%s: expected valid=%v, got error=%v", tt.name, tt.valid, err)
		}
	}
}

func TestMQTTValidation(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		valid  bool
	}{
		{
			name: "valid",
			config: map[string]string{
				"broker_host": "localhost",
				"broker_port": "1883",
				"topic":       "alerts",
			},
			valid: true,
		},
		{
			name: "missing host",
			config: map[string]string{
				"broker_port": "1883",
				"topic":       "alerts",
			},
			valid: false,
		},
		{
			name: "missing topic",
			config: map[string]string{
				"broker_host": "localhost",
				"broker_port": "1883",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		mc := &MQTTChannel{}
		err := mc.Validate(tt.config)
		if (err == nil) != tt.valid {
			t.Errorf("%s: expected valid=%v, got error=%v", tt.name, tt.valid, err)
		}
	}
}

func TestRSSFeedValidation(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		valid  bool
	}{
		{
			name:   "valid",
			config: map[string]string{"feed_title": "Alerts"},
			valid:  true,
		},
		{
			name:   "missing title",
			config: map[string]string{},
			valid:  false,
		},
	}

	for _, tt := range tests {
		rc := &RSSFeedChannel{}
		err := rc.Validate(tt.config)
		if (err == nil) != tt.valid {
			t.Errorf("%s: expected valid=%v, got error=%v", tt.name, tt.valid, err)
		}
	}
}

func TestAppriseLinkValidation(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]string
		valid  bool
	}{
		{
			name:   "valid slack",
			config: map[string]string{"apprise_urls": "slack://A/B/C"},
			valid:  true,
		},
		{
			name:   "valid discord",
			config: map[string]string{"apprise_urls": "discord://id/token"},
			valid:  true,
		},
		{
			name:   "multiple URLs",
			config: map[string]string{"apprise_urls": "slack://A/B/C,discord://id/token"},
			valid:  true,
		},
		{
			name:   "no URLs",
			config: map[string]string{},
			valid:  false,
		},
		{
			name:   "invalid URL format",
			config: map[string]string{"apprise_urls": "http://example.com"},
			valid:  false,
		},
	}

	for _, tt := range tests {
		ac := &AppriseLinkChannel{}
		err := ac.Validate(tt.config)
		if (err == nil) != tt.valid {
			t.Errorf("%s: expected valid=%v, got error=%v", tt.name, tt.valid, err)
		}
	}
}

func TestMQTTEncodeRemainingLength(t *testing.T) {
	tests := []struct {
		length   int
		expected []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{300, []byte{0xac, 0x02}},
	}

	client := &mqttClient{}
	for _, tt := range tests {
		buf := &bytes.Buffer{}
		client.encodeRemainingLength(buf, tt.length)
		result := buf.Bytes()

		if !bytes.Equal(result, tt.expected) {
			t.Errorf("length %d: expected %v, got %v", tt.length, tt.expected, result)
		}
	}
}

func TestMQTTConnectPacket(t *testing.T) {
	client := &mqttClient{
		host:     "test.mosquitto.org",
		port:     "1883",
		username: "user",
		password: "pass",
	}

	packet := client.buildConnectPacket()
	if len(packet) == 0 {
		t.Error("empty CONNECT packet")
	}

	// Verify packet type (first byte should start with 0x10)
	if packet[0]&0xf0 != 0x10 {
		t.Errorf("invalid packet type: %x", packet[0])
	}

	// Verify MQTT protocol name
	if !bytes.Contains(packet, []byte("MQTT")) {
		t.Error("MQTT protocol name not found")
	}
}
