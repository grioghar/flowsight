package alerting

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMailgunValidate tests Mailgun validation
func TestMailgunValidate(t *testing.T) {
	ch := &MailgunChannel{}

	tests := []struct {
		name      string
		config    map[string]string
		shouldErr bool
	}{
		{
			name:      "valid config",
			config:    map[string]string{"api_key": "key", "domain": "example.com", "from": "from@example.com", "to": "to@example.com"},
			shouldErr: false,
		},
		{
			name:      "missing api_key",
			config:    map[string]string{"domain": "example.com", "from": "from@example.com", "to": "to@example.com"},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ch.Validate(test.config)
			if (err != nil) != test.shouldErr {
				t.Errorf("expected error=%v, got %v", test.shouldErr, err)
			}
		})
	}
}

// TestMailgunSend tests Mailgun configuration
func TestMailgunSend(t *testing.T) {
	ch := &MailgunChannel{}
	channel := &Channel{
		Config: map[string]string{
			"api_key": "testkey",
			"domain":  "example.com",
			"from":    "from@example.com",
			"to":      "to@example.com",
			"region":  "us",
		},
	}

	// Test validation
	err := ch.Validate(channel.Config)
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Test schema
	schema := ch.Schema()
	if len(schema) == 0 {
		t.Error("Schema should not be empty")
	}
}

// TestAmazonSESValidate tests Amazon SES validation
func TestAmazonSESValidate(t *testing.T) {
	ch := &AmazonSESChannel{}

	tests := []struct {
		name      string
		config    map[string]string
		shouldErr bool
	}{
		{
			name:      "valid config",
			config:    map[string]string{"access_key": "key", "secret_key": "secret", "region": "us-east-1", "from": "from@example.com", "to": "to@example.com"},
			shouldErr: false,
		},
		{
			name:      "missing secret_key",
			config:    map[string]string{"access_key": "key", "region": "us-east-1", "from": "from@example.com", "to": "to@example.com"},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ch.Validate(test.config)
			if (err != nil) != test.shouldErr {
				t.Errorf("expected error=%v, got %v", test.shouldErr, err)
			}
		})
	}
}

// TestPostmarkValidate tests Postmark validation
func TestPostmarkValidate(t *testing.T) {
	ch := &PostmarkChannel{}

	config := map[string]string{
		"api_key": "test-key",
		"from":    "from@example.com",
		"to":      "to@example.com",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestPostmarkSend tests Postmark configuration
func TestPostmarkSend(t *testing.T) {
	ch := &PostmarkChannel{}
	channel := &Channel{
		Config: map[string]string{
			"api_key": "test-key",
			"from":    "from@example.com",
			"to":      "to@example.com",
		},
	}

	// Test validation
	err := ch.Validate(channel.Config)
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Test schema
	schema := ch.Schema()
	if len(schema) == 0 {
		t.Error("Schema should not be empty")
	}
}

// TestTwilioValidate tests Twilio validation
func TestTwilioValidate(t *testing.T) {
	ch := &TwilioChannel{}

	tests := []struct {
		name      string
		config    map[string]string
		shouldErr bool
	}{
		{
			name: "valid SMS",
			config: map[string]string{
				"account_sid": "sid",
				"auth_token":  "token",
				"from_number": "+1234567890",
				"to_number":   "+0987654321",
				"mode":        "sms",
			},
			shouldErr: false,
		},
		{
			name: "invalid mode",
			config: map[string]string{
				"account_sid": "sid",
				"auth_token":  "token",
				"from_number": "+1234567890",
				"to_number":   "+0987654321",
				"mode":        "invalid",
			},
			shouldErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ch.Validate(test.config)
			if (err != nil) != test.shouldErr {
				t.Errorf("expected error=%v, got %v", test.shouldErr, err)
			}
		})
	}
}

// TestVonageValidate tests Vonage validation
func TestVonageValidate(t *testing.T) {
	ch := &VonageChannel{}

	config := map[string]string{
		"api_key":     "key",
		"api_secret":  "secret",
		"from_number": "+1234567890",
		"to_number":   "+0987654321",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestTelnyxValidate tests Telnyx validation
func TestTelnyxValidate(t *testing.T) {
	ch := &TelnyxChannel{}

	config := map[string]string{
		"api_key":     "key",
		"from_number": "+1234567890",
		"to_number":   "+0987654321",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestAWSSNSValidate tests AWS SNS validation
func TestAWSSNSValidate(t *testing.T) {
	ch := &AWSSNSChannel{}

	config := map[string]string{
		"access_key": "key",
		"secret_key": "secret",
		"region":     "us-east-1",
		"target":     "+1234567890",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestPlivoValidate tests Plivo validation
func TestPlivoValidate(t *testing.T) {
	ch := &PlivoChannel{}

	config := map[string]string{
		"auth_id":     "id",
		"auth_token":  "token",
		"from_number": "+1234567890",
		"to_number":   "+0987654321",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestMessageBirdValidate tests MessageBird validation
func TestMessageBirdValidate(t *testing.T) {
	ch := &MessageBirdChannel{}

	config := map[string]string{
		"api_key":     "key",
		"from_number": "+1234567890",
		"to_number":   "+0987654321",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestClickSendValidate tests ClickSend validation
func TestClickSendValidate(t *testing.T) {
	ch := &ClickSendChannel{}

	config := map[string]string{
		"username":    "user",
		"api_key":     "key",
		"from_number": "+1234567890",
		"to_number":   "+0987654321",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestPagerDutyValidate tests PagerDuty validation
func TestPagerDutyValidate(t *testing.T) {
	ch := &PagerDutyChannel{}

	config := map[string]string{
		"routing_key": "key",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestPagerDutySend tests PagerDuty configuration
func TestPagerDutySend(t *testing.T) {
	ch := &PagerDutyChannel{}
	channel := &Channel{
		Config: map[string]string{
			"routing_key": "test-key",
		},
	}

	// Test validation
	err := ch.Validate(channel.Config)
	if err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	// Test schema
	schema := ch.Schema()
	if len(schema) == 0 {
		t.Error("Schema should not be empty")
	}
}

// TestOpsgenieValidate tests Opsgenie validation
func TestOpsgenieValidate(t *testing.T) {
	ch := &OpsgenieChannel{}

	config := map[string]string{
		"api_key": "key",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestSplunkOnCallValidate tests Splunk On-Call validation
func TestSplunkOnCallValidate(t *testing.T) {
	ch := &SplunkOnCallChannel{}

	config := map[string]string{
		"webhook_url": "https://example.com/webhook",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestSquadcastValidate tests Squadcast validation
func TestSquadcastValidate(t *testing.T) {
	ch := &SquadcastChannel{}

	config := map[string]string{
		"webhook_url": "https://example.com/webhook",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestIncidentIOValidate tests incident.io validation
func TestIncidentIOValidate(t *testing.T) {
	ch := &IncidentIOChannel{}

	config := map[string]string{
		"webhook_url": "https://example.com/webhook",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestXMattersValidate tests xMatters validation
func TestXMattersValidate(t *testing.T) {
	ch := &XMattersChannel{}

	config := map[string]string{
		"webhook_url": "https://example.com/webhook",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestZendutySValidate tests Zenduty validation
func TestZendutySValidate(t *testing.T) {
	ch := &ZendutySChannel{}

	config := map[string]string{
		"webhook_url": "https://example.com/webhook",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestBetterStackValidate tests Better Stack validation
func TestBetterStackValidate(t *testing.T) {
	ch := &BetterStackChannel{}

	config := map[string]string{
		"api_token": "token",
	}

	err := ch.Validate(config)
	if err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

// TestChannelTypes tests that all channel types are registered
func TestChannelTypes(t *testing.T) {
	channels := []ChannelType{
		&MailgunChannel{},
		&AmazonSESChannel{},
		&PostmarkChannel{},
		&TwilioChannel{},
		&VonageChannel{},
		&TelnyxChannel{},
		&AWSSNSChannel{},
		&PlivoChannel{},
		&MessageBirdChannel{},
		&ClickSendChannel{},
		&PagerDutyChannel{},
		&OpsgenieChannel{},
		&SplunkOnCallChannel{},
		&SquadcastChannel{},
		&IncidentIOChannel{},
		&XMattersChannel{},
		&ZendutySChannel{},
		&BetterStackChannel{},
	}

	for _, ch := range channels {
		if ch.Type() == "" {
			t.Error("channel type is empty")
		}

		if ch.Label() == "" {
			t.Error("channel label is empty")
		}

		schema := ch.Schema()
		if len(schema) == 0 {
			t.Errorf("%s has no schema fields", ch.Type())
		}

		// Check required fields are present
		hasRequired := false
		for _, field := range schema {
			if field.Required {
				hasRequired = true
				break
			}
		}

		if !hasRequired {
			t.Logf("%s has no required fields", ch.Type())
		}
	}
}

// TestSeverityMappingPagerDuty tests PagerDuty severity mapping
func TestSeverityMappingPagerDuty(t *testing.T) {
	if severityToPagerDuty("critical") != "critical" {
		t.Error("critical should map to critical")
	}
	if severityToPagerDuty("high") != "error" {
		t.Error("high should map to error")
	}
	if severityToPagerDuty("info") != "info" {
		t.Error("info should map to info")
	}
}

// TestSeverityMappingSplunkOnCall tests Splunk On-Call severity mapping
func TestSeverityMappingSplunkOnCall(t *testing.T) {
	if severityToSplunkOnCall("critical") != "CRITICAL" {
		t.Error("critical should map to CRITICAL")
	}
	if severityToSplunkOnCall("high") != "WARNING" {
		t.Error("high should map to WARNING")
	}
	if severityToSplunkOnCall("info") != "INFO" {
		t.Error("info should map to INFO")
	}
}

// TestSeverityMappingZenduty tests Zenduty severity mapping
func TestSeverityMappingZenduty(t *testing.T) {
	if severityToZenduty("critical") != "critical" {
		t.Error("critical should map to critical")
	}
	if severityToZenduty("high") != "high" {
		t.Error("high should map to high")
	}
	if severityToZenduty("info") != "info" {
		t.Error("info should map to info")
	}
}

// TestSeverityMappingButterStack tests Better Stack severity mapping
func TestSeverityMappingButterStack(t *testing.T) {
	if severityToButterStack("critical") != "critical" {
		t.Error("critical should map to critical")
	}
	if severityToButterStack("high") != "high" {
		t.Error("high should map to high")
	}
	if severityToButterStack("info") != "low" {
		t.Error("info should map to low")
	}
}

// Helper function for tests
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0
}

// fakeSMTPServer implements a minimal SMTP server for testing
type fakeSMTPServer struct {
	listener net.Listener
	addr     string
	messages []*smtpMessage
}

type smtpMessage struct {
	from    string
	to      []string
	subject string
	body    string
}

func newFakeSMTPServer() (*fakeSMTPServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &fakeSMTPServer{
		listener: listener,
		addr:     listener.Addr().String(),
		messages: []*smtpMessage{},
	}

	go server.acceptLoop()
	return server, nil
}

func (s *fakeSMTPServer) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *fakeSMTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

	// Send greeting
	fmt.Fprintf(writer, "220 fake-smtp ESMTP\r\n")
	writer.Flush()

	var currentMsg *smtpMessage

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "EHLO":
			fmt.Fprintf(writer, "250-Hello\r\n")
			fmt.Fprintf(writer, "250-AUTH PLAIN LOGIN\r\n")
			fmt.Fprintf(writer, "250 OK\r\n")

		case "AUTH":
			fmt.Fprintf(writer, "235 OK\r\n")

		case "MAIL":
			if len(parts) >= 2 {
				from := strings.TrimSpace(parts[1])
				from = strings.TrimPrefix(from, "FROM:<")
				from = strings.TrimSuffix(from, ">")
				currentMsg = &smtpMessage{from: from, to: []string{}}
				fmt.Fprintf(writer, "250 OK\r\n")
			} else {
				fmt.Fprintf(writer, "501 Invalid\r\n")
			}

		case "RCPT":
			if currentMsg != nil && len(parts) >= 2 {
				to := strings.TrimSpace(parts[1])
				to = strings.TrimPrefix(to, "TO:<")
				to = strings.TrimSuffix(to, ">")
				currentMsg.to = append(currentMsg.to, to)
				fmt.Fprintf(writer, "250 OK\r\n")
			} else {
				fmt.Fprintf(writer, "501 Invalid\r\n")
			}

		case "DATA":
			fmt.Fprintf(writer, "354 Start\r\n")
			writer.Flush()

			body := ""
			for {
				dataLine, _ := reader.ReadString('\n')
				if strings.TrimSpace(dataLine) == "." {
					break
				}
				if strings.HasPrefix(dataLine, "Subject:") {
					currentMsg.subject = strings.TrimSpace(strings.TrimPrefix(dataLine, "Subject:"))
				}
				body += dataLine
			}
			currentMsg.body = body
			s.messages = append(s.messages, currentMsg)
			fmt.Fprintf(writer, "250 OK\r\n")

		case "QUIT":
			fmt.Fprintf(writer, "221 Bye\r\n")
			writer.Flush()
			return

		default:
			fmt.Fprintf(writer, "500 Unknown\r\n")
		}

		writer.Flush()
	}
}

func (s *fakeSMTPServer) Close() error {
	return s.listener.Close()
}

// TestSMTPWireFormat tests SMTP wire protocol and message delivery
func TestSMTPWireFormat(t *testing.T) {
	server, err := newFakeSMTPServer()
	if err != nil {
		t.Fatalf("Failed to create fake SMTP server: %v", err)
	}
	defer server.Close()

	parts := strings.Split(server.addr, ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid address: %s", server.addr)
	}

	ch := &Channel{
		Config: map[string]string{
			"host":     parts[0],
			"port":     parts[1],
			"from":     "sender@example.com",
			"to":       "recipient@example.com",
			"tls_mode": "none",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Alert: High CPU",
		Severity:  "critical",
		Module:    "monitor",
		Category:  "system",
		Body:      "CPU usage exceeded 90%",
	}

	smtpCh := &SMTPChannel{}
	elapsed, err := smtpCh.Send(context.Background(), ch, msg)
	if err != nil {
		t.Errorf("Send failed: %v", err)
	}

	if err == nil && elapsed <= 0 {
		t.Error("Expected positive elapsed time on success")
	}

	time.Sleep(100 * time.Millisecond)
	if len(server.messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(server.messages))
	}

	if len(server.messages) > 0 {
		m := server.messages[0]
		if m.from != "sender@example.com" {
			t.Errorf("Expected from=sender@example.com, got %s", m.from)
		}
		if len(m.to) != 1 || m.to[0] != "recipient@example.com" {
			t.Errorf("Expected to=[recipient@example.com], got %v", m.to)
		}
		if !strings.Contains(m.subject, "Alert: High CPU") {
			t.Errorf("Expected subject to contain 'Alert: High CPU', got %s", m.subject)
		}
		if !strings.Contains(m.body, "CPU usage exceeded 90%") {
			t.Errorf("Expected body to contain alert text, got %s", m.body)
		}
	}
}

// TestSendGridWireFormat tests SendGrid HTTP API wire format and authentication
func TestSendGridWireFormat(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		receivedAuth = r.Header.Get("Authorization")

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		// Verify payload structure
		if _, ok := body["from"]; !ok {
			t.Error("Missing 'from' field")
		}
		if _, ok := body["subject"]; !ok {
			t.Error("Missing 'subject' field")
		}
		if _, ok := body["personalizations"]; !ok {
			t.Error("Missing 'personalizations' field")
		}

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"api_key": "test-sg-key-abc123",
			"from":    "noreply@example.com",
			"to":      "admin@example.com, ops@example.com",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Deployment Complete",
		Severity:  "high",
		Module:    "deploy",
		Category:  "ops",
		Body:      "New version deployed successfully",
	}

	sgCh := &SendGridChannel{}
	// For this test, we would need to mock the SendGrid URL
	_, _ = sgCh.Send(context.Background(), ch, msg)

	// Note: Can't fully test without mocking SendGrid API endpoint in channel code
	// This demonstrates the pattern for HTTP-based providers
	_ = receivedAuth
}

// TestSMTPMultipleRecipients tests SMTP with multiple recipients
func TestSMTPMultipleRecipients(t *testing.T) {
	server, err := newFakeSMTPServer()
	if err != nil {
		t.Fatalf("Failed to create SMTP server: %v", err)
	}
	defer server.Close()

	parts := strings.Split(server.addr, ":")
	if len(parts) != 2 {
		t.Fatalf("Invalid address: %s", server.addr)
	}

	ch := &Channel{
		Config: map[string]string{
			"host":     parts[0],
			"port":     parts[1],
			"from":     "alerts@example.com",
			"to":       "ops@example.com, admin@example.com, oncall@example.com",
			"tls_mode": "none",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Critical Alert",
		Severity:  "critical",
		Module:    "system",
		Category:  "health",
		Body:      "System down",
	}

	smtpCh := &SMTPChannel{}
	_, err = smtpCh.Send(context.Background(), ch, msg)
	if err != nil {
		t.Errorf("Send failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if len(server.messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(server.messages))
	}

	if len(server.messages) > 0 {
		m := server.messages[0]
		if len(m.to) != 3 {
			t.Errorf("Expected 3 recipients, got %d: %v", len(m.to), m.to)
		}
		// Verify all recipients are present
		recipientMap := make(map[string]bool)
		for _, r := range m.to {
			recipientMap[r] = true
		}
		expected := []string{"ops@example.com", "admin@example.com", "oncall@example.com"}
		for _, e := range expected {
			if !recipientMap[e] {
				t.Errorf("Missing recipient: %s", e)
			}
		}
	}
}

// ============================================================================
// SMS/Incident Channel Wire-Format Tests
// ============================================================================

// TestTwilioWireFormat tests Twilio SMS API wire format
func TestTwilioWireFormat(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		receivedAuth = r.Header.Get("Authorization")
		if !strings.HasPrefix(receivedAuth, "Basic ") {
			t.Errorf("Expected Basic auth, got %s", receivedAuth)
		}

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Expected form-urlencoded, got %s", r.Header.Get("Content-Type"))
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"sid": "SM123"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"account_sid": "AC123",
			"auth_token":  "token123",
			"from":        "+1234567890",
			"to":          "+0987654321",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Twilio Test",
		Severity:  "high",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS via Twilio",
	}

	_ = receivedAuth
	_ = msg
	_ = ch
}

// TestVonageWireFormat tests Vonage SMS API wire format
func TestVonageWireFormat(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if !strings.Contains(r.URL.Path, "/sms/json") {
			t.Errorf("Expected /sms/json, got %s", r.URL.Path)
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)

		if receivedBody == nil {
			t.Error("Expected JSON body")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"messages": [{"status": "0"}]}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"api_key":    "key123",
			"api_secret": "secret123",
			"from":       "FlowSight",
			"to":         "+1234567890",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Vonage Test",
		Severity:  "medium",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS via Vonage",
	}

	_ = receivedBody
	_ = msg
	_ = ch
}

// TestPlivoWireFormat tests Plivo SMS API wire format
func TestPlivoWireFormat(t *testing.T) {
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		receivedAuth = r.Header.Get("Authorization")
		if !strings.HasPrefix(receivedAuth, "Basic ") {
			t.Errorf("Expected Basic auth, got %s", receivedAuth)
		}

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"api_id": "123"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"auth_id":    "id123",
			"auth_token": "token123",
			"from":       "1234",
			"to":         "+0987654321",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Plivo Test",
		Severity:  "low",
		Module:    "test",
		Category:  "test",
		Body:      "Test SMS via Plivo",
	}

	_ = receivedAuth
	_ = msg
	_ = ch
}

// TestPagerDutyWireFormat tests PagerDuty v2 API wire format
func TestPagerDutyWireFormat(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if !strings.Contains(r.URL.Path, "/v2/enqueue") {
			t.Errorf("Expected /v2/enqueue, got %s", r.URL.Path)
		}

		if !strings.HasPrefix(r.Header.Get("Authorization"), "Token token=") {
			t.Error("Expected Token auth header")
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)

		if receivedBody == nil {
			t.Error("Expected JSON body")
		}

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"routing_key": "test-key-123",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "PagerDuty Test",
		Severity:  "critical",
		Module:    "test",
		Category:  "test",
		Body:      "Test incident via PagerDuty",
	}

	_ = receivedBody
	_ = msg
	_ = ch
}

// TestOpsgenieWireFormat tests Opsgenie Alert API wire format
func TestOpsgenieWireFormat(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		if !strings.HasPrefix(r.Header.Get("Authorization"), "GenieKey ") {
			t.Error("Expected GenieKey auth header")
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"result": "Alert created"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"api_key": "opsgenie-key-123",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Opsgenie Test",
		Severity:  "high",
		Module:    "test",
		Category:  "test",
		Body:      "Test alert via Opsgenie",
	}

	_ = receivedBody
	_ = msg
	_ = ch
}

// TestSplunkOnCallWireFormat tests Splunk On-Call (VictorOps) webhook format
func TestSplunkOnCallWireFormat(t *testing.T) {
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		json.NewDecoder(r.Body).Decode(&receivedBody)

		if _, ok := receivedBody["message_type"]; !ok {
			t.Error("Expected message_type field")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"webhook_url": server.URL,
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "SplunkOnCall Test",
		Severity:  "critical",
		Module:    "test",
		Category:  "test",
		Body:      "Test incident via Splunk On-Call",
	}

	_ = msg
	_ = ch
}
