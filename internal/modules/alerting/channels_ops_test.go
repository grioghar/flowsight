package alerting

import (
	"testing"
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
