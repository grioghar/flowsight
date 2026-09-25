package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMatrixValidate tests Matrix channel validation
func TestMatrixValidate(t *testing.T) {
	m := &MatrixChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"homeserver":   "https://matrix.org",
				"room_id":      "!abc:matrix.org",
				"access_token": "token123",
			},
			wantErr: false,
		},
		{
			name: "missing homeserver",
			config: map[string]string{
				"room_id":      "!abc:matrix.org",
				"access_token": "token123",
			},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: map[string]string{
				"homeserver":   "not a url",
				"room_id":      "!abc:matrix.org",
				"access_token": "token123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMatrixSend tests Matrix Send method
func TestMatrixSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "_matrix/client/v3/rooms") {
			t.Errorf("Expected Matrix path, got %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("Expected Bearer token, got %s", auth)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"event_id":"$event123"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"homeserver":   server.URL,
			"room_id":      "!abc:matrix.org",
			"access_token": "token123",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "critical",
		Body:      "Test message",
	}

	m := &MatrixChannel{}
	latency, err := m.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
	if latency < 0 {
		t.Errorf("Expected non-negative latency, got %d", latency)
	}
}

// TestMattermostValidate tests Mattermost validation
func TestMattermostValidate(t *testing.T) {
	m := &MattermostChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"webhook_url": "https://mattermost.example.com/hooks/xxx",
			},
			wantErr: false,
		},
		{
			name: "missing webhook_url",
			config: map[string]string{
				"channel": "test",
			},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: map[string]string{
				"webhook_url": "not a url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMattermostSend tests Mattermost Send method
func TestMattermostSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["text"]; !ok {
			t.Error("Expected 'text' field in payload")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"webhook_url": server.URL,
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "high",
		Body:      "Test message",
	}

	m := &MattermostChannel{}
	_, err := m.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

// TestRocketChatValidate tests Rocket.Chat validation
func TestRocketChatValidate(t *testing.T) {
	r := &RocketChatChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"webhook_url": "https://rocketchat.example.com/hooks/xxx",
			},
			wantErr: false,
		},
		{
			name:    "missing webhook_url",
			config:  map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGoogleChatSend tests Google Chat Send method
func TestGoogleChatSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["cardsV2"]; !ok {
			t.Error("Expected 'cardsV2' field in payload")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"webhook_url": server.URL,
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "critical",
		Body:      "Test message",
	}

	g := &GoogleChatChannel{}
	_, err := g.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

// TestPushoverValidate tests Pushover validation
func TestPushoverValidate(t *testing.T) {
	p := &PushoverChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"user_key":  "user123",
				"app_token": "token456",
			},
			wantErr: false,
		},
		{
			name: "missing user_key",
			config: map[string]string{
				"app_token": "token456",
			},
			wantErr: true,
		},
		{
			name: "missing app_token",
			config: map[string]string{
				"user_key": "user123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPushbulletValidate tests Pushbullet validation
func TestPushbulletValidate(t *testing.T) {
	p := &PushbulletChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"api_key": "key123",
			},
			wantErr: false,
		},
		{
			name:    "missing api_key",
			config:  map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPushbulletSend tests Pushbullet Send method
func TestPushbulletSend(t *testing.T) {
	// Note: Since Pushbullet uses a hard-coded URL, we can't easily
	// test the actual Send without mocking the HTTP client.
	// This test verifies the structure is correct.
	p := &PushbulletChannel{}

	config := map[string]string{
		"api_key": "key123",
	}

	err := p.Validate(config)
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}

	// Verify schema includes required fields
	schema := p.Schema()
	hasAPIKey := false
	for _, field := range schema {
		if field.Key == "api_key" && field.Required {
			hasAPIKey = true
		}
	}
	if !hasAPIKey {
		t.Error("Schema should require api_key")
	}
}

// TestGotifyValidate tests Gotify validation
func TestGotifyValidate(t *testing.T) {
	g := &GotifyChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"server": "https://gotify.example.com",
				"token":  "token123",
			},
			wantErr: false,
		},
		{
			name: "missing server",
			config: map[string]string{
				"token": "token123",
			},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: map[string]string{
				"server": "not a url",
				"token":  "token123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := g.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGotifySend tests Gotify Send method
func TestGotifySend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/message") {
			t.Errorf("Expected /message path, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("token") == "" {
			t.Error("Expected token in query params")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["priority"]; !ok {
			t.Error("Expected 'priority' field in payload")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":1}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"server": server.URL,
			"token":  "token123",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "critical",
		Body:      "Test message",
	}

	g := &GotifyChannel{}
	_, err := g.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

// TestHomeAssistantValidate tests Home Assistant validation
func TestHomeAssistantValidate(t *testing.T) {
	h := &HomeAssistantChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"webhook_url": "https://homeassistant.example.com/api/webhook/xyz",
			},
			wantErr: false,
		},
		{
			name:    "missing webhook_url",
			config:  map[string]string{},
			wantErr: true,
		},
		{
			name: "invalid URL",
			config: map[string]string{
				"webhook_url": "not a url",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestHomeAssistantSend tests Home Assistant Send method
func TestHomeAssistantSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["title"]; !ok {
			t.Error("Expected 'title' field in payload")
		}
		if _, ok := payload["severity"]; !ok {
			t.Error("Expected 'severity' field in payload")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"webhook_url": server.URL,
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "high",
		Body:      "Test message",
	}

	h := &HomeAssistantChannel{}
	_, err := h.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

// TestSignalValidate tests Signal validation
func TestSignalValidate(t *testing.T) {
	s := &SignalChannel{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
	}{
		{
			name: "valid config",
			config: map[string]string{
				"api_url":     "http://localhost:8080",
				"from_number": "+1234567890",
				"to_number":   "+0987654321",
			},
			wantErr: false,
		},
		{
			name: "missing api_url",
			config: map[string]string{
				"from_number": "+1234567890",
				"to_number":   "+0987654321",
			},
			wantErr: true,
		},
		{
			name: "invalid API URL",
			config: map[string]string{
				"api_url":     "not a url",
				"from_number": "+1234567890",
				"to_number":   "+0987654321",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Validate(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSignalSend tests Signal Send method
func TestSignalSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/v2/send") {
			t.Errorf("Expected /v2/send path, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		if _, ok := payload["message"]; !ok {
			t.Error("Expected 'message' field in payload")
		}
		if _, ok := payload["recipients"]; !ok {
			t.Error("Expected 'recipients' field in payload")
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"api_url":     server.URL,
			"from_number": "+1234567890",
			"to_number":   "+0987654321",
		},
	}

	msg := &Message{
		Timestamp: time.Now(),
		Title:     "Test Alert",
		Severity:  "medium",
		Body:      "Test message",
	}

	s := &SignalChannel{}
	_, err := s.Send(context.Background(), ch, msg)

	if err != nil {
		t.Errorf("Send() error = %v", err)
	}
}

// TestMatrixTest tests the Test method
func TestMatrixTest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"event_id":"$test"}`))
	}))
	defer server.Close()

	ch := &Channel{
		Config: map[string]string{
			"homeserver":   server.URL,
			"room_id":      "!abc:matrix.org",
			"access_token": "token123",
		},
	}

	m := &MatrixChannel{}
	_, err := m.Test(context.Background(), ch)

	if err != nil {
		t.Errorf("Test() error = %v", err)
	}
}

// TestAllChannelTypes tests that all channels implement the interface correctly
func TestAllChannelTypes(t *testing.T) {
	channels := []ChannelType{
		&MatrixChannel{},
		&MattermostChannel{},
		&RocketChatChannel{},
		&GoogleChatChannel{},
		&PushoverChannel{},
		&PushbulletChannel{},
		&GotifyChannel{},
		&HomeAssistantChannel{},
		&SignalChannel{},
	}

	for _, ch := range channels {
		if ch.Type() == "" {
			t.Errorf("%T.Type() returned empty string", ch)
		}
		if ch.Label() == "" {
			t.Errorf("%T.Label() returned empty string", ch)
		}
		schema := ch.Schema()
		if len(schema) == 0 {
			t.Errorf("%T.Schema() returned empty schema", ch)
		}
	}
}
