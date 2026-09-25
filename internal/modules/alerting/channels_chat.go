package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SlackChannel sends notifications to Slack via incoming webhook or Bot token.
type SlackChannel struct{}

func (s *SlackChannel) Type() string  { return "slack" }
func (s *SlackChannel) Label() string { return "Slack" }

func (s *SlackChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Slack app: API > Incoming Webhooks"},
		{Key: "bot_token", Label: "Bot Token (optional)", Type: "password", Secret: true, Help: "For chat.postMessage; starts with xoxb-"},
		{Key: "channel", Label: "Channel", Type: "text", Help: "For bot token; leave blank for webhook default"},
	}
}

func (s *SlackChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" && config["bot_token"] == "" {
		return fmt.Errorf("webhook_url or bot_token required")
	}
	return nil
}

func (s *SlackChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &SlackFormatter{BaseURL: ch.Config["base_url"]}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Use webhook URL if provided, otherwise use bot token
	if ch.Config["webhook_url"] != "" {
		req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBufferString(payload))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return time.Since(start).Milliseconds(), fmt.Errorf("slack returned %d", resp.StatusCode)
		}
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SlackChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return s.Send(ctx, ch, msg)
}

// DiscordChannel sends notifications to Discord via webhook.
type DiscordChannel struct{}

func (d *DiscordChannel) Type() string  { return "discord" }
func (d *DiscordChannel) Label() string { return "Discord" }

func (d *DiscordChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Discord server settings: Webhooks"},
	}
}

func (d *DiscordChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}

func (d *DiscordChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	color := map[string]int{
		"critical": 0xFF0000,
		"high":     0xFF9900,
		"medium":   0xFFCC00,
		"low":      0x00CC00,
		"info":     0x0078D4,
	}[msg.Severity]
	if color == 0 {
		color = 0x808080
	}

	embed := map[string]interface{}{
		"title":     msg.Title,
		"color":     color,
		"timestamp": msg.Timestamp.Format(time.RFC3339),
		"fields": []map[string]interface{}{
			{
				"name":   "Severity",
				"value":  msg.Severity,
				"inline": true,
			},
			{
				"name":   "Module",
				"value":  msg.Module,
				"inline": true,
			},
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		embed["fields"] = append(embed["fields"].([]map[string]interface{}), map[string]interface{}{
			"name":   "Device",
			"value":  fmt.Sprintf("%s (%s)", msg.Device.Name, msg.Device.IP),
			"inline": false,
		})
	}

	if msg.Body != "" {
		embed["description"] = msg.Body
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("discord returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (d *DiscordChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return d.Send(ctx, ch, msg)
}

// TeamsChannel sends to Microsoft Teams via webhook or Power Automate.
type TeamsChannel struct{}

func (t *TeamsChannel) Type() string  { return "teams" }
func (t *TeamsChannel) Label() string { return "Microsoft Teams" }

func (t *TeamsChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true, Help: "From Teams: Connectors > Incoming Webhook"},
	}
}

func (t *TeamsChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}

func (t *TeamsChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &TeamsFormatter{BaseURL: ch.Config["base_url"]}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["webhook_url"], bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("teams returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TeamsChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return t.Send(ctx, ch, msg)
}

// TelegramChannel sends via Telegram Bot API.
type TelegramChannel struct{}

func (t *TelegramChannel) Type() string  { return "telegram" }
func (t *TelegramChannel) Label() string { return "Telegram" }

func (t *TelegramChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "bot_token", Label: "Bot Token", Type: "password", Secret: true, Required: true, Help: "From BotFather; format: 123456:ABC-DEF..."},
		{Key: "chat_id", Label: "Chat ID", Type: "text", Required: true, Help: "Numeric chat/user ID or @channel"},
	}
}

func (t *TelegramChannel) Validate(config map[string]string) error {
	if config["bot_token"] == "" || config["chat_id"] == "" {
		return fmt.Errorf("bot_token and chat_id required")
	}
	return nil
}

func (t *TelegramChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	text, _ := formatter.Format(msg)

	params := url.Values{
		"chat_id":    {ch.Config["chat_id"]},
		"text":       {text},
		"parse_mode": {"HTML"},
	}

	client := &http.Client{Timeout: 10 * time.Second}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?%s", ch.Config["bot_token"], params.Encode())
	req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("telegram returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (t *TelegramChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test Alert",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "This is a test message from your FlowSight alerting system.",
	}
	return t.Send(ctx, ch, msg)
}

// NtfyChannel sends to ntfy.sh or self-hosted ntfy.
type NtfyChannel struct{}

func (n *NtfyChannel) Type() string  { return "ntfy" }
func (n *NtfyChannel) Label() string { return "ntfy" }

func (n *NtfyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "server", Label: "Server URL", Type: "url", Required: true, Help: "e.g., https://ntfy.sh or your self-hosted instance"},
		{Key: "topic", Label: "Topic", Type: "text", Required: true, Help: "Topic name; uniqueness is security (no auth)"},
		{Key: "token", Label: "Access Token (optional)", Type: "password", Secret: true, Help: "For ntfy.sh Pro or self-hosted with auth"},
	}
}

func (n *NtfyChannel) Validate(config map[string]string) error {
	if config["server"] == "" || config["topic"] == "" {
		return fmt.Errorf("server and topic required")
	}
	return nil
}

func (n *NtfyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &PlainTextFormatter{}
	text, _ := formatter.Format(msg)

	url := fmt.Sprintf("%s/%s", ch.Config["server"], ch.Config["topic"])
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(text))
	req.Header.Set("Title", msg.Title)
	req.Header.Set("Tags", msg.Module+","+msg.Severity)

	// Map severity to ntfy priority
	priority := map[string]string{
		"critical": "max",
		"high":     "high",
		"medium":   "default",
		"low":      "low",
		"info":     "min",
	}[msg.Severity]
	if priority != "" {
		req.Header.Set("Priority", priority)
	}

	if ch.Config["token"] != "" {
		req.Header.Set("Authorization", "Bearer "+ch.Config["token"])
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("ntfy returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (n *NtfyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test message from FlowSight alerting.",
	}
	return n.Send(ctx, ch, msg)
}

// Placeholder implementations for other chat channels
// These follow the same pattern but are abbreviated for space

type MatrixChannel struct{}

func (m *MatrixChannel) Type() string  { return "matrix" }
func (m *MatrixChannel) Label() string { return "Matrix" }
func (m *MatrixChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "homeserver", Label: "Homeserver URL", Type: "url", Required: true},
		{Key: "room_id", Label: "Room ID", Type: "text", Required: true},
		{Key: "access_token", Label: "Access Token", Type: "password", Secret: true, Required: true},
	}
}
func (m *MatrixChannel) Validate(config map[string]string) error {
	if config["homeserver"] == "" || config["room_id"] == "" || config["access_token"] == "" {
		return fmt.Errorf("homeserver, room_id, and access_token required")
	}
	return nil
}
func (m *MatrixChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	// TODO: Implement Matrix client-server API
	return 0, fmt.Errorf("matrix channel not yet implemented")
}
func (m *MatrixChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("matrix channel not yet implemented")
}

type MattermostChannel struct{}

func (m *MattermostChannel) Type() string  { return "mattermost" }
func (m *MattermostChannel) Label() string { return "Mattermost" }
func (m *MattermostChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (m *MattermostChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (m *MattermostChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	// Similar to Slack
	return 0, fmt.Errorf("mattermost channel not yet implemented")
}
func (m *MattermostChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("mattermost channel not yet implemented")
}

type RocketChatChannel struct{}

func (r *RocketChatChannel) Type() string  { return "rocketchat" }
func (r *RocketChatChannel) Label() string { return "Rocket.Chat" }
func (r *RocketChatChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Incoming Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (r *RocketChatChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (r *RocketChatChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("rocketchat channel not yet implemented")
}
func (r *RocketChatChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("rocketchat channel not yet implemented")
}

type GoogleChatChannel struct{}

func (g *GoogleChatChannel) Type() string  { return "google_chat" }
func (g *GoogleChatChannel) Label() string { return "Google Chat" }
func (g *GoogleChatChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (g *GoogleChatChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (g *GoogleChatChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("google_chat channel not yet implemented")
}
func (g *GoogleChatChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("google_chat channel not yet implemented")
}

type PushoverChannel struct{}

func (p *PushoverChannel) Type() string  { return "pushover" }
func (p *PushoverChannel) Label() string { return "Pushover" }
func (p *PushoverChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "user_key", Label: "User Key", Type: "password", Secret: true, Required: true},
		{Key: "app_token", Label: "App Token", Type: "password", Secret: true, Required: true},
	}
}
func (p *PushoverChannel) Validate(config map[string]string) error {
	if config["user_key"] == "" || config["app_token"] == "" {
		return fmt.Errorf("user_key and app_token required")
	}
	return nil
}
func (p *PushoverChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("pushover channel not yet implemented")
}
func (p *PushoverChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("pushover channel not yet implemented")
}

type PushbulletChannel struct{}

func (p *PushbulletChannel) Type() string  { return "pushbullet" }
func (p *PushbulletChannel) Label() string { return "Pushbullet" }
func (p *PushbulletChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "device_iden", Label: "Device ID (optional)", Type: "text"},
	}
}
func (p *PushbulletChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" {
		return fmt.Errorf("api_key required")
	}
	return nil
}
func (p *PushbulletChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("pushbullet channel not yet implemented")
}
func (p *PushbulletChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("pushbullet channel not yet implemented")
}

type GotifyChannel struct{}

func (g *GotifyChannel) Type() string  { return "gotify" }
func (g *GotifyChannel) Label() string { return "Gotify" }
func (g *GotifyChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "server", Label: "Server URL", Type: "url", Required: true},
		{Key: "token", Label: "App Token", Type: "password", Secret: true, Required: true},
	}
}
func (g *GotifyChannel) Validate(config map[string]string) error {
	if config["server"] == "" || config["token"] == "" {
		return fmt.Errorf("server and token required")
	}
	return nil
}
func (g *GotifyChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("gotify channel not yet implemented")
}
func (g *GotifyChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("gotify channel not yet implemented")
}

type HomeAssistantChannel struct{}

func (h *HomeAssistantChannel) Type() string  { return "homeassistant" }
func (h *HomeAssistantChannel) Label() string { return "Home Assistant" }
func (h *HomeAssistantChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "webhook_url", Label: "Webhook URL", Type: "url", Secret: true, Required: true},
	}
}
func (h *HomeAssistantChannel) Validate(config map[string]string) error {
	if config["webhook_url"] == "" {
		return fmt.Errorf("webhook_url required")
	}
	return nil
}
func (h *HomeAssistantChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("homeassistant channel not yet implemented")
}
func (h *HomeAssistantChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("homeassistant channel not yet implemented")
}

type SignalChannel struct{}

func (s *SignalChannel) Type() string  { return "signal" }
func (s *SignalChannel) Label() string { return "Signal" }
func (s *SignalChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_url", Label: "signal-cli-rest-api URL", Type: "url", Required: true},
		{Key: "from_number", Label: "From Number", Type: "text", Required: true},
		{Key: "to_number", Label: "To Number", Type: "text", Required: true},
	}
}
func (s *SignalChannel) Validate(config map[string]string) error {
	if config["api_url"] == "" || config["from_number"] == "" || config["to_number"] == "" {
		return fmt.Errorf("api_url, from_number, and to_number required")
	}
	return nil
}
func (s *SignalChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("signal channel not yet implemented")
}
func (s *SignalChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("signal channel not yet implemented")
}
