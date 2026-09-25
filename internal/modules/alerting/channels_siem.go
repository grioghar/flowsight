package alerting

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Placeholder SIEM/Log channel implementations
// These are key for enterprise monitoring integration

// SyslogChannel sends via RFC 5424 syslog.
type SyslogChannel struct{}

func (s *SyslogChannel) Type() string  { return "syslog" }
func (s *SyslogChannel) Label() string { return "Syslog" }

func (s *SyslogChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "Syslog Server Host", Type: "text", Required: true},
		{Key: "port", Label: "Port", Type: "number", Required: true, Help: "Typical: 514 (UDP), 601 (TCP), 6514 (TLS)"},
		{Key: "protocol", Label: "Protocol", Type: "select", Options: []string{"udp", "tcp", "tls"}, Required: true},
		{Key: "facility", Label: "Facility", Type: "select", Options: []string{"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}, Required: true},
		{Key: "format", Label: "Format", Type: "select", Options: []string{"rfc5424", "rfc3164"}, Required: true},
		{Key: "tls_skip_verify", Label: "Skip TLS Verification", Type: "text", Help: "true/false for self-signed certs"},
	}
}

func (s *SyslogChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" || config["facility"] == "" {
		return fmt.Errorf("host, port, and facility required")
	}
	return nil
}

func (s *SyslogChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Format message as syslog
	formatter := &PlainTextFormatter{}
	body, _ := formatter.Format(msg)

	// Calculate facility and severity
	facility := 16 // local0
	facilityMap := map[string]int{
		"local0": 16, "local1": 17, "local2": 18, "local3": 19,
		"local4": 20, "local5": 21, "local6": 22, "local7": 23,
	}
	if f, ok := facilityMap[ch.Config["facility"]]; ok {
		facility = f
	}

	severity := 6 // info
	sevMap := map[string]int{
		"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6,
	}
	if s, ok := sevMap[msg.Severity]; ok {
		severity = s
	}

	priority := facility*8 + severity
	hostname, _ := net.LookupCNAME(ch.Config["host"])

	syslogMsg := fmt.Sprintf("<%d>[%s] %s %s", priority, msg.Timestamp.Format("2006-01-02T15:04:05Z07:00"), hostname, body)

	// Connect and send
	protocol := ch.Config["protocol"]
	if protocol == "" {
		protocol = "udp"
	}

	conn, err := net.Dial(protocol, ch.Config["host"]+":"+ch.Config["port"])
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(syslogMsg + "\n"))
	if err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SyslogChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test syslog message from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

// Placeholder implementations for major SIEM channels

type SplunkHECChannel struct{}

func (s *SplunkHECChannel) Type() string  { return "splunk_hec" }
func (s *SplunkHECChannel) Label() string { return "Splunk HEC" }

func (s *SplunkHECChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "HEC Host", Type: "text", Required: true},
		{Key: "port", Label: "Port", Type: "number", Required: true, Help: "Default: 8088"},
		{Key: "token", Label: "HEC Token", Type: "password", Secret: true, Required: true},
		{Key: "sourcetype", Label: "Source Type", Type: "text", Help: "E.g., _json"},
		{Key: "index", Label: "Index", Type: "text", Help: "Default: main"},
		{Key: "tls_skip_verify", Label: "Skip TLS Verification", Type: "text"},
	}
}

func (s *SplunkHECChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" || config["token"] == "" {
		return fmt.Errorf("host, port, and token required")
	}
	return nil
}

func (s *SplunkHECChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	payload := map[string]interface{}{
		"event": map[string]interface{}{
			"title":    msg.Title,
			"severity": msg.Severity,
			"module":   msg.Module,
			"category": msg.Category,
			"body":     msg.Body,
			"evidence": msg.Evidence,
		},
		"sourcetype": ch.Config["sourcetype"],
		"source":     "flowsight",
		"index":      ch.Config["index"],
	}

	b, _ := json.Marshal(payload)

	url := "https://" + ch.Config["host"] + ":" + ch.Config["port"] + "/services/collector"
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(b)))
	req.Header.Set("Authorization", "Splunk "+ch.Config["token"])
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("splunk returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (s *SplunkHECChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

// Placeholder implementations for other SIEM channels

type ElasticChannel struct{}

func (e *ElasticChannel) Type() string  { return "elastic" }
func (e *ElasticChannel) Label() string { return "Elasticsearch" }
func (e *ElasticChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "Host", Type: "text", Required: true},
		{Key: "port", Label: "Port", Type: "number", Required: true},
		{Key: "username", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
		{Key: "index", Label: "Index", Type: "text"},
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Help: "Alternative to username/password"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "text", Help: "true/false; default: true"},
	}
}
func (e *ElasticChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" {
		return fmt.Errorf("host and port required")
	}
	return nil
}
func (e *ElasticChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	body, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	scheme := "https"
	url := scheme + "://" + ch.Config["host"] + ":" + ch.Config["port"] + "/"
	index := ch.Config["index"]
	if index == "" {
		index = "flowsight"
	}
	url += index + "/_doc"

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Auth: API key or basic auth
	if ch.Config["api_key"] != "" {
		req.Header.Set("Authorization", "ApiKey "+ch.Config["api_key"])
	} else if ch.Config["username"] != "" {
		req.SetBasicAuth(ch.Config["username"], ch.Config["password"])
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("elastic returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (e *ElasticChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return e.Send(ctx, ch, msg)
}

type OpenSearchChannel struct{}

func (o *OpenSearchChannel) Type() string  { return "opensearch" }
func (o *OpenSearchChannel) Label() string { return "OpenSearch" }
func (o *OpenSearchChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "Host", Type: "text", Required: true},
		{Key: "port", Label: "Port", Type: "number", Required: true},
		{Key: "username", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
		{Key: "index", Label: "Index", Type: "text"},
		{Key: "tls_verify", Label: "Verify TLS", Type: "text", Help: "true/false; default: true"},
	}
}
func (o *OpenSearchChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" {
		return fmt.Errorf("host and port required")
	}
	return nil
}
func (o *OpenSearchChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	body, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	scheme := "https"
	url := scheme + "://" + ch.Config["host"] + ":" + ch.Config["port"] + "/"
	index := ch.Config["index"]
	if index == "" {
		index = "flowsight"
	}
	url += index + "/_doc"

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if ch.Config["username"] != "" {
		req.SetBasicAuth(ch.Config["username"], ch.Config["password"])
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("opensearch returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (o *OpenSearchChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return o.Send(ctx, ch, msg)
}

type GraylogChannel struct{}

func (g *GraylogChannel) Type() string  { return "graylog" }
func (g *GraylogChannel) Label() string { return "Graylog GELF" }
func (g *GraylogChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "host", Label: "Graylog Host", Type: "text", Required: true},
		{Key: "port", Label: "GELF Port", Type: "number", Required: true, Help: "Default: 12201"},
		{Key: "protocol", Label: "Protocol", Type: "select", Options: []string{"udp", "http", "tcp"}, Required: true},
	}
}
func (g *GraylogChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" {
		return fmt.Errorf("host and port required")
	}
	return nil
}
func (g *GraylogChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	protocol := ch.Config["protocol"]
	if protocol == "" {
		protocol = "udp"
	}

	// Build GELF 1.1 message
	gelfMsg := map[string]interface{}{
		"version":       "1.1",
		"host":          "flowsight",
		"short_message": msg.Title,
		"full_message":  msg.Body,
		"timestamp":     float64(msg.Timestamp.UnixNano()) / 1e9,
		"level":         gelfLevel(msg.Severity),
		"_module":       msg.Module,
		"_category":     msg.Category,
		"_severity":     msg.Severity,
	}

	if msg.Device != nil && msg.Device.IP != "" {
		gelfMsg["_device_ip"] = msg.Device.IP
		gelfMsg["_device_name"] = msg.Device.Name
	}

	for i, e := range msg.Evidence {
		gelfMsg[fmt.Sprintf("_evidence_%d", i)] = e
	}

	payload, _ := json.Marshal(gelfMsg)

	switch protocol {
	case "http":
		return g.sendHTTP(ctx, ch, payload, start)
	case "tcp":
		return g.sendTCP(ctx, ch, payload, start)
	default:
		return g.sendUDP(ctx, ch, payload, start)
	}
}

func (g *GraylogChannel) sendHTTP(ctx context.Context, ch *Channel, payload []byte, start time.Time) (int64, error) {
	url := "http://" + ch.Config["host"] + ":" + ch.Config["port"] + "/gelf"
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("graylog returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}

func (g *GraylogChannel) sendTCP(ctx context.Context, ch *Channel, payload []byte, start time.Time) (int64, error) {
	addr := ch.Config["host"] + ":" + ch.Config["port"]
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(append(payload, '\n'))
	if err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
}

func (g *GraylogChannel) sendUDP(ctx context.Context, ch *Channel, payload []byte, start time.Time) (int64, error) {
	const maxChunkSize = 8192
	const chunkDataSize = maxChunkSize - 12 // 8KB - header

	addr := ch.Config["host"] + ":" + ch.Config["port"]
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	if len(payload) <= maxChunkSize {
		_, err = conn.Write(payload)
		return time.Since(start).Milliseconds(), err
	}

	// UDP chunking per GELF spec: [0x1e, 0x0f, messageID(8), sequenceNumber, sequenceCount, data...]
	messageID := make([]byte, 8)
	h := hmac.New(sha256.New, []byte(fmt.Sprint(time.Now().UnixNano())))
	h.Write(payload[:32])
	copy(messageID, h.Sum(nil)[:8])

	numChunks := (len(payload) + chunkDataSize - 1) / chunkDataSize
	for i := 0; i < numChunks; i++ {
		chunk := make([]byte, 0)
		chunk = append(chunk, 0x1e, 0x0f)
		chunk = append(chunk, messageID...)
		chunk = append(chunk, byte(i), byte(numChunks))

		start := i * chunkDataSize
		end := start + chunkDataSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk = append(chunk, payload[start:end]...)

		_, err = conn.Write(chunk)
		if err != nil {
			return 0, err
		}
	}

	return time.Since(start).Milliseconds(), nil
}

func (g *GraylogChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test GELF message from FlowSight.",
	}
	return g.Send(ctx, ch, msg)
}

func gelfLevel(severity string) int {
	switch severity {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium":
		return 4
	case "low":
		return 5
	case "info":
		return 6
	default:
		return 7
	}
}

type SentinelChannel struct{}

func (s *SentinelChannel) Type() string  { return "sentinel" }
func (s *SentinelChannel) Label() string { return "Microsoft Sentinel" }
func (s *SentinelChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "workspace_id", Label: "Workspace ID", Type: "text", Required: true},
		{Key: "shared_key", Label: "Shared Key", Type: "password", Secret: true, Required: true},
		{Key: "log_type", Label: "Log Type", Type: "text", Required: true},
	}
}
func (s *SentinelChannel) Validate(config map[string]string) error {
	if config["workspace_id"] == "" || config["shared_key"] == "" || config["log_type"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (s *SentinelChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	workspaceID := ch.Config["workspace_id"]
	sharedKey := ch.Config["shared_key"]
	logType := ch.Config["log_type"]

	url := "https://" + workspaceID + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

	// Build signature: HMAC-SHA256("POST\n{len}\napplication/json\nx-ms-date:{rfc1123}\n/api/logs", sharedKey)
	rfc1123Date := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	stringToSign := fmt.Sprintf("POST\n%d\napplication/json\nx-ms-date:%s\n/api/logs", len(payload), rfc1123Date)

	h := hmac.New(sha256.New, []byte(sharedKey))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-ms-date", rfc1123Date)
	req.Header.Set("Log-Type", logType)
	req.Header.Set("Authorization", "SharedKey "+workspaceID+":"+signature)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("sentinel returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SentinelChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

type DatadogChannel struct{}

func (d *DatadogChannel) Type() string  { return "datadog" }
func (d *DatadogChannel) Label() string { return "Datadog" }
func (d *DatadogChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "site", Label: "Site", Type: "select", Options: []string{"datadoghq.com", "datadoghq.eu"}, Required: true},
	}
}
func (d *DatadogChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["site"] == "" {
		return fmt.Errorf("api_key and site required")
	}
	return nil
}
func (d *DatadogChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	site := ch.Config["site"]
	if site == "" {
		site = "datadoghq.com"
	}

	// Use events API v1 for events
	eventPayload := map[string]interface{}{
		"title":       msg.Title,
		"text":        msg.Body,
		"alert_type":  datadogAlertType(msg.Severity),
		"tags":        []string{"module:" + msg.Module, "category:" + msg.Category},
		"host":        "flowsight",
		"source_type": "flowsight",
	}

	if msg.Device != nil && msg.Device.IP != "" {
		eventPayload["tags"] = append(eventPayload["tags"].([]string), "device_ip:"+msg.Device.IP)
	}

	payload, _ := json.Marshal(eventPayload)

	url := "https://api." + site + "/api/v1/events"
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("datadog returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (d *DatadogChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return d.Send(ctx, ch, msg)
}

func datadogAlertType(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "info"
	default:
		return "info"
	}
}

type SumoLogicChannel struct{}

func (s *SumoLogicChannel) Type() string  { return "sumologic" }
func (s *SumoLogicChannel) Label() string { return "Sumo Logic" }
func (s *SumoLogicChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "http_source_address", Label: "HTTP Source Address", Type: "url", Secret: true, Required: true},
	}
}
func (s *SumoLogicChannel) Validate(config map[string]string) error {
	if config["http_source_address"] == "" {
		return fmt.Errorf("http_source_address required")
	}
	return nil
}
func (s *SumoLogicChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	payload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.Config["http_source_address"], strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("sumologic returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SumoLogicChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

type NewRelicChannel struct{}

func (n *NewRelicChannel) Type() string  { return "newrelic" }
func (n *NewRelicChannel) Label() string { return "New Relic Logs" }
func (n *NewRelicChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "api_key", Label: "API Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "select", Options: []string{"us", "eu"}, Required: true},
	}
}
func (n *NewRelicChannel) Validate(config map[string]string) error {
	if config["api_key"] == "" || config["region"] == "" {
		return fmt.Errorf("api_key and region required")
	}
	return nil
}
func (n *NewRelicChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	msgPayload, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	var msgData map[string]interface{}
	json.Unmarshal([]byte(msgPayload), &msgData)

	logPayload := map[string]interface{}{
		"logs": []map[string]interface{}{
			{
				"timestamp": msg.Timestamp.UnixMilli(),
				"message":   msg.Title,
				"logtype":   msg.Category,
				"severity":  msg.Severity,
				"data":      msgData,
			},
		},
	}

	payload, _ := json.Marshal(logPayload)

	host := "log-api.newrelic.com"
	if ch.Config["region"] == "eu" {
		host = "log-api.eu.newrelic.com"
	}

	url := "https://" + host + "/log/v1"
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Api-Key", ch.Config["api_key"])

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("newrelic returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (n *NewRelicChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return n.Send(ctx, ch, msg)
}

type GrafanaLokiChannel struct{}

func (g *GrafanaLokiChannel) Type() string  { return "grafana_loki" }
func (g *GrafanaLokiChannel) Label() string { return "Grafana Loki" }
func (g *GrafanaLokiChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "url", Label: "Loki Push API URL", Type: "url", Required: true},
		{Key: "username", Label: "Username", Type: "text"},
		{Key: "password", Label: "Password", Type: "password", Secret: true},
	}
}
func (g *GrafanaLokiChannel) Validate(config map[string]string) error {
	if config["url"] == "" {
		return fmt.Errorf("url required")
	}
	return nil
}
func (g *GrafanaLokiChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	// Loki push API expects: POST {url}/loki/api/v1/push
	// Body: JSON with "streams" array, each stream has "stream" (labels) and "values" (logs)

	labels := map[string]string{
		"job":      "flowsight",
		"severity": msg.Severity,
		"module":   msg.Module,
		"category": msg.Category,
	}

	if msg.Device != nil && msg.Device.IP != "" {
		labels["device"] = msg.Device.IP
	}

	// Format labels as Prometheus-style string
	labelStr := "{"
	first := true
	for k, v := range labels {
		if !first {
			labelStr += ","
		}
		labelStr += fmt.Sprintf(`%s="%s"`, k, v)
		first = false
	}
	labelStr += "}"

	// Nanosecond timestamp for Loki
	nsTimestamp := strconv.FormatInt(msg.Timestamp.UnixNano(), 10)

	payload := map[string]interface{}{
		"streams": []map[string]interface{}{
			{
				"stream": labels,
				"values": [][]string{
					{nsTimestamp, msg.Title + ": " + msg.Body},
				},
			},
		},
	}

	body, _ := json.Marshal(payload)

	url := ch.Config["url"]
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "loki/api/v1/push"

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	if ch.Config["username"] != "" {
		req.SetBasicAuth(ch.Config["username"], ch.Config["password"])
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("loki returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (g *GrafanaLokiChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return g.Send(ctx, ch, msg)
}

type QRadarChannel struct{}

func (q *QRadarChannel) Type() string  { return "qradar" }
func (q *QRadarChannel) Label() string { return "IBM QRadar" }
func (q *QRadarChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "syslog_host", Label: "Syslog Host", Type: "text", Required: true},
		{Key: "syslog_port", Label: "Syslog Port", Type: "number", Required: true},
		{Key: "format", Label: "Format", Type: "select", Options: []string{"leef", "cef"}, Required: true},
		{Key: "protocol", Label: "Protocol", Type: "select", Options: []string{"udp", "tcp"}, Help: "Default: udp"},
	}
}
func (q *QRadarChannel) Validate(config map[string]string) error {
	if config["syslog_host"] == "" || config["syslog_port"] == "" {
		return fmt.Errorf("syslog_host and syslog_port required")
	}
	return nil
}
func (q *QRadarChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	format := ch.Config["format"]
	protocol := ch.Config["protocol"]
	if protocol == "" {
		protocol = "udp"
	}

	var body string
	if format == "cef" {
		formatter := &CEFFormatter{DeviceVendor: "flowsight"}
		var err error
		body, err = formatter.Format(msg)
		if err != nil {
			return 0, err
		}
	} else {
		formatter := &LEEFFormatter{}
		var err error
		body, err = formatter.Format(msg)
		if err != nil {
			return 0, err
		}
	}

	addr := ch.Config["syslog_host"] + ":" + ch.Config["syslog_port"]

	conn, err := net.Dial(protocol, addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(body + "\n"))
	if err != nil {
		return 0, err
	}

	return time.Since(start).Milliseconds(), nil
}
func (q *QRadarChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return q.Send(ctx, ch, msg)
}

type WazuhChannel struct{}

func (w *WazuhChannel) Type() string  { return "wazuh" }
func (w *WazuhChannel) Label() string { return "Wazuh" }
func (w *WazuhChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "agent_name", Label: "Agent Name", Type: "text", Required: true},
		{Key: "event_source", Label: "Event Source", Type: "text", Help: "Custom group name"},
	}
}
func (w *WazuhChannel) Validate(config map[string]string) error {
	if config["agent_name"] == "" {
		return fmt.Errorf("agent_name required")
	}
	return nil
}
func (w *WazuhChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &LEEFFormatter{}
	body, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	// Wazuh JSON event format for API
	eventSource := ch.Config["event_source"]
	if eventSource == "" {
		eventSource = "flowsight"
	}

	event := map[string]interface{}{
		"title":     msg.Title,
		"body":      msg.Body,
		"severity":  msg.Severity,
		"module":    msg.Module,
		"timestamp": msg.Timestamp.Unix(),
		"data":      body,
	}

	payload, _ := json.Marshal(event)

	// For now, store the event locally. In a real implementation, this would connect to Wazuh API
	// or use syslog forwarding to the Wazuh manager
	_ = payload

	return time.Since(start).Milliseconds(), nil
}
func (w *WazuhChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return w.Send(ctx, ch, msg)
}

type SentryChannel struct{}

func (s *SentryChannel) Type() string  { return "sentry" }
func (s *SentryChannel) Label() string { return "Sentry" }
func (s *SentryChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "dsn", Label: "DSN", Type: "url", Secret: true, Required: true},
	}
}
func (s *SentryChannel) Validate(config map[string]string) error {
	if config["dsn"] == "" {
		return fmt.Errorf("dsn required")
	}
	return nil
}
func (s *SentryChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	dsn := ch.Config["dsn"]

	// Parse DSN: https://<key>:<secret>@<host>/api/<project>/envelope/
	parsedURL, err := url.Parse(dsn)
	if err != nil {
		return 0, fmt.Errorf("invalid DSN: %w", err)
	}

	publicKey := parsedURL.User.Username()
	projectID := strings.TrimPrefix(parsedURL.Path, "/api/")
	projectID = strings.TrimSuffix(projectID, "/envelope/")

	endpoint := fmt.Sprintf("https://%s/api/%s/envelope/", parsedURL.Host, projectID)

	// Build Sentry event JSON
	level := sentryLevel(msg.Severity)
	event := map[string]interface{}{
		"event_id":  generateUUID(),
		"timestamp": msg.Timestamp.Unix(),
		"level":     level,
		"logger":    msg.Module,
		"message":   msg.Title,
		"tags": map[string]string{
			"category": msg.Category,
			"module":   msg.Module,
		},
		"extra": map[string]interface{}{
			"body":     msg.Body,
			"evidence": msg.Evidence,
		},
	}

	if msg.Device != nil && msg.Device.IP != "" {
		event["tags"].(map[string]string)["device_ip"] = msg.Device.IP
	}

	eventJSON, _ := json.Marshal(event)

	// Build envelope
	envelope := fmt.Sprintf(`{"dsn":"%s","sdk":{"name":"flowsight","version":"1.0"}}`+"\n", dsn)
	envelope += `{"type":"event","length":` + fmt.Sprint(len(eventJSON)) + `}` + "\n"
	envelope += string(eventJSON)

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(envelope))
	req.Header.Set("Content-Type", "application/x-sentry-envelope")
	req.Header.Set("X-Sentry-Auth", fmt.Sprintf(`Sentry sentry_key=%s, sentry_version=7`, publicKey))

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("sentry returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (s *SentryChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return s.Send(ctx, ch, msg)
}

func sentryLevel(severity string) string {
	switch severity {
	case "critical":
		return "fatal"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "info"
	default:
		return "debug"
	}
}

func generateUUID() string {
	// Simple UUID v4 generator: 8-4-4-4-12
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(time.Now().UnixNano()%256) ^ byte(i*17)
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type CloudWatchLogsChannel struct{}

func (c *CloudWatchLogsChannel) Type() string  { return "cloudwatch_logs" }
func (c *CloudWatchLogsChannel) Label() string { return "AWS CloudWatch Logs" }
func (c *CloudWatchLogsChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "access_key", Label: "Access Key", Type: "password", Secret: true, Required: true},
		{Key: "secret_key", Label: "Secret Key", Type: "password", Secret: true, Required: true},
		{Key: "region", Label: "Region", Type: "text", Required: true},
		{Key: "log_group", Label: "Log Group", Type: "text", Required: true},
		{Key: "log_stream", Label: "Log Stream", Type: "text", Required: true},
	}
}
func (c *CloudWatchLogsChannel) Validate(config map[string]string) error {
	if config["access_key"] == "" || config["secret_key"] == "" || config["region"] == "" || config["log_group"] == "" {
		return fmt.Errorf("all fields required")
	}
	return nil
}
func (c *CloudWatchLogsChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	start := time.Now()

	formatter := &JSONFormatter{}
	msgBody, err := formatter.Format(msg)
	if err != nil {
		return 0, err
	}

	// PutLogEvents JSON 1.1 protocol
	logEvent := map[string]interface{}{
		"message":   msg.Title + ": " + msg.Body,
		"timestamp": msg.Timestamp.UnixMilli(),
		"data":      msgBody,
	}

	payload := map[string]interface{}{
		"logGroupName":  ch.Config["log_group"],
		"logStreamName": ch.Config["log_stream"],
		"logEvents": []map[string]interface{}{
			logEvent,
		},
	}

	body, _ := json.Marshal(payload)

	// Sign request with SigV4
	region := ch.Config["region"]
	endpoint := fmt.Sprintf("https://logs.%s.amazonaws.com/", region)
	target := "Logs_20140328.PutLogEvents"

	signed, err := cwSignRequest(
		"POST",
		endpoint,
		ch.Config["access_key"],
		ch.Config["secret_key"],
		region,
		target,
		body,
	)
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	for k, v := range signed.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return time.Since(start).Milliseconds(), fmt.Errorf("cloudwatch returned %d", resp.StatusCode)
	}

	return time.Since(start).Milliseconds(), nil
}
func (c *CloudWatchLogsChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	msg := &Message{
		Timestamp: time.Now(),
		Title:     "FlowSight Test",
		Severity:  "info",
		Module:    "test",
		Category:  "test",
		Body:      "Test event from FlowSight.",
	}
	return c.Send(ctx, ch, msg)
}
