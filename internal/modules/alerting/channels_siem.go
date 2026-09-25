package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
	}
}
func (e *ElasticChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" {
		return fmt.Errorf("host and port required")
	}
	return nil
}
func (e *ElasticChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("elastic channel not yet implemented")
}
func (e *ElasticChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("elastic channel not yet implemented")
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
	}
}
func (o *OpenSearchChannel) Validate(config map[string]string) error {
	if config["host"] == "" || config["port"] == "" {
		return fmt.Errorf("host and port required")
	}
	return nil
}
func (o *OpenSearchChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("opensearch channel not yet implemented")
}
func (o *OpenSearchChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("opensearch channel not yet implemented")
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
	return 0, fmt.Errorf("graylog channel not yet implemented")
}
func (g *GraylogChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("graylog channel not yet implemented")
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
	return 0, fmt.Errorf("sentinel channel not yet implemented")
}
func (s *SentinelChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("sentinel channel not yet implemented")
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
	return 0, fmt.Errorf("datadog channel not yet implemented")
}
func (d *DatadogChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("datadog channel not yet implemented")
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
	return 0, fmt.Errorf("sumologic channel not yet implemented")
}
func (s *SumoLogicChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("sumologic channel not yet implemented")
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
	return 0, fmt.Errorf("newrelic channel not yet implemented")
}
func (n *NewRelicChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("newrelic channel not yet implemented")
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
	return 0, fmt.Errorf("grafana_loki channel not yet implemented")
}
func (g *GrafanaLokiChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("grafana_loki channel not yet implemented")
}

type QRadarChannel struct{}

func (q *QRadarChannel) Type() string  { return "qradar" }
func (q *QRadarChannel) Label() string { return "IBM QRadar" }
func (q *QRadarChannel) Schema() []SettingField {
	return []SettingField{
		{Key: "syslog_host", Label: "Syslog Host", Type: "text", Required: true},
		{Key: "syslog_port", Label: "Syslog Port", Type: "number", Required: true},
		{Key: "format", Label: "Format", Type: "select", Options: []string{"leef", "cef"}, Required: true},
	}
}
func (q *QRadarChannel) Validate(config map[string]string) error {
	if config["syslog_host"] == "" || config["syslog_port"] == "" {
		return fmt.Errorf("syslog_host and syslog_port required")
	}
	return nil
}
func (q *QRadarChannel) Send(ctx context.Context, ch *Channel, msg *Message) (int64, error) {
	return 0, fmt.Errorf("qradar channel not yet implemented")
}
func (q *QRadarChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("qradar channel not yet implemented")
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
	return 0, fmt.Errorf("wazuh channel not yet implemented")
}
func (w *WazuhChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("wazuh channel not yet implemented")
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
	return 0, fmt.Errorf("sentry channel not yet implemented")
}
func (s *SentryChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("sentry channel not yet implemented")
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
	return 0, fmt.Errorf("cloudwatch_logs channel not yet implemented")
}
func (c *CloudWatchLogsChannel) Test(ctx context.Context, ch *Channel) (int64, error) {
	return 0, fmt.Errorf("cloudwatch_logs channel not yet implemented")
}
