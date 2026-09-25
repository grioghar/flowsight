// Package telemetry exports the store's metrics, events and alerts to an OTLP/HTTP endpoint.
package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module exports metrics and events to an OpenTelemetry HTTP endpoint.
type Module struct {
	ctx         *core.Context
	client      *http.Client
	lastShipped int64
	lastError   string
	lastSuccess time.Time
	metricsURL  string
	logsURL     string
	hostName    string
	shipEvents  bool
	headers     map[string]string
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "telemetry",
		Version:     "1.0",
		Tier:        "business",
		Description: "Export metrics, events and alerts to an OpenTelemetry/HTTP endpoint (Grafana Mimir/Loki).",
		Defaults: map[string]any{
			"enabled":          false,
			"metrics_endpoint": "http://127.0.0.1:4318/v1/metrics",
			"logs_endpoint":    "http://127.0.0.1:4318/v1/logs",
			"interval_seconds": 30,
			"host_name":        "",
			"headers":          map[string]any{},
			"events":           false,
		},
		Schema: []core.SettingField{
			{Key: "enabled", Label: "Enabled", Type: "bool"},
			{Key: "metrics_endpoint", Label: "Metrics endpoint", Type: "string",
				Placeholder: "http://127.0.0.1:4318/v1/metrics"},
			{Key: "logs_endpoint", Label: "Logs endpoint", Type: "string",
				Placeholder: "http://127.0.0.1:4318/v1/logs"},
			{Key: "interval_seconds", Label: "Export interval (seconds)", Type: "int"},
			{Key: "host_name", Label: "Host name (default: hostname)", Type: "string"},
			{Key: "headers", Label: "HTTP headers (JSON map)", Type: "text",
				Help: "Authentication headers, e.g. {\"Authorization\": \"Bearer token\"}"},
			{Key: "events", Label: "Also export events/alerts as log records", Type: "bool"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.client = &http.Client{Timeout: 10 * time.Second}

	settings := ctx.Settings()
	m.metricsURL = core.Str(settings, "metrics_endpoint", "http://127.0.0.1:4318/v1/metrics")
	m.logsURL = core.Str(settings, "logs_endpoint", "http://127.0.0.1:4318/v1/logs")
	m.hostName = core.Str(settings, "host_name", "")
	if m.hostName == "" {
		m.hostName, _ = os.Hostname()
	}
	m.shipEvents = core.Bool(settings, "events", false)

	// Parse headers from settings
	m.headers = map[string]string{}
	if headersMap, ok := settings["headers"].(map[string]any); ok {
		for k, v := range headersMap {
			if s, ok := v.(string); ok {
				m.headers[k] = s
			}
		}
	}

	// Initialize last shipped to "now" so first run exports only recent metrics
	m.lastShipped = time.Now().Unix()

	interval := time.Duration(core.Int(settings, "interval_seconds", 30)) * time.Second
	ctx.Every("export", interval, m.export, core.NeedsJob("telemetry.export"), core.Delayed())

	ctx.Route("GET", "/api/telemetry/status", m.apiStatus,
		core.Doc("Last telemetry export status"), core.Returns("Success", map[string]any{"ok": true}))
	return nil
}

func (m *Module) Health() core.Health {
	if m.lastError != "" {
		return core.Health{OK: false, Detail: m.lastError}
	}
	if m.lastSuccess.IsZero() {
		return core.Health{OK: true, Detail: "waiting for first export"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("last export: %s",
		time.Since(m.lastSuccess).Round(time.Second).String()+" ago")}
}

func (m *Module) export() error {
	now := time.Now()

	// Fetch metrics since last shipped
	rows, err := m.ctx.Store.Rows(
		`SELECT ts, name, labels, value FROM metrics WHERE ts > ? ORDER BY ts`,
		m.lastShipped)
	if err != nil {
		m.lastError = fmt.Sprintf("metrics query failed: %v", err)
		return nil
	}

	var lastTS int64
	metrics := []otlpMetricRecord{}
	for _, row := range rows {
		ts := int64(row["ts"].(float64))
		lastTS = ts
		name := row["name"].(string)
		labelsStr := ""
		if l, ok := row["labels"].(string); ok && l != "" {
			labelsStr = l
		}
		value := 0.0
		if v, ok := row["value"].(float64); ok {
			value = v
		}

		var labels map[string]string
		if labelsStr != "" {
			_ = json.Unmarshal([]byte(labelsStr), &labels)
		}
		if labels == nil {
			labels = map[string]string{}
		}

		metrics = append(metrics, otlpMetricRecord{
			ts:     ts,
			name:   name,
			labels: labels,
			value:  value,
		})
	}

	// Add derived counters (monotonic sums with fixed start time)
	moduleStartTime := m.ctx.Core.Started.Unix() * 1e9

	// DNS queries total
	dnsCount := m.ctx.Store.Int(`SELECT COUNT(*) FROM dns`)
	if dnsCount > 0 {
		metrics = append(metrics, otlpMetricRecord{
			ts:          lastTS,
			name:        "flowsight_dns_queries_total",
			value:       float64(dnsCount),
			startTime:   moduleStartTime,
			isMonotonic: true,
		})
	}

	// DNS blocked total
	dnsBlocked := m.ctx.Store.Int(
		`SELECT COUNT(*) FROM dns WHERE action NOT IN ('pass', '')`)
	if dnsBlocked > 0 {
		metrics = append(metrics, otlpMetricRecord{
			ts:          lastTS,
			name:        "flowsight_dns_blocked_total",
			value:       float64(dnsBlocked),
			startTime:   moduleStartTime,
			isMonotonic: true,
		})
	}

	// Flows total
	flowCount := m.ctx.Store.Int(`SELECT COUNT(*) FROM flows`)
	if flowCount > 0 {
		metrics = append(metrics, otlpMetricRecord{
			ts:          lastTS,
			name:        "flowsight_flows_total",
			value:       float64(flowCount),
			startTime:   moduleStartTime,
			isMonotonic: true,
		})
	}

	// Blocked flows total
	blockedFlows := m.ctx.Store.Int(
		`SELECT COUNT(*) FROM flows WHERE verdict = 'blocked'`)
	if blockedFlows > 0 {
		metrics = append(metrics, otlpMetricRecord{
			ts:          lastTS,
			name:        "flowsight_blocked_flows_total",
			value:       float64(blockedFlows),
			startTime:   moduleStartTime,
			isMonotonic: true,
		})
	}

	// IDS alerts total
	alertCount := m.ctx.Store.Int(`SELECT COUNT(*) FROM alerts`)
	if alertCount > 0 {
		metrics = append(metrics, otlpMetricRecord{
			ts:          lastTS,
			name:        "flowsight_ids_alerts_total",
			value:       float64(alertCount),
			startTime:   moduleStartTime,
			isMonotonic: true,
		})
	}

	// Send metrics if any
	if len(metrics) > 0 {
		if err := m.shipMetrics(metrics); err != nil {
			m.lastError = fmt.Sprintf("ship metrics failed: %v", err)
			return nil
		}
	}

	// Ship events/alerts/blocks as log records if enabled
	if m.shipEvents {
		if err := m.shipLogs(); err != nil {
			m.lastError = fmt.Sprintf("ship logs failed: %v", err)
			return nil
		}
	}

	m.lastShipped = now.Unix()
	m.lastSuccess = now
	m.lastError = ""
	return nil
}

func (m *Module) shipMetrics(records []otlpMetricRecord) error {
	payload := m.buildMetricsPayload(records)
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", m.metricsURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range m.headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *Module) shipLogs() error {
	// Fetch recent events, alerts and blocks
	eventRows, _ := m.ctx.Store.Rows(
		`SELECT ts, kind, source, severity, verdict, actor_ip, target_ip, target_domain,
		        rule_id, rule_name, message FROM events WHERE ts > ?
		 ORDER BY ts DESC LIMIT 1000`, time.Now().Unix()-3600)

	payload := m.buildLogsPayload(eventRows)
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", m.logsURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range m.headers {
		req.Header.Set(k, v)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (m *Module) buildMetricsPayload(records []otlpMetricRecord) map[string]any {
	// Group by metric name
	byName := map[string][]otlpMetricRecord{}
	for _, r := range records {
		byName[r.name] = append(byName[r.name], r)
	}

	resourceAttrs := map[string]any{
		"host.name":    m.hostName,
		"service.name": "flowsight",
	}

	var metrics []map[string]any
	for name, recs := range byName {
		var dataPoints []map[string]any
		for _, rec := range recs {
			attrs := map[string]any{"flowsight": "gauge"}
			for k, v := range rec.labels {
				attrs[k] = v
			}

			dp := map[string]any{
				"timeUnixNano": rec.ts * 1e9,
				"asGauge": map[string]any{
					"dataPoints": []map[string]any{{
						"timeUnixNano": rec.ts * 1e9,
						"asDouble":     rec.value,
						"attributes":   attrs,
					}},
				},
			}

			// Use asSum for monotonic counters
			if rec.isMonotonic {
				dp = map[string]any{
					"timeUnixNano": rec.ts * 1e9,
					"asSum": map[string]any{
						"dataPoints": []map[string]any{{
							"timeUnixNano":      rec.ts * 1e9,
							"asDouble":          rec.value,
							"startTimeUnixNano": rec.startTime,
							"attributes":        attrs,
						}},
						"aggregationTemporality": 2, // CUMULATIVE
						"isMonotonic":            true,
					},
				}
			}

			dataPoints = append(dataPoints, dp)
		}

		metric := map[string]any{
			"name":        name,
			"description": "",
			"unit":        "",
			"sum": map[string]any{
				"dataPoints":             dataPoints,
				"aggregationTemporality": 2,
				"isMonotonic":            true,
			},
		}
		metrics = append(metrics, metric)
	}

	return map[string]any{
		"resourceMetrics": []map[string]any{{
			"resource": map[string]any{
				"attributes": resourceAttrs,
			},
			"scopeMetrics": []map[string]any{{
				"scope": map[string]any{
					"name": "flowsight",
				},
				"metrics": metrics,
			}},
		}},
	}
}

func (m *Module) buildLogsPayload(eventRows []map[string]any) map[string]any {
	resourceAttrs := map[string]any{
		"host.name":    m.hostName,
		"service.name": "flowsight",
	}

	var logRecords []map[string]any
	for _, row := range eventRows {
		ts := int64(0)
		if t, ok := row["ts"].(float64); ok {
			ts = int64(t)
		}

		attrs := map[string]any{
			"event_kind": row["kind"],
			"source":     row["source"],
			"severity":   row["severity"],
			"verdict":    row["verdict"],
		}

		// Add optional fields
		if ip, ok := row["actor_ip"].(string); ok && ip != "" {
			attrs["actor_ip"] = ip
		}
		if ip, ok := row["target_ip"].(string); ok && ip != "" {
			attrs["target_ip"] = ip
		}
		if domain, ok := row["target_domain"].(string); ok && domain != "" {
			attrs["target_domain"] = domain
		}
		if ruleID, ok := row["rule_id"].(string); ok && ruleID != "" {
			attrs["rule_id"] = ruleID
		}
		if ruleName, ok := row["rule_name"].(string); ok && ruleName != "" {
			attrs["rule_name"] = ruleName
		}

		var severity int
		switch row["severity"] {
		case "critical":
			severity = 21
		case "high":
			severity = 17
		case "medium":
			severity = 13
		case "low":
			severity = 11
		default:
			severity = 9
		}

		logRecord := map[string]any{
			"timeUnixNano":   ts * 1e9,
			"severityNumber": severity,
			"severityText":   row["severity"],
			"body": map[string]any{
				"stringValue": row["message"],
			},
			"attributes": attrs,
		}
		logRecords = append(logRecords, logRecord)
	}

	return map[string]any{
		"resourceLogs": []map[string]any{{
			"resource": map[string]any{
				"attributes": resourceAttrs,
			},
			"scopeLogs": []map[string]any{{
				"scope": map[string]any{
					"name": "flowsight",
				},
				"logRecords": logRecords,
			}},
		}},
	}
}

func (m *Module) apiStatus(req *core.Req) (any, error) {
	return map[string]any{
		"enabled":      true,
		"metrics_url":  m.metricsURL,
		"logs_url":     m.logsURL,
		"host_name":    m.hostName,
		"last_shipped": m.lastShipped,
		"last_success": m.lastSuccess.Unix(),
		"last_error":   m.lastError,
	}, nil
}

type otlpMetricRecord struct {
	ts          int64
	name        string
	labels      map[string]string
	value       float64
	startTime   int64
	isMonotonic bool
}
