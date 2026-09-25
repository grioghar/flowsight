package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Definition describes a saved report template.
type Definition struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Sections   []string  `json:"sections"`   // section keys in order
	Filters    *Filters  `json:"filters"`    // applied to all sections
	Formats    []string  `json:"formats"`    // "html", "markdown", "csv", "json"
	Schedule   *Schedule `json:"schedule"`   // cron-like: daily, weekly, monthly at HH:MM
	Recipients []string  `json:"recipients"` // alerting channel IDs
	Retention  int       `json:"retention"`  // keep last N runs; 0 = no limit
	ReadOnly   bool      `json:"read_only"`  // built-in definitions
	CreatedAt  int64     `json:"created_at"`
	UpdatedAt  int64     `json:"updated_at"`
}

// Schedule describes when a report runs.
type Schedule struct {
	Enabled  bool   `json:"enabled"`
	Cadence  string `json:"cadence"`  // "hourly", "daily", "weekly", "monthly"
	TimeUTC  string `json:"time_utc"` // HH:MM in UTC
	Timezone string `json:"timezone"` // system timezone
}

// Run is a single report execution result.
type Run struct {
	ID           string         `json:"id"`
	DefinitionID string         `json:"definition_id"`
	StartedAt    int64          `json:"started_at"`
	CompletedAt  int64          `json:"completed_at"`
	Status       string         `json:"status"` // "pending", "running", "done", "failed"
	Error        string         `json:"error"`
	Sizes        map[string]int `json:"sizes"`        // "html", "pdf", "md", "csv", "json"
	SectionData  map[string]any `json:"section_data"` // cached section results
}

// Engine produces reports from definitions.
type Engine struct {
	ctx      *core.Context
	sections map[string]Section
}

func NewEngine(ctx *core.Context) *Engine {
	secs := registerSections()
	sections := make(map[string]Section)
	for _, s := range secs {
		sections[s.Key()] = s
	}
	return &Engine{ctx: ctx, sections: sections}
}

// Execute runs a definition over the given window, storing results.
func (e *Engine) Execute(def *Definition, window *TimeWindow) (*Run, error) {
	run := &Run{
		ID:           fmt.Sprintf("%d-%s", time.Now().UnixNano(), def.ID),
		DefinitionID: def.ID,
		StartedAt:    time.Now().Unix(),
		Status:       "running",
		Sizes:        map[string]int{},
		SectionData:  map[string]any{},
	}

	// Collect section data
	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		data, err := sec.Run(e.ctx, window, def.Filters)
		if err != nil {
			run.Status = "failed"
			run.Error = err.Error()
			run.CompletedAt = time.Now().Unix()
			return run, nil // return run even if failed
		}
		run.SectionData[key] = data
	}

	run.Status = "done"
	run.CompletedAt = time.Now().Unix()
	return run, nil
}

// RenderHTML produces an HTML report.
func (e *Engine) RenderHTML(def *Definition, run *Run) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><style>`)
	buf.WriteString(reportCSS)
	buf.WriteString(`</style><title>`)
	buf.WriteString(escapeHTML(def.Name))
	buf.WriteString(`</title></head><body>`)

	// Header
	buf.WriteString(fmt.Sprintf(`<h1>%s</h1>`, escapeHTML(def.Name)))
	buf.WriteString(fmt.Sprintf(`<p class="meta">Generated %s</p>`, time.Now().Format("2006-01-02 15:04 MST")))

	// Table of contents
	buf.WriteString(`<aside class="toc"><h3>Contents</h3><ul>`)
	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		buf.WriteString(fmt.Sprintf(`<li><a href="#%s">%s</a></li>`, escapeHTML(key), escapeHTML(sec.Title())))
	}
	buf.WriteString(`</ul></aside>`)

	// Sections
	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		data := run.SectionData[key]
		buf.WriteString(fmt.Sprintf(`<section id="%s">`, escapeHTML(key)))
		buf.WriteString(fmt.Sprintf(`<h2>%s</h2>`, escapeHTML(sec.Title())))
		buf.WriteString(fmt.Sprintf(`<p class="note">%s</p>`, escapeHTML(sec.Notes())))
		e.renderSectionHTML(&buf, key, data)
		buf.WriteString(`</section>`)
	}

	buf.WriteString(`</body></html>`)
	return buf.String(), nil
}

func (e *Engine) renderSectionHTML(buf *bytes.Buffer, key string, data any) {
	if data == nil {
		return
	}
	switch key {
	case "executive_summary":
		if es, ok := data.(ExecutiveSummary); ok {
			e.renderExecSummaryHTML(buf, es)
		}
	case "traffic_by_device":
		if tbd, ok := data.(TrafficByDevice); ok {
			e.renderTrafficByDeviceHTML(buf, tbd)
		}
	case "blocked_activity":
		if ba, ok := data.(BlockedActivity); ok {
			e.renderBlockedActivityHTML(buf, ba)
		}
	case "dns_summary":
		if dns, ok := data.(DNSSummary); ok {
			e.renderDNSSummaryHTML(buf, dns)
		}
	case "tls_posture":
		if tls, ok := data.(TLSPosture); ok {
			e.renderTLSPostureHTML(buf, tls)
		}
	case "traffic_by_zone":
		if tbz, ok := data.(TrafficByZone); ok {
			e.renderTrafficByZoneHTML(buf, tbz)
		}
	case "traffic_by_app":
		if tba, ok := data.(TrafficByApp); ok {
			e.renderTrafficByAppHTML(buf, tba)
		}
	case "traffic_by_category":
		if tbc, ok := data.(TrafficByCategory); ok {
			e.renderTrafficByCategoryHTML(buf, tbc)
		}
	case "traffic_by_site":
		if tbs, ok := data.(TrafficBySite); ok {
			e.renderTrafficBySiteHTML(buf, tbs)
		}
	case "egress_activity":
		if ea, ok := data.(EgressActivity); ok {
			e.renderEgressActivityHTML(buf, ea)
		}
	case "scan_findings":
		if sf, ok := data.(ScanFindings); ok {
			e.renderScanFindingsHTML(buf, sf)
		}
	case "device_inventory":
		if di, ok := data.(DeviceInventoryChanges); ok {
			e.renderDeviceInventoryHTML(buf, di)
		}
	case "alerting_deliveries":
		if ad, ok := data.(AlertingDeliveries); ok {
			e.renderAlertingDeliveriesHTML(buf, ad)
		}
	case "system_health":
		if sh, ok := data.(SystemHealth); ok {
			e.renderSystemHealthHTML(buf, sh)
		}
	case "alerts":
		if alerts, ok := data.(Alerts); ok {
			e.renderAlertsHTML(buf, alerts)
		}
	default:
		// Generic JSON rendering
		buf.WriteString(`<pre>`)
		if b, err := json.MarshalIndent(data, "", "  "); err == nil {
			buf.WriteString(escapeHTML(string(b)))
		}
		buf.WriteString(`</pre>`)
	}
}

func (e *Engine) renderTrafficByZoneHTML(buf *bytes.Buffer, tbz TrafficByZone) {
	buf.WriteString(`<table><tr><th>Zone</th><th>Flows</th><th>Bytes In</th><th>Bytes Out</th><th>Blocked</th><th>Devices</th></tr>`)
	for _, row := range tbz.Rows {
		buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>`,
			escapeHTML(row.Zone), row.Flows, formatBytes(row.BytesIn), formatBytes(row.BytesOut), row.Blocked, row.Devices))
	}
	buf.WriteString(`</table>`)
}

func (e *Engine) renderTrafficByAppHTML(buf *bytes.Buffer, tba TrafficByApp) {
	buf.WriteString(`<table><tr><th>Application</th><th>Flows</th><th>Bytes</th><th>Blocked</th><th>Devices</th></tr>`)
	for _, row := range tba.Rows {
		buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td></tr>`,
			escapeHTML(row.App), row.Flows, formatBytes(row.Bytes), row.Blocked, row.Devices))
	}
	buf.WriteString(`</table>`)
}

func (e *Engine) renderTrafficByCategoryHTML(buf *bytes.Buffer, tbc TrafficByCategory) {
	buf.WriteString(`<table><tr><th>Category</th><th>Flows</th><th>Bytes</th><th>Blocked</th><th>Devices</th><th>Apps</th></tr>`)
	for _, row := range tbc.Rows {
		buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%d</td></tr>`,
			escapeHTML(row.Category), row.Flows, formatBytes(row.Bytes), row.Blocked, row.Devices, row.Apps))
	}
	buf.WriteString(`</table>`)
}

func (e *Engine) renderTrafficBySiteHTML(buf *bytes.Buffer, tbs TrafficBySite) {
	buf.WriteString(`<table><tr><th>Domain</th><th>Flows</th><th>Bytes</th><th>Blocked</th></tr>`)
	for _, row := range tbs.Rows {
		buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%d</td></tr>`,
			escapeHTML(row.Domain), row.Flows, formatBytes(row.Bytes), row.Blocked))
	}
	buf.WriteString(`</table>`)
}

func (e *Engine) renderEgressActivityHTML(buf *bytes.Buffer, ea EgressActivity) {
	buf.WriteString(fmt.Sprintf(`<p>Total Outbound: %s</p>`, formatBytes(ea.TotalOutbound)))
	if len(ea.Rows) > 0 {
		buf.WriteString(`<table><tr><th>Source IP</th><th>Destination IP</th><th>Bytes</th><th>App</th></tr>`)
		for _, row := range ea.Rows {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				escapeHTML(row.DeviceIP), escapeHTML(row.DestIP), formatBytes(row.Bytes), escapeHTML(row.App)))
		}
		buf.WriteString(`</table>`)
	}
}

func (e *Engine) renderScanFindingsHTML(buf *bytes.Buffer, sf ScanFindings) {
	if len(sf.Rows) > 0 {
		buf.WriteString(`<table><tr><th>Severity</th><th>Finding</th><th>Timestamp</th></tr>`)
		for _, row := range sf.Rows {
			buf.WriteString(fmt.Sprintf(`<tr><td><span class="pill %s">%s</span></td><td>%s</td><td>%s</td></tr>`,
				sevClass(row.Severity), escapeHTML(row.Severity), escapeHTML(row.Finding), time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04")))
		}
		buf.WriteString(`</table>`)
	} else {
		buf.WriteString(`<p class="muted">No findings.</p>`)
	}
}

func (e *Engine) renderDeviceInventoryHTML(buf *bytes.Buffer, di DeviceInventoryChanges) {
	if len(di.Rows) > 0 {
		buf.WriteString(`<table><tr><th>Device IP</th><th>Device Name</th><th>Change Type</th><th>Previous Value</th><th>Timestamp</th></tr>`)
		for _, row := range di.Rows {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td><span class="pill info">%s</span></td><td>%s</td><td>%s</td></tr>`,
				escapeHTML(row.DeviceIP), escapeHTML(row.DeviceName), escapeHTML(row.ChangeType), escapeHTML(row.PreviousVal), time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04")))
		}
		buf.WriteString(`</table>`)
	} else {
		buf.WriteString(`<p class="muted">No inventory changes.</p>`)
	}
}

func (e *Engine) renderAlertingDeliveriesHTML(buf *bytes.Buffer, ad AlertingDeliveries) {
	buf.WriteString(fmt.Sprintf(`<p>Sent: %d | Failed: %d</p>`, ad.TotalSent, ad.TotalFailed))
	if len(ad.Rows) > 0 {
		buf.WriteString(`<table><tr><th>Rule</th><th>Channel</th><th>Subject</th><th>Status</th><th>Timestamp</th></tr>`)
		for _, row := range ad.Rows {
			statusClass := "ok"
			if row.Status == "failed" {
				statusClass = "bad"
			}
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td><td><span class="pill %s">%s</span></td><td>%s</td></tr>`,
				escapeHTML(row.RuleName), escapeHTML(row.Channel), escapeHTML(row.Subject), statusClass, escapeHTML(row.Status), time.Unix(row.Timestamp, 0).Format("2006-01-02 15:04")))
		}
		buf.WriteString(`</table>`)
	}
}

func (e *Engine) renderSystemHealthHTML(buf *bytes.Buffer, sh SystemHealth) {
	buf.WriteString(`<div class="kpis">`)
	if sh.Uptime > 0 {
		hours := sh.Uptime / 3600
		days := hours / 24
		buf.WriteString(renderKPI("Uptime", fmt.Sprintf("%dd %dh", days, hours%24), ""))
	}
	if sh.MemoryMB > 0 {
		buf.WriteString(renderKPI("Memory", fmt.Sprintf("%d MB", sh.MemoryMB), ""))
	}
	buf.WriteString(renderKPI("Jobs Failed", fmt.Sprint(sh.JobsFailed), ""))
	if sh.DataSince > 0 {
		buf.WriteString(renderKPI("Data Since", time.Unix(sh.DataSince, 0).Format("2006-01-02"), ""))
	}
	buf.WriteString(`</div>`)
}

func (e *Engine) renderBlockedActivityHTML(buf *bytes.Buffer, ba BlockedActivity) {
	if len(ba.ByPolicy) > 0 {
		buf.WriteString(`<h3>By Policy</h3><table><tr><th>Policy</th><th>Count</th></tr>`)
		for _, row := range ba.ByPolicy {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(row.PolicyName), row.Count))
		}
		buf.WriteString(`</table>`)
	}
	if len(ba.ByApp) > 0 {
		buf.WriteString(`<h3>By Application</h3><table><tr><th>Application</th><th>Count</th></tr>`)
		for _, row := range ba.ByApp {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(row.PolicyName), row.Count))
		}
		buf.WriteString(`</table>`)
	}
}

func (e *Engine) renderDNSSummaryHTML(buf *bytes.Buffer, dns DNSSummary) {
	buf.WriteString(fmt.Sprintf(`<p>Total Queries: %d | Blocked: %d</p>`, dns.TotalQueries, dns.TotalBlocked))
	if len(dns.TopDomains) > 0 {
		buf.WriteString(`<h3>Top Domains</h3><table><tr><th>Domain</th><th>Count</th></tr>`)
		for _, row := range dns.TopDomains {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(row.Domain), row.Count))
		}
		buf.WriteString(`</table>`)
	}
	if len(dns.TopBlocked) > 0 {
		buf.WriteString(`<h3>Top Blocked</h3><table><tr><th>Domain</th><th>Count</th></tr>`)
		for _, row := range dns.TopBlocked {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(row.Domain), row.Count))
		}
		buf.WriteString(`</table>`)
	}
}

func (e *Engine) renderTLSPostureHTML(buf *bytes.Buffer, tls TLSPosture) {
	buf.WriteString(fmt.Sprintf(`<p>Total Connections: %d | Untrusted Certs: %d</p>`, tls.TotalConnections, tls.UntrustedCerts))
	if len(tls.Versions) > 0 {
		buf.WriteString(`<h3>TLS Versions</h3><table><tr><th>Version</th><th>Count</th></tr>`)
		for _, row := range tls.Versions {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(row.Version), row.Count))
		}
		buf.WriteString(`</table>`)
	}
}

func (e *Engine) renderAlertsHTML(buf *bytes.Buffer, alerts Alerts) {
	buf.WriteString(fmt.Sprintf(`<p>Total: %d | Critical: %d | High: %d</p>`, alerts.TotalAlerts, alerts.CriticalCount, alerts.HighCount))
	if len(alerts.TopSignatures) > 0 {
		buf.WriteString(`<h3>Top Threats</h3><table><tr><th>Signature</th><th>Severity</th><th>Count</th></tr>`)
		for _, row := range alerts.TopSignatures {
			buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><span class="pill %s">%s</span></td><td>%d</td></tr>`,
				escapeHTML(row.Signature), sevClass(row.Severity), escapeHTML(row.Severity), row.Count))
		}
		buf.WriteString(`</table>`)
	}
}

func sevClass(sev string) string {
	switch sev {
	case "critical", "high":
		return "bad"
	case "medium":
		return "warn"
	default:
		return "ok"
	}
}

func (e *Engine) renderExecSummaryHTML(buf *bytes.Buffer, es ExecutiveSummary) {
	buf.WriteString(`<div class="kpis">`)
	buf.WriteString(renderKPI("Hosts", fmt.Sprint(es.ThisPeriod.Hosts), ""))
	buf.WriteString(renderKPI("Devices", fmt.Sprint(es.ThisPeriod.Devices), ""))
	buf.WriteString(renderKPI("Flows", fmt.Sprint(es.ThisPeriod.Flows), fmt.Sprintf("%.0f%% vs last", es.Changes.FlowsPercent)))
	buf.WriteString(renderKPI("Traffic", formatBytes(es.ThisPeriod.BytesIn+es.ThisPeriod.BytesOut), fmt.Sprintf("%.0f%% vs last", es.Changes.BytesPercent)))
	buf.WriteString(renderKPI("Blocked", fmt.Sprint(es.ThisPeriod.Blocked), fmt.Sprintf("%.0f%% vs last", es.Changes.BlockedPercent)))
	buf.WriteString(renderKPI("DNS Queries", fmt.Sprint(es.ThisPeriod.DNSQueries), ""))
	buf.WriteString(renderKPI("DNS Blocked", fmt.Sprint(es.ThisPeriod.DNSBlocked), ""))
	buf.WriteString(renderKPI("TLS Conns", fmt.Sprint(es.ThisPeriod.TLSConnections), ""))
	buf.WriteString(renderKPI("Alerts", fmt.Sprint(es.ThisPeriod.Alerts), fmt.Sprintf("%.0f%% vs last", es.Changes.AlertsPercent)))
	if es.ThisPeriod.AlertsCritical > 0 {
		buf.WriteString(renderKPI("Critical", fmt.Sprint(es.ThisPeriod.AlertsCritical), "bad"))
	}
	buf.WriteString(renderKPI("Findings", fmt.Sprint(es.ThisPeriod.Findings), ""))
	buf.WriteString(`</div>`)
}

func renderKPI(label, value, info string) string {
	var class string
	if info == "bad" {
		class = `class="kpi bad"`
		info = ""
	} else {
		class = `class="kpi"`
	}
	if info != "" {
		return fmt.Sprintf(`<div %s><h3>%s</h3><div class="v">%s</div><div class="info">%s</div></div>`, class, escapeHTML(label), escapeHTML(value), escapeHTML(info))
	}
	return fmt.Sprintf(`<div %s><h3>%s</h3><div class="v">%s</div></div>`, class, escapeHTML(label), escapeHTML(value))
}

func (e *Engine) renderTrafficByDeviceHTML(buf *bytes.Buffer, tbd TrafficByDevice) {
	buf.WriteString(`<table><tr><th>Device</th><th>Zone</th><th>Flows</th><th>Bytes In</th><th>Bytes Out</th><th>Top App</th><th>Blocked</th></tr>`)
	for _, row := range tbd.Rows {
		buf.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td></tr>`,
			escapeHTML(row.DeviceName), escapeHTML(row.Zone), row.Flows,
			formatBytes(row.BytesIn), formatBytes(row.BytesOut),
			escapeHTML(row.TopApp), row.BlockedFlows))
	}
	buf.WriteString(`</table>`)
}

// RenderJSON produces a JSON report.
func (e *Engine) RenderJSON(def *Definition, run *Run) ([]byte, error) {
	output := map[string]any{
		"definition": def,
		"run":        run,
	}
	return json.MarshalIndent(output, "", "  ")
}

// RenderMarkdown produces a Markdown report.
func (e *Engine) RenderMarkdown(def *Definition, run *Run) (string, error) {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("# %s\n\n", def.Name))
	buf.WriteString(fmt.Sprintf("Generated %s\n\n", time.Now().Format("2006-01-02 15:04 MST")))
	buf.WriteString("## Contents\n\n")
	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		buf.WriteString(fmt.Sprintf("- [%s](#%s)\n", sec.Title(), strings.ReplaceAll(sec.Title(), " ", "-")))
	}
	buf.WriteString("\n")

	for _, key := range def.Sections {
		sec, ok := e.sections[key]
		if !ok {
			continue
		}
		data := run.SectionData[key]
		buf.WriteString(fmt.Sprintf("## %s\n\n", sec.Title()))
		buf.WriteString(fmt.Sprintf("*%s*\n\n", sec.Notes()))
		e.renderSectionMarkdown(&buf, key, data)
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

func (e *Engine) renderSectionMarkdown(buf *bytes.Buffer, key string, data any) {
	if data == nil {
		return
	}
	switch key {
	case "executive_summary":
		if es, ok := data.(ExecutiveSummary); ok {
			e.renderExecSummaryMarkdown(buf, es)
		}
	case "traffic_by_device":
		if tbd, ok := data.(TrafficByDevice); ok {
			e.renderTrafficByDeviceMarkdown(buf, tbd)
		}
	case "blocked_activity":
		if ba, ok := data.(BlockedActivity); ok {
			e.renderBlockedActivityMarkdown(buf, ba)
		}
	case "dns_summary":
		if dns, ok := data.(DNSSummary); ok {
			e.renderDNSSummaryMarkdown(buf, dns)
		}
	case "tls_posture":
		if tls, ok := data.(TLSPosture); ok {
			e.renderTLSPostureMarkdown(buf, tls)
		}
	case "traffic_by_zone":
		if tbz, ok := data.(TrafficByZone); ok {
			e.renderTrafficByZoneMarkdown(buf, tbz)
		}
	case "traffic_by_app":
		if tba, ok := data.(TrafficByApp); ok {
			e.renderTrafficByAppMarkdown(buf, tba)
		}
	case "traffic_by_category":
		if tbc, ok := data.(TrafficByCategory); ok {
			e.renderTrafficByCategoryMarkdown(buf, tbc)
		}
	case "traffic_by_site":
		if tbs, ok := data.(TrafficBySite); ok {
			e.renderTrafficBySiteMarkdown(buf, tbs)
		}
	case "egress_activity", "scan_findings", "device_inventory", "alerting_deliveries", "system_health":
		// Default to JSON for new sections
		fallthrough
	case "alerts":
		if alerts, ok := data.(Alerts); ok {
			e.renderAlertsMarkdown(buf, alerts)
		}
	default:
		if b, err := json.MarshalIndent(data, "", "  "); err == nil {
			buf.WriteString("```json\n")
			buf.WriteString(string(b))
			buf.WriteString("\n```\n")
		}
	}
}

func (e *Engine) renderTrafficByZoneMarkdown(buf *bytes.Buffer, tbz TrafficByZone) {
	buf.WriteString("| Zone | Flows | Bytes In | Bytes Out | Blocked | Devices |\n")
	buf.WriteString("|------|-------|----------|-----------|---------|----------|\n")
	for _, row := range tbz.Rows {
		buf.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %d | %d |\n",
			row.Zone, row.Flows, formatBytes(row.BytesIn), formatBytes(row.BytesOut), row.Blocked, row.Devices))
	}
}

func (e *Engine) renderTrafficByAppMarkdown(buf *bytes.Buffer, tba TrafficByApp) {
	buf.WriteString("| Application | Flows | Bytes | Blocked | Devices |\n")
	buf.WriteString("|-------------|-------|-------|---------|----------|\n")
	for _, row := range tba.Rows {
		buf.WriteString(fmt.Sprintf("| %s | %d | %s | %d | %d |\n",
			row.App, row.Flows, formatBytes(row.Bytes), row.Blocked, row.Devices))
	}
}

func (e *Engine) renderTrafficByCategoryMarkdown(buf *bytes.Buffer, tbc TrafficByCategory) {
	buf.WriteString("| Category | Flows | Bytes | Blocked | Devices | Apps |\n")
	buf.WriteString("|----------|-------|-------|---------|---------|------|\n")
	for _, row := range tbc.Rows {
		buf.WriteString(fmt.Sprintf("| %s | %d | %s | %d | %d | %d |\n",
			row.Category, row.Flows, formatBytes(row.Bytes), row.Blocked, row.Devices, row.Apps))
	}
}

func (e *Engine) renderTrafficBySiteMarkdown(buf *bytes.Buffer, tbs TrafficBySite) {
	buf.WriteString("| Domain | Flows | Bytes | Blocked |\n")
	buf.WriteString("|--------|-------|-------|----------|\n")
	for _, row := range tbs.Rows {
		buf.WriteString(fmt.Sprintf("| %s | %d | %s | %d |\n",
			row.Domain, row.Flows, formatBytes(row.Bytes), row.Blocked))
	}
}

func (e *Engine) renderExecSummaryMarkdown(buf *bytes.Buffer, es ExecutiveSummary) {
	buf.WriteString("| Metric | Value |\n")
	buf.WriteString("|--------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Hosts | %d |\n", es.ThisPeriod.Hosts))
	buf.WriteString(fmt.Sprintf("| Devices | %d |\n", es.ThisPeriod.Devices))
	buf.WriteString(fmt.Sprintf("| Flows | %d (%.0f%% vs last) |\n", es.ThisPeriod.Flows, es.Changes.FlowsPercent))
	buf.WriteString(fmt.Sprintf("| Traffic | %s (%.0f%% vs last) |\n", formatBytes(es.ThisPeriod.BytesIn+es.ThisPeriod.BytesOut), es.Changes.BytesPercent))
	buf.WriteString(fmt.Sprintf("| Blocked | %d (%.0f%% vs last) |\n", es.ThisPeriod.Blocked, es.Changes.BlockedPercent))
	buf.WriteString(fmt.Sprintf("| DNS Queries | %d |\n", es.ThisPeriod.DNSQueries))
	buf.WriteString(fmt.Sprintf("| DNS Blocked | %d |\n", es.ThisPeriod.DNSBlocked))
	buf.WriteString(fmt.Sprintf("| Alerts | %d (%.0f%% vs last) |\n", es.ThisPeriod.Alerts, es.Changes.AlertsPercent))
	if es.ThisPeriod.AlertsCritical > 0 {
		buf.WriteString(fmt.Sprintf("| Critical Alerts | %d |\n", es.ThisPeriod.AlertsCritical))
	}
	buf.WriteString(fmt.Sprintf("| Findings | %d |\n", es.ThisPeriod.Findings))
}

func (e *Engine) renderTrafficByDeviceMarkdown(buf *bytes.Buffer, tbd TrafficByDevice) {
	buf.WriteString("| Device | Zone | Flows | Bytes In | Bytes Out | Top App | Blocked |\n")
	buf.WriteString("|--------|------|-------|----------|-----------|---------|----------|\n")
	for _, row := range tbd.Rows {
		buf.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s | %s | %d |\n",
			row.DeviceName, row.Zone, row.Flows,
			formatBytes(row.BytesIn), formatBytes(row.BytesOut),
			row.TopApp, row.BlockedFlows))
	}
}

func (e *Engine) renderBlockedActivityMarkdown(buf *bytes.Buffer, ba BlockedActivity) {
	if len(ba.ByPolicy) > 0 {
		buf.WriteString("#### By Policy\n\n")
		buf.WriteString("| Policy | Count |\n")
		buf.WriteString("|--------|-------|\n")
		for _, row := range ba.ByPolicy {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", row.PolicyName, row.Count))
		}
		buf.WriteString("\n")
	}
	if len(ba.ByApp) > 0 {
		buf.WriteString("#### By Application\n\n")
		buf.WriteString("| Application | Count |\n")
		buf.WriteString("|-------------|-------|\n")
		for _, row := range ba.ByApp {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", row.PolicyName, row.Count))
		}
	}
}

func (e *Engine) renderDNSSummaryMarkdown(buf *bytes.Buffer, dns DNSSummary) {
	buf.WriteString(fmt.Sprintf("Total Queries: **%d** | Blocked: **%d**\n\n", dns.TotalQueries, dns.TotalBlocked))
	if len(dns.TopDomains) > 0 {
		buf.WriteString("#### Top Domains\n\n")
		buf.WriteString("| Domain | Count |\n")
		buf.WriteString("|--------|-------|\n")
		for _, row := range dns.TopDomains {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", row.Domain, row.Count))
		}
		buf.WriteString("\n")
	}
	if len(dns.TopBlocked) > 0 {
		buf.WriteString("#### Top Blocked\n\n")
		buf.WriteString("| Domain | Count |\n")
		buf.WriteString("|--------|-------|\n")
		for _, row := range dns.TopBlocked {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", row.Domain, row.Count))
		}
	}
}

func (e *Engine) renderTLSPostureMarkdown(buf *bytes.Buffer, tls TLSPosture) {
	buf.WriteString(fmt.Sprintf("Total Connections: **%d** | Untrusted Certs: **%d**\n\n", tls.TotalConnections, tls.UntrustedCerts))
	if len(tls.Versions) > 0 {
		buf.WriteString("#### TLS Versions\n\n")
		buf.WriteString("| Version | Count |\n")
		buf.WriteString("|---------|-------|\n")
		for _, row := range tls.Versions {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", row.Version, row.Count))
		}
	}
}

func (e *Engine) renderAlertsMarkdown(buf *bytes.Buffer, alerts Alerts) {
	buf.WriteString(fmt.Sprintf("Total: **%d** | Critical: **%d** | High: **%d**\n\n", alerts.TotalAlerts, alerts.CriticalCount, alerts.HighCount))
	if len(alerts.TopSignatures) > 0 {
		buf.WriteString("#### Top Threats\n\n")
		buf.WriteString("| Signature | Severity | Count |\n")
		buf.WriteString("|-----------|----------|-------|\n")
		for _, row := range alerts.TopSignatures {
			buf.WriteString(fmt.Sprintf("| %s | %s | %d |\n", row.Signature, row.Severity, row.Count))
		}
	}
}

// RenderCSV produces a CSV export. Returns one CSV per section.
func (e *Engine) RenderCSV(def *Definition, run *Run) (map[string]string, error) {
	result := make(map[string]string)

	for _, key := range def.Sections {
		data := run.SectionData[key]
		csv, err := e.renderSectionCSV(key, data)
		if err != nil {
			continue
		}
		result[key] = csv
	}

	return result, nil
}

func (e *Engine) renderSectionCSV(key string, data any) (string, error) {
	if data == nil {
		return "", nil
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	switch key {
	case "executive_summary":
		if es, ok := data.(ExecutiveSummary); ok {
			w.Write([]string{"metric", "this_period", "previous_period", "change_percent"})
			w.Write([]string{"hosts", fmt.Sprint(es.ThisPeriod.Hosts), "", ""})
			w.Write([]string{"flows", fmt.Sprint(es.ThisPeriod.Flows), fmt.Sprint(es.PreviousPeriod.Flows), fmt.Sprintf("%.2f", es.Changes.FlowsPercent)})
			w.Write([]string{"bytes", fmt.Sprint(es.ThisPeriod.BytesIn + es.ThisPeriod.BytesOut), fmt.Sprint(es.PreviousPeriod.BytesIn + es.PreviousPeriod.BytesOut), fmt.Sprintf("%.2f", es.Changes.BytesPercent)})
			w.Write([]string{"blocked", fmt.Sprint(es.ThisPeriod.Blocked), fmt.Sprint(es.PreviousPeriod.Blocked), fmt.Sprintf("%.2f", es.Changes.BlockedPercent)})
			w.Write([]string{"alerts", fmt.Sprint(es.ThisPeriod.Alerts), fmt.Sprint(es.PreviousPeriod.Alerts), fmt.Sprintf("%.2f", es.Changes.AlertsPercent)})
		}
	case "traffic_by_device":
		if tbd, ok := data.(TrafficByDevice); ok {
			w.Write([]string{"device_name", "zone", "flows", "bytes_in", "bytes_out", "top_app", "blocked_flows"})
			for _, row := range tbd.Rows {
				w.Write([]string{row.DeviceName, row.Zone, fmt.Sprint(row.Flows), fmt.Sprint(row.BytesIn), fmt.Sprint(row.BytesOut), row.TopApp, fmt.Sprint(row.BlockedFlows)})
			}
		}
	}

	w.Flush()
	return buf.String(), nil
}

// ListBuiltIns returns built-in report definitions.
func ListBuiltIns() []Definition {
	now := time.Now().Unix()
	return []Definition{
		{
			ID:        "daily_digest",
			Name:      "Daily Digest",
			Sections:  []string{"executive_summary", "traffic_by_device"},
			Filters:   &Filters{},
			Formats:   []string{"html", "pdf"},
			Schedule:  &Schedule{Enabled: false, Cadence: "daily", TimeUTC: "08:00"},
			ReadOnly:  true,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "weekly_household",
			Name:      "Weekly Household",
			Sections:  []string{"executive_summary", "traffic_by_device"},
			Filters:   &Filters{},
			Formats:   []string{"html", "pdf"},
			Schedule:  &Schedule{Enabled: false, Cadence: "weekly", TimeUTC: "09:00"},
			ReadOnly:  true,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "monthly_executive",
			Name:      "Monthly Executive",
			Sections:  []string{"executive_summary", "traffic_by_device"},
			Filters:   &Filters{},
			Formats:   []string{"html", "pdf"},
			Schedule:  &Schedule{Enabled: false, Cadence: "monthly", TimeUTC: "09:00"},
			ReadOnly:  true,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}
