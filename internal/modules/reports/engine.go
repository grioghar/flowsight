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
	default:
		// Generic JSON rendering
		buf.WriteString(`<pre>`)
		if b, err := json.MarshalIndent(data, "", "  "); err == nil {
			buf.WriteString(escapeHTML(string(b)))
		}
		buf.WriteString(`</pre>`)
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
	default:
		if b, err := json.MarshalIndent(data, "", "  "); err == nil {
			buf.WriteString("```json\n")
			buf.WriteString(string(b))
			buf.WriteString("\n```\n")
		}
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
