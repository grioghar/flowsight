// Package reports generates HTML reports and CSV exports with scheduling.
//
// Reports include executive summary, top hosts/apps/categories/sites/destinations,
// blocked activity, threats, DNS and TLS summaries, and open findings.
package reports

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx      *core.Context
	mu       sync.RWMutex
	lastErr  string
	identity core.Identity
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "reports", Version: "1.0",
		Description:  "HTML reports and CSV exports with scheduling.",
		Capabilities: []string{},
		After:        []string{"identity", "alerting"},
		Defaults: map[string]any{
			"schedules": []any{},
		},
		Schema: []core.SettingField{
			{Key: "schedules", Label: "Report schedules", Type: "list", Help: "Configured report schedules."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)

	// Initialize schedules in KV if not present
	if !ctx.Store.KVGet("reports.schedules", &[]Schedule{}) {
		_ = ctx.Store.KVSet("reports.schedules", []Schedule{})
	}

	// Run scheduler job every 10 minutes
	ctx.Every("scheduler", 10*time.Minute, m.sendDueReports)

	// API routes
	ctx.Route("GET", "/api/reports/preview", m.apiPreview, core.Doc("Generate and preview a report as HTML"),
		core.Params("hours", "window"))
	ctx.Route("GET", "/api/reports/export", m.apiExport, core.Doc("Export data as CSV"),
		core.Params("kind", "flows|dns|alerts|hosts", "hours", "window"))
	ctx.Route("GET", "/api/reports/schedules", m.apiGetSchedules, core.Doc("List report schedules"))
	ctx.Route("POST", "/api/reports/schedules", m.apiSetSchedules, core.Write(), core.Doc("Replace report schedules"))
	ctx.Route("POST", "/api/reports/run", m.apiRunReport, core.Write(), core.Doc("Generate and send a report now"))

	ctx.Panel(core.Panel{ID: "reports", Title: "Reports", Group: "Operations", Order: 180, Icon: "reports"})

	return nil
}

func (m *Module) Health() core.Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	return core.Health{OK: true, Detail: "reports ready"}
}

type Schedule struct {
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Cadence    string   `json:"cadence"` // daily, weekly, monthly
	Hour       int      `json:"hour"`    // 0-23
	Recipients []string `json:"recipients"`
	Window     int      `json:"window"` // hours
}

// getEmailer returns the alerting notifier service's SendEmail method.
func (m *Module) getEmailer() EmailSender {
	if svc := m.ctx.Service("notifier"); svc != nil {
		if es, ok := svc.(EmailSender); ok {
			return es
		}
	}
	return nil
}

type EmailSender interface {
	SendEmail(subject, html string, to []string) error
}

// buildReport generates an HTML report for the given window.
func (m *Module) buildReport(hours int) string {
	st := m.ctx.Store
	since := time.Now().Unix() - int64(hours)*3600

	// Collect data
	hostCount := st.Int(`SELECT COUNT(*) FROM hosts WHERE is_local=1`)
	flowCount := st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=?`, since)
	blockedCount := st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=? AND verdict='blocked'`, since)
	dnsCount := st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=?`, since)
	dnsBlockedCount := st.Int(`SELECT COUNT(*) FROM dns WHERE ts>=? AND action='block'`, since)
	alertCount := st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=?`, since)
	alertCritical := st.Int(`SELECT COUNT(*) FROM alerts WHERE ts>=? AND severity='critical'`, since)
	findingCount := st.Int(`SELECT COUNT(*) FROM findings WHERE resolved_ts IS NULL`, since)

	// Get top data
	topHosts, _ := st.Rows(`SELECT src_ip, bytes_out, bytes_in FROM hosts WHERE is_local=1 ORDER BY bytes_out+bytes_in DESC LIMIT 10`)
	topApps, _ := st.Rows(`SELECT app, SUM(bytes_out+bytes_in) as bytes, COUNT(*) as flows FROM flows WHERE ts>=? GROUP BY app ORDER BY bytes DESC LIMIT 10`, since)
	topDomains, _ := st.Rows(`SELECT domain, COUNT(*) as count FROM flows WHERE ts>=? AND domain IS NOT NULL GROUP BY domain ORDER BY count DESC LIMIT 10`, since)

	blockedByPolicy, _ := st.Rows(`SELECT policy, COUNT(*) as count FROM flows WHERE ts>=? AND verdict='blocked' GROUP BY policy ORDER BY count DESC LIMIT 10`, since)
	blockedByHost, _ := st.Rows(`SELECT src_ip, COUNT(*) as count FROM flows WHERE ts>=? AND verdict='blocked' GROUP BY src_ip ORDER BY count DESC LIMIT 10`, since)

	threatsBySig, _ := st.Rows(`SELECT signature, COUNT(*) as count, severity FROM alerts WHERE ts>=? GROUP BY signature ORDER BY count DESC LIMIT 10`, since)
	threatsBySource, _ := st.Rows(`SELECT src_ip, COUNT(*) as count FROM alerts WHERE ts>=? GROUP BY src_ip ORDER BY count DESC LIMIT 10`, since)

	dnsBlocked, _ := st.Rows(`SELECT domain, COUNT(*) as count, list FROM dns WHERE ts>=? AND action='block' GROUP BY domain ORDER BY count DESC LIMIT 10`, since)
	dnsClients, _ := st.Rows(`SELECT client, COUNT(*) as count FROM dns WHERE ts>=? GROUP BY client ORDER BY count DESC LIMIT 10`, since)

	tlsVersions, _ := st.Rows(`SELECT tls_version, COUNT(*) as count FROM flows WHERE ts>=? AND tls_version IS NOT NULL GROUP BY tls_version`, since)
	tlsProblems, _ := st.Rows(`SELECT subject, reason FROM tls_certs WHERE trusted=0 AND last_seen>=? LIMIT 20`, since)

	findings, _ := st.Rows(`SELECT title, severity FROM findings WHERE resolved_ts IS NULL ORDER BY severity DESC LIMIT 20`)

	// Build HTML
	var html bytes.Buffer
	html.WriteString(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><style>`)
	html.WriteString(reportCSS)
	html.WriteString(`</style><title>Flowsight Report</title></head><body>`)

	html.WriteString(fmt.Sprintf(`<h1>Flowsight Report</h1><p>Generated %s · Window: last %d hours</p>`, time.Now().Format("2006-01-02 15:04 MST"), hours))

	// Executive summary
	html.WriteString(`<section><h2>Executive Summary</h2><div class="kpis">`)
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>Hosts</h3><div class="v">%d</div></div>`, hostCount))
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>Flows</h3><div class="v">%d</div></div>`, flowCount))
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>Blocked</h3><div class="v">%d</div></div>`, blockedCount))
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>Alerts</h3><div class="v">%d</div></div>`, alertCount))
	if alertCritical > 0 {
		html.WriteString(fmt.Sprintf(`<div class="kpi bad"><h3>Critical</h3><div class="v">%d</div></div>`, alertCritical))
	}
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>DNS Queries</h3><div class="v">%d</div></div>`, dnsCount))
	if dnsBlockedCount > 0 {
		html.WriteString(fmt.Sprintf(`<div class="kpi warn"><h3>DNS Blocked</h3><div class="v">%d</div></div>`, dnsBlockedCount))
	}
	html.WriteString(fmt.Sprintf(`<div class="kpi"><h3>Findings</h3><div class="v">%d</div></div>`, findingCount))
	html.WriteString(`</div></section>`)

	// Top hosts
	if len(topHosts) > 0 {
		html.WriteString(`<section><h2>Top Hosts (by traffic)</h2><table><tr><th>Host</th><th>Upload</th><th>Download</th></tr>`)
		for _, row := range topHosts {
			ip, _ := row["src_ip"].(string)
			name := ip
			if m.identity != nil {
				if n := m.identity.Name(ip); n != "" {
					name = n
				}
			}
			out, _ := row["bytes_out"].(int64)
			in, _ := row["bytes_in"].(int64)
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s</td></tr>`, escapeHTML(name), formatBytes(out), formatBytes(in)))
		}
		html.WriteString(`</table></section>`)
	}

	// Top apps
	if len(topApps) > 0 {
		html.WriteString(`<section><h2>Top Applications</h2><table><tr><th>Application</th><th>Bytes</th><th>Flows</th></tr>`)
		for _, row := range topApps {
			app, _ := row["app"].(string)
			if app == "" {
				app = "Unknown"
			}
			bytes, _ := row["bytes"].(int64)
			flows, _ := row["flows"].(int64)
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td></tr>`, escapeHTML(app), formatBytes(bytes), flows))
		}
		html.WriteString(`</table></section>`)
	}

	// Top domains
	if len(topDomains) > 0 {
		html.WriteString(`<section><h2>Top Domains</h2><table><tr><th>Domain</th><th>Flows</th></tr>`)
		for _, row := range topDomains {
			domain, _ := row["domain"].(string)
			count, _ := row["count"].(int64)
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(domain), count))
		}
		html.WriteString(`</table></section>`)
	}

	// Blocked activity
	if len(blockedByPolicy) > 0 || len(blockedByHost) > 0 {
		html.WriteString(`<section><h2>Blocked Activity</h2>`)
		if len(blockedByPolicy) > 0 {
			html.WriteString(`<h3>By Policy</h3><table><tr><th>Policy</th><th>Count</th></tr>`)
			for _, row := range blockedByPolicy {
				policy, _ := row["policy"].(string)
				count, _ := row["count"].(int64)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(policy), count))
			}
			html.WriteString(`</table>`)
		}
		if len(blockedByHost) > 0 {
			html.WriteString(`<h3>By Source Host</h3><table><tr><th>Host</th><th>Count</th></tr>`)
			for _, row := range blockedByHost {
				ip, _ := row["src_ip"].(string)
				count, _ := row["count"].(int64)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(ip), count))
			}
			html.WriteString(`</table>`)
		}
		html.WriteString(`</section>`)
	}

	// Threats
	if len(threatsBySig) > 0 || len(threatsBySource) > 0 {
		html.WriteString(`<section><h2>Threats</h2>`)
		if len(threatsBySig) > 0 {
			html.WriteString(`<h3>By Signature</h3><table><tr><th>Signature</th><th>Count</th><th>Severity</th></tr>`)
			for _, row := range threatsBySig {
				sig, _ := row["signature"].(string)
				count, _ := row["count"].(int64)
				sev, _ := row["severity"].(string)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td><span class="pill %s">%s</span></td></tr>`, escapeHTML(sig), count, sevClass(sev), escapeHTML(sev)))
			}
			html.WriteString(`</table>`)
		}
		if len(threatsBySource) > 0 {
			html.WriteString(`<h3>By Source</h3><table><tr><th>Host</th><th>Count</th></tr>`)
			for _, row := range threatsBySource {
				ip, _ := row["src_ip"].(string)
				count, _ := row["count"].(int64)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(ip), count))
			}
			html.WriteString(`</table>`)
		}
		html.WriteString(`</section>`)
	}

	// DNS summary
	if len(dnsBlocked) > 0 || len(dnsClients) > 0 {
		html.WriteString(`<section><h2>DNS Summary</h2>`)
		if len(dnsBlocked) > 0 {
			html.WriteString(`<h3>Top Blocked Domains</h3><table><tr><th>Domain</th><th>Count</th><th>Policy</th></tr>`)
			for _, row := range dnsBlocked {
				domain, _ := row["domain"].(string)
				count, _ := row["count"].(int64)
				list, _ := row["list"].(string)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td></tr>`, escapeHTML(domain), count, escapeHTML(list)))
			}
			html.WriteString(`</table>`)
		}
		if len(dnsClients) > 0 {
			html.WriteString(`<h3>Top Clients</h3><table><tr><th>Client</th><th>Queries</th></tr>`)
			for _, row := range dnsClients {
				client, _ := row["client"].(string)
				count, _ := row["count"].(int64)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(client), count))
			}
			html.WriteString(`</table>`)
		}
		html.WriteString(`</section>`)
	}

	// TLS summary
	if len(tlsVersions) > 0 || len(tlsProblems) > 0 {
		html.WriteString(`<section><h2>TLS Summary</h2>`)
		if len(tlsVersions) > 0 {
			html.WriteString(`<h3>TLS Versions</h3><table><tr><th>Version</th><th>Count</th></tr>`)
			for _, row := range tlsVersions {
				version, _ := row["tls_version"].(string)
				count, _ := row["count"].(int64)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, escapeHTML(version), count))
			}
			html.WriteString(`</table>`)
		}
		if len(tlsProblems) > 0 {
			html.WriteString(`<h3>Problem Certificates</h3><table><tr><th>Subject</th><th>Issue</th></tr>`)
			for _, row := range tlsProblems {
				subject, _ := row["subject"].(string)
				reason, _ := row["reason"].(string)
				html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td></tr>`, escapeHTML(subject), escapeHTML(reason)))
			}
			html.WriteString(`</table>`)
		}
		html.WriteString(`</section>`)
	}

	// Open findings
	if len(findings) > 0 {
		html.WriteString(`<section><h2>Open Findings</h2><table><tr><th>Title</th><th>Severity</th></tr>`)
		for _, row := range findings {
			title, _ := row["title"].(string)
			sev, _ := row["severity"].(string)
			html.WriteString(fmt.Sprintf(`<tr><td>%s</td><td><span class="pill %s">%s</span></td></tr>`, escapeHTML(title), sevClass(sev), escapeHTML(sev)))
		}
		html.WriteString(`</table></section>`)
	}

	html.WriteString(`</body></html>`)

	return html.String()
}

const reportCSS = `
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #333; background: #f5f5f5; margin: 0; padding: 20px; }
h1 { font-size: 2em; margin-top: 0; }
h2 { font-size: 1.5em; margin-top: 1.5em; border-bottom: 2px solid #ddd; padding-bottom: 0.5em; }
h3 { font-size: 1.1em; margin-top: 1em; }
section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f9f9f9; font-weight: 600; }
tr:hover { background: #f9f9f9; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1em; margin: 1em 0; }
.kpi { background: #f9f9f9; padding: 1em; border-radius: 6px; text-align: center; }
.kpi.bad { background: #fee; }
.kpi.warn { background: #fef3c7; }
.kpi h3 { margin: 0 0 0.5em; font-size: 0.9em; color: #666; }
.kpi .v { font-size: 2em; font-weight: bold; }
.pill { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; }
.pill.bad { background: #fee; color: #c00; }
.pill.warn { background: #fef3c7; color: #b8860b; }
.pill.ok { background: #efe; color: #080; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a1a; color: #e0e0e0; }
  section { background: #2a2a2a; }
  th { background: #333; }
  tr:hover { background: #333; }
  .kpi { background: #333; }
  .kpi.bad { background: #3a1a1a; }
  .kpi.warn { background: #3a3a1a; }
}
`

func escapeHTML(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	).Replace(s)
}

func formatBytes(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(b)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", int64(v))
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
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

func (m *Module) exportCSV(kind string, hours int) ([]byte, error) {
	st := m.ctx.Store
	since := time.Now().Unix() - int64(hours)*3600

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	switch kind {
	case "flows":
		w.Write([]string{"time", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "app", "domain", "bytes_in", "bytes_out", "verdict"})
		rows, _ := st.Rows(`SELECT ts, src_ip, src_port, dst_ip, dst_port, proto, app, domain, bytes_in, bytes_out, verdict
			FROM flows WHERE ts>=? ORDER BY ts DESC LIMIT 10000`, since)
		for _, row := range rows {
			ts, _ := row["ts"].(int64)
			record := []string{
				time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%v", row["src_ip"]),
				fmt.Sprintf("%v", row["src_port"]),
				fmt.Sprintf("%v", row["dst_ip"]),
				fmt.Sprintf("%v", row["dst_port"]),
				fmt.Sprintf("%v", row["proto"]),
				fmt.Sprintf("%v", row["app"]),
				fmt.Sprintf("%v", row["domain"]),
				fmt.Sprintf("%v", row["bytes_in"]),
				fmt.Sprintf("%v", row["bytes_out"]),
				fmt.Sprintf("%v", row["verdict"]),
			}
			w.Write(record)
		}

	case "dns":
		w.Write([]string{"time", "client", "domain", "qtype", "action", "list"})
		rows, _ := st.Rows(`SELECT ts, client, domain, qtype, action, list FROM dns WHERE ts>=? ORDER BY ts DESC LIMIT 10000`, since)
		for _, row := range rows {
			ts, _ := row["ts"].(int64)
			record := []string{
				time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%v", row["client"]),
				fmt.Sprintf("%v", row["domain"]),
				fmt.Sprintf("%v", row["qtype"]),
				fmt.Sprintf("%v", row["action"]),
				fmt.Sprintf("%v", row["list"]),
			}
			w.Write(record)
		}

	case "alerts":
		w.Write([]string{"time", "source", "severity", "signature", "src_ip", "dst_ip", "message"})
		rows, _ := st.Rows(`SELECT ts, source, severity, signature, src_ip, dst_ip, message FROM alerts WHERE ts>=? ORDER BY ts DESC LIMIT 5000`, since)
		for _, row := range rows {
			ts, _ := row["ts"].(int64)
			record := []string{
				time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%v", row["source"]),
				fmt.Sprintf("%v", row["severity"]),
				fmt.Sprintf("%v", row["signature"]),
				fmt.Sprintf("%v", row["src_ip"]),
				fmt.Sprintf("%v", row["dst_ip"]),
				fmt.Sprintf("%v", row["message"]),
			}
			w.Write(record)
		}

	case "hosts":
		w.Write([]string{"ip", "name", "vendor", "bytes_in", "bytes_out", "flows", "blocked", "alerts"})
		rows, _ := st.Rows(`SELECT ip, name, vendor, bytes_in, bytes_out, flows, blocked, alerts FROM hosts WHERE is_local=1 ORDER BY bytes_out DESC`)
		for _, row := range rows {
			record := []string{
				fmt.Sprintf("%v", row["ip"]),
				fmt.Sprintf("%v", row["name"]),
				fmt.Sprintf("%v", row["vendor"]),
				fmt.Sprintf("%v", row["bytes_in"]),
				fmt.Sprintf("%v", row["bytes_out"]),
				fmt.Sprintf("%v", row["flows"]),
				fmt.Sprintf("%v", row["blocked"]),
				fmt.Sprintf("%v", row["alerts"]),
			}
			w.Write(record)
		}
	}

	w.Flush()
	return buf.Bytes(), nil
}

func (m *Module) sendDueReports() error {
	schedules := make([]Schedule, 0)
	if !m.ctx.Store.KVGet("reports.schedules", &schedules) {
		return nil
	}

	now := time.Now()
	emailer := m.getEmailer()

	for _, sched := range schedules {
		if !sched.Enabled || len(sched.Recipients) == 0 {
			continue
		}

		// Check if report is due
		isDue := false
		lastRunKey := "reports.last_run." + sched.Name
		var lastRun int64
		m.ctx.Store.KVGet(lastRunKey, &lastRun)
		lastRunTime := time.Unix(lastRun, 0)

		switch sched.Cadence {
		case "daily":
			isDue = lastRun == 0 || now.Sub(lastRunTime) >= 24*time.Hour
		case "weekly":
			isDue = lastRun == 0 || now.Sub(lastRunTime) >= 7*24*time.Hour
		case "monthly":
			isDue = lastRun == 0 || now.Sub(lastRunTime) >= 30*24*time.Hour
		}

		if !isDue {
			continue
		}

		// Generate and send report
		html := m.buildReport(sched.Window)
		subject := fmt.Sprintf("Flowsight Report: %s", sched.Name)

		if emailer != nil {
			if err := emailer.SendEmail(subject, html, sched.Recipients); err != nil {
				m.mu.Lock()
				m.lastErr = err.Error()
				m.mu.Unlock()
			}
		}

		// Update last run time
		_ = m.ctx.Store.KVSet(lastRunKey, now.Unix())
	}

	return nil
}

// API Routes

func (m *Module) apiPreview(r *core.Req) (any, error) {
	hours := r.Hours(24)
	html := m.buildReport(hours)
	return core.Raw{
		ContentType: "text/html; charset=utf-8",
		Body:        []byte(html),
	}, nil
}

func (m *Module) apiExport(r *core.Req) (any, error) {
	kind, err := r.QSafe("kind", "flows", 20)
	if err != nil {
		return nil, err
	}

	if kind != "flows" && kind != "dns" && kind != "alerts" && kind != "hosts" {
		return nil, core.BadRequest("invalid export kind")
	}

	hours := r.Hours(24)
	data, err := m.exportCSV(kind, hours)
	if err != nil {
		return nil, err
	}

	filename := fmt.Sprintf("flowsight-%s-%dh.csv", kind, hours)
	return core.Raw{
		ContentType: "text/csv; charset=utf-8",
		Filename:    filename,
		Body:        data,
	}, nil
}

func (m *Module) apiGetSchedules(r *core.Req) (any, error) {
	schedules := make([]Schedule, 0)
	m.ctx.Store.KVGet("reports.schedules", &schedules)
	return map[string]any{"schedules": schedules}, nil
}

func (m *Module) apiSetSchedules(r *core.Req) (any, error) {
	schedules := make([]Schedule, 0)
	if err := r.Decode(&schedules); err != nil {
		return nil, err
	}

	// Normalize cadences
	for i := range schedules {
		if schedules[i].Cadence != "daily" && schedules[i].Cadence != "weekly" && schedules[i].Cadence != "monthly" {
			schedules[i].Cadence = "daily"
		}
		if schedules[i].Window <= 0 {
			schedules[i].Window = 24
		}
		if schedules[i].Hour < 0 || schedules[i].Hour > 23 {
			schedules[i].Hour = 0
		}
	}

	if err := m.ctx.Store.KVSet("reports.schedules", schedules); err != nil {
		return nil, err
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiRunReport(r *core.Req) (any, error) {
	body := r.Body()
	name, ok := body["name"].(string)
	if !ok {
		return nil, core.BadRequest("schedule name required")
	}

	schedules := make([]Schedule, 0)
	m.ctx.Store.KVGet("reports.schedules", &schedules)

	var sched *Schedule
	for i := range schedules {
		if schedules[i].Name == name {
			sched = &schedules[i]
			break
		}
	}

	if sched == nil {
		return nil, core.NotFound("schedule not found")
	}

	html := m.buildReport(sched.Window)
	subject := fmt.Sprintf("Flowsight Report: %s", sched.Name)

	emailer := m.getEmailer()
	if emailer != nil && len(sched.Recipients) > 0 {
		if err := emailer.SendEmail(subject, html, sched.Recipients); err != nil {
			return nil, core.Errorf(500, "send failed: %v", err)
		}
	}

	return core.Raw{
		ContentType: "text/html; charset=utf-8",
		Body:        []byte(html),
	}, nil
}
