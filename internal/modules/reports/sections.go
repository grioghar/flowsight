// Package reports sections: modular report building blocks.
package reports

import (
	"fmt"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Section produces data for a part of a report.
type Section interface {
	// Key returns a unique identifier (e.g., "executive_summary").
	Key() string
	// Title returns the section title.
	Title() string
	// Run queries data and returns it as a typed object.
	Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error)
	// Notes describes what the section computes (e.g., "bytes counted at flow layer").
	Notes() string
}

// TimeWindow specifies a reporting period.
type TimeWindow struct {
	From int64 // unix timestamp
	To   int64 // unix timestamp
}

func (tw *TimeWindow) Hours() float64 {
	return float64(tw.To-tw.From) / 3600.0
}

func (tw *TimeWindow) String() string {
	return fmt.Sprintf("%s to %s (%dh)",
		time.Unix(tw.From, 0).Format("2006-01-02 15:04 MST"),
		time.Unix(tw.To, 0).Format("2006-01-02 15:04 MST"),
		int(tw.Hours()))
}

// Filters control which data is included in sections.
type Filters struct {
	IPs         []string `json:"ips"`          // filter by source IP address
	Apps        []string `json:"apps"`         // filter by application
	Categories  []string `json:"categories"`   // filter by category
	SitePattern string   `json:"site_pattern"` // filter by domain pattern (substring)
	Verdict     string   `json:"verdict"`      // "" (all), "allowed", "blocked"
	SeverityGE  string   `json:"severity_gte"` // filter alerts: "" (all), "low", "medium", "high", "critical"
	TopN        int      `json:"top_n"`        // limit results; 0 = no limit
	GroupBy     string   `json:"group_by"`     // "app" | "category" | "site" | "hour" | "day" | ""
}

func (f *Filters) ipSQL() string {
	if len(f.IPs) == 0 {
		return ""
	}
	ph := strings.Repeat("?,", len(f.IPs))
	ph = ph[:len(ph)-1]
	return " AND src_ip IN (" + ph + ")"
}

func (f *Filters) ipArgs() []any {
	args := make([]any, len(f.IPs))
	for i, ip := range f.IPs {
		args[i] = ip
	}
	return args
}

func (f *Filters) appSQL() string {
	if len(f.Apps) == 0 {
		return ""
	}
	ph := strings.Repeat("?,", len(f.Apps))
	ph = ph[:len(ph)-1]
	return " AND app IN (" + ph + ")"
}

func (f *Filters) appArgs() []any {
	args := make([]any, len(f.Apps))
	for i, a := range f.Apps {
		args[i] = a
	}
	return args
}

func (f *Filters) categorySQL() string {
	if len(f.Categories) == 0 {
		return ""
	}
	ph := strings.Repeat("?,", len(f.Categories))
	ph = ph[:len(ph)-1]
	return " AND category IN (" + ph + ")"
}

func (f *Filters) categoryArgs() []any {
	args := make([]any, len(f.Categories))
	for i, c := range f.Categories {
		args[i] = c
	}
	return args
}

func (f *Filters) siteSQL() string {
	if f.SitePattern == "" {
		return ""
	}
	return " AND domain LIKE ?"
}

func (f *Filters) siteArgs() []any {
	if f.SitePattern == "" {
		return nil
	}
	return []any{"%" + f.SitePattern + "%"}
}

func (f *Filters) verdictSQL() string {
	if f.Verdict == "" {
		return ""
	}
	return " AND verdict = ?"
}

func (f *Filters) verdictArgs() []any {
	if f.Verdict == "" {
		return nil
	}
	return []any{f.Verdict}
}

func (f *Filters) severitySQL() string {
	if f.SeverityGE == "" {
		return ""
	}
	// Map severity to numeric for >= comparison: low=1, medium=2, high=3, critical=4
	severityMap := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	sev, ok := severityMap[f.SeverityGE]
	if !ok {
		return ""
	}
	sevList := []string{}
	for k, v := range severityMap {
		if v >= sev {
			sevList = append(sevList, k)
		}
	}
	ph := strings.Repeat("?,", len(sevList))
	ph = ph[:len(ph)-1]
	return " AND severity IN (" + ph + ")"
}

func (f *Filters) severityArgs() []any {
	if f.SeverityGE == "" {
		return nil
	}
	severityMap := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	sev, ok := severityMap[f.SeverityGE]
	if !ok {
		return nil
	}
	args := []any{}
	for k, v := range severityMap {
		if v >= sev {
			args = append(args, k)
		}
	}
	return args
}

// allArgs merges all filter arguments in order.
func (f *Filters) allArgs() []any {
	var args []any
	args = append(args, f.ipArgs()...)
	args = append(args, f.appArgs()...)
	args = append(args, f.categoryArgs()...)
	args = append(args, f.siteArgs()...)
	args = append(args, f.verdictArgs()...)
	args = append(args, f.severityArgs()...)
	return args
}

// whereClause combines all filter conditions for flows.
func (f *Filters) whereClause() string {
	var clauses []string
	if sql := f.ipSQL(); sql != "" {
		clauses = append(clauses, sql)
	}
	if sql := f.appSQL(); sql != "" {
		clauses = append(clauses, sql)
	}
	if sql := f.categorySQL(); sql != "" {
		clauses = append(clauses, sql)
	}
	if sql := f.siteSQL(); sql != "" {
		clauses = append(clauses, sql)
	}
	if sql := f.verdictSQL(); sql != "" {
		clauses = append(clauses, sql)
	}
	return strings.Join(clauses, "")
}

// ExecutiveSummary shows high-level metrics and changes from previous period.
type ExecutiveSummary struct {
	ThisPeriod struct {
		Hosts          int64 `json:"hosts"`
		Devices        int64 `json:"devices"`
		Flows          int64 `json:"flows"`
		BytesIn        int64 `json:"bytes_in"`
		BytesOut       int64 `json:"bytes_out"`
		Blocked        int64 `json:"blocked"`
		DNSQueries     int64 `json:"dns_queries"`
		DNSBlocked     int64 `json:"dns_blocked"`
		TLSConnections int64 `json:"tls_connections"`
		Alerts         int64 `json:"alerts"`
		AlertsCritical int64 `json:"alerts_critical"`
		Findings       int64 `json:"findings"`
	} `json:"this_period"`
	PreviousPeriod struct {
		Flows      int64 `json:"flows"`
		BytesIn    int64 `json:"bytes_in"`
		BytesOut   int64 `json:"bytes_out"`
		Blocked    int64 `json:"blocked"`
		DNSBlocked int64 `json:"dns_blocked"`
		Alerts     int64 `json:"alerts"`
	} `json:"previous_period"`
	Changes struct {
		FlowsPercent   float64 `json:"flows_percent"`
		BytesPercent   float64 `json:"bytes_percent"`
		BlockedPercent float64 `json:"blocked_percent"`
		AlertsPercent  float64 `json:"alerts_percent"`
	} `json:"changes"`
}

type execSummarySec struct{}

func (s *execSummarySec) Key() string   { return "executive_summary" }
func (s *execSummarySec) Title() string { return "Executive Summary" }
func (s *execSummarySec) Notes() string {
	return "Aggregated counts of flows, hosts, alerts, and DNS queries. Changes show percentage delta vs. previous period."
}

func (s *execSummarySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := ExecutiveSummary{}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	// This period
	result.ThisPeriod.Flows = st.Int(`SELECT COUNT(*) FROM flows`+whereClause, args...)
	result.ThisPeriod.BytesIn = st.Int(`SELECT COALESCE(SUM(bytes_in), 0) FROM flows`+whereClause, args...)
	result.ThisPeriod.BytesOut = st.Int(`SELECT COALESCE(SUM(bytes_out), 0) FROM flows`+whereClause, args...)
	result.ThisPeriod.Blocked = st.Int(`SELECT COUNT(*) FROM flows`+whereClause+` AND verdict='blocked'`, args...)
	result.ThisPeriod.Hosts = st.Int(`SELECT COUNT(DISTINCT src_ip) FROM flows`+whereClause, args...)
	result.ThisPeriod.Devices = st.Int(`SELECT COUNT(DISTINCT src_ip) FROM flows`+whereClause, args...) // Simplified: count unique IPs as devices

	dnsWhere := " WHERE ts>=?"
	dnsArgs := []any{window.From}
	if window.To > 0 {
		dnsWhere += " AND ts<?"
		dnsArgs = append(dnsArgs, window.To)
	}
	result.ThisPeriod.DNSQueries = st.Int(`SELECT COUNT(*) FROM dns`+dnsWhere, dnsArgs...)
	result.ThisPeriod.DNSBlocked = st.Int(`SELECT COUNT(*) FROM dns`+dnsWhere+` AND action='block'`, dnsArgs...)

	tlsWhere := " WHERE ts>=? AND ts<?" + filters.whereClause()
	tlsArgs := []any{window.From, window.To}
	tlsArgs = append(tlsArgs, filters.allArgs()...)
	result.ThisPeriod.TLSConnections = st.Int(`SELECT COUNT(*) FROM tls_sessions`+tlsWhere, tlsArgs...)

	alertWhere := " WHERE ts>=? AND ts<?" + strings.TrimPrefix(filters.severitySQL(), " AND")
	alertArgs := []any{window.From, window.To}
	alertArgs = append(alertArgs, filters.severityArgs()...)
	result.ThisPeriod.Alerts = st.Int(`SELECT COUNT(*) FROM alerts`+alertWhere, alertArgs...)
	result.ThisPeriod.AlertsCritical = st.Int(`SELECT COUNT(*) FROM alerts`+alertWhere+` AND severity='critical'`, alertArgs...)

	result.ThisPeriod.Findings = st.Int(`SELECT COUNT(*) FROM findings WHERE resolved_ts IS NULL`)

	// Previous period (same duration)
	duration := window.To - window.From
	prevWhere := " WHERE ts>=? AND ts<?" + filters.whereClause()
	prevArgs := []any{window.From - duration, window.To - duration}
	prevArgs = append(prevArgs, filters.allArgs()...)
	result.PreviousPeriod.Flows = st.Int(`SELECT COUNT(*) FROM flows`+prevWhere, prevArgs...)
	result.PreviousPeriod.BytesIn = st.Int(`SELECT COALESCE(SUM(bytes_in), 0) FROM flows`+prevWhere, prevArgs...)
	result.PreviousPeriod.BytesOut = st.Int(`SELECT COALESCE(SUM(bytes_out), 0) FROM flows`+prevWhere, prevArgs...)
	result.PreviousPeriod.Blocked = st.Int(`SELECT COUNT(*) FROM flows`+prevWhere+` AND verdict='blocked'`, prevArgs...)
	result.PreviousPeriod.Alerts = st.Int(`SELECT COUNT(*) FROM alerts`+alertWhere[:len(alertWhere)-len(" AND ts<=?")], alertArgs[:len(alertArgs)-1]...)

	// Compute changes
	if result.PreviousPeriod.Flows > 0 {
		result.Changes.FlowsPercent = float64(result.ThisPeriod.Flows-result.PreviousPeriod.Flows) / float64(result.PreviousPeriod.Flows) * 100
	}
	if result.PreviousPeriod.BytesIn+result.PreviousPeriod.BytesOut > 0 {
		thisTotalBytes := result.ThisPeriod.BytesIn + result.ThisPeriod.BytesOut
		prevTotalBytes := result.PreviousPeriod.BytesIn + result.PreviousPeriod.BytesOut
		result.Changes.BytesPercent = float64(thisTotalBytes-prevTotalBytes) / float64(prevTotalBytes) * 100
	}
	if result.PreviousPeriod.Blocked > 0 {
		result.Changes.BlockedPercent = float64(result.ThisPeriod.Blocked-result.PreviousPeriod.Blocked) / float64(result.PreviousPeriod.Blocked) * 100
	}
	if result.PreviousPeriod.Alerts > 0 {
		result.Changes.AlertsPercent = float64(result.ThisPeriod.Alerts-result.PreviousPeriod.Alerts) / float64(result.PreviousPeriod.Alerts) * 100
	}

	return result, nil
}

// TrafficByDeviceRow is a row in the traffic by device report.
type TrafficByDeviceRow struct {
	DeviceName   string `json:"device_name"`
	DeviceMAC    string `json:"device_mac"`
	Zone         string `json:"zone"`
	Flows        int64  `json:"flows"`
	BytesIn      int64  `json:"bytes_in"`
	BytesOut     int64  `json:"bytes_out"`
	FirstSeen    int64  `json:"first_seen"`
	LastSeen     int64  `json:"last_seen"`
	TopApp       string `json:"top_app"`
	TopAppBytes  int64  `json:"top_app_bytes"`
	BlockedFlows int64  `json:"blocked_flows"`
}

// TrafficByDevice shows flows and bytes per device.
type TrafficByDevice struct {
	Rows []TrafficByDeviceRow `json:"rows"`
}

type trafficByDeviceSec struct{}

func (s *trafficByDeviceSec) Key() string   { return "traffic_by_device" }
func (s *trafficByDeviceSec) Title() string { return "Traffic by Device" }
func (s *trafficByDeviceSec) Notes() string {
	return "Bytes and flow counts per device with top application and blocked activity."
}

func (s *trafficByDeviceSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TrafficByDevice{Rows: []TrafficByDeviceRow{}}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	// Query flows grouped by source IP (simplified version without device_mac and zone)
	rows, err := st.Rows(`SELECT src_ip, COUNT(*) AS flows, SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out, MIN(ts) AS first_seen, MAX(ts) AS last_seen FROM flows`+whereClause+` GROUP BY src_ip ORDER BY bytes_out DESC`+([]string{"", fmt.Sprintf(" LIMIT %d", filters.TopN)}[minInt(1, filters.TopN)]), args...)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		ip, _ := row["src_ip"].(string)

		dr := TrafficByDeviceRow{
			DeviceMAC: ip, // Use IP as MAC for now
			Flows:     toI(row["flows"]),
			BytesIn:   toI(row["bytes_in"]),
			BytesOut:  toI(row["bytes_out"]),
			FirstSeen: toI(row["first_seen"]),
			LastSeen:  toI(row["last_seen"]),
		}

		// Get device name from identity service if available
		if ctx != nil && ctx.Core != nil {
			if identity, ok := ctx.Service("identity").(core.Identity); ok && identity != nil {
				if name := identity.Name(ip); name != "" {
					dr.DeviceName = name
				}
			}
		}

		// Get top app
		if topApp, err := st.Row(`SELECT app, SUM(bytes_in+bytes_out) AS total FROM flows WHERE ts>=? AND ts<? AND src_ip=? GROUP BY app ORDER BY total DESC LIMIT 1`, window.From, window.To, ip); err == nil && topApp != nil {
			if app, ok := topApp["app"].(string); ok {
				dr.TopApp = app
				dr.TopAppBytes = toI(topApp["total"])
			}
		}

		// Blocked flows
		dr.BlockedFlows = st.Int(`SELECT COUNT(*) FROM flows WHERE ts>=? AND ts<? AND src_ip=? AND verdict='blocked'`, window.From, window.To, ip)

		result.Rows = append(result.Rows, dr)
	}

	return result, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func toI(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	default:
		return 0
	}
}

func getStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

// BlockedActivity shows traffic that was blocked by policy or verdict.
type BlockedActivityRow struct {
	PolicyName string `json:"policy_name"`
	Count      int64  `json:"count"`
	TopIP      string `json:"top_ip"`
	TopApp     string `json:"top_app"`
}

type BlockedActivity struct {
	ByPolicy []BlockedActivityRow `json:"by_policy"`
	ByApp    []BlockedActivityRow `json:"by_app"`
}

type blockedActivitySec struct{}

func (s *blockedActivitySec) Key() string   { return "blocked_activity" }
func (s *blockedActivitySec) Title() string { return "Blocked Activity" }
func (s *blockedActivitySec) Notes() string {
	return "Flows rejected by policy or verdict filter, grouped by policy and application."
}

func (s *blockedActivitySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := BlockedActivity{
		ByPolicy: []BlockedActivityRow{},
		ByApp:    []BlockedActivityRow{},
	}

	whereClause := " WHERE ts>=? AND ts<? AND verdict='blocked'" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	// By policy
	rows, _ := st.Rows(`SELECT policy, COUNT(*) AS count FROM flows`+whereClause+` GROUP BY policy ORDER BY count DESC LIMIT 10`, args...)
	for _, row := range rows {
		policy, _ := row["policy"].(string)
		count := toI(row["count"])
		result.ByPolicy = append(result.ByPolicy, BlockedActivityRow{
			PolicyName: policy,
			Count:      count,
		})
	}

	// By app
	rows, _ = st.Rows(`SELECT app, COUNT(*) AS count FROM flows`+whereClause+` GROUP BY app ORDER BY count DESC LIMIT 10`, args...)
	for _, row := range rows {
		app, _ := row["app"].(string)
		count := toI(row["count"])
		result.ByApp = append(result.ByApp, BlockedActivityRow{
			PolicyName: app,
			Count:      count,
		})
	}

	return result, nil
}

// DNSSummary shows DNS queries, blocks, and top domains.
type DNSQueryRow struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
	Action string `json:"action"`
}

type DNSSummary struct {
	TotalQueries int64         `json:"total_queries"`
	TotalBlocked int64         `json:"total_blocked"`
	TopDomains   []DNSQueryRow `json:"top_domains"`
	TopBlocked   []DNSQueryRow `json:"top_blocked"`
}

type dnsSummarySec struct{}

func (s *dnsSummarySec) Key() string   { return "dns_summary" }
func (s *dnsSummarySec) Title() string { return "DNS Summary" }
func (s *dnsSummarySec) Notes() string {
	return "DNS query counts and top domains, including blocked queries by policy."
}

func (s *dnsSummarySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := DNSSummary{
		TopDomains: []DNSQueryRow{},
		TopBlocked: []DNSQueryRow{},
	}

	whereClause := " WHERE ts>=? AND ts<?"
	args := []any{window.From, window.To}

	result.TotalQueries = st.Int(`SELECT COUNT(*) FROM dns`+whereClause, args...)
	result.TotalBlocked = st.Int(`SELECT COUNT(*) FROM dns`+whereClause+` AND action='block'`, args...)

	// Top domains
	rows, _ := st.Rows(`SELECT domain, COUNT(*) AS count FROM dns`+whereClause+` GROUP BY domain ORDER BY count DESC LIMIT 10`, args...)
	for _, row := range rows {
		domain, _ := row["domain"].(string)
		count := toI(row["count"])
		result.TopDomains = append(result.TopDomains, DNSQueryRow{
			Domain: domain,
			Count:  count,
		})
	}

	// Top blocked
	rows, _ = st.Rows(`SELECT domain, COUNT(*) AS count FROM dns`+whereClause+` AND action='block' GROUP BY domain ORDER BY count DESC LIMIT 10`, args...)
	for _, row := range rows {
		domain, _ := row["domain"].(string)
		count := toI(row["count"])
		result.TopBlocked = append(result.TopBlocked, DNSQueryRow{
			Domain: domain,
			Count:  count,
			Action: "block",
		})
	}

	return result, nil
}

// TLSPosture shows TLS versions, certificates, and interception coverage.
type TLSVersion struct {
	Version string `json:"version"`
	Count   int64  `json:"count"`
}

type TLSPosture struct {
	TotalConnections int64        `json:"total_connections"`
	Versions         []TLSVersion `json:"versions"`
	InterceptedCount int64        `json:"intercepted_count"`
	UntrustedCerts   int64        `json:"untrusted_certs"`
}

type tlsPostureSec struct{}

func (s *tlsPostureSec) Key() string   { return "tls_posture" }
func (s *tlsPostureSec) Title() string { return "TLS Posture" }
func (s *tlsPostureSec) Notes() string {
	return "TLS protocol versions, certificate trust status, and interception coverage."
}

func (s *tlsPostureSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TLSPosture{
		Versions: []TLSVersion{},
	}

	whereClause := " WHERE ts>=? AND ts<?"
	args := []any{window.From, window.To}

	result.TotalConnections = st.Int(`SELECT COUNT(*) FROM tls_sessions`+whereClause, args...)

	// TLS versions
	rows, _ := st.Rows(`SELECT tls_version, COUNT(*) AS count FROM tls_sessions`+whereClause+` GROUP BY tls_version ORDER BY count DESC`, args...)
	for _, row := range rows {
		version, _ := row["tls_version"].(string)
		count := toI(row["count"])
		result.Versions = append(result.Versions, TLSVersion{
			Version: version,
			Count:   count,
		})
	}

	result.UntrustedCerts = st.Int(`SELECT COUNT(*) FROM tls_certs WHERE trusted=0`)

	return result, nil
}

// Alerts shows security alerts and threats detected.
type AlertRow struct {
	Signature string `json:"signature"`
	Severity  string `json:"severity"`
	Count     int64  `json:"count"`
	SourceIP  string `json:"source_ip"`
}

type Alerts struct {
	TotalAlerts   int64      `json:"total_alerts"`
	CriticalCount int64      `json:"critical_count"`
	HighCount     int64      `json:"high_count"`
	BySeverity    []AlertRow `json:"by_severity"`
	TopSignatures []AlertRow `json:"top_signatures"`
}

type alertsSec struct{}

func (s *alertsSec) Key() string   { return "alerts" }
func (s *alertsSec) Title() string { return "Security Alerts" }
func (s *alertsSec) Notes() string {
	return "Alerts and threats detected by IDS/IPS, grouped by severity and signature."
}

func (s *alertsSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := Alerts{
		BySeverity:    []AlertRow{},
		TopSignatures: []AlertRow{},
	}

	whereClause := " WHERE ts>=? AND ts<?"
	args := []any{window.From, window.To}

	result.TotalAlerts = st.Int(`SELECT COUNT(*) FROM alerts`+whereClause, args...)
	result.CriticalCount = st.Int(`SELECT COUNT(*) FROM alerts`+whereClause+` AND severity='critical'`, args...)
	result.HighCount = st.Int(`SELECT COUNT(*) FROM alerts`+whereClause+` AND severity='high'`, args...)

	// Top signatures
	rows, _ := st.Rows(`SELECT signature, severity, COUNT(*) AS count FROM alerts`+whereClause+` GROUP BY signature ORDER BY count DESC LIMIT 15`, args...)
	for _, row := range rows {
		sig, _ := row["signature"].(string)
		sev, _ := row["severity"].(string)
		count := toI(row["count"])
		result.TopSignatures = append(result.TopSignatures, AlertRow{
			Signature: sig,
			Severity:  sev,
			Count:     count,
		})
	}

	return result, nil
}

// TrafficByZone shows traffic grouped by zone.
type TrafficByZoneRow struct {
	Zone     string `json:"zone"`
	Flows    int64  `json:"flows"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Blocked  int64  `json:"blocked"`
	Devices  int64  `json:"devices"`
}

type TrafficByZone struct {
	Rows []TrafficByZoneRow `json:"rows"`
}

type trafficByZoneSec struct{}

func (s *trafficByZoneSec) Key() string   { return "traffic_by_zone" }
func (s *trafficByZoneSec) Title() string { return "Traffic by Zone" }
func (s *trafficByZoneSec) Notes() string { return "Flows and bytes aggregated by network zone." }

func (s *trafficByZoneSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TrafficByZone{Rows: []TrafficByZoneRow{}}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	rows, _ := st.Rows(`SELECT src_zone, COUNT(*) AS flows, COALESCE(SUM(bytes_in), 0) AS bytes_in, COALESCE(SUM(bytes_out), 0) AS bytes_out, SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked, COUNT(DISTINCT src_ip) AS devices FROM flows`+whereClause+` GROUP BY src_zone ORDER BY bytes_out DESC`+([]string{"", fmt.Sprintf(" LIMIT %d", filters.TopN)}[minInt(1, filters.TopN)]), args...)
	for _, row := range rows {
		zone, _ := row["src_zone"].(string)
		result.Rows = append(result.Rows, TrafficByZoneRow{
			Zone:     zone,
			Flows:    toI(row["flows"]),
			BytesIn:  toI(row["bytes_in"]),
			BytesOut: toI(row["bytes_out"]),
			Blocked:  toI(row["blocked"]),
			Devices:  toI(row["devices"]),
		})
	}
	return result, nil
}

// TrafficByApp shows traffic grouped by application.
type TrafficByAppRow struct {
	App      string `json:"app"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	Blocked  int64  `json:"blocked"`
	Devices  int64  `json:"devices"`
	Category string `json:"category"`
}

type TrafficByApp struct {
	Rows []TrafficByAppRow `json:"rows"`
}

type trafficByAppSec struct{}

func (s *trafficByAppSec) Key() string   { return "traffic_by_app" }
func (s *trafficByAppSec) Title() string { return "Traffic by Application" }
func (s *trafficByAppSec) Notes() string {
	return "Flows and bytes per application with category and blocked counts."
}

func (s *trafficByAppSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TrafficByApp{Rows: []TrafficByAppRow{}}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	rows, _ := st.Rows(`SELECT app, COUNT(*) AS flows, COALESCE(SUM(bytes_in+bytes_out), 0) AS bytes, SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked, COUNT(DISTINCT src_ip) AS devices FROM flows`+whereClause+` GROUP BY app ORDER BY bytes DESC`+([]string{"", fmt.Sprintf(" LIMIT %d", filters.TopN)}[minInt(1, filters.TopN)]), args...)
	for _, row := range rows {
		result.Rows = append(result.Rows, TrafficByAppRow{
			App:     getStr(row["app"]),
			Flows:   toI(row["flows"]),
			Bytes:   toI(row["bytes"]),
			Blocked: toI(row["blocked"]),
			Devices: toI(row["devices"]),
		})
	}
	return result, nil
}

// TrafficByCategory shows traffic grouped by category.
type TrafficByCategoryRow struct {
	Category string `json:"category"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	Blocked  int64  `json:"blocked"`
	Devices  int64  `json:"devices"`
	Apps     int64  `json:"apps"`
}

type TrafficByCategory struct {
	Rows []TrafficByCategoryRow `json:"rows"`
}

type trafficByCategorySec struct{}

func (s *trafficByCategorySec) Key() string   { return "traffic_by_category" }
func (s *trafficByCategorySec) Title() string { return "Traffic by Category" }
func (s *trafficByCategorySec) Notes() string { return "Flows and bytes per content category." }

func (s *trafficByCategorySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TrafficByCategory{Rows: []TrafficByCategoryRow{}}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	rows, _ := st.Rows(`SELECT category, COUNT(*) AS flows, COALESCE(SUM(bytes_in+bytes_out), 0) AS bytes, SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked, COUNT(DISTINCT src_ip) AS devices, COUNT(DISTINCT app) AS apps FROM flows`+whereClause+` GROUP BY category ORDER BY bytes DESC`+([]string{"", fmt.Sprintf(" LIMIT %d", filters.TopN)}[minInt(1, filters.TopN)]), args...)
	for _, row := range rows {
		result.Rows = append(result.Rows, TrafficByCategoryRow{
			Category: getStr(row["category"]),
			Flows:    toI(row["flows"]),
			Bytes:    toI(row["bytes"]),
			Blocked:  toI(row["blocked"]),
			Devices:  toI(row["devices"]),
			Apps:     toI(row["apps"]),
		})
	}
	return result, nil
}

// TrafficBySite shows traffic grouped by destination domain.
type TrafficBySiteRow struct {
	Domain  string `json:"domain"`
	Flows   int64  `json:"flows"`
	Bytes   int64  `json:"bytes"`
	Blocked int64  `json:"blocked"`
}

type TrafficBySite struct {
	Rows []TrafficBySiteRow `json:"rows"`
}

type trafficBySiteSec struct{}

func (s *trafficBySiteSec) Key() string   { return "traffic_by_site" }
func (s *trafficBySiteSec) Title() string { return "Traffic by Site" }
func (s *trafficBySiteSec) Notes() string { return "Top destination domains by traffic volume." }

func (s *trafficBySiteSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := TrafficBySite{Rows: []TrafficBySiteRow{}}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	rows, _ := st.Rows(`SELECT domain, COUNT(*) AS flows, COALESCE(SUM(bytes_in+bytes_out), 0) AS bytes, SUM(CASE WHEN verdict='blocked' THEN 1 ELSE 0 END) AS blocked FROM flows`+whereClause+` AND domain!='' GROUP BY domain ORDER BY bytes DESC`+([]string{"", fmt.Sprintf(" LIMIT %d", filters.TopN)}[minInt(1, filters.TopN)]), args...)
	for _, row := range rows {
		result.Rows = append(result.Rows, TrafficBySiteRow{
			Domain:  getStr(row["domain"]),
			Flows:   toI(row["flows"]),
			Bytes:   toI(row["bytes"]),
			Blocked: toI(row["blocked"]),
		})
	}
	return result, nil
}

// EgressActivityRow shows large outbound transfers.
type EgressActivityRow struct {
	DeviceIP       string `json:"device_ip"`
	DestIP         string `json:"dest_ip"`
	Bytes          int64  `json:"bytes"`
	FirstSeen      int64  `json:"first_seen_ts"`
	App            string `json:"app"`
	IsFirstSeenDst bool   `json:"is_first_seen_dst"`
}

type EgressActivity struct {
	TotalOutbound int64               `json:"total_outbound"`
	Rows          []EgressActivityRow `json:"rows"`
	Note          string              `json:"note"`
}

type egressActivitySec struct{}

func (s *egressActivitySec) Key() string   { return "egress_activity" }
func (s *egressActivitySec) Title() string { return "Egress Activity & DLP" }
func (s *egressActivitySec) Notes() string {
	return "Large outbound transfers and first-seen destination IPs (potential data exfiltration)."
}

func (s *egressActivitySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := EgressActivity{Rows: []EgressActivityRow{}, Note: "Sort by bytes (largest transfers first). New destination IPs are flagged."}

	whereClause := " WHERE ts>=? AND ts<?" + filters.whereClause()
	args := []any{window.From, window.To}
	args = append(args, filters.allArgs()...)

	result.TotalOutbound = st.Int(`SELECT COALESCE(SUM(bytes_out), 0) FROM flows`+whereClause, args...)

	// Top outbound destinations
	rows, _ := st.Rows(`SELECT src_ip, dst_ip, app, COALESCE(SUM(bytes_out), 0) AS bytes, MIN(ts) AS first_ts FROM flows`+whereClause+` AND bytes_out>0 GROUP BY src_ip, dst_ip ORDER BY bytes DESC LIMIT 50`, args...)
	for _, row := range rows {
		result.Rows = append(result.Rows, EgressActivityRow{
			DeviceIP:  getStr(row["src_ip"]),
			DestIP:    getStr(row["dst_ip"]),
			Bytes:     toI(row["bytes"]),
			FirstSeen: toI(row["first_ts"]),
			App:       getStr(row["app"]),
		})
	}
	return result, nil
}

// ScanFindingsRow is a security finding from device scanning.
type ScanFindingsRow struct {
	DeviceIP  string `json:"device_ip"`
	Severity  string `json:"severity"`
	Finding   string `json:"finding"`
	Timestamp int64  `json:"timestamp"`
}

type ScanFindings struct {
	Rows []ScanFindingsRow `json:"rows"`
	Note string            `json:"note"`
}

type scanFindingsSec struct{}

func (s *scanFindingsSec) Key() string   { return "scan_findings" }
func (s *scanFindingsSec) Title() string { return "Scan Findings" }
func (s *scanFindingsSec) Notes() string {
	return "Security findings from identity/vulnerability scans of discovered devices."
}

func (s *scanFindingsSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := ScanFindings{
		Rows: []ScanFindingsRow{},
		Note: "Scans of identified devices. Click a device to view full findings.",
	}

	// Check if findings table has scan-related data
	rows, _ := st.Rows(`SELECT NULL AS device_ip, severity, title AS finding, ts FROM findings WHERE resolved_ts IS NULL LIMIT 50`)
	for _, row := range rows {
		result.Rows = append(result.Rows, ScanFindingsRow{
			Severity:  getStr(row["severity"]),
			Finding:   getStr(row["finding"]),
			Timestamp: toI(row["ts"]),
		})
	}
	return result, nil
}

// DeviceInventoryChangeRow tracks device changes.
type DeviceInventoryChangeRow struct {
	DeviceIP    string `json:"device_ip"`
	DeviceName  string `json:"device_name"`
	ChangeType  string `json:"change_type"` // "new", "renamed", "zone_changed", "online", "offline"
	PreviousVal string `json:"previous_val"`
	Timestamp   int64  `json:"timestamp"`
}

type DeviceInventoryChanges struct {
	Rows []DeviceInventoryChangeRow `json:"rows"`
}

type deviceInventorySec struct{}

func (s *deviceInventorySec) Key() string   { return "device_inventory" }
func (s *deviceInventorySec) Title() string { return "Device Inventory Changes" }
func (s *deviceInventorySec) Notes() string {
	return "New devices, renames, zone changes, and online/offline events."
}

func (s *deviceInventorySec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := DeviceInventoryChanges{Rows: []DeviceInventoryChangeRow{}}

	// Query events table for device-related changes
	rows, _ := st.Rows(`SELECT subject AS device_ip, kind, ts FROM events WHERE ts>=? AND ts<? AND kind IN ('device.new', 'device.renamed', 'device.zone_changed') ORDER BY ts DESC LIMIT 100`, window.From, window.To)
	for _, row := range rows {
		changeType := strings.TrimPrefix(getStr(row["kind"]), "device.")
		result.Rows = append(result.Rows, DeviceInventoryChangeRow{
			DeviceIP:   getStr(row["device_ip"]),
			ChangeType: changeType,
			Timestamp:  toI(row["ts"]),
		})
	}
	return result, nil
}

// AlertingDeliveryRow shows notification delivery attempts.
type AlertingDeliveryRow struct {
	RuleName  string `json:"rule_name"`
	Channel   string `json:"channel"`
	Subject   string `json:"subject"`
	Status    string `json:"status"` // "sent", "failed"
	Error     string `json:"error"`
	Timestamp int64  `json:"timestamp"`
}

type AlertingDeliveries struct {
	Rows        []AlertingDeliveryRow `json:"rows"`
	TotalSent   int64                 `json:"total_sent"`
	TotalFailed int64                 `json:"total_failed"`
}

type alertingDeliveriesSec struct{}

func (s *alertingDeliveriesSec) Key() string   { return "alerting_deliveries" }
func (s *alertingDeliveriesSec) Title() string { return "Alerting Deliveries" }
func (s *alertingDeliveriesSec) Notes() string {
	return "Log of notification delivery attempts through configured channels."
}

func (s *alertingDeliveriesSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := AlertingDeliveries{Rows: []AlertingDeliveryRow{}}

	// Query notifications table
	rows, _ := st.Rows(`SELECT rule, channel, subject, ts FROM notifications WHERE ts>=? AND ts<? ORDER BY ts DESC LIMIT 100`, window.From, window.To)
	for _, row := range rows {
		status := "sent"
		result.TotalSent++
		result.Rows = append(result.Rows, AlertingDeliveryRow{
			RuleName:  getStr(row["rule"]),
			Channel:   getStr(row["channel"]),
			Subject:   getStr(row["subject"]),
			Status:    status,
			Timestamp: toI(row["ts"]),
		})
	}
	return result, nil
}

// SystemHealthRow is a health metric.
type SystemHealthMetric struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

type SystemHealth struct {
	Uptime     int64                `json:"uptime_seconds"`
	MemoryMB   int64                `json:"memory_mb"`
	JobsFailed int64                `json:"jobs_failed"`
	DataSince  int64                `json:"data_since_ts"`
	Metrics    []SystemHealthMetric `json:"metrics"`
}

type systemHealthSec struct{}

func (s *systemHealthSec) Key() string   { return "system_health" }
func (s *systemHealthSec) Title() string { return "System Health" }
func (s *systemHealthSec) Notes() string {
	return "Uptime, memory usage, job failures, and data collection metrics."
}

func (s *systemHealthSec) Run(ctx *core.Context, window *TimeWindow, filters *Filters) (any, error) {
	st := ctx.Store
	result := SystemHealth{Metrics: []SystemHealthMetric{}}

	// Get uptime from first event or a reasonable estimate
	startRow, _ := st.Row("SELECT MIN(ts) as start FROM events")
	if startRow != nil && startRow["start"] != nil {
		result.DataSince = toI(startRow["start"])
		result.Uptime = time.Now().Unix() - result.DataSince
	}

	// Count job failures from events table
	jobFailures := st.Int("SELECT COUNT(*) FROM events WHERE kind LIKE 'job.%' AND subject LIKE '%failed%'")
	result.JobsFailed = jobFailures

	return result, nil
}

// Register all sections
func registerSections() []Section {
	return []Section{
		&execSummarySec{},
		&trafficByDeviceSec{},
		&trafficByZoneSec{},
		&trafficByAppSec{},
		&trafficByCategorySec{},
		&trafficBySiteSec{},
		&blockedActivitySec{},
		&egressActivitySec{},
		&dnsSummarySec{},
		&scanFindingsSec{},
		&tlsPostureSec{},
		&deviceInventorySec{},
		&alertingDeliveriesSec{},
		&systemHealthSec{},
		&alertsSec{},
	}
}
