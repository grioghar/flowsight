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

// Register all sections
func registerSections() []Section {
	return []Section{
		&execSummarySec{},
		&trafficByDeviceSec{},
	}
}
