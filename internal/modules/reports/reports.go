// Package reports generates HTML, Markdown, CSV, JSON, and PDF reports with scheduling.
package reports

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx         *core.Context
	engine      *Engine
	mu          sync.RWMutex
	lastErr     string
	identity    core.Identity
	dataDir     string
	keepRuns    map[string]int // per-definition retention count
	maxTotalMB  int             // global retention limit
}

// RunIndex tracks stored runs for retention
type RunIndex struct {
	DefinitionID string            `json:"definition_id"`
	RunID        string            `json:"run_id"`
	StartedAt    int64             `json:"started_at"`
	FinishedAt   int64             `json:"finished_at"`
	Status       string            `json:"status"`
	Error        string            `json:"error,omitempty"`
	Sizes        map[string]int    `json:"sizes"` // bytes per format
	Formats      []string          `json:"formats"` // ["html", "pdf", etc]
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "reports", Version: "2.0",
		Description:  "Comprehensive reporting with sections, filters, scheduling, and multiple formats.",
		Capabilities: []string{},
		After:        []string{"identity", "alerting"},
		Defaults: map[string]any{
			"definitions":  []any{},
			"keep_runs":    10,
			"max_total_mb": 500,
		},
		Schema: []core.SettingField{
			{Key: "definitions", Label: "Report definitions", Type: "list", Help: "Custom report templates."},
			{Key: "keep_runs", Label: "Keep last N runs per definition", Type: "number", Help: "Number of recent runs to retain per definition (0 = unlimited)."},
			{Key: "max_total_mb", Label: "Max total storage (MB)", Type: "number", Help: "Maximum total size of all stored runs (oldest pruned first)."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.engine = NewEngine(ctx)
	m.dataDir = filepath.Join(ctx.Platform.DataDir, "reports")
	_ = os.MkdirAll(m.dataDir, 0o750)

	// Load retention settings
	m.keepRuns = make(map[string]int)
	m.maxTotalMB = 500
	settings := ctx.Settings()
	if val, ok := settings["max_total_mb"]; ok {
		if v, ok := val.(float64); ok {
			m.maxTotalMB = int(v)
		}
	}

	// Initialize definitions in KV if not present
	if !ctx.Store.KVGet("reports.definitions", &[]Definition{}) {
		_ = ctx.Store.KVSet("reports.definitions", ListBuiltIns())
	}

	// Initialize runs index if not present
	if !ctx.Store.KVGet("reports.runs.index", &[]RunIndex{}) {
		_ = ctx.Store.KVSet("reports.runs.index", []RunIndex{})
	}

	// Scheduler job: send due reports and prune old runs
	ctx.Every("scheduler", time.Minute, func() error {
		_ = m.sendDueReports()
		_ = m.pruneOldRuns()
		return nil
	})

	// API routes
	ctx.Route("GET", "/api/reports/definitions", m.apiGetDefinitions,
		core.Doc("List all report definitions"))
	ctx.Route("POST", "/api/reports/definitions", m.apiCreateDefinition,
		core.Write(), core.Doc("Create a custom report definition"))
	ctx.Route("GET", "/api/reports/definitions/{id}", m.apiGetDefinition,
		core.Doc("Get a report definition"))
	ctx.Route("PUT", "/api/reports/definitions/{id}", m.apiUpdateDefinition,
		core.Write(), core.Doc("Update a report definition"))
	ctx.Route("DELETE", "/api/reports/definitions/{id}", m.apiDeleteDefinition,
		core.Write(), core.Doc("Delete a report definition"))

	ctx.Route("POST", "/api/reports/preview", m.apiPreview,
		core.Write(), core.Doc("Generate and preview a report"))
	ctx.Route("POST", "/api/reports/run/{id}", m.apiRunReport,
		core.Write(), core.Doc("Execute a report definition"))
	ctx.Route("GET", "/api/reports/runs", m.apiListRuns,
		core.Doc("List recent report runs"))
	ctx.Route("GET", "/api/reports/runs/{run}", m.apiGetRun,
		core.Doc("Get report run details"))
	ctx.Route("GET", "/api/reports/runs/{run}/download", m.apiDownloadRun,
		core.Doc("Download report in specified format"))
	ctx.Route("DELETE", "/api/reports/runs/{run}", m.apiDeleteRun,
		core.Write(), core.Doc("Delete a report run"))

	ctx.Panel(core.Panel{ID: "reports", Title: "Reports", Group: "Administration", Order: 180, Icon: "reports"})

	ctx.Log.Info("reports module ready", slog.String("data_dir", m.dataDir))
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

// API: Definitions -------------------------------------------------------

func (m *Module) apiGetDefinitions(r *core.Req) (any, error) {
	defs := []Definition{}
	if !m.ctx.Store.KVGet("reports.definitions", &defs) {
		defs = ListBuiltIns()
	}
	return map[string]any{"definitions": defs}, nil
}

func (m *Module) apiCreateDefinition(r *core.Req) (any, error) {
	var def Definition
	if err := r.Decode(&def); err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	def.ID = fmt.Sprintf("def-%d", now)
	def.CreatedAt = now
	def.UpdatedAt = now
	def.ReadOnly = false

	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)
	defs = append(defs, def)
	if err := m.ctx.Store.KVSet("reports.definitions", defs); err != nil {
		return nil, err
	}

	return def, nil
}

func (m *Module) apiGetDefinition(r *core.Req) (any, error) {
	id := r.Params["id"]
	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)

	for _, def := range defs {
		if def.ID == id {
			return def, nil
		}
	}
	return nil, core.NotFound("definition not found")
}

func (m *Module) apiUpdateDefinition(r *core.Req) (any, error) {
	id := r.Params["id"]
	var updatedDef Definition
	if err := r.Decode(&updatedDef); err != nil {
		return nil, err
	}

	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)

	for i, def := range defs {
		if def.ID == id {
			if def.ReadOnly {
				return nil, core.Forbidden("cannot edit built-in definitions")
			}
			updatedDef.ID = id
			updatedDef.CreatedAt = def.CreatedAt
			updatedDef.UpdatedAt = time.Now().Unix()
			updatedDef.ReadOnly = false
			defs[i] = updatedDef
			if err := m.ctx.Store.KVSet("reports.definitions", defs); err != nil {
				return nil, err
			}
			return updatedDef, nil
		}
	}
	return nil, core.NotFound("definition not found")
}

func (m *Module) apiDeleteDefinition(r *core.Req) (any, error) {
	id := r.Params["id"]
	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)

	for i, def := range defs {
		if def.ID == id {
			if def.ReadOnly {
				return nil, core.Forbidden("cannot delete built-in definitions")
			}
			defs = append(defs[:i], defs[i+1:]...)
			_ = m.ctx.Store.KVSet("reports.definitions", defs)
			return map[string]any{"ok": true}, nil
		}
	}
	return nil, core.NotFound("definition not found")
}

// API: Execution -------------------------------------------------------

func (m *Module) apiPreview(r *core.Req) (any, error) {
	var def Definition
	if err := r.Decode(&def); err != nil {
		return nil, err
	}

	window := parseWindow(r)
	run, err := m.engine.Execute(&def, window)
	if err != nil {
		return nil, err
	}

	html, err := m.engine.RenderHTML(&def, run)
	if err != nil {
		return nil, err
	}

	return core.Raw{ContentType: "text/html; charset=utf-8", Body: []byte(html)}, nil
}

func (m *Module) apiRunReport(r *core.Req) (any, error) {
	id := r.Params["id"]
	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)

	var def *Definition
	for i := range defs {
		if defs[i].ID == id {
			def = &defs[i]
			break
		}
	}
	if def == nil {
		return nil, core.NotFound("definition not found")
	}

	window := parseWindow(r)
	run, err := m.engine.Execute(def, window)
	if err != nil {
		return nil, err
	}

	// Store run metadata
	_ = m.storeRun(run, def)

	// Store all formats
	if html, _ := m.engine.RenderHTML(def, run); html != "" {
		_ = m.storeRunFormat(run, def, "html", []byte(html))
	}
	if md, _ := m.engine.RenderMarkdown(def, run); md != "" {
		_ = m.storeRunFormat(run, def, "markdown", []byte(md))
	}
	if json, _ := m.engine.RenderJSON(def, run); len(json) > 0 {
		_ = m.storeRunFormat(run, def, "json", json)
	}

	return run, nil
}

func (m *Module) apiListRuns(r *core.Req) (any, error) {
	defID := r.Q("definition", "")

	var index []RunIndex
	m.ctx.Store.KVGet("reports.runs.index", &index)

	var runs []map[string]any
	for _, idx := range index {
		if defID == "" || idx.DefinitionID == defID {
			runs = append(runs, map[string]any{
				"id":           idx.RunID,
				"definition":   idx.DefinitionID,
				"started_at":   idx.StartedAt,
				"finished_at":  idx.FinishedAt,
				"status":       idx.Status,
				"error":        idx.Error,
				"sizes":        idx.Sizes,
				"formats":      idx.Formats,
			})
		}
	}
	return map[string]any{"runs": runs, "definition": defID}, nil
}

func (m *Module) apiGetRun(r *core.Req) (any, error) {
	runID := r.Params["run"]
	run, err := m.loadRun(runID)
	if err != nil {
		return nil, core.NotFound("run not found")
	}
	return run, nil
}

func (m *Module) apiDownloadRun(r *core.Req) (any, error) {
	runID := r.Params["run"]
	format := r.Q("format", "html")

	run, err := m.loadRun(runID)
	if err != nil {
		return nil, core.NotFound("run not found")
	}

	defs := []Definition{}
	m.ctx.Store.KVGet("reports.definitions", &defs)
	var def *Definition
	for i := range defs {
		if defs[i].ID == run.DefinitionID {
			def = &defs[i]
			break
		}
	}
	if def == nil {
		return nil, core.NotFound("definition not found")
	}

	// Try to load from disk first
	defDir := filepath.Join(m.dataDir, def.ID)
	filePath := filepath.Join(defDir, runID+"."+format)
	if data, err := os.ReadFile(filePath); err == nil {
		// File exists on disk
		var contentType string
		switch format {
		case "html":
			contentType = "text/html; charset=utf-8"
		case "json":
			contentType = "application/json"
		case "markdown":
			contentType = "text/markdown"
		case "pdf":
			contentType = "application/pdf"
		case "csv":
			contentType = "text/csv"
		default:
			contentType = "application/octet-stream"
		}
		return core.Raw{ContentType: contentType, Filename: def.ID + "." + format, Body: data}, nil
	}

	// Fall back to rendering
	switch format {
	case "html":
		html, _ := m.engine.RenderHTML(def, run)
		return core.Raw{ContentType: "text/html; charset=utf-8", Filename: def.ID + ".html", Body: []byte(html)}, nil
	case "json":
		data, _ := m.engine.RenderJSON(def, run)
		return core.Raw{ContentType: "application/json", Filename: def.ID + ".json", Body: data}, nil
	case "markdown":
		md, _ := m.engine.RenderMarkdown(def, run)
		return core.Raw{ContentType: "text/markdown", Filename: def.ID + ".md", Body: []byte(md)}, nil
	case "pdf":
		pdf := NewSimplePDF()
		pdf.AddHeading(def.Name)
		pdf.AddText(fmt.Sprintf("Generated %s", time.Now().Format("2006-01-02 15:04 MST")))
		return core.Raw{ContentType: "application/pdf", Filename: def.ID + ".pdf", Body: pdf.Bytes()}, nil
	case "csv":
		csvs, _ := m.engine.RenderCSV(def, run)
		if len(csvs) > 0 {
			for _, csv := range csvs {
				return core.Raw{ContentType: "text/csv", Filename: def.ID + ".csv", Body: []byte(csv)}, nil
			}
		}
	}

	return nil, core.BadRequest("unsupported format: %s", format)
}

func (m *Module) apiDeleteRun(r *core.Req) (any, error) {
	runID := r.Params["run"]

	var index []RunIndex
	m.ctx.Store.KVGet("reports.runs.index", &index)

	var removed *RunIndex
	for _, idx := range index {
		if idx.RunID == runID {
			removed = &idx
			break
		}
	}
	if removed == nil {
		return nil, core.NotFound("run not found")
	}

	m.deleteRunFiles(removed.DefinitionID, runID)
	index = removeRunFromIndex(index, runID)
	_ = m.ctx.Store.KVSet("reports.runs.index", index)

	return map[string]any{"ok": true}, nil
}

// Helpers -------------------------------------------------------

func parseWindow(r *core.Req) *TimeWindow {
	// Parse ?from=<unix>&to=<unix> or ?hours=<N>
	from := r.Q("from", "")
	to := r.Q("to", "")

	if from != "" && to != "" {
		// Parse unix timestamps
		var fromI, toI int64
		fmt.Sscanf(from, "%d", &fromI)
		fmt.Sscanf(to, "%d", &toI)
		if fromI > 0 && toI > 0 && fromI < toI {
			return &TimeWindow{From: fromI, To: toI}
		}
	}

	// Default: last N hours
	hours := r.Hours(24)
	now := time.Now().Unix()
	return &TimeWindow{
		From: now - int64(hours)*3600,
		To:   now,
	}
}

func (m *Module) storeRun(run *Run, def *Definition) error {
	// Create definition directory
	defDir := filepath.Join(m.dataDir, def.ID)
	if err := os.MkdirAll(defDir, 0o750); err != nil {
		return err
	}

	// Store metadata in index
	idx := RunIndex{
		DefinitionID: def.ID,
		RunID:        run.ID,
		StartedAt:    run.StartedAt,
		FinishedAt:   run.CompletedAt,
		Status:       run.Status,
		Error:        run.Error,
		Sizes:        make(map[string]int),
		Formats:      []string{},
	}

	// Store runs metadata in KV
	var index []RunIndex
	m.ctx.Store.KVGet("reports.runs.index", &index)
	index = append(index, idx)
	_ = m.ctx.Store.KVSet("reports.runs.index", index)

	// Store metadata as JSON
	metaPath := filepath.Join(defDir, run.ID+".meta.json")
	metaData, _ := json.Marshal(idx)
	_ = os.WriteFile(metaPath, metaData, 0o640)

	return nil
}

func (m *Module) storeRunFormat(run *Run, def *Definition, format string, content []byte) error {
	defDir := filepath.Join(m.dataDir, def.ID)
	path := filepath.Join(defDir, run.ID+"."+format)
	if err := os.WriteFile(path, content, 0o640); err != nil {
		return err
	}

	// Update metadata
	idx := m.getRunIndex(run.ID)
	if idx != nil {
		idx.Sizes[format] = len(content)
		idx.Formats = append(idx.Formats, format)
		// Update in KV
		var index []RunIndex
		m.ctx.Store.KVGet("reports.runs.index", &index)
		for i, r := range index {
			if r.RunID == run.ID {
				index[i] = *idx
				break
			}
		}
		_ = m.ctx.Store.KVSet("reports.runs.index", index)
	}

	return nil
}

func (m *Module) getRunIndex(runID string) *RunIndex {
	var index []RunIndex
	if !m.ctx.Store.KVGet("reports.runs.index", &index) {
		return nil
	}
	for _, r := range index {
		if r.RunID == runID {
			return &r
		}
	}
	return nil
}

func (m *Module) loadRun(runID string) (*Run, error) {
	var index []RunIndex
	m.ctx.Store.KVGet("reports.runs.index", &index)

	var runIdx *RunIndex
	for _, r := range index {
		if r.RunID == runID {
			runIdx = &r
			break
		}
	}
	if runIdx == nil {
		return nil, core.NotFound("run not found")
	}

	run := &Run{
		ID:           runID,
		DefinitionID: runIdx.DefinitionID,
		StartedAt:    runIdx.StartedAt,
		CompletedAt:  runIdx.FinishedAt,
		Status:       runIdx.Status,
		Error:        runIdx.Error,
		Sizes:        runIdx.Sizes,
		SectionData:  make(map[string]any),
	}

	return run, nil
}

func (m *Module) pruneOldRuns() error {
	var index []RunIndex
	if !m.ctx.Store.KVGet("reports.runs.index", &index) {
		return nil
	}

	// Group runs by definition
	runsByDef := make(map[string][]RunIndex)
	for _, r := range index {
		runsByDef[r.DefinitionID] = append(runsByDef[r.DefinitionID], r)
	}

	// Prune by definition's keep_runs limit
	keepRuns := 10 // default
	settings := m.ctx.Settings()
	if val, ok := settings["keep_runs"]; ok {
		if v, ok := val.(float64); ok {
			keepRuns = int(v)
		}
	}

	for defID, runs := range runsByDef {
		if keepRuns > 0 && len(runs) > keepRuns {
			// Sort by started time (oldest first)
			sortByStartedAsc(runs)
			// Remove oldest
			toDelete := runs[:len(runs)-keepRuns]
			for _, r := range toDelete {
				m.deleteRunFiles(defID, r.RunID)
				// Remove from index
				index = removeRunFromIndex(index, r.RunID)
			}
		}
	}

	// Check global size limit
	if m.maxTotalMB > 0 {
		totalSize := int64(0)
		for _, r := range index {
			for _, size := range r.Sizes {
				totalSize += int64(size)
			}
		}

		maxBytes := int64(m.maxTotalMB) * 1024 * 1024
		if totalSize > maxBytes {
			// Sort all by started time and prune oldest
			sortByStartedAsc(index)
			for totalSize > maxBytes && len(index) > 0 {
				removed := index[0]
				m.deleteRunFiles(removed.DefinitionID, removed.RunID)
				index = index[1:]
				for _, size := range removed.Sizes {
					totalSize -= int64(size)
				}
			}
		}
	}

	_ = m.ctx.Store.KVSet("reports.runs.index", index)
	return nil
}

func (m *Module) deleteRunFiles(defID, runID string) {
	defDir := filepath.Join(m.dataDir, defID)
	_ = os.Remove(filepath.Join(defDir, runID+".meta.json"))
	for _, fmt := range []string{"html", "pdf", "json", "markdown", "csv"} {
		_ = os.Remove(filepath.Join(defDir, runID+"."+fmt))
	}
}

func removeRunFromIndex(index []RunIndex, runID string) []RunIndex {
	for i, r := range index {
		if r.RunID == runID {
			return append(index[:i], index[i+1:]...)
		}
	}
	return index
}

func sortByStartedAsc(runs []RunIndex) {
	// Simple bubble sort (small array)
	for i := 0; i < len(runs); i++ {
		for j := i + 1; j < len(runs); j++ {
			if runs[j].StartedAt < runs[i].StartedAt {
				runs[i], runs[j] = runs[j], runs[i]
			}
		}
	}
}

// Scheduler -------------------------------------------------------

func (m *Module) sendDueReports() error {
	defs := []Definition{}
	if !m.ctx.Store.KVGet("reports.definitions", &defs) {
		return nil
	}

	now := time.Now()

	for _, def := range defs {
		if def.Schedule == nil || !def.Schedule.Enabled || len(def.Recipients) == 0 {
			continue
		}

		if isDue(now, def.Schedule) {
			// Generate report
			window := &TimeWindow{
				From: now.Unix() - 24*3600, // Last 24h default
				To:   now.Unix(),
			}
			run, err := m.engine.Execute(&def, window)
			if err != nil {
				m.mu.Lock()
				m.lastErr = err.Error()
				m.mu.Unlock()
				continue
			}

			// Store run metadata
			_ = m.storeRun(run, &def)

			// Send via alerting (when alerting branch implements Send)
			// For now, just log
			m.ctx.Log.Info("scheduled report executed", "definition", def.ID, "run", run.ID)

			// Update last run time
			_ = m.ctx.Store.KVSet("reports.last_run."+def.ID, now.Unix())
		}
	}

	return nil
}

func isDue(now time.Time, sched *Schedule) bool {
	var lastRunTime int64
	// Simplified: check if last run was more than cadence ago
	switch sched.Cadence {
	case "hourly":
		return now.Unix()-lastRunTime > 3600
	case "daily":
		return now.Unix()-lastRunTime > 86400
	case "weekly":
		return now.Unix()-lastRunTime > 7*86400
	case "monthly":
		return now.Unix()-lastRunTime > 30*86400
	}
	return false
}

// Helper functions
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

func escapeHTML(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	).Replace(s)
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
.kpi h3 { margin: 0 0 0.5em; font-size: 0.9em; color: #666; }
.kpi .v { font-size: 2em; font-weight: bold; }
.kpi .info { font-size: 0.8em; color: #666; margin-top: 0.5em; }
.meta { color: #666; font-size: 0.9em; }
.note { font-size: 0.9em; color: #666; font-style: italic; }
aside.toc { float: right; background: #f9f9f9; padding: 1em; border-radius: 6px; margin: 0 0 1em 1em; width: 200px; }
aside.toc h3 { margin-top: 0; }
aside.toc ul { margin: 0; padding-left: 1.2em; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a1a; color: #e0e0e0; }
  section { background: #2a2a2a; }
  th { background: #333; }
  tr:hover { background: #333; }
  .kpi { background: #333; }
  .kpi.bad { background: #3a1a1a; }
  aside.toc { background: #333; }
}
@media print {
  body { background: white; }
  section { page-break-inside: avoid; }
  table { page-break-inside: avoid; }
}
`
