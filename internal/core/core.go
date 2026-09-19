package core

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Core wires everything together. Modules register themselves at build time
// through Register(); Core instantiates the ones the config enables, in
// dependency order, and runs them.
type Core struct {
	Version   string
	Platform  *Platform
	Config    *Config
	Store     *Store
	Scheduler *Scheduler
	API       *API
	Log       *slog.Logger
	Started   time.Time

	mu        sync.RWMutex
	Modules   map[string]Module
	Infos     map[string]ModuleInfo
	Errors    map[string]string
	Providers []Provider
	Panels    []Panel
	Services  map[string]any
	readOnly  bool
}

var registry []func() Module

// Register adds a module constructor. Called from each module's init().
func Register(ctor func() Module) { registry = append(registry, ctor) }

// New builds a Core. configPath "" means the platform default.
func New(version, configPath, dataDir string, static fs.FS, log *slog.Logger) (*Core, error) {
	p := DetectPlatform()
	if configPath == "" {
		configPath = os.Getenv("FLOWSIGHT_CONFIG")
	}
	if configPath == "" {
		configPath = filepath.Join(p.EtcDir, "flowsight.json")
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	applyPathOverrides(p, cfg.Core().Paths)
	if dataDir == "" {
		dataDir = cfg.Core().DataDir
	}
	if dataDir == "" {
		dataDir = p.DataDir
	}
	st, err := OpenStore(dataDir)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	c := &Core{Version: version, Platform: p, Config: cfg, Store: st, Log: log,
		Started: time.Now(), Modules: map[string]Module{}, Infos: map[string]ModuleInfo{},
		Errors: map[string]string{}, Services: map[string]any{}}
	c.Scheduler = NewScheduler(cfg.Core().Workers, log.With("component", "scheduler"))
	c.API = NewAPI(c, static, log.With("component", "api"))
	return c, nil
}

func applyPathOverrides(p *Platform, over map[string]any) {
	if len(over) == 0 {
		return
	}
	b, _ := json.Marshal(over)
	_ = json.Unmarshal(b, p)
}

// ReadOnly is true when the instance refuses writes (a future entitlement or
// an operator lock can set it).
func (c *Core) ReadOnly() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.readOnly
}

// LoadModules instantiates and sets up every enabled module.
func (c *Core) LoadModules() {
	type cand struct {
		m    Module
		info ModuleInfo
	}
	cands := map[string]cand{}
	for _, ctor := range registry {
		m := ctor()
		info := m.Info()
		cands[info.Name] = cand{m, info}
		c.Config.DeclareModule(info.Name, info.Defaults)
	}
	var order []string
	seen := map[string]bool{}
	var visit func(string)
	visit = func(n string) {
		if seen[n] {
			return
		}
		cd, ok := cands[n]
		if !ok {
			return
		}
		seen[n] = true
		for _, dep := range cd.info.After {
			visit(dep)
		}
		order = append(order, n)
	}
	names := make([]string, 0, len(cands))
	for n := range cands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		visit(n)
	}
	for _, n := range order {
		cd := cands[n]
		c.Infos[n] = cd.info
		if !Bool(c.Config.Module(n), "enabled", true) {
			c.Log.Info("module disabled", "module", n)
			continue
		}
		ctx := &Context{Core: c, Name: n, Store: c.Store, Platform: c.Platform, Config: c.Config,
			Log: c.Log.With("module", n)}
		if err := c.setup(cd.m, ctx); err != nil {
			c.Errors[n] = err.Error()
			c.Log.Error("module setup failed", "module", n, "error", err.Error())
			continue
		}
		c.mu.Lock()
		c.Modules[n] = cd.m
		c.mu.Unlock()
		c.Log.Info("module loaded", "module", n, "version", cd.info.Version)
	}
}

func (c *Core) setup(m Module, ctx *Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return m.Setup(ctx)
}

// ProviderList returns a snapshot of registered providers.
func (c *Core) ProviderList() []Provider {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Provider(nil), c.Providers...)
}

// Capabilities returns capability -> modules offering it.
func (c *Core) Capabilities() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string][]string{}
	for n := range c.Modules {
		for _, cap := range c.Infos[n].Capabilities {
			out[cap] = append(out[cap], n)
		}
	}
	for _, p := range c.Providers {
		for _, cap := range p.Capabilities() {
			out[cap] = append(out[cap], "provider:"+p.Name())
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

func (c *Core) audit(user, method, p string, body map[string]any, client string) {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > 12 {
		keys = keys[:12]
	}
	_ = c.Store.AddEvents([]Event{{TS: time.Now().Unix(), Kind: "audit", Source: "api",
		Severity: "info", Verdict: "observed", ActorName: user, ActorIP: client,
		Message: method + " " + p, Attrs: map[string]any{"keys": strings.Join(keys, ",")}}})
}

// Run starts jobs and the API and blocks until stop is closed.
func (c *Core) Run(stop <-chan struct{}) error {
	c.systemRoutes()
	c.LoadModules()
	c.Scheduler.Add(&Job{Name: "rollup", Module: "core", Every: 5 * time.Minute,
		Fn: c.Store.Rollup, nextRun: time.Now().Add(20 * time.Second)})
	c.Scheduler.Add(&Job{Name: "prune", Module: "core", Every: time.Hour,
		Fn:      func() error { return c.Store.Prune(c.Config.Core().Retention) },
		nextRun: time.Now().Add(2 * time.Minute)})
	c.Scheduler.Start()
	_ = c.Store.AddEvents([]Event{{TS: time.Now().Unix(), Kind: "system", Source: "core",
		Message: "flowsightd " + c.Version + " started"}})
	cs := c.Config.Core()
	srv, err := c.API.Listen(cs.Bind, cs.Port)
	if err != nil {
		return err
	}
	<-stop
	c.Log.Info("stopping")
	c.Scheduler.Stop()
	c.mu.RLock()
	for _, m := range c.Modules {
		if s, ok := m.(Stopper); ok {
			s.Stop()
		}
	}
	c.mu.RUnlock()
	ctxTimeout := 5 * time.Second
	srv.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(ctxTimeout):
	}
	return c.Store.Close()
}

// ------------------------------------------------------------ system API

func (c *Core) systemRoutes() {
	a := c.API
	a.Add("GET", "/api/system/info", c.apiInfo, "system", Doc("Version, platform, uptime, site"))
	a.Add("GET", "/api/system/health", c.apiHealth, "system", Doc("Module and job health, capabilities, store size"))
	a.Add("GET", "/api/system/panels", c.apiPanels, "system", Doc("UI panels contributed by loaded modules"))
	a.Add("GET", "/api/system/modules", c.apiModules, "system", Doc("Every module with settings and schema"))
	a.Add("POST", "/api/system/modules/save", c.apiModuleSave, "system", Write(), Doc("Save one module's settings"))
	a.Add("POST", "/api/system/jobs/run", c.apiJobRun, "system", Write(), Doc("Run a scheduled job now"))
	a.Add("GET", "/api/system/audit", c.apiAudit, "system", Doc("Recent write operations"), Params("limit", "rows"))
	a.Add("GET", "/api/system/events", c.apiEvents, "system", Doc("Normalised events"),
		Params("kind", "event kind", "hours", "window", "limit", "rows"))
	a.Add("GET", "/api/system/findings", c.apiFindings, "system", Doc("Open findings across modules"),
		Params("module", "filter by module"))
	a.Add("POST", "/api/system/findings/ack", c.apiFindingAck, "system", Write(), Doc("Acknowledge a finding"))
	a.Add("GET", "/api/system/changes", c.apiChanges, "system", Doc("Configuration change history"),
		Params("limit", "rows", "module", "filter"))
	a.Add("GET", "/api/openapi.json", func(r *Req) (any, error) { return a.OpenAPI(), nil }, "system",
		Doc("This document, generated from the route table"))
	a.Add("GET", "/api/system/logout", func(r *Req) (any, error) { return map[string]any{"ok": true}, nil },
		"system", Doc("Drop the session"))
}

func (c *Core) apiInfo(r *Req) (any, error) {
	host, _ := os.Hostname()
	cs := c.Config.Core()
	site := cs.SiteName
	if site == "" {
		site = host
	}
	return map[string]any{"version": c.Version, "platform": c.Platform, "hostname": host,
		"site": site, "started": c.Started.Unix(), "uptime": int(time.Since(c.Started).Seconds()),
		"user": r.User, "go": runtime.Version(), "auth": cs.APIToken != "",
		"read_only": c.ReadOnly()}, nil
}

func (c *Core) apiHealth(r *Req) (any, error) {
	c.mu.RLock()
	mods := map[string]any{}
	allOK := true
	jobs := c.Scheduler.Jobs()
	for n, m := range c.Modules {
		h := Health{OK: true}
		if hh, ok := m.(Healther); ok {
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						h = Health{OK: false, Detail: fmt.Sprint("health panic: ", rec)}
					}
				}()
				h = hh.Health()
			}()
		} else {
			var bad []string
			for _, j := range jobs {
				if j["module"] == n {
					if ok, _ := j["ok"].(bool); j["ok"] != nil && !ok {
						bad = append(bad, fmt.Sprintf("%s: %s", j["name"], j["error"]))
					}
				}
			}
			if len(bad) > 0 {
				h = Health{OK: false, Detail: strings.Join(bad, "; ")}
			}
		}
		if !h.OK {
			allOK = false
		}
		info := c.Infos[n]
		mods[n] = map[string]any{"ok": h.OK, "detail": h.Detail, "extra": h.Extra,
			"version": info.Version, "capabilities": info.Capabilities, "description": info.Description}
	}
	for n, e := range c.Errors {
		allOK = false
		mods[n] = map[string]any{"ok": false, "detail": e, "failed": true}
	}
	var provs []map[string]any
	for _, p := range c.Providers {
		provs = append(provs, map[string]any{"name": p.Name(), "capabilities": p.Capabilities()})
	}
	c.mu.RUnlock()
	caps := c.Capabilities()
	var observe, enforce []string
	for k := range caps {
		if EnforceCaps[k] {
			enforce = append(enforce, k)
		} else {
			observe = append(observe, k)
		}
	}
	sort.Strings(observe)
	sort.Strings(enforce)
	return map[string]any{"ok": allOK, "modules": mods, "jobs": jobs,
		"observe_capabilities": observe, "enforce_capabilities": enforce, "capability_owners": caps,
		"providers": provs, "store": c.Store.Stats(),
		"uptime": int(time.Since(c.Started).Seconds())}, nil
}

func (c *Core) apiPanels(r *Req) (any, error) {
	c.mu.RLock()
	ps := append([]Panel(nil), c.Panels...)
	c.mu.RUnlock()
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Order != ps[j].Order {
			return ps[i].Order < ps[j].Order
		}
		return ps[i].Title < ps[j].Title
	})
	return map[string]any{"panels": ps}, nil
}

func (c *Core) apiModules(r *Req) (any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.Infos))
	for n := range c.Infos {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []map[string]any
	for _, n := range names {
		info := c.Infos[n]
		_, loaded := c.Modules[n]
		settings := c.Config.Module(n)
		for _, f := range info.Schema {
			if f.Type == "secret" {
				if v, ok := settings[f.Key].(string); ok && v != "" {
					settings[f.Key] = "********"
				}
			}
		}
		out = append(out, map[string]any{"name": n, "loaded": loaded, "version": info.Version,
			"description": info.Description, "capabilities": info.Capabilities,
			"requires": info.Requires, "settings": settings, "schema": info.Schema,
			"tier": info.Tier, "error": c.Errors[n]})
	}
	return map[string]any{"modules": out}, nil
}

// lockedKeys may never be changed through the API: they decide where the
// daemon listens and what it executes.
var lockedKeys = map[string]bool{"bind": true, "port": true, "api_token": true, "data_dir": true,
	"workers": true, "paths": true}

func (c *Core) apiModuleSave(r *Req) (any, error) {
	var in struct {
		Module   string         `json:"module"`
		Settings map[string]any `json:"settings"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	c.mu.RLock()
	info, known := c.Infos[in.Module]
	m := c.Modules[in.Module]
	c.mu.RUnlock()
	if !known {
		return nil, NotFound("unknown module %q", in.Module)
	}
	if in.Settings == nil {
		return nil, BadRequest("settings must be an object")
	}
	schema := map[string]SettingField{}
	for _, f := range info.Schema {
		schema[f.Key] = f
	}
	for k, v := range in.Settings {
		if lockedKeys[k] || strings.Contains(k, "_bin") || strings.Contains(k, "binary") {
			return nil, Forbidden("%q cannot be changed through the API", k)
		}
		f, ok := schema[k]
		if !ok && k != "enabled" {
			return nil, BadRequest("unknown setting %q", k)
		}
		switch f.Type {
		case "int":
			n, ok := v.(float64)
			if !ok || n != float64(int64(n)) {
				return nil, BadRequest("%s must be an integer", k)
			}
			in.Settings[k] = int(n)
		case "bool":
			if _, ok := v.(bool); !ok {
				return nil, BadRequest("%s must be true or false", k)
			}
		case "choice":
			s, _ := v.(string)
			found := false
			for _, ch := range f.Choices {
				if ch == s {
					found = true
				}
			}
			if !found {
				return nil, BadRequest("%s must be one of %s", k, strings.Join(f.Choices, ", "))
			}
		case "secret":
			if s, _ := v.(string); s == "********" {
				delete(in.Settings, k) // unchanged placeholder
			}
		case "list":
			if _, ok := v.([]any); !ok {
				return nil, BadRequest("%s must be a list", k)
			}
		}
	}
	before := c.Config.Module(in.Module)
	if err := c.Config.SetModule(in.Module, in.Settings); err != nil {
		return nil, err
	}
	after := c.Config.Module(in.Module)
	if rc, ok := m.(Reconfigurable); ok && m != nil {
		if err := rc.OnConfigChange(after); err != nil {
			return nil, BadRequest("saved, but the module rejected the change: %v", err)
		}
	}
	bb, _ := json.MarshalIndent(before, "", " ")
	ab, _ := json.MarshalIndent(after, "", " ")
	keys := make([]string, 0, len(in.Settings))
	for k := range in.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	_ = c.Store.RecordChange("system", "module:"+in.Module, r.User, "", "",
		"--- before\n"+string(bb)+"\n+++ after\n"+string(ab), "settings changed: "+strings.Join(keys, ", "))
	note := ""
	if Bool(before, "enabled", true) != Bool(after, "enabled", true) {
		note = "restart flowsightd to apply the enable/disable change"
	}
	return map[string]any{"ok": true, "settings": after, "note": note}, nil
}

func (c *Core) apiJobRun(r *Req) (any, error) {
	b := r.Body()
	name, _ := b["job"].(string)
	module, _ := b["module"].(string)
	if !c.Scheduler.RunNow(module, name) {
		return nil, NotFound("unknown job %q", name)
	}
	return map[string]any{"ok": true}, nil
}

func (c *Core) apiAudit(r *Req) (any, error) {
	rows, err := c.Store.Rows(`SELECT * FROM events WHERE kind='audit' ORDER BY ts DESC LIMIT ?`,
		r.QInt("limit", 100, 1, 1000))
	return map[string]any{"events": rows}, err
}

func (c *Core) apiEvents(r *Req) (any, error) {
	kind, err := r.QSafe("kind", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM events WHERE ts>=?`
	args := []any{r.Since(24)}
	if kind != "" {
		q += ` AND kind=?`
		args = append(args, kind)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := c.Store.Rows(q, args...)
	return map[string]any{"events": rows}, err
}

func (c *Core) apiFindings(r *Req) (any, error) {
	module, err := r.QSafe("module", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM findings WHERE resolved_ts IS NULL`
	args := []any{}
	if module != "" {
		q += ` AND module=?`
		args = append(args, module)
	}
	q += ` ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		WHEN 'low' THEN 3 ELSE 4 END, ts DESC LIMIT 500`
	rows, err := c.Store.Rows(q, args...)
	return map[string]any{"findings": rows}, err
}

func (c *Core) apiFindingAck(r *Req) (any, error) {
	id, _ := r.Body()["id"].(float64)
	if id <= 0 {
		return nil, BadRequest("id is required")
	}
	return map[string]any{"ok": true}, c.Store.Exec(`UPDATE findings SET acked=1 WHERE id=?`, int64(id))
}

func (c *Core) apiChanges(r *Req) (any, error) {
	module, err := r.QSafe("module", "", 40)
	if err != nil {
		return nil, err
	}
	q := `SELECT id,ts,module,subject,actor,summary,before_hash,after_hash,LENGTH(diff) AS diff_bytes FROM changes`
	args := []any{}
	if module != "" {
		q += ` WHERE module=?`
		args = append(args, module)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 100, 1, 1000))
	rows, err := c.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	if id := r.QInt("id", 0, 0, 0); id > 0 {
		row, err := c.Store.Row(`SELECT * FROM changes WHERE id=?`, id)
		if err != nil {
			return nil, err
		}
		return map[string]any{"change": row}, nil
	}
	return map[string]any{"changes": rows}, nil
}

// Helper for modules: serve a plain HTTP handler (e.g. a block page) on a
// separate listener owned by the module.
func ServeOn(addr string, h http.Handler) (*http.Server, error) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = srv.Serve(ln) }()
	return srv, nil
}
