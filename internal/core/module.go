package core

import (
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Capabilities are the vocabulary policy speaks. Observe capabilities on the
// left, enforce capabilities on the right. A module must never claim an
// enforce capability it cannot deliver: the policy compiler trusts these
// declarations, and a false one produces policy that silently does nothing.
const (
	CapTrafficObserve = "traffic.observe"
	CapHostInventory  = "host.inventory"
	CapAppObserve     = "app.observe"
	CapAppBlock       = "app.block"
	CapThreatDetect   = "threat.detect"
	CapThreatBlock    = "threat.block"
	CapDNSObserve     = "dns.observe"
	CapDNSBlock       = "dns.block"
	CapWebObserve     = "web.observe"
	CapWebBlock       = "web.block"
	CapNetBlock       = "net.block"
	CapTLSObserve     = "tls.observe"
	CapTLSInspect     = "tls.inspect"
	CapRuleAnalyse    = "firewall.analyse"
	CapIdentity       = "identity.resolve"
	CapNotify         = "notify"
)

var EnforceCaps = map[string]bool{
	CapAppBlock: true, CapThreatBlock: true, CapDNSBlock: true, CapWebBlock: true,
	CapNetBlock: true, CapTLSInspect: true,
}

// Module is what every feature implements. Setup registers jobs, routes,
// providers and panels through the Context; nothing else is required.
type Module interface {
	Info() ModuleInfo
	Setup(ctx *Context) error
}

// Healther is optional: modules with something to say about their own state.
type Healther interface {
	Health() Health
}

// Reconfigurable is optional: called after the operator saves settings.
type Reconfigurable interface {
	OnConfigChange(settings map[string]any) error
}

// Stopper is optional.
type Stopper interface {
	Stop()
}

type ModuleInfo struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Description  string         `json:"description"`
	Capabilities []string       `json:"capabilities"`
	Requires     []string       `json:"requires"` // informational: backends it uses
	After        []string       `json:"after"`    // modules whose services it consumes
	Defaults     map[string]any `json:"-"`
	Schema       []SettingField `json:"schema"` // what the UI renders
	Tier         string         `json:"tier"`   // entitlement tier, "" = free
}

// SettingField describes one operator-editable setting for the generic UI.
type SettingField struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Type        string   `json:"type"` // string, int, bool, choice, text, list, secret
	Choices     []string `json:"choices,omitempty"`
	Help        string   `json:"help,omitempty"`
	Restart     bool     `json:"restart,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
}

type Health struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Extra  any    `json:"extra,omitempty"`
}

// Effective is optional: a module that treats an empty setting as "use the
// platform default" reports what it is actually using, so the settings page
// can say so next to the empty field instead of leaving the operator to guess.
type Effective interface {
	EffectiveSettings() map[string]any
}

// Provider is a backend a policy can be compiled onto.
type Provider interface {
	Name() string
	Capabilities() []string
	// Compile renders the desired artifact for the policy document.
	Compile(doc *PolicyDoc) (Artifact, error)
	// Current returns what is in place now.
	Current() (Artifact, error)
	// Apply installs the artifact. It must validate first, keep a backup,
	// and revert on failure. It returns a short note for the operator.
	Apply(a Artifact) (string, error)
}

// Artifact is provider output: usually one text file, sometimes several.
type Artifact struct {
	Files map[string]string `json:"files"` // path -> content
	Note  string            `json:"note"`
}

// Panel is a UI surface a module contributes.
type Panel struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Group  string `json:"group"`
	Order  int    `json:"order"`
	Icon   string `json:"icon"`
	Detail bool   `json:"detail"` // reached by link, not from the menu
	// Feature, when set, is the tier feature the panel belongs to; the menu
	// shows it locked below that tier.
	Feature string `json:"feature,omitempty"`
}

// Context is what a module sees of the core.
type Context struct {
	Core     *Core
	Name     string
	Store    *Store
	Platform *Platform
	Config   *Config
	Log      *slog.Logger
	settings map[string]any
}

// Settings returns the merged settings map for this module.
func (c *Context) Settings() map[string]any { return c.Config.Module(c.Name) }

// Decode decodes settings into a typed struct.
func (c *Context) Decode(into any) error { return c.Config.Settings(c.Name, into) }

// Every schedules fn on an interval. Jobs run on a shared pool; one slow job
// never stalls another, and a panic is contained and reported.
func (c *Context) Every(name string, every time.Duration, fn func() error, opts ...JobOption) {
	j := &Job{Name: name, Module: c.Name, Every: every, Fn: fn, nextRun: time.Now()}
	for _, o := range opts {
		o(j)
	}
	if j.Feature != "" {
		core, feature := c.Core, j.Feature
		j.gate = func() error { return core.License().Allowed(feature) }
	}
	c.Core.Scheduler.Add(j)
}

type JobOption func(*Job)

// Delayed makes the first run wait one interval.
func Delayed() JobOption { return func(j *Job) { j.nextRun = time.Now().Add(j.Every) } }

// Route registers an API handler. Write routes must not be GET and pass
// through the single write gate in the API layer.
func (c *Context) Route(method, path string, h Handler, opts ...RouteOption) {
	c.Core.API.Add(method, path, h, c.Name, opts...)
}

func (c *Context) Provider(p Provider) {
	c.Core.mu.Lock()
	defer c.Core.mu.Unlock()
	c.Core.Providers = append(c.Core.Providers, p)
}

func (c *Context) Panel(p Panel) {
	c.Core.mu.Lock()
	defer c.Core.mu.Unlock()
	c.Core.Panels = append(c.Core.Panels, p)
}

// Publish makes a service object available to other modules by name.
func (c *Context) Publish(name string, svc any) {
	c.Core.mu.Lock()
	defer c.Core.mu.Unlock()
	c.Core.Services[name] = svc
}

// Service looks up a service another module published.
func (c *Context) Service(name string) any {
	c.Core.mu.RLock()
	defer c.Core.mu.RUnlock()
	return c.Core.Services[name]
}

// Event records a normalised event.
func (c *Context) Event(kind, message string, fields map[string]any) {
	e := Event{TS: time.Now().Unix(), Kind: kind, Source: c.Name, Severity: "info",
		Verdict: "observed", Message: message}
	e.apply(fields)
	_ = c.Store.AddEvents([]Event{e})
}

// ---------------------------------------------------------------- scheduler

type Job struct {
	Name   string        `json:"name"`
	Module string        `json:"module"`
	Every  time.Duration `json:"-"`
	Fn     func() error  `json:"-"`
	// Feature gates the job on a license tier; gate is set by the context.
	Feature string `json:"feature,omitempty"`
	gate    func() error
	locked  bool

	mu        sync.Mutex
	nextRun   time.Time
	running   bool
	Runs      int       `json:"runs"`
	Failures  int       `json:"failures"`
	LastRun   time.Time `json:"last_run"`
	LastOK    *bool     `json:"ok"`
	LastError string    `json:"error"`
	LastDur   float64   `json:"duration"`
}

func (j *Job) state() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	var ok any
	if j.LastOK != nil {
		ok = *j.LastOK
	}
	return map[string]any{"name": j.Name, "module": j.Module, "every": j.Every.Seconds(),
		"runs": j.Runs, "failures": j.Failures, "ok": ok, "error": j.LastError,
		"last_run": j.LastRun.Unix(), "duration": j.LastDur, "running": j.running,
		"next_run": j.nextRun.Unix(), "feature": j.Feature, "locked": j.locked}
}

type Scheduler struct {
	mu      sync.Mutex
	jobs    []*Job
	workers int
	stop    chan struct{}
	log     *slog.Logger
}

func NewScheduler(workers int, log *slog.Logger) *Scheduler {
	if workers < 1 {
		workers = 2
	}
	return &Scheduler{workers: workers, stop: make(chan struct{}), log: log}
}

func (s *Scheduler) Add(j *Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, j)
}

func (s *Scheduler) Jobs() []map[string]any {
	s.mu.Lock()
	jobs := append([]*Job(nil), s.jobs...)
	s.mu.Unlock()
	sort.Slice(jobs, func(i, k int) bool {
		if jobs[i].Module != jobs[k].Module {
			return jobs[i].Module < jobs[k].Module
		}
		return jobs[i].Name < jobs[k].Name
	})
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.state())
	}
	return out
}

// RunNow schedules a job to run at the next tick.
func (s *Scheduler) RunNow(module, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.Name == name && (module == "" || j.Module == module) {
			j.mu.Lock()
			j.nextRun = time.Now()
			j.mu.Unlock()
			return true
		}
	}
	return false
}

func (s *Scheduler) Start() {
	for i := 0; i < s.workers; i++ {
		go s.loop()
	}
}

func (s *Scheduler) Stop() { close(s.stop) }

func (s *Scheduler) claim() *Job {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var pick *Job
	for _, j := range s.jobs {
		j.mu.Lock()
		due := !j.running && !j.nextRun.After(now)
		if due && (pick == nil || j.nextRun.Before(pick.nextRun)) {
			pick = j
		}
		j.mu.Unlock()
	}
	if pick != nil {
		pick.mu.Lock()
		pick.running = true
		pick.mu.Unlock()
	}
	return pick
}

func (s *Scheduler) loop() {
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		j := s.claim()
		if j == nil {
			select {
			case <-s.stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}
		s.run(j)
	}
}

func (s *Scheduler) run(j *Job) {
	if j.gate != nil {
		if gerr := j.gate(); gerr != nil {
			// Not licensed: do not run, do not count a failure, try again
			// next interval in case a license arrived.
			j.mu.Lock()
			j.locked = true
			j.LastError = "locked: " + gerr.Error()
			j.running = false
			j.nextRun = time.Now().Add(j.Every)
			j.mu.Unlock()
			return
		}
		j.mu.Lock()
		j.locked = false
		j.mu.Unlock()
	}
	t0 := time.Now()
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = &panicError{r}
			}
		}()
		err = j.Fn()
	}()
	j.mu.Lock()
	ok := err == nil
	j.LastOK = &ok
	j.LastError = ""
	if err != nil {
		j.LastError = err.Error()
		if len(j.LastError) > 400 {
			j.LastError = j.LastError[:400]
		}
		j.Failures++
	}
	j.Runs++
	j.LastRun = time.Now()
	j.LastDur = time.Since(t0).Seconds()
	j.nextRun = time.Now().Add(j.Every)
	j.running = false
	j.mu.Unlock()
	if err != nil {
		s.log.Warn("job failed", "module", j.Module, "job", j.Name, "error", err.Error())
	}
}

type panicError struct{ v any }

func (p *panicError) Error() string { return "panic: " + toString(p.v) }

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	}
	return "unknown"
}
