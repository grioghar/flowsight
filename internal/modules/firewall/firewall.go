// Package firewall owns FlowSight's pf anchors. Every rule FlowSight needs,
// whether a policy block, a proxy redirect or a zone boundary, is loaded into
// a sub-anchor of "flowsight" with pfctl and never touches the operator's own
// ruleset. On OPNsense the plugin hook references the anchor from the
// generated ruleset; on plain FreeBSD the operator adds two lines to pf.conf.
//
// It is also the net.block provider: per-policy blocks on ports, on internet
// access, and on dynamic address tables that the app-control module fills.
package firewall

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

const rootAnchor = "flowsight"

type Module struct {
	legacyLocalFlushed bool
	ctx                *core.Context
	dir                string
	mu                 sync.Mutex
	lastErr            string
	identity           core.Identity
	loaded             map[string]string // anchor -> hash of rules loaded
	geoTables          map[string]*TableInfo // geo table info
}

// TableInfo holds information about a pf table.
type TableInfo struct {
	Name     string `json:"name"`
	Prefixes int    `json:"prefixes"`
	Epoch    int64  `json:"epoch"` // database build epoch when last updated
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "firewall", Version: "1.0",
		Description:  "FlowSight's own pf anchors: policy blocks, proxy redirects and dynamic address tables.",
		Capabilities: []string{},
		Requires:     []string{"pf"},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"log_blocks": true,
		},
		Schema: []core.SettingField{
			{Key: "log_blocks", Label: "Log blocked packets to pflog", Type: "bool"},
		},
	}
}

// Firewall is the service other modules use.
type Firewall interface {
	// LoadAnchor replaces the rules of sub-anchor name (e.g. "web").
	LoadAnchor(name, rules string) error
	// FlushAnchor removes a sub-anchor's rules.
	FlushAnchor(name string) error
	// ReplaceTable sets the contents of a table inside a sub-anchor.
	ReplaceTable(anchor, table string, addrs []string) error
	// AddToTable adds addresses to a table inside a sub-anchor.
	AddToTable(anchor, table string, addrs []string) error
	// KillStates drops existing states between two hosts (either may be "").
	KillStates(src, dst string) error
	// Counters returns per-rule evaluation and packet counters for an anchor.
	Counters(anchor string) ([]RuleCounter, error)
	// LocalTable is the name of the table holding local networks.
	LocalTable() string
	Available() bool
}

type RuleCounter struct {
	Rule        string `json:"rule"`
	Label       string `json:"label"`
	Evaluations int64  `json:"evaluations"`
	Packets     int64  `json:"packets"`
	Bytes       int64  `json:"bytes"`
	States      int64  `json:"states"`
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.dir = filepath.Join(ctx.Platform.EtcDir, "pf")
	m.loaded = map[string]string{}
	m.geoTables = make(map[string]*TableInfo)
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return err
	}
	ctx.Publish("firewall", m)
	if m.Available() {
		ctx.Provider(&provider{m: m})
		ctx.Every("local-table", 60*time.Second, m.refreshLocal)
		ctx.Every("anchor-check", 60*time.Second, m.checkAnchor)
	}
	ctx.Route("GET", "/api/firewall/status", m.apiStatus, core.Doc("Anchor state, tables and rule counters"))
	return nil
}

func (m *Module) Available() bool {
	return m.ctx.Platform.Firewall == "pf" && m.ctx.Platform.Pfctl != ""
}

func (m *Module) Health() core.Health {
	if !m.Available() {
		return core.Health{OK: true, Detail: "no pf on this platform; net.block unavailable"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d anchor(s) loaded", len(m.loaded))}
}

func (m *Module) LocalTable() string { return "flowsight_local" }

// UpdateGeoTableInfo records information about a geo table for status reporting.
func (m *Module) UpdateGeoTableInfo(cc string, prefixes int, epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.geoTables[cc] = &TableInfo{
		Name:     "fs_geo_" + strings.ToLower(cc),
		Prefixes: prefixes,
		Epoch:    epoch,
	}
}

func (m *Module) pfctl(args ...string) (string, error) {
	return core.Run(30*time.Second, m.ctx.Platform.Pfctl, args...)
}

var anchorNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

func (m *Module) LoadAnchor(name, rules string) error {
	if !anchorNameRe.MatchString(name) {
		return fmt.Errorf("invalid anchor name %q", name)
	}
	path := filepath.Join(m.dir, name+".conf")
	if strings.TrimSpace(rules) == "" {
		return m.FlushAnchor(name)
	}
	if err := os.WriteFile(path+".tmp", []byte(rules), 0o644); err != nil {
		return err
	}
	// Syntax check without loading, then load.
	if out, err := m.pfctl("-a", rootAnchor+"/"+name, "-n", "-f", path+".tmp"); err != nil {
		_ = os.Remove(path + ".tmp")
		return fmt.Errorf("pfctl rejected anchor %s: %s", name, strings.TrimSpace(out))
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	if out, err := m.pfctl("-a", rootAnchor+"/"+name, "-f", path); err != nil {
		return fmt.Errorf("pfctl load %s: %s", name, strings.TrimSpace(out))
	}
	m.mu.Lock()
	m.loaded[name] = fmt.Sprint(len(rules))
	m.mu.Unlock()
	return nil
}

func (m *Module) FlushAnchor(name string) error {
	_, _ = m.pfctl("-a", rootAnchor+"/"+name, "-F", "rules")
	_, _ = m.pfctl("-a", rootAnchor+"/"+name, "-F", "nat")
	_ = os.Remove(filepath.Join(m.dir, name+".conf"))
	m.mu.Lock()
	delete(m.loaded, name)
	m.mu.Unlock()
	return nil
}

var tableRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,40}$`)

func (m *Module) tableCmd(anchor, table, op string, addrs []string) error {
	if !tableRe.MatchString(table) {
		return fmt.Errorf("invalid table name %q", table)
	}
	args := []string{}
	if anchor != "" {
		args = append(args, "-a", rootAnchor+"/"+anchor)
	}
	args = append(args, "-t", table, "-T", op)
	if op != "flush" {
		if len(addrs) == 0 {
			if op == "replace" {
				op = "flush"
				args[len(args)-1] = "flush"
			} else {
				return nil
			}
		}
		if op != "flush" {
			// Feed addresses through a file to stay clear of argv limits.
			f, err := os.CreateTemp(m.dir, "table-*")
			if err != nil {
				return err
			}
			defer os.Remove(f.Name())
			for _, a := range addrs {
				if net.ParseIP(a) == nil {
					if _, _, err := net.ParseCIDR(a); err != nil {
						continue
					}
				}
				fmt.Fprintln(f, a)
			}
			f.Close()
			args = append(args, "-f", f.Name())
		}
	}
	if out, err := m.pfctl(args...); err != nil {
		return fmt.Errorf("pfctl table %s: %s", table, strings.TrimSpace(out))
	}
	return nil
}

func (m *Module) ReplaceTable(anchor, table string, addrs []string) error {
	return m.tableCmd(anchor, table, "replace", addrs)
}

func (m *Module) AddToTable(anchor, table string, addrs []string) error {
	return m.tableCmd(anchor, table, "add", addrs)
}

func (m *Module) KillStates(src, dst string) error {
	args := []string{"-k"}
	if src == "" {
		src = "0.0.0.0/0"
	}
	args = append(args, src)
	if dst != "" {
		args = append(args, "-k", dst)
	}
	_, err := m.pfctl(args...)
	return err
}

var counterRe = regexp.MustCompile(`Evaluations: (\d+)\s+Packets: (\d+)\s+Bytes: (\d+)\s+States: (\d+)`)
var labelRe = regexp.MustCompile(`label "([^"]*)"`)

func (m *Module) Counters(anchor string) ([]RuleCounter, error) {
	out, err := m.pfctl("-a", rootAnchor+"/"+anchor, "-vsr")
	if err != nil {
		return nil, err
	}
	var res []RuleCounter
	var cur *RuleCounter
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "[") {
			if cur != nil {
				if mm := counterRe.FindStringSubmatch(t); mm != nil {
					cur.Evaluations, _ = strconv.ParseInt(mm[1], 10, 64)
					cur.Packets, _ = strconv.ParseInt(mm[2], 10, 64)
					cur.Bytes, _ = strconv.ParseInt(mm[3], 10, 64)
					cur.States, _ = strconv.ParseInt(mm[4], 10, 64)
				}
			}
			continue
		}
		res = append(res, RuleCounter{Rule: t})
		cur = &res[len(res)-1]
		if lm := labelRe.FindStringSubmatch(t); lm != nil {
			cur.Label = lm[1]
		}
	}
	return res, nil
}

// refreshLocal keeps the local-networks table current so "internet" denies
// can be expressed as "to anything not local".
func (m *Module) refreshLocal() error {
	var nets []string
	if m.identity != nil {
		nets = m.identity.LocalNetworks()
	}
	nets = append(nets, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10",
		"127.0.0.0/8", "::1/128", "169.254.0.0/16", "224.0.0.0/4", "ff00::/8")
	// The table must live in the root ruleset: a rule inside an anchor that
	// names a table the anchor does not define falls through to the root
	// table of that name. Defining it inside an anchor (or inside the anchor
	// that references it) would give each anchor its own empty copy, and
	// "to ! <local>" would then match everything.
	if !m.legacyLocalFlushed {
		// Earlier releases defined the table inside anchors; a persist
		// table outlives the rules that defined it, so kill those copies
		// or they keep shadowing the root table.
		_ = m.FlushAnchor("local")
		for _, a := range []string{"local", "policy", "web"} {
			_, _ = m.pfctl("-a", rootAnchor+"/"+a, "-t", m.LocalTable(), "-T", "kill")
		}
		m.legacyLocalFlushed = true
	}
	return m.tableCmd("", m.LocalTable(), "replace", nets)
}

// checkAnchor verifies the main ruleset references our anchor and records a
// finding when it does not, which is the difference between blocking and
// silently doing nothing.
func (m *Module) checkAnchor() error {
	out, err := m.pfctl("-sr")
	if err != nil {
		return err
	}
	ok := strings.Contains(out, `anchor "flowsight/*"`) || strings.Contains(out, "anchor \"flowsight")
	if !ok {
		hint := "reference it from the main ruleset"
		if m.ctx.Platform.IsOPNsense() {
			hint = "enable FlowSight in the plugin and apply firewall changes so the anchor is generated"
		} else {
			hint = "add 'anchor \"flowsight/*\"' and 'rdr-anchor \"flowsight/*\"' to pf.conf"
		}
		_, _ = m.ctx.Store.AddFinding("firewall", "anchor-missing", "high", "pf",
			"FlowSight's pf anchor is not in the active ruleset",
			"Rules loaded into flowsight/* are never evaluated: "+hint+".", "firewall:anchor")
		m.mu.Lock()
		m.lastErr = "anchor flowsight/* is not referenced by the active ruleset"
		m.mu.Unlock()
		return nil
	}
	_, _ = m.ctx.Store.ResolveFindings("firewall", map[string]bool{})
	m.mu.Lock()
	m.lastErr = ""
	m.mu.Unlock()
	return nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	if !m.Available() {
		return map[string]any{"available": false}, nil
	}
	anchors, _ := m.pfctl("-a", rootAnchor, "-sA")
	var list []string
	for _, a := range strings.Split(anchors, "\n") {
		if t := strings.TrimSpace(a); t != "" {
			list = append(list, t)
		}
	}
	sort.Strings(list)
	counters := map[string]any{}
	for _, a := range list {
		name := strings.TrimPrefix(a, rootAnchor+"/")
		c, err := m.Counters(name)
		if err == nil {
			counters[name] = c
		}
	}
	m.mu.Lock()
	geoTables := make([]any, 0, len(m.geoTables))
	for _, ti := range m.geoTables {
		geoTables = append(geoTables, ti)
	}
	m.mu.Unlock()
	main, _ := m.pfctl("-sr")
	return map[string]any{"available": true, "anchors": list, "counters": counters,
		"referenced": strings.Contains(main, "flowsight"), "geo_tables": geoTables}, nil
}
