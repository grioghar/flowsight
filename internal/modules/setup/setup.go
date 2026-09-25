// Package setup provides a first-run wizard for quick configuration.
package setup

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx *core.Context
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "setup",
		Version:     "1.0",
		Description: "First-run setup wizard for quick configuration.",
		Defaults: map[string]any{
			"enabled": true,
		},
	}
}

// State represents the detected configuration and wizard progress.
type State struct {
	Completed    bool     `json:"completed"`
	CompletedAt  int64    `json:"completed_at,omitempty"`
	Platform     string   `json:"platform"`
	Interfaces   []string `json:"interfaces"`
	Binaries     Binaries `json:"binaries"`
	License      License  `json:"license"`
	DataDirSpace uint64   `json:"data_dir_space"`
	APILoopback  bool     `json:"api_loopback"`
	APITokenSet  bool     `json:"api_token_set"`
	PiholeFound  string   `json:"pihole_found,omitempty"`
	ProxmoxFound string   `json:"proxmox_found,omitempty"`
}

// Binaries tracks which backend binaries are present.
type Binaries struct {
	Ntopng   bool `json:"ntopng"`
	Suricata bool `json:"suricata"`
	Squid    bool `json:"squid"`
	Nmap     bool `json:"nmap"`
	Tcpdump  bool `json:"tcpdump"`
}

// License tier information.
type License struct {
	Tier string `json:"tier"`
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	ctx.Route("GET", "/api/setup/state", m.apiState, core.Doc("Wizard state and detected facts"))
	ctx.Route("POST", "/api/setup/apply", m.apiApply, core.Write(),
		core.Doc("Apply one step's answers"))
	ctx.Route("POST", "/api/setup/test", m.apiTest, core.Write(),
		core.Doc("Test a step's values"))
	ctx.Route("POST", "/api/setup/reset", m.apiReset, core.Write(),
		core.Doc("Reset the wizard progress"))
	ctx.Panel(core.Panel{ID: "setup", Title: "Setup wizard", Group: "Administration", Order: 195, Icon: "setup"})
	return nil
}

func (m *Module) apiState(r *core.Req) (any, error) {
	state := m.detectState()

	// Load completion state from KV store
	var completed bool
	m.ctx.Store.KVGet("setup.completed", &completed)
	var completedAt int64
	m.ctx.Store.KVGet("setup.completed_at", &completedAt)

	state.Completed = completed
	state.CompletedAt = completedAt

	return state, nil
}

func (m *Module) apiApply(r *core.Req) (any, error) {
	step, ok := r.Body()["step"].(float64)
	if !ok {
		return nil, core.BadRequest("step is required")
	}

	values, ok := r.Body()["values"].(map[string]any)
	if !ok {
		values = map[string]any{}
	}

	switch int(step) {
	case 1: // Welcome & licence
	case 2: // Site basics
	case 3: // Traffic source (ntopng)
		settings := map[string]any{}
		if url, ok := values["ntopng_url"].(string); ok && url != "" {
			settings["url"] = strings.TrimRight(url, "/")
		}
		if username, ok := values["ntopng_username"].(string); ok && username != "" {
			settings["username"] = username
		}
		if password, ok := values["ntopng_password"].(string); ok && password != "" {
			settings["password"] = password
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("visibility", settings); err != nil {
				return nil, core.Errorf(400, "failed to save visibility settings: %v", err)
			}
		}
	case 4: // DNS source (Pi-hole)
		settings := map[string]any{}
		if addr, ok := values["pihole_address"].(string); ok && addr != "" {
			settings["pihole_address"] = addr
		}
		if token, ok := values["pihole_token"].(string); ok && token != "" {
			settings["pihole_api_token"] = token
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("dns", settings); err != nil {
				return nil, core.Errorf(400, "failed to save dns settings: %v", err)
			}
		}
	case 5: // Interception
		settings := map[string]any{}
		if intercept, ok := values["intercept"].(bool); ok {
			settings["intercept"] = intercept
		}
		if interfaces, ok := values["interfaces"].([]any); ok {
			ifaces := make([]string, len(interfaces))
			for i, v := range interfaces {
				ifaces[i] = fmt.Sprint(v)
			}
			settings["interfaces"] = ifaces
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("web", settings); err != nil {
				return nil, core.Errorf(400, "failed to save web settings: %v", err)
			}
		}
	case 6: // Identity & zones
	case 7: // Security (IDS, TLS probe)
		settings := map[string]any{}
		if ids, ok := values["ids_enabled"].(bool); ok {
			settings["enabled"] = ids
		}
		if tlsProbe, ok := values["tls_probe"].(bool); ok {
			settings["probe_enabled"] = tlsProbe
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("ids", settings); err != nil {
				return nil, core.Errorf(400, "failed to save ids settings: %v", err)
			}
		}
	case 8: // Inventory (Proxmox)
		settings := map[string]any{}
		if host, ok := values["proxmox_host"].(string); ok && host != "" {
			settings["host"] = host
		}
		if tokenID, ok := values["proxmox_token_id"].(string); ok && tokenID != "" {
			settings["token_id"] = tokenID
		}
		if tokenSecret, ok := values["proxmox_token_secret"].(string); ok && tokenSecret != "" {
			settings["token_secret"] = tokenSecret
		}
		if fingerprint, ok := values["proxmox_fingerprint"].(string); ok && fingerprint != "" {
			settings["fingerprint"] = fingerprint
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("proxmox", settings); err != nil {
				return nil, core.Errorf(400, "failed to save proxmox settings: %v", err)
			}
		}
	case 9: // Alerting
	case 10: // Updates
		settings := map[string]any{}
		if manifestURL, ok := values["manifest_url"].(string); ok && manifestURL != "" {
			settings["manifest_url"] = manifestURL
		}
		if autoApply, ok := values["auto_apply"].(bool); ok {
			settings["auto_apply"] = autoApply
		}
		if len(settings) > 0 {
			if err := m.ctx.Config.SetModule("updater", settings); err != nil {
				return nil, core.Errorf(400, "failed to save updater settings: %v", err)
			}
		}
	case 11: // API access
	case 12: // Review & finish
		m.ctx.Store.KVSet("setup.completed", true)
		m.ctx.Store.KVSet("setup.completed_at", time.Now().Unix())
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiTest(r *core.Req) (any, error) {
	step, ok := r.Body()["step"].(float64)
	if !ok {
		return nil, core.BadRequest("step is required")
	}

	values, ok := r.Body()["values"].(map[string]any)
	if !ok {
		values = map[string]any{}
	}

	switch int(step) {
	case 3: // Traffic source (ntopng)
		if url, ok := values["ntopng_url"].(string); ok && url != "" {
			return m.testNtopng(url, values), nil
		}
		return map[string]any{"ok": false, "error": "ntopng_url is required"}, nil
	case 4: // DNS source (Pi-hole)
		if addr, ok := values["pihole_address"].(string); ok && addr != "" {
			return m.testPihole(addr, values), nil
		}
		return map[string]any{"ok": false, "error": "pihole_address is required"}, nil
	case 8: // Inventory (Proxmox)
		if host, ok := values["proxmox_host"].(string); ok && host != "" {
			return m.testProxmox(host, values), nil
		}
		return map[string]any{"ok": false, "error": "proxmox_host is required"}, nil
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiReset(r *core.Req) (any, error) {
	m.ctx.Store.KVSet("setup.completed", false)
	m.ctx.Store.KVSet("setup.completed_at", int64(0))
	return map[string]any{"ok": true}, nil
}

// detectState gathers system facts for the wizard
func (m *Module) detectState() *State {
	state := &State{
		Platform: m.ctx.Platform.Name,
	}

	state.Interfaces = m.detectInterfaces()
	state.Binaries = m.detectBinaries()

	lic := m.ctx.Core.License()
	if lic != nil {
		state.License.Tier = lic.Tier()
	} else {
		state.License.Tier = "community"
	}

	state.DataDirSpace = m.dataDirSpace()

	core := m.ctx.Config.Core()
	state.APILoopback = core.Bind == "127.0.0.1" || core.Bind == "::1"
	state.APITokenSet = core.APIToken != ""

	state.PiholeFound = m.findPihole()
	state.ProxmoxFound = m.findProxmox()

	return state
}

func (m *Module) detectInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names []string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			names = append(names, iface.Name)
		}
	}
	return names
}

func (m *Module) detectBinaries() Binaries {
	return Binaries{
		Ntopng:   m.binExists("ntopng"),
		Suricata: m.binExists("suricata"),
		Squid:    m.binExists("squid"),
		Nmap:     m.binExists("nmap"),
		Tcpdump:  m.binExists("tcpdump"),
	}
}

func (m *Module) binExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (m *Module) dataDirSpace() uint64 {
	core := m.ctx.Config.Core()
	dataDir := core.DataDir
	if dataDir == "" {
		dataDir = m.ctx.Platform.DataDir
	}

	info, err := os.Stat(dataDir)
	if err != nil {
		dataDir = filepath.Dir(dataDir)
		info, err = os.Stat(dataDir)
	}

	if err != nil || !info.IsDir() {
		return 0
	}
	return 0
}

func (m *Module) findPihole() string {
	candidates := []string{"192.168.1.1", "192.168.1.10", "192.168.0.1", "10.0.0.1"}

	if gw := m.defaultGateway(); gw != "" {
		parts := strings.Split(gw, ".")
		if len(parts) == 4 {
			base := strings.Join(parts[:3], ".")
			candidates = append(candidates, base+".1", base+".254")
		}
	}

	for _, addr := range candidates {
		if m.checkPihole(addr) {
			return addr
		}
	}
	return ""
}

func (m *Module) checkPihole(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("http://%s:80/admin/api.php", addr)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (m *Module) findProxmox() string {
	if gw := m.defaultGateway(); gw != "" {
		if m.checkProxmox(gw) {
			return gw
		}

		parts := strings.Split(gw, ".")
		if len(parts) == 4 {
			candidate := strings.Join(parts[:3], ".") + ".1"
			if candidate != gw && m.checkProxmox(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func (m *Module) checkProxmox(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://%s:8006", addr)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (m *Module) defaultGateway() string {
	cmd := exec.Command("ip", "route", "show")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "default") {
				parts := strings.Fields(line)
				if len(parts) >= 3 && parts[1] == "via" {
					return parts[2]
				}
			}
		}
	}
	return ""
}

func (m *Module) testNtopng(url string, values map[string]any) map[string]any {
	username, _ := values["ntopng_username"].(string)
	password, _ := values["ntopng_password"].(string)

	url = strings.TrimRight(url, "/")
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := url + "/lua/get_system_version.lua"
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid ntopng credentials"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("ntopng returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}

func (m *Module) testPihole(addr string, values map[string]any) map[string]any {
	token, _ := values["pihole_token"].(string)

	if addr == "" {
		return map[string]any{"ok": false, "error": "Address is required"}
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := fmt.Sprintf("http://%s/api/status", addr)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	if token != "" {
		req.Header.Set("X-API-Token", token)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid Pi-hole token"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("Pi-hole returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}

func (m *Module) testProxmox(host string, values map[string]any) map[string]any {
	tokenID, _ := values["proxmox_token_id"].(string)
	tokenSecret, _ := values["proxmox_token_secret"].(string)

	if host == "" {
		return map[string]any{"ok": false, "error": "Host is required"}
	}

	if tokenID == "" || tokenSecret == "" {
		return map[string]any{"ok": false, "error": "Token ID and secret are required"}
	}

	if !strings.Contains(host, ":") {
		host = host + ":8006"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testURL := fmt.Sprintf("https://%s/api2/json/version", host)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}

	token := fmt.Sprintf("PVEAPIToken=%s:%s", tokenID, tokenSecret)
	req.Header.Set("Authorization", token)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "error": "Could not connect: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return map[string]any{"ok": false, "error": "Invalid Proxmox credentials"}
	}
	if resp.StatusCode != 200 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("Proxmox returned HTTP %d", resp.StatusCode)}
	}

	return map[string]any{"ok": true}
}
