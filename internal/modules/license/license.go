// Package license is the entitlement module: it keeps the installation's
// signed license, verifies it, refreshes online activations, and answers the
// core's Licensing questions. Without a license the installation is
// Community, which is a complete product, not a trial.
package license

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/licensing"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// PublicKeyBase64 is the ed25519 key licenses are verified against. Release
// builds set it with
//
//	-ldflags "-X github.com/grioghar/flowsight/internal/modules/license.PublicKeyBase64=<key>"
//
// (packaging/release/license.pub). A build without it cannot verify any
// license and therefore runs Community.
var PublicKeyBase64 = ""

const defaultServer = "https://license.grio.co"

// kv keys
const (
	kvInstallation = "license.installation"
	kvToken        = "license.token"
	kvKey          = "license.key"
	kvState        = "license.state"
)

type state struct {
	LastRefresh int64  `json:"last_refresh"`
	LastError   string `json:"last_error"`
	Revoked     string `json:"revoked,omitempty"` // server's reason when it withdrew the license
	Source      string `json:"source,omitempty"`  // online | offline
}

// Module implements core.Module and core.Licensing.
type Module struct {
	ctx    *core.Context
	pub    ed25519.PublicKey
	client *http.Client

	mu           sync.RWMutex
	installation string
	lic          *licensing.License
	token        string
	key          string
	st           state
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "license",
		Version:     "1.0",
		Description: "Entitlements: Community, Pro and Business tiers, activated online or with a signed license file.",
		Defaults: map[string]any{
			"enabled":     true,
			"server_url":  defaultServer,
			"check_hours": 24,
		},
		Schema: []core.SettingField{
			{Key: "server_url", Label: "License server", Type: "string",
				Help: "Used for online activation and lease refresh. Offline license files never contact it."},
			{Key: "check_hours", Label: "Refresh interval (hours)", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.client = &http.Client{Timeout: 20 * time.Second}
	if PublicKeyBase64 != "" {
		k, err := licensing.ParseKey(PublicKeyBase64, ed25519.PublicKeySize)
		if err != nil {
			return fmt.Errorf("license public key: %v", err)
		}
		m.pub = ed25519.PublicKey(k)
	}
	// Installation id: created once, kept for the life of the data dir.
	if !ctx.Store.KVGet(kvInstallation, &m.installation) || m.installation == "" {
		m.installation = licensing.NewID("inst")
		_ = ctx.Store.KVSet(kvInstallation, m.installation)
	}
	ctx.Store.KVGet(kvToken, &m.token)
	ctx.Store.KVGet(kvKey, &m.key)
	ctx.Store.KVGet(kvState, &m.st)
	if m.token != "" {
		if l, err := m.verify(m.token); err == nil {
			m.lic = l
		} else {
			m.st.LastError = "stored license rejected: " + err.Error()
		}
	}
	ctx.Publish("license", m)

	hours := core.Int(ctx.Settings(), "check_hours", 24)
	if hours < 1 {
		hours = 1
	}
	ctx.Every("refresh", time.Duration(hours)*time.Hour, m.refreshJob, core.Delayed())

	ctx.Route("GET", "/api/license", m.apiStatus, core.Doc("Current tier, license, features and limits"))
	ctx.Route("GET", "/api/license/features", m.apiFeatures, core.Doc("The feature catalogue with what this installation has"))
	ctx.Route("POST", "/api/license/activate", m.apiActivate, core.Write(),
		core.Doc("Activate an activation key against the license server"))
	ctx.Route("POST", "/api/license/install", m.apiInstall, core.Write(),
		core.Doc("Install a signed license file (offline)"))
	ctx.Route("POST", "/api/license/refresh", m.apiRefresh, core.Write(),
		core.Doc("Refresh the online lease now"))
	ctx.Route("POST", "/api/license/remove", m.apiRemove, core.Write(),
		core.Doc("Remove the license and return to Community (tells the server, when it was an online activation)"))
	ctx.Panel(core.Panel{ID: "license", Title: "License", Group: "Operations", Order: 250, Icon: "license"})
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.pub == nil {
		return core.Health{OK: true, Detail: "Community (this build carries no license key; licenses cannot be verified)"}
	}
	if m.lic == nil {
		if m.st.Revoked != "" {
			return core.Health{OK: true, Detail: "Community (license withdrawn: " + m.st.Revoked + ")"}
		}
		return core.Health{OK: true, Detail: "Community"}
	}
	d := strings.ToUpper(m.lic.Tier[:1]) + m.lic.Tier[1:]
	if m.lic.Expired(time.Now()) {
		return core.Health{OK: true, Detail: d + " (expired " + m.lic.Expires + "; renew to change tier features)"}
	}
	if m.st.LastError != "" {
		return core.Health{OK: true, Detail: d + " (" + m.st.LastError + ")"}
	}
	return core.Health{OK: true, Detail: d}
}

// ---------------------------------------------------------------- Licensing

func (m *Module) current() *licensing.License {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lic
}

func (m *Module) Tier() string {
	if l := m.current(); l != nil {
		return l.Tier
	}
	return licensing.TierCommunity
}

func (m *Module) Allowed(feature string) error {
	if l := m.current(); l != nil && l.Includes(feature) {
		return nil
	}
	return core.LockedError(feature, m.Tier())
}

func (m *Module) Limit(name string) int {
	if l := m.current(); l != nil {
		return l.Limit(name)
	}
	return licensing.Limit(licensing.TierCommunity, name)
}

func (m *Module) Expired() bool {
	l := m.current()
	return l != nil && l.Expired(time.Now())
}

// ---------------------------------------------------------------- verify / store

func (m *Module) verify(token string) (*licensing.License, error) {
	if m.pub == nil {
		return nil, errors.New("this build carries no license public key and cannot verify licenses")
	}
	l, err := licensing.Parse(token, m.pub)
	if err != nil {
		return nil, err
	}
	if l.Installation != "" && l.Installation != m.installation {
		return nil, fmt.Errorf("this license was issued for installation %s, not this one (%s)", l.Installation, m.installation)
	}
	return l, nil
}

func (m *Module) store(l *licensing.License, token, key, source string) {
	m.mu.Lock()
	m.lic, m.token, m.key = l, token, key
	m.st.LastError, m.st.Revoked, m.st.Source = "", "", source
	m.st.LastRefresh = time.Now().Unix()
	st := m.st
	m.mu.Unlock()
	_ = m.ctx.Store.KVSet(kvToken, token)
	_ = m.ctx.Store.KVSet(kvKey, key)
	_ = m.ctx.Store.KVSet(kvState, st)
}

func (m *Module) clear(reason string) {
	m.mu.Lock()
	m.lic, m.token, m.key = nil, "", ""
	m.st.Revoked = reason
	m.st.LastError = ""
	st := m.st
	m.mu.Unlock()
	_ = m.ctx.Store.KVSet(kvToken, "")
	_ = m.ctx.Store.KVSet(kvKey, "")
	_ = m.ctx.Store.KVSet(kvState, st)
}

func (m *Module) setErr(s string) {
	m.mu.Lock()
	m.st.LastError = s
	st := m.st
	m.mu.Unlock()
	_ = m.ctx.Store.KVSet(kvState, st)
}

// ---------------------------------------------------------------- server protocol

type serverReply struct {
	Token string `json:"token"`
	Error string `json:"error"`
	Code  string `json:"code"` // revoked | unknown | seats | expired
}

var errWithdrawn = errors.New("withdrawn")

// call posts to the license server. A 403 with code revoked/unknown means the
// license is gone and returns errWithdrawn (wrapped with the reason); any
// other failure is transient and leaves the current license alone.
func (m *Module) call(path, key string) (string, error) {
	base := strings.TrimRight(core.Str(m.ctx.Settings(), "server_url", defaultServer), "/")
	if base == "" {
		return "", errors.New("no license server configured")
	}
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]any{
		"product": "flowsight", "key": key, "installation": m.installation,
		"hostname": host, "version": m.ctx.Core.Version,
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
	})
	req, err := http.NewRequest("POST", base+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "flowsightd/"+m.ctx.Core.Version)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("license server unreachable: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var rep serverReply
	_ = json.Unmarshal(raw, &rep)
	switch {
	case resp.StatusCode == 200 && rep.Token != "":
		return rep.Token, nil
	case resp.StatusCode == 403 && (rep.Code == "revoked" || rep.Code == "unknown"):
		return "", fmt.Errorf("%w: %s", errWithdrawn, rep.Error)
	case rep.Error != "":
		return "", fmt.Errorf("license server: %s", rep.Error)
	default:
		return "", fmt.Errorf("license server answered HTTP %d", resp.StatusCode)
	}
}

func (m *Module) activate(key string) (*licensing.License, error) {
	key = licensing.NormalizeKey(key)
	if key == "" {
		return nil, core.BadRequest("enter an activation key")
	}
	if m.pub == nil {
		return nil, core.Errorf(500, "this build carries no license public key and cannot verify licenses")
	}
	token, err := m.call("/v1/activate", key)
	if err != nil {
		if errors.Is(err, errWithdrawn) {
			return nil, core.Forbidden("%s", strings.TrimPrefix(err.Error(), errWithdrawn.Error()+": "))
		}
		return nil, core.Errorf(502, "%v", err)
	}
	l, err := m.verify(token)
	if err != nil {
		return nil, core.Errorf(502, "the server sent a license that does not verify: %v", err)
	}
	m.store(l, token, key, "online")
	m.ctx.Event("license", "license activated", map[string]any{"tier": l.Tier, "licensee": l.Licensee, "expires": l.Expires})
	return l, nil
}

func (m *Module) refresh() error {
	m.mu.RLock()
	key, lic := m.key, m.lic
	m.mu.RUnlock()
	if key == "" || lic == nil {
		return nil // offline license or nothing to refresh
	}
	token, err := m.call("/v1/refresh", key)
	if err != nil {
		if errors.Is(err, errWithdrawn) {
			reason := strings.TrimPrefix(err.Error(), errWithdrawn.Error()+": ")
			m.clear(reason)
			m.ctx.Event("license", "license withdrawn by the server; running Community", map[string]any{"reason": reason})
			return nil
		}
		// Transient: keep what we have, say so.
		m.setErr(err.Error())
		return nil
	}
	l, err := m.verify(token)
	if err != nil {
		m.setErr("refresh returned a license that does not verify: " + err.Error())
		return nil
	}
	m.store(l, token, key, "online")
	return nil
}

func (m *Module) refreshJob() error {
	m.mu.RLock()
	lic := m.lic
	m.mu.RUnlock()
	if lic == nil || !lic.NeedsRefresh(time.Now()) {
		return nil
	}
	return m.refresh()
}

// ---------------------------------------------------------------- API

func (m *Module) status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := map[string]any{
		"tier":         m.Tier(),
		"installation": m.installation,
		"verifiable":   m.pub != nil,
		"server_url":   core.Str(m.ctx.Settings(), "server_url", defaultServer),
		"tiers":        licensing.Tiers(),
		"last_error":   m.st.LastError,
		"revoked":      m.st.Revoked,
		"source":       m.st.Source,
		"last_refresh": m.st.LastRefresh,
	}
	limits := map[string]int{}
	for _, n := range licensing.LimitNames() {
		limits[n] = m.Limit(n)
	}
	out["limits"] = limits
	if m.lic != nil {
		out["license"] = m.lic
		out["expired"] = m.lic.Expired(now)
		out["days_left"] = m.lic.DaysLeft(now)
		out["needs_refresh"] = m.lic.NeedsRefresh(now)
		out["key_hint"] = keyHint(m.key)
	}
	return out
}

func keyHint(k string) string {
	if len(k) < 4 {
		return ""
	}
	return "…" + k[len(k)-4:]
}

func (m *Module) apiStatus(r *core.Req) (any, error) { return m.status(), nil }

func (m *Module) apiFeatures(r *core.Req) (any, error) {
	type row struct {
		licensing.Feature
		Included bool `json:"included"`
	}
	var rows []row
	for _, f := range licensing.Features {
		rows = append(rows, row{Feature: f, Included: m.Allowed(f.Key) == nil})
	}
	tiers := map[string]map[string]int{}
	for _, t := range licensing.Tiers() {
		tiers[t] = licensing.Limits(t)
	}
	return map[string]any{"features": rows, "tier": m.Tier(), "limits_by_tier": tiers}, nil
}

func (m *Module) apiActivate(r *core.Req) (any, error) {
	key, _ := r.Body()["key"].(string)
	l, err := m.activate(key)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "tier": l.Tier, "licensee": l.Licensee, "expires": l.Expires, "status": m.status()}, nil
}

func (m *Module) apiInstall(r *core.Req) (any, error) {
	token, _ := r.Body()["token"].(string)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, core.BadRequest("paste the license file contents")
	}
	l, err := m.verify(token)
	if err != nil {
		return nil, core.BadRequest("%v", err)
	}
	// An offline document carries no refresh time and needs no key.
	m.store(l, token, "", "offline")
	m.ctx.Event("license", "license file installed", map[string]any{"tier": l.Tier, "licensee": l.Licensee, "expires": l.Expires})
	return map[string]any{"ok": true, "tier": l.Tier, "licensee": l.Licensee, "expires": l.Expires, "status": m.status()}, nil
}

func (m *Module) apiRefresh(r *core.Req) (any, error) {
	m.mu.RLock()
	key := m.key
	m.mu.RUnlock()
	if key == "" {
		return nil, core.BadRequest("this license was installed from a file; there is nothing to refresh")
	}
	if err := m.refresh(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "status": m.status()}, nil
}

func (m *Module) apiRemove(r *core.Req) (any, error) {
	m.mu.RLock()
	key := m.key
	m.mu.RUnlock()
	if key != "" {
		// Free the seat; a failure here is not fatal.
		if _, err := m.call("/v1/deactivate", key); err != nil && !errors.Is(err, errWithdrawn) {
			m.ctx.Log.Warn("deactivate", "error", err)
		}
	}
	m.clear("")
	m.ctx.Event("license", "license removed; running Community", nil)
	return map[string]any{"ok": true, "status": m.status()}, nil
}
