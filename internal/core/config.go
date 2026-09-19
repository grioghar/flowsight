package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Config is the operator's single JSON document plus per-module defaults.
//
// The file holds only what the operator changed; defaults are merged at load
// time, so a fresh install has every key and an upgrade that adds a key needs
// no migration. Module settings live under "modules.<name>".
type Config struct {
	Path string

	mu       sync.RWMutex
	user     map[string]any            // exactly what is on disk
	defaults map[string]map[string]any // module name -> defaults
	core     CoreSettings
}

// CoreSettings are the keys the daemon itself reads. They are never settable
// through the API: whoever can change where the daemon listens or what it
// executes is root, so those are changed in the file, by root.
type CoreSettings struct {
	SiteName string `json:"site_name"`
	Bind     string `json:"bind"`
	Port     int    `json:"port"`
	APIToken string `json:"api_token"`
	LogLevel string `json:"log_level"`
	DataDir  string `json:"data_dir"`
	Workers  int    `json:"workers"`
	// MemoryLimitMB is the Go soft memory limit (default 256).
	MemoryLimitMB int       `json:"memory_limit_mb"`
	Retention     Retention `json:"retention"`
	// Overrides for platform paths, applied on top of detection.
	Paths map[string]any `json:"paths"`
}

type Retention struct {
	FlowsDays  int `json:"flows_days"`
	DNSDays    int `json:"dns_days"`
	AlertsDays int `json:"alerts_days"`
	EventsDays int `json:"events_days"`
	RollupDays int `json:"rollup_days"`
	TLSDays    int `json:"tls_days"`
}

func defaultCore() CoreSettings {
	return CoreSettings{
		Bind: "127.0.0.1", Port: 8080, LogLevel: "info", Workers: 4,
		Retention: Retention{FlowsDays: 7, DNSDays: 7, AlertsDays: 30, EventsDays: 30,
			RollupDays: 400, TLSDays: 90},
	}
}

// LoadConfig reads the document at path (missing is fine: all defaults).
func LoadConfig(path string) (*Config, error) {
	c := &Config{Path: path, user: map[string]any{}, defaults: map[string]map[string]any{}}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Reload() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	user := map[string]any{}
	data, err := os.ReadFile(c.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return err
	case len(data) > 0:
		if err := json.Unmarshal(data, &user); err != nil {
			return fmt.Errorf("%s: %w", c.Path, err)
		}
	}
	c.user = user
	core := defaultCore()
	// Re-marshal the top level (without modules) into the typed struct.
	top := map[string]any{}
	for k, v := range user {
		if k != "modules" {
			top[k] = v
		}
	}
	b, _ := json.Marshal(top)
	if err := json.Unmarshal(b, &core); err != nil {
		return fmt.Errorf("%s: %w", c.Path, err)
	}
	c.core = core
	return nil
}

func (c *Config) Core() CoreSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.core
}

// DeclareModule registers a module's defaults so Module() can merge them.
func (c *Config) DeclareModule(name string, defaults map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := map[string]any{"enabled": true}
	for k, v := range defaults {
		d[k] = v
	}
	c.defaults[name] = d
}

// Module returns the merged settings for one module.
func (c *Config) Module(name string) map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]any{}
	for k, v := range c.defaults[name] {
		out[k] = v
	}
	if mods, ok := c.user["modules"].(map[string]any); ok {
		if m, ok := mods[name].(map[string]any); ok {
			for k, v := range m {
				out[k] = v
			}
		}
	}
	if _, ok := out["enabled"]; !ok {
		out["enabled"] = true
	}
	return out
}

// Settings decodes one module's merged settings into a typed struct.
func (c *Config) Settings(name string, into any) error {
	b, _ := json.Marshal(c.Module(name))
	return json.Unmarshal(b, into)
}

// SetModule replaces the operator's overrides for a module and writes the file.
func (c *Config) SetModule(name string, values map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	mods, _ := c.user["modules"].(map[string]any)
	if mods == nil {
		mods = map[string]any{}
	}
	cur, _ := mods[name].(map[string]any)
	if cur == nil {
		cur = map[string]any{}
	}
	for k, v := range values {
		cur[k] = v
	}
	mods[name] = cur
	c.user["modules"] = mods
	return c.saveLocked()
}

// SetCore writes one top-level key (used by install/setup, never by the API).
func (c *Config) SetCore(key string, value any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.user[key] = value
	if err := c.saveLocked(); err != nil {
		return err
	}
	c.mu.Unlock()
	err := c.Reload()
	c.mu.Lock()
	return err
}

func (c *Config) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c.user, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

// Helpers for module code reading loosely typed settings.

func Str(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

func Int(m map[string]any, key string, def int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
	}
	return def
}

func Bool(m map[string]any, key string, def bool) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return def
}

func Strs(m map[string]any, key string) []string {
	var out []string
	switch v := m[key].(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = v
	}
	return out
}
