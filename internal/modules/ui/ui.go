// Package ui holds interface preferences that belong to the installation
// rather than to one browser: the colour theme for now. The front end reads
// them at start; nothing else in the daemon does.
package ui

import "github.com/grioghar/flowsight/internal/core"

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct{ ctx *core.Context }

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:        "ui",
		Version:     "1.0",
		Description: "Interface preferences: colour theme.",
		Defaults: map[string]any{
			"enabled": true,
			"theme":   "auto",
		},
		Schema: []core.SettingField{
			{Key: "theme", Label: "Theme", Type: "choice", Choices: []string{"auto", "light", "dark"},
				Help: "auto follows the OPNsense theme when FlowSight is shown inside the OPNsense GUI (light, dark, or the GUI's own automatic mode), and the operating system preference otherwise."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	ctx.Route("GET", "/api/ui/prefs", m.apiPrefs,
		core.Doc("Get user interface preferences and display settings applied at front-end startup"),
		core.Returns("UI preferences", map[string]any{
			"theme":    "auto",
			"language": "en",
		}))
	ctx.Panel(core.Panel{ID: "api", Title: "API", Group: "Administration", Order: 200, Icon: "api"})
	return nil
}

func (m *Module) apiPrefs(r *core.Req) (any, error) {
	theme := core.Str(m.ctx.Settings(), "theme", "auto")
	if theme != "light" && theme != "dark" {
		theme = "auto"
	}
	return map[string]any{"theme": theme}, nil
}
