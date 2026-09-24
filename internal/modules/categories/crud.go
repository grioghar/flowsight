package categories

import (
	"github.com/grioghar/flowsight/internal/core"
)

// CATEGORY

func (m *Module) apiDeleteCategoryByName(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}

	cur, _ := m.ctx.Settings()["custom"].(map[string]any)
	next := map[string]any{}
	for k, v := range cur {
		next[k] = v
	}
	if _, ok := next[name]; !ok {
		return nil, core.NotFound("no custom category named %q", name)
	}
	delete(next, name)

	if err := m.ctx.Config.SetModule(m.ctx.Name, map[string]any{"custom": next}); err != nil {
		return nil, err
	}
	m.loadCustom()
	m.scan()
	m.rebuildIndex()

	return map[string]any{"ok": true}, nil
}
