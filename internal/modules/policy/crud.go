package policy

import (
	"github.com/grioghar/flowsight/internal/core"
)

// ================================================================ CRUD routes

// GROUPS

func (m *Module) apiGetGroups(r *core.Req) (any, error) {
	doc := m.Doc()
	groups := make([]map[string]any, 0, len(doc.Groups))
	for name, g := range doc.Groups {
		groups = append(groups, map[string]any{
			"name":  name,
			"group": g,
		})
	}
	return map[string]any{"groups": groups}, nil
}

func (m *Module) apiGetGroup(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	doc := m.Doc()
	g, ok := doc.Groups[name]
	if !ok {
		return nil, core.NotFound("no group named %q", name)
	}
	return map[string]any{"name": name, "group": g}, nil
}

func (m *Module) apiUpdateGroup(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	var in struct {
		Group core.Group `json:"group"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	doc.Groups[name] = in.Group
	return map[string]any{"ok": true}, m.save(doc, r.User, "group "+name+" updated")
}

func (m *Module) apiDeleteGroupByName(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	doc := m.Doc()
	if _, ok := doc.Groups[name]; !ok {
		return nil, core.NotFound("no group named %q", name)
	}
	for _, p := range doc.Policies {
		for _, g := range p.Match.Groups {
			if g == name {
				return nil, core.BadRequest("group %q is used by policy %q", name, p.Name)
			}
		}
	}
	delete(doc.Groups, name)
	return map[string]any{"ok": true}, m.save(doc, r.User, "group "+name+" deleted")
}

// SCHEDULES

func (m *Module) apiGetSchedules(r *core.Req) (any, error) {
	doc := m.Doc()
	schedules := make([]map[string]any, 0, len(doc.Schedules))
	for name, s := range doc.Schedules {
		schedules = append(schedules, map[string]any{
			"name":     name,
			"schedule": s,
		})
	}
	return map[string]any{"schedules": schedules}, nil
}

func (m *Module) apiGetSchedule(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	doc := m.Doc()
	s, ok := doc.Schedules[name]
	if !ok {
		return nil, core.NotFound("no schedule named %q", name)
	}
	return map[string]any{"name": name, "schedule": s}, nil
}

func (m *Module) apiUpdateSchedule(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	var in struct {
		Schedule core.Schedule `json:"schedule"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	doc := m.Doc()
	doc.Schedules[name] = in.Schedule
	return map[string]any{"ok": true}, m.save(doc, r.User, "schedule "+name+" updated")
}

func (m *Module) apiDeleteScheduleByName(r *core.Req) (any, error) {
	name := r.Params["name"]
	if name == "" {
		return nil, core.BadRequest("name is required")
	}
	doc := m.Doc()
	if _, ok := doc.Schedules[name]; !ok {
		return nil, core.NotFound("no schedule named %q", name)
	}
	for _, p := range doc.Policies {
		if p.Schedule == name {
			return nil, core.BadRequest("schedule %q is used by policy %q", name, p.Name)
		}
	}
	delete(doc.Schedules, name)
	return map[string]any{"ok": true}, m.save(doc, r.User, "schedule "+name+" deleted")
}
