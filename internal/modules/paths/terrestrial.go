package paths

// Fibre on land, where anybody publishes it.
//
// A sea crossing has to follow a cable, so the cable's length is a genuine
// bound and raising the floor by it is sound. Land is not like that: a
// straight line between two cities is merely something nobody built, and
// treating unbuilt as impossible would convict placements of a crime they
// have not committed. So mapped land routes never touch the floor. What they
// do is sharpen the second question -- not what physics forbids, but what a
// route that exists could manage -- by replacing an estimated detour with a
// measured one.
//
// What is actually out there is thin. AfTerFibre covers Africa under a
// Creative Commons licence and is the one openly licensed long-haul dataset
// of any substance; the comprehensive maps of North America, Europe and Asia
// are commercial products, and OpenStreetMap's telecoms tagging is dense in a
// few well-mapped countries and absent elsewhere. Rather than pretend
// otherwise, this takes whatever sources are configured, uses them where they
// reach, and falls back to the detour estimate everywhere else. Adding a
// source later is a line of configuration, not a change of design.

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// defaultTerrestrialURLs are the openly licensed sets worth having. AfTerFibre
// is CC-BY: African terrestrial and undersea routes with the operator and the
// source recorded per route.
var defaultTerrestrialURLs = []string{
	"https://data.apps.fao.org/catalog/dataset/5358ddcc-4fd2-43c8-9557-b8ea2ac232f6/resource/79b92f44-6575-483c-a9d1-015d3bba7731/download/afterfibre_20200514.geojson",
}

func (m *Module) terrestrialDir() string {
	return filepath.Join(m.ctx.Platform.DataDir, "terrestrial")
}

// terrestrialURLs is what to fetch: whatever the operator listed, or the
// defaults. Blank lines and comments are allowed, as everywhere else a list
// is edited by hand.
func (m *Module) terrestrialURLs() []string {
	raw := strings.TrimSpace(core.Str(m.ctx.Settings(), "terrestrial_urls", ""))
	if raw == "" {
		return defaultTerrestrialURLs
	}
	var out []string
	for _, line := range core.StripComments(strings.Split(raw, "\n")) {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return defaultTerrestrialURLs
	}
	return out
}

// refreshTerrestrial keeps a local copy of each source, fetching one that is
// missing or a month old.
//
// A month is not caution, it is the truth about the subject: a long-haul
// route takes years to build and the datasets themselves are revised rarely
// -- the African one is dated 2020. Asking more often would spend somebody
// else's bandwidth to be told the same thing.
func (m *Module) refreshTerrestrial() error {
	if !core.Bool(m.ctx.Settings(), "terrestrial", false) {
		m.mu.Lock()
		m.landNets, m.landErr, m.landRoutes = nil, "", 0
		m.mu.Unlock()
		m.routes.reset()
		return nil
	}
	dir := m.terrestrialDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.mu.Lock()
		m.landErr = err.Error()
		m.mu.Unlock()
		return nil
	}

	var nets []cableNet
	var problems []string
	for i, url := range m.terrestrialURLs() {
		path := filepath.Join(dir, terrestrialFile(url, i))
		st, err := os.Stat(path)
		if err != nil || time.Since(st.ModTime()) > 30*24*time.Hour {
			if err := m.downloadTo(url, path); err != nil {
				problems = append(problems, shortHost(url)+": "+err.Error())
				// An old copy beats none; fall through and try to load it.
				if _, e := os.Stat(path); e != nil {
					continue
				}
			}
		}
		routes, err := loadCables(path)
		if err != nil {
			problems = append(problems, shortHost(url)+": "+err.Error())
			continue
		}
		for _, r := range routes {
			nets = append(nets, buildNet(r))
		}
	}

	m.mu.Lock()
	m.landNets, m.landRoutes = nets, len(nets)
	m.landErr = strings.Join(problems, "; ")
	m.mu.Unlock()
	m.routes.reset() // answers were for the old networks
	return nil
}

// terrestrialFile names the local copy after the source, so several sources
// can live side by side and a changed URL fetches rather than reuses.
func terrestrialFile(url string, i int) string {
	base := url
	if q := strings.IndexAny(base, "?#"); q >= 0 {
		base = base[:q]
	}
	base = filepath.Base(base)
	if base == "" || base == "." || base == "/" {
		base = "source"
	}
	if !strings.HasSuffix(base, ".json") && !strings.HasSuffix(base, ".geojson") {
		base += ".geojson"
	}
	return string(rune('a'+i%26)) + "-" + base
}

func shortHost(url string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	return s
}
