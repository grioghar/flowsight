package enrich

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

// ctxWith builds a module context whose enrich settings are the ones given.
func ctxWith(t *testing.T, settings map[string]any) *core.Context {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "flowsight.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeclareModule("enrich", settings)
	return &core.Context{Name: "enrich", Config: cfg, Platform: &core.Platform{DataDir: dir}}
}

// The database path carries the detail level. Sharing one filename would let
// a country file already on disk stand in for the city one that was asked
// for, and the only symptom would be a map with nothing on it.
func TestDatabasePathAndURLFollowTheDetailLevel(t *testing.T) {
	mk := func(detail, url string) *Module {
		return &Module{ctx: ctxWith(t, map[string]any{"geoip_detail": detail, "geoip_url": url})}
	}
	country, city := mk("country", ""), mk("city", "")
	if country.dbPath() == city.dbPath() {
		t.Fatalf("country and city must not share a file: %s", country.dbPath())
	}
	if country.geoURL() != defaultGeoURL {
		t.Errorf("country should use the country file, got %s", country.geoURL())
	}
	if city.geoURL() != defaultGeoCityURL {
		t.Errorf("city should use the city file, got %s", city.geoURL())
	}
	// An explicit URL wins over both, so a licensed MaxMind file still works.
	custom := mk("city", "https://example.test/GeoLite2-City.mmdb")
	if custom.geoURL() != "https://example.test/GeoLite2-City.mmdb" {
		t.Errorf("a configured URL must win, got %s", custom.geoURL())
	}
	// Anything that is not "city" means country; no third behaviour.
	if mk("nonsense", "").detail() != "country" {
		t.Error("an unknown detail level must fall back to country")
	}
}
