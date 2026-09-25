package updater

import "testing"

func TestManifestURLAllowed(t *testing.T) {
	for _, ok := range []string{"https://github.com/x/releases/latest/download/manifest.json", "http://192.168.1.119:877/dist/v/manifest.json", "http://127.0.0.1:8000/m.json", "http://localhost/m.json", "http://10.0.0.5/m.json"} {
		if err := manifestURLAllowed(ok); err != nil {
			t.Fatalf("%s should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/manifest.json", "http://8.8.8.8/m.json", "ftp://x/y", "not a url", ""} {
		if err := manifestURLAllowed(bad); err == nil {
			t.Fatalf("%q should be refused", bad)
		}
	}
}
