package core

import "testing"

// KVCount answers "how much is known" under a prefix. It once read zero for
// every prefix because the LIKE escape reached SQLite as two characters and
// the error was discarded; -1 now says "could not count", which is not the
// same as none.
func TestKVCountCountsUnderAPrefixOnly(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, k := range []string{"paths.ipmap.1.1.1.1", "paths.ipmap.8.8.8.8", "paths.ipmap.2001:db8::1", "paths.detail.1.1.1.1", "other"} {
		if err := s.KVSet(k, map[string]any{"ok": true}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.KVCount("paths.ipmap."); n != 3 {
		t.Fatalf("want 3 under the prefix, got %d", n)
	}
	if n := s.KVCount("paths.detail."); n != 1 {
		t.Fatalf("want 1, got %d", n)
	}
	if n := s.KVCount("nothing."); n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
	// Wildcards in a prefix are literal, not patterns.
	if n := s.KVCount("paths.ipmap.%%"); n != 0 {
		t.Fatalf("a literal percent should match nothing, got %d", n)
	}
	if n := s.KVCount("paths_ipmap."); n != 0 {
		t.Fatalf("a literal underscore should not match a dot, got %d", n)
	}
}
