package core

import (
	"reflect"
	"testing"
)

func TestStripComments(t *testing.T) {
	got := StripComments([]string{
		"chase.com",
		"# a bank we decided not to inspect",
		"  # indented comments count too",
		"1password.com",
		"// off for now, put back after the audit",
		"/* the whole holiday-let block",
		"airbnb.com",
		"vrbo.com",
		"   still inside the block */",
		"apple.com",
		"",
		"/* one-liner */",
		"/* closes and continues */ github.com",
	})
	want := []string{"chase.com", "1password.com", "apple.com", "github.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// Entries in these lists are addresses, domains and feed URLs, and every URL
// contains "//" in the middle of it. Treating that as a comment would quietly
// delete half the list, so only a marker at the start of a line counts.
func TestStripCommentsLeavesURLsAlone(t *testing.T) {
	in := []string{
		"https://example.com/lists/ads.txt",
		"http://feeds.example.org/block#section",
		"192.168.1.0/24",
	}
	got := StripComments(in)
	if !reflect.DeepEqual(got, in) {
		t.Errorf("a marker inside a line must not comment it out:\ngot  %q\nwant %q", got, in)
	}
}

// An unterminated block comments out everything after it rather than
// silently reverting to live entries, which is the safer way to be wrong.
func TestUnterminatedBlockSwallowsTheRest(t *testing.T) {
	got := StripComments([]string{"keep.example", "/* oops, never closed", "gone.example", "also.gone"})
	want := []string{"keep.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestStrsStripsComments(t *testing.T) {
	m := map[string]any{"rules": []any{"a.example", "# off", "b.example"}}
	if got := Strs(m, "rules"); !reflect.DeepEqual(got, []string{"a.example", "b.example"}) {
		t.Errorf("list settings must strip comments, got %q", got)
	}
}
