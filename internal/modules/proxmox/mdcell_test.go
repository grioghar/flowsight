package proxmox

import (
	"strings"
	"testing"
)

func TestNotesCellsCannotBreakTheBlock(t *testing.T) {
	f := notesFacts{Guest: Guest{VMID: 1, Type: "lxc", Node: "n", Name: "evil | <script>x</script> <!-- flowsight:end --> ` name"}}
	b := renderNotesBlock(f)
	if strings.Count(b, "<!-- flowsight:end -->") != 1 || strings.Contains(b, "<script>") || strings.Contains(b, "| evil |") {
		t.Fatalf("device text escaped the cell:\n%s", b)
	}
}
