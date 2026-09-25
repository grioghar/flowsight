package proxmox

import (
	"strings"
	"testing"
	"time"
)

func TestNotesBlockSaysWhatItKnowsAndHashesStably(t *testing.T) {
	f := notesFacts{Guest: Guest{VMID: 3140, Type: "lxc", Node: "proxmox", Name: "overpass", IPs: []string{"192.168.1.56"}, MACs: []string{"bc:24:11:da:5f:e5"}, AgentState: ""},
		Device: "overpass", Class: "server", Zone: "infra", Vendor: "Proxmox VE lxc on proxmox", BytesIn: 5 << 30, BytesOut: 1 << 20,
		OSGuess: "Linux or BSD host (SSH)", OSConf: 0.35, OpenPorts: []string{"22 ssh", "80 http"}, FirstSeen: 1790000000, LastSeen: 1790360000,
		GatewayURL: "https://gw.example", Now: time.Unix(1790364000, 0)}
	b := renderNotesBlock(f)
	for _, want := range []string{"<!-- flowsight:begin -->", "<!-- flowsight:end -->", "### FlowSight: overpass", "container 3140 on proxmox", "server / infra", "192.168.1.56", "5.0 GB down, 1.0 MB up", "22 ssh, 80 http", "Linux or BSD host (SSH) (35%)", "https://gw.example/flowsight.php?page=hosts#host/192.168.1.56", "_Updated "} {
		if !strings.Contains(b, want) {
			t.Fatalf("block lacks %q:\n%s", want, b)
		}
	}
	f2 := f
	f2.Now = f.Now.Add(time.Hour)
	if stripUpdatedLine(renderNotesBlock(f)) != stripUpdatedLine(renderNotesBlock(f2)) {
		t.Fatal("only the timestamp changed; the hashed content must be identical")
	}
	if got := splitTags("deprecated;no-backup;storage;tier-service"); len(got) != 4 || got[1] != "no-backup" {
		t.Fatalf("tags: %v", got)
	}
}
