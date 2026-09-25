package proxmox

import (
	"encoding/json"
	"os"
	"testing"
)

// Proxmox 9 sends memory as a string; a strict int made the config
// unreadable and every VM came back without addresses.
func TestQEMUConfigFixtureParses(t *testing.T) {
	b, err := os.ReadFile("testdata/qemu_102_config.json")
	if err != nil {
		t.Skip("fixture missing")
	}
	var wrapped struct {
		Data json.RawMessage `json:"data"`
	}
	raw := b
	if json.Unmarshal(b, &wrapped) == nil && len(wrapped.Data) > 0 {
		raw = []byte(`{"data":` + string(wrapped.Data) + `}`)
	} else {
		raw = []byte(`{"data":` + string(b) + `}`)
	}
	var cfg pveQEMUConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config must parse: %v", err)
	}
	if cfg.Data.Memory.String() != "8192" || !agentEnabled(cfg.Data.Agent.String()) || cfg.Data.Cores != 4 {
		t.Fatalf("unexpected: %+v", cfg.Data)
	}
	for _, v := range []string{"1", "enabled=1,fstrim_cloned_disks=1", "1,type=virtio"} {
		if !agentEnabled(v) {
			t.Fatalf("%q should mean enabled", v)
		}
	}
	if agentEnabled("0") || agentEnabled("enabled=0") {
		t.Fatal("0 must mean disabled")
	}
}
