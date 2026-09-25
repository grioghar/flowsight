package proxmox

import (
	"testing"
)

func TestIntFromQ(t *testing.T) {
	tests := []struct {
		input    string
		def      int
		expected int
	}{
		{"24", 10, 24},
		{"", 10, 10},
		{"invalid", 10, 10},
		{"0", 10, 0},
		{"168", 10, 168},
	}

	for _, tt := range tests {
		result := intFromQ(tt.input, tt.def)
		if result != tt.expected {
			t.Errorf("intFromQ(%q, %d) = %d, expected %d", tt.input, tt.def, result, tt.expected)
		}
	}
}

func TestDedupeRelations(t *testing.T) {
	guestByVMID := map[int]*Guest{
		1: &Guest{VMID: 1, Name: "vm1"},
		2: &Guest{VMID: 2, Name: "vm2"},
	}

	relations := []DependencyRelation{
		{VMID: 2, Port: 443, Proto: "tcp", Source: "observed"},
		{VMID: 2, Port: 443, Proto: "tcp", Source: "observed"},
		{VMID: 1, Port: 80, Proto: "tcp", Source: "declared"},
	}

	result := dedupeRelations(relations, guestByVMID)

	// Should have 2 unique relations after deduplication
	if len(result) != 2 {
		t.Errorf("expected 2 deduped relations, got %d", len(result))
	}

	// Check that names are filled in
	for _, rel := range result {
		if rel.Name == "" {
			t.Errorf("expected name for VMID %d, got empty", rel.VMID)
		}
	}
}

func TestBuildRequirements(t *testing.T) {
	m := &Module{}

	guest := Guest{
		VMID:   102,
		Node:   "proxmox",
		Name:   "opnsense",
		Type:   "qemu",
		Cores:  4,
		Memory: 8192,
		Tags:   []string{"net", "spof"},
	}

	guestByVMID := map[int]*Guest{
		102: &guest,
	}

	edges := []Edge{
		{From: 102, To: 101, Port: 443, Proto: "tcp", Flows: 100, Bytes: 50000, Source: "observed"},
		{From: 100, To: 102, Port: 22, Proto: "tcp", Flows: 50, Bytes: 25000, Source: "observed"},
	}

	req := m.buildRequirements(&guest, guestByVMID, edges, 24)

	if req.VMID != 102 {
		t.Errorf("expected VMID 102, got %d", req.VMID)
	}
	if req.Cores != 4 {
		t.Errorf("expected 4 cores, got %d", req.Cores)
	}
	if len(req.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(req.Tags))
	}

	// Check edges
	if len(req.DependsOn) != 1 {
		t.Errorf("expected 1 depends_on edge, got %d", len(req.DependsOn))
	}
	if len(req.DependentOn) != 1 {
		t.Errorf("expected 1 dependent_on edge, got %d", len(req.DependentOn))
	}
}

func TestMapResponseStructure(t *testing.T) {
	// Test that MapResponse properly structures the data
	resp := &MapResponse{
		Guests:       []Guest{{VMID: 1, Name: "vm1"}},
		Edges:        []Edge{{From: 1, To: 2, Port: 443, Proto: "tcp"}},
		External:     []ExternalDep{{Guest: 1, Destination: "example.com", Bytes: 1000}},
		Requirements: map[string]Requirements{},
	}

	if len(resp.Guests) != 1 {
		t.Error("expected 1 guest in response")
	}
	if len(resp.Edges) != 1 {
		t.Error("expected 1 edge in response")
	}
	if len(resp.External) != 1 {
		t.Error("expected 1 external dep in response")
	}
}

func TestParseStartupOrder(t *testing.T) {
	tests := []struct {
		input       string
		expectOrder int
		expectUp    int
		expectDown  int
	}{
		{"order=1,up=10,down=5", 1, 10, 5},
		{"order=2", 2, 0, 0},
		{"up=20,order=3,down=10", 3, 20, 10},
		{"", 0, 0, 0},
	}

	for _, tt := range tests {
		order, up, down := parseStartupOrder(tt.input)
		if order != tt.expectOrder || up != tt.expectUp || down != tt.expectDown {
			t.Errorf("parseStartupOrder(%q) = (%d,%d,%d), expected (%d,%d,%d)",
				tt.input, order, up, down, tt.expectOrder, tt.expectUp, tt.expectDown)
		}
	}
}

func TestExtractStorageFromConfig(t *testing.T) {
	config := map[string]interface{}{
		"scsi0":  "local-lvm:vm-102-disk-1,discard=on,iothread=1,size=32G",
		"rootfs": "local-lvm:subvol-root,size=100G",
		"memory": 8192,
	}

	storage := extractStorageFromConfig(config)

	if len(storage) != 2 {
		t.Errorf("expected 2 storage mounts, got %d", len(storage))
	}
	if storage["scsi0"] != "local-lvm:vm-102-disk-1" {
		t.Errorf("expected scsi0 to map to local-lvm:vm-102-disk-1, got %q", storage["scsi0"])
	}
	if storage["rootfs"] != "local-lvm:subvol-root" {
		t.Errorf("expected rootfs to map to local-lvm:subvol-root, got %q", storage["rootfs"])
	}
}

func TestExtractBridgesFromConfig(t *testing.T) {
	config := map[string]interface{}{
		"net0": "virtio=BC:24:11:94:97:32,bridge=vmbr0,queues=4",
		"net1": "virtio=BC:24:11:23:0D:37,bridge=vmbr1,tag=100,queues=4",
	}

	bridges, vlans := extractBridgesFromConfig(config)

	if len(bridges) != 2 {
		t.Errorf("expected 2 bridges, got %d: %v", len(bridges), bridges)
	}
	if len(vlans) != 1 {
		t.Errorf("expected 1 VLAN, got %d: %v", len(vlans), vlans)
	}
	if vlans[0] != 100 {
		t.Errorf("expected VLAN 100, got %v", vlans)
	}
}
