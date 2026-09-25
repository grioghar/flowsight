package proxmox

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExtractMACs(t *testing.T) {
	m := &Module{}

	tests := []struct {
		name     string
		config   map[string]interface{}
		expected int
	}{
		{
			name: "single MAC",
			config: map[string]interface{}{
				"net0": "virtio=BC:24:11:94:97:32,bridge=vmbr0",
			},
			expected: 1,
		},
		{
			name: "multiple MACs",
			config: map[string]interface{}{
				"net0": "virtio=BC:24:11:94:97:32,bridge=vmbr0",
				"net1": "virtio=BC:24:11:23:0D:37,bridge=vmbr1",
			},
			expected: 2,
		},
		{
			name: "no MACs",
			config: map[string]interface{}{
				"memory": 4096,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			macs := m.extractMACs(tt.config)
			if len(macs) != tt.expected {
				t.Errorf("expected %d MACs, got %d", tt.expected, len(macs))
			}
		})
	}
}

func TestParseQEMUConfigRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/qemu_102_config.json")
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	// Check basic fields
	if agent, ok := config["agent"].(string); !ok || agent != "1" {
		t.Error("expected agent=1")
	}
	if cores, ok := config["cores"].(float64); !ok || cores != 4 {
		t.Error("expected 4 cores")
	}

	// Test MAC extraction
	m := &Module{}
	macs := m.extractMACs(config)
	if len(macs) != 2 {
		t.Errorf("expected 2 MACs, got %d: %v", len(macs), macs)
	}
}

func TestParseAgentNetworkRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/qemu_102_agent_network.json")
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	var agentNet pveAgentNetworkResp
	if err := json.Unmarshal(data, &agentNet); err != nil {
		t.Fatalf("failed to parse agent network: %v", err)
	}

	if len(agentNet.Result) == 0 {
		t.Fatal("expected agent network interfaces, got none")
	}

	// Count non-loopback MACs
	var validMACs []string
	for _, iface := range agentNet.Result {
		if iface.HardwareAddress != "" && iface.HardwareAddress != "00:00:00:00:00:00" {
			validMACs = append(validMACs, iface.HardwareAddress)
		}
	}

	if len(validMACs) < 2 {
		t.Errorf("expected at least 2 valid MACs, got %d", len(validMACs))
	}
}

func TestParseAgentHostnameRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/qemu_102_agent_hostname.json")
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	var hostname pveAgentHostname
	if err := json.Unmarshal(data, &hostname); err != nil {
		t.Fatalf("failed to parse hostname: %v", err)
	}

	if hostname.Result.HostName == "" {
		t.Error("expected hostname, got empty string")
	}
	if !strings.Contains(hostname.Result.HostName, "OPNsense") {
		t.Errorf("expected OPNsense in hostname, got %q", hostname.Result.HostName)
	}
}

func TestParseAgentOSInfoRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/qemu_102_agent_osinfo.json")
	if err != nil {
		t.Fatalf("failed to read testdata: %v", err)
	}

	var osinfo pveAgentOSInfo
	if err := json.Unmarshal(data, &osinfo); err != nil {
		t.Fatalf("failed to parse osinfo: %v", err)
	}

	if osinfo.Result.KernelRelease == "" {
		t.Error("expected kernel release")
	}
	if !strings.Contains(osinfo.Result.KernelRelease, "RELEASE") {
		t.Errorf("expected RELEASE in kernel, got %q", osinfo.Result.KernelRelease)
	}
}

func TestMergeNotesBlock(t *testing.T) {
	m := &Module{}

	tests := []struct {
		name        string
		currentDesc string
		newBlock    string
		expected    string
	}{
		{
			name:        "no existing block",
			currentDesc: "Old description",
			newBlock:    "<!-- flowsight:begin -->\nNew block\n<!-- flowsight:end -->",
			expected:    "Old description\n\n<!-- flowsight:begin -->\nNew block\n<!-- flowsight:end -->",
		},
		{
			name:        "replace existing block",
			currentDesc: "Old text\n<!-- flowsight:begin -->\nOld block\n<!-- flowsight:end -->\nMore text",
			newBlock:    "<!-- flowsight:begin -->\nNew block\n<!-- flowsight:end -->",
			expected:    "Old text\n<!-- flowsight:begin -->\nNew block\n<!-- flowsight:end -->\nMore text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.mergeNotesBlock(tt.currentDesc, tt.newBlock)
			if result != tt.expected {
				t.Errorf("expected:\n%q\ngot:\n%q", tt.expected, result)
			}
		})
	}
}

func TestBuildNotesBlock(t *testing.T) {
	m := &Module{}

	guest := Guest{
		Name:       "test-vm",
		Type:       "qemu",
		Node:       "proxmox",
		IPs:        []string{"192.168.1.10", "2600::1"},
		Hostname:   "test.local",
		OS:         "Ubuntu 22.04",
		AgentState: "responding",
	}

	block := m.buildNotesBlock(guest)

	if !strings.Contains(block, "<!-- flowsight:begin -->") {
		t.Error("missing begin marker")
	}
	if !strings.Contains(block, "<!-- flowsight:end -->") {
		t.Error("missing end marker")
	}
	if !strings.Contains(block, "test-vm") {
		t.Error("missing guest name")
	}
}
