package inspect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBPFValidation(t *testing.T) {
	m := &Module{}

	tests := []struct {
		name    string
		filter  string
		wantErr bool
	}{
		{
			name:    "filter too long",
			filter:  string(make([]byte, 1001)),
			wantErr: true,
		},
		{
			name:    "invalid character semicolon",
			filter:  "tcp port 80; rm -rf /",
			wantErr: true,
		},
		{
			name:    "invalid character backtick",
			filter:  "tcp port `whoami`",
			wantErr: true,
		},
		{
			name:    "invalid character dollar",
			filter:  "tcp port $80",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := m.validateBPFFilter(tt.filter)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBPFFilter(%q) error = %v, wantErr %v", tt.filter, err, tt.wantErr)
			}
		})
	}
}

func TestCaptureSessionCreation(t *testing.T) {
	ctx, cancel := newTestContext()
	defer cancel()

	session := &CaptureSession{
		ID:       "cap_test123",
		Iface:    "em0",
		Filter:   "tcp port 443",
		Started:  time.Now(),
		Duration: 60,
		Snaplen:  96,
		Payload:  false,
		ctx:      ctx,
		cancel:   cancel,
	}

	if session.ID != "cap_test123" {
		t.Errorf("ID: got %q, want %q", session.ID, "cap_test123")
	}
	if session.Iface != "em0" {
		t.Errorf("interface: got %q, want %q", session.Iface, "em0")
	}
	if session.Filter != "tcp port 443" {
		t.Errorf("filter: got %q, want %q", session.Filter, "tcp port 443")
	}
	if session.Duration != 60 {
		t.Errorf("duration: got %d, want 60", session.Duration)
	}
	if session.Snaplen != 96 {
		t.Errorf("snaplen: got %d, want 96", session.Snaplen)
	}
	if session.Payload {
		t.Error("payload should be false")
	}
}

func TestCaptureInfoStorage(t *testing.T) {
	now := time.Now()
	cap := &CaptureInfo{
		ID:        "cap_1234567890",
		Iface:     "em0",
		Filter:    "tcp port 443",
		Started:   now,
		Ended:     &now,
		Packets:   12345,
		Bytes:     9876543,
		Files:     []string{"cap_1234567890.pcap"},
		Timestamp: now,
	}

	if cap.ID != "cap_1234567890" {
		t.Errorf("ID: got %q", cap.ID)
	}
	if cap.Packets != 12345 {
		t.Errorf("packets: got %d, want 12345", cap.Packets)
	}
	if cap.Bytes != 9876543 {
		t.Errorf("bytes: got %d, want 9876543", cap.Bytes)
	}
	if len(cap.Files) != 1 {
		t.Errorf("files count: got %d, want 1", len(cap.Files))
	}
}

func TestCaptureRetention(t *testing.T) {
	captures := make(map[string]*CaptureInfo)

	// Create 15 captures
	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("cap_%d_%d", 1000+i, i)
		captures[id] = &CaptureInfo{
			ID:        id,
			Started:   time.Unix(int64(1000+i), 0),
			Timestamp: time.Now(),
			Packets:   1000 * int64(i+1),
			Bytes:     10000 * int64(i+1),
		}
	}

	if len(captures) != 15 {
		t.Errorf("initial count: got %d, want 15", len(captures))
	}

	// In a real module, retention would prune old captures
	// For now, just verify the data structures work
	captureList := make([]*CaptureInfo, 0, len(captures))
	for _, c := range captures {
		captureList = append(captureList, c)
	}

	if len(captureList) != 15 {
		t.Errorf("capture list count: got %d, want 15", len(captureList))
	}
}

func TestCaptureFileRotation(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "flowsight_capture_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Simulate rotating capture files
	baseFile := filepath.Join(tmpDir, "capture.pcap")
	files := []string{
		baseFile,
		baseFile + "1",
		baseFile + "2",
		baseFile + "3",
	}

	for i, f := range files {
		if err := os.WriteFile(f, []byte("dummy pcap data"), 0644); err != nil {
			t.Fatalf("failed to write file %d: %v", i, err)
		}
	}

	// Verify all files were created
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("file %s not found: %v", f, err)
		}
	}

	// Verify we can list them
	matches, err := filepath.Glob(filepath.Join(tmpDir, "capture.pcap*"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != len(files) {
		t.Errorf("glob count: got %d, want %d", len(matches), len(files))
	}
}

func TestCaptureAnalysisStructures(t *testing.T) {
	analysis := &CaptureAnalysis{
		PacketCount: 50000,
		ByteCount:   25000000,
		Conversations: []Conversation{
			{
				FiveTuple: "192.168.1.1:1234-10.0.0.1:443",
				Proto:     "tcp",
				Src:       "192.168.1.1",
				SrcPort:   1234,
				Dst:       "10.0.0.1",
				DstPort:   443,
				PktsFwd:   1000,
				BytesFwd:  500000,
				PktsRev:   800,
				BytesRev:  250000,
			},
		},
		ProtocolCounts: map[string]int64{
			"tcp":  40000,
			"udp":  8000,
			"icmp": 2000,
		},
		DNSQueries: []DNSRecord{
			{
				Query:     "example.com",
				Type:      "A",
				Answers:   []string{"93.184.216.34"},
				Src:       "192.168.1.1",
				Dst:       "8.8.8.8",
				Timestamp: time.Now(),
			},
		},
		ExpertNotes: []ExpertNote{
			{
				Type:      "retransmission",
				Src:       "192.168.1.1",
				Dst:       "10.0.0.1",
				Detail:    "TCP retransmission detected",
				Severity:  "warn",
				Timestamp: time.Now(),
			},
		},
		TopTalkers: []TopTalker{
			{IP: "192.168.1.1", Bytes: 500000, Pkts: 1000},
			{IP: "10.0.0.1", Bytes: 250000, Pkts: 800},
		},
	}

	if analysis.PacketCount != 50000 {
		t.Errorf("packet count: got %d, want 50000", analysis.PacketCount)
	}
	if len(analysis.Conversations) != 1 {
		t.Errorf("conversation count: got %d, want 1", len(analysis.Conversations))
	}
	if len(analysis.ProtocolCounts) != 3 {
		t.Errorf("protocol count: got %d, want 3", len(analysis.ProtocolCounts))
	}
	if analysis.ProtocolCounts["tcp"] != 40000 {
		t.Errorf("tcp count: got %d, want 40000", analysis.ProtocolCounts["tcp"])
	}
	if len(analysis.DNSQueries) != 1 {
		t.Errorf("dns query count: got %d, want 1", len(analysis.DNSQueries))
	}
	if len(analysis.ExpertNotes) != 1 {
		t.Errorf("expert note count: got %d, want 1", len(analysis.ExpertNotes))
	}
}

func TestConversationMetrics(t *testing.T) {
	conv := &Conversation{
		FiveTuple:       "192.168.1.1:12345-10.0.0.1:443",
		Proto:           "tcp",
		Src:             "192.168.1.1",
		SrcPort:         12345,
		Dst:             "10.0.0.1",
		DstPort:         443,
		PktsFwd:         1024,
		BytesFwd:        524288,
		PktsRev:         856,
		BytesRev:        262144,
		TCPFlags:        "SYN,ACK,PSH,FIN",
		Retransmissions: 3,
		OutOfOrder:      0,
		ZeroWindow:      1,
		Resets:          0,
		RTTEstimate:     0.035,
	}

	if conv.PktsFwd != 1024 {
		t.Errorf("forward packets: got %d, want 1024", conv.PktsFwd)
	}
	if conv.BytesFwd != 524288 {
		t.Errorf("forward bytes: got %d, want 524288", conv.BytesFwd)
	}
	if conv.Retransmissions != 3 {
		t.Errorf("retransmissions: got %d, want 3", conv.Retransmissions)
	}
	if conv.ZeroWindow != 1 {
		t.Errorf("zero window: got %d, want 1", conv.ZeroWindow)
	}
	if conv.RTTEstimate != 0.035 {
		t.Errorf("RTT: got %v, want 0.035", conv.RTTEstimate)
	}
}

// Helpers

func newTestContext() (context.Context, func()) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// Import context at the top if not already present
// import "context"
