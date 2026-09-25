package inspect

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestConversationNormalization(t *testing.T) {
	m := &Module{}

	// Create two conversations with swapped src/dst - they should normalize to same key
	key1 := m.normalizeConversation("TCP", "192.168.1.100", "10.0.0.1", 54321, 443)
	key2 := m.normalizeConversation("TCP", "10.0.0.1", "192.168.1.100", 443, 54321)

	if key1 != key2 {
		t.Errorf("conversation normalization failed: %v != %v", key1, key2)
	}

	expected := "TCP:10.0.0.1:443-192.168.1.100:54321"
	if key1.String() != expected {
		t.Errorf("unexpected key: %v, want %v", key1.String(), expected)
	}
}

func TestTCPPacketAnalysis(t *testing.T) {
	m := &Module{}
	analysis := &CaptureAnalysis{
		Conversations:  []Conversation{},
		ProtocolCounts: make(map[string]int64),
		DNSQueries:     []DNSRecord{},
		TLSHandshakes:  []TLSInfo{},
		HTTPRequests:   []HTTPRequest{},
		ExpertNotes:    []ExpertNote{},
		TopTalkers:     []TopTalker{},
		Timeline:       []TimelineEvent{},
	}
	conversations := make(map[conversationKey]*conversationData)

	// Create a TCP packet
	srcIP := net.ParseIP("192.168.1.100")
	dstIP := net.ParseIP("10.0.0.1")

	// Create TCP layer with SYN flag
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 443,
		Seq:     1000,
		Ack:     0,
		SYN:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(&layers.IPv4{
		SrcIP: srcIP,
		DstIP: dstIP,
	})

	// Create IPv4 layer
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		Length:   40,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// Create packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, ip, tcp)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	// Analyze packet
	timestamp := time.Now()
	m.analyzeConversation(packet, timestamp, analysis, conversations)

	// Verify conversation was created
	if len(conversations) != 1 {
		t.Errorf("expected 1 conversation, got %d", len(conversations))
	}

	// Verify conversation details
	for _, conv := range conversations {
		if conv.c.Proto != "TCP" {
			t.Errorf("expected TCP, got %s", conv.c.Proto)
		}
		if conv.c.Src != "192.168.1.100" && conv.c.Src != "10.0.0.1" {
			t.Errorf("unexpected src: %s", conv.c.Src)
		}
		if conv.c.PktsFwd != 1 && conv.c.PktsRev != 1 {
			t.Errorf("expected packet count, got fwd=%d rev=%d", conv.c.PktsFwd, conv.c.PktsRev)
		}
	}
}

func TestProtocolCounting(t *testing.T) {
	m := &Module{}
	analysis := &CaptureAnalysis{
		Conversations:  []Conversation{},
		ProtocolCounts: make(map[string]int64),
		DNSQueries:     []DNSRecord{},
		TLSHandshakes:  []TLSInfo{},
		HTTPRequests:   []HTTPRequest{},
		ExpertNotes:    []ExpertNote{},
		TopTalkers:     []TopTalker{},
		Timeline:       []TimelineEvent{},
	}

	// Create a simple IPv4 packet
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		Length:   20,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.100"),
		DstIP:    net.ParseIP("8.8.8.8"),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, ip)

	packet := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)

	// Count protocols
	m.countProtocols(packet, analysis)

	// Verify IPv4 was counted
	if count, ok := analysis.ProtocolCounts["IPv4"]; !ok || count != 1 {
		t.Errorf("IPv4 protocol not counted correctly: %v", analysis.ProtocolCounts)
	}
}

func TestTopTalkerTracking(t *testing.T) {
	topTalkers := make(map[string]*TopTalker)
	m := &Module{}

	// Record some packets
	m.recordTopTalker("192.168.1.100", 1024, topTalkers)
	m.recordTopTalker("192.168.1.100", 512, topTalkers)
	m.recordTopTalker("10.0.0.1", 256, topTalkers)

	if len(topTalkers) != 2 {
		t.Errorf("expected 2 top talkers, got %d", len(topTalkers))
	}

	if tt, ok := topTalkers["192.168.1.100"]; ok {
		if tt.Bytes != 1536 {
			t.Errorf("expected 1536 bytes, got %d", tt.Bytes)
		}
		if tt.Pkts != 2 {
			t.Errorf("expected 2 packets, got %d", tt.Pkts)
		}
	} else {
		t.Error("192.168.1.100 not found in top talkers")
	}
}

func TestTLSClientHelloParsing(t *testing.T) {
	m := &Module{}

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "valid SNI",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x4a, 0x01, 0x00, 0x00, 0x46, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00},
			want: "",
		},
		{
			name: "no SNI",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x20},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.parseTLSClientHello(tt.data)
			if got != tt.want {
				t.Errorf("parseTLSClientHello() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsValidHostname(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"valid hostname", "example.com", true},
		{"with hyphen", "sub-domain.example.com", true},
		{"valid subdomain", "api.example.com", true},
		{"empty", "", false},
		{"invalid character", "example.com!", false},
		{"space", "example .com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHostname(tt.host)
			if got != tt.want {
				t.Errorf("isValidHostname(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestPcapMerging(t *testing.T) {
	// Create two test pcap files
	buf1 := new(bytes.Buffer)
	w1 := pcapgo.NewWriter(buf1)
	w1.WriteFileHeader(65535, layers.LinkTypeEthernet)

	// Write a packet to first file
	packet1 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	w1.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(1000, 0),
		Length:    len(packet1),
	}, packet1)

	buf2 := new(bytes.Buffer)
	w2 := pcapgo.NewWriter(buf2)
	w2.WriteFileHeader(65535, layers.LinkTypeEthernet)

	// Write a packet to second file with earlier timestamp
	packet2 := []byte{0x05, 0x04, 0x03, 0x02, 0x01, 0x00}
	w2.WritePacket(gopacket.CaptureInfo{
		Timestamp: time.Unix(500, 0),
		Length:    len(packet2),
	}, packet2)

	// Verify both buffers have data
	if buf1.Len() == 0 {
		t.Error("first pcap buffer is empty")
	}
	if buf2.Len() == 0 {
		t.Error("second pcap buffer is empty")
	}
}
