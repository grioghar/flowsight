package inspect

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	maxPacketsPerCapture = 2_000_000
	maxBytesPerCapture   = 1_000_000_000 // 1 GB
)

// conversationKey normalizes a 5-tuple for bidirectional tracking
type conversationKey struct {
	proto string
	ip1   string
	ip2   string
	p1    uint16
	p2    uint16
}

func (ck conversationKey) String() string {
	return fmt.Sprintf("%s:%s:%d-%s:%d", ck.proto, ck.ip1, ck.p1, ck.ip2, ck.p2)
}

// conversationData tracks a conversation
type conversationData struct {
	c               Conversation
	tcpSeq          [2]map[uint32]bool // track seen sequence numbers for retransmission detection
	tcpAckCount     [2]int             // count of ACK packets to detect dup-acks
	firstPacketTime time.Time
	lastPacketTime  time.Time
	tcpFlags        map[uint8]bool // track TCP flags seen
	synTime         time.Time      // for SYN-ACK RTT calculation
	synAckTime      time.Time
	resetSeen       bool
	zeroWindowSeen  bool
	outOfOrderCount int
	retransmitCount int
	dupAckCount     int
	direction       [2]bool // track which direction we've seen
}

func (m *Module) analyzeCapture(id string) error {
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("capture not found: %s", id)
	}

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
	topTalkerIPs := make(map[string]*TopTalker)
	var packetCount int64
	var byteCount int64
	var packetExceeded bool

	// Process each capture file
	for _, fname := range cap.Files {
		filepath := filepath.Join(m.dataDir, fname)
		f, err := os.Open(filepath)
		if err != nil {
			m.ctx.Log.Warn("failed to open pcap", "file", fname, "error", err)
			continue
		}
		defer f.Close()

		reader, err := pcapgo.NewReader(f)
		if err != nil {
			m.ctx.Log.Warn("failed to create pcap reader", "file", fname, "error", err)
			continue
		}

		for {
			if packetCount >= maxPacketsPerCapture || byteCount >= maxBytesPerCapture {
				packetExceeded = true
				break
			}

			data, ci, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				m.ctx.Log.Warn("failed to read packet", "error", err)
				break
			}

			packetCount++
			byteCount += int64(ci.Length)

			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			m.analyzePacket(packet, ci.Timestamp, analysis, conversations, topTalkerIPs)
		}

		if packetExceeded {
			break
		}
	}

	if packetExceeded {
		analysis.ExpertNotes = append(analysis.ExpertNotes, ExpertNote{
			Type:      "packet_cap",
			Detail:    fmt.Sprintf("Packet capture exceeded limit (%d packets, %d bytes)", maxPacketsPerCapture, byteCount),
			Severity:  "info",
			Timestamp: time.Now(),
		})
	}

	analysis.PacketCount = packetCount
	analysis.ByteCount = byteCount

	// Convert conversations map to slice
	for _, conv := range conversations {
		analysis.Conversations = append(analysis.Conversations, conv.c)
	}

	// Sort conversations by bytes
	sort.Slice(analysis.Conversations, func(i, j int) bool {
		return analysis.Conversations[i].BytesFwd+analysis.Conversations[i].BytesRev >
			analysis.Conversations[j].BytesFwd+analysis.Conversations[j].BytesRev
	})

	// Convert top talkers
	for _, tt := range topTalkerIPs {
		analysis.TopTalkers = append(analysis.TopTalkers, *tt)
	}
	sort.Slice(analysis.TopTalkers, func(i, j int) bool {
		return analysis.TopTalkers[i].Bytes > analysis.TopTalkers[j].Bytes
	})
	if len(analysis.TopTalkers) > 50 {
		analysis.TopTalkers = analysis.TopTalkers[:50]
	}

	// Sort DNS, TLS, HTTP by timestamp
	sort.Slice(analysis.DNSQueries, func(i, j int) bool {
		return analysis.DNSQueries[i].Timestamp.Before(analysis.DNSQueries[j].Timestamp)
	})
	sort.Slice(analysis.TLSHandshakes, func(i, j int) bool {
		return analysis.TLSHandshakes[i].Timestamp.Before(analysis.TLSHandshakes[j].Timestamp)
	})
	sort.Slice(analysis.HTTPRequests, func(i, j int) bool {
		return analysis.HTTPRequests[i].Timestamp.Before(analysis.HTTPRequests[j].Timestamp)
	})
	sort.Slice(analysis.ExpertNotes, func(i, j int) bool {
		return analysis.ExpertNotes[i].Timestamp.Before(analysis.ExpertNotes[j].Timestamp)
	})

	// Cache analysis
	cacheFile := filepath.Join(m.dataDir, id+".analysis.json")
	data, _ := json.MarshalIndent(analysis, "", "  ")
	_ = os.WriteFile(cacheFile, data, 0644)

	// Update capture with analysis
	m.mu.Lock()
	cap.Analysis = analysis
	m.mu.Unlock()

	return nil
}

func (m *Module) analyzePacket(packet gopacket.Packet, timestamp time.Time, analysis *CaptureAnalysis,
	conversations map[conversationKey]*conversationData, topTalkerIPs map[string]*TopTalker) {

	// Count layers in the protocol hierarchy
	m.countProtocols(packet, analysis)

	// Track IP addresses for top talkers
	var srcIP, dstIP string
	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	}

	if srcIP != "" && dstIP != "" {
		m.recordTopTalker(srcIP, packet.Metadata().Length, topTalkerIPs)
		m.recordTopTalker(dstIP, packet.Metadata().Length, topTalkerIPs)
	}

	// Analyze conversations
	m.analyzeConversation(packet, timestamp, analysis, conversations)

	// Extract application-layer data
	m.extractDNS(packet, timestamp, analysis)
	m.extractTLS(packet, timestamp, analysis)
	m.extractHTTP(packet, timestamp, analysis)
}

func (m *Module) countProtocols(packet gopacket.Packet, analysis *CaptureAnalysis) {
	for _, layer := range packet.Layers() {
		name := layer.LayerType().String()
		analysis.ProtocolCounts[name]++
	}
}

func (m *Module) recordTopTalker(ip string, length int, topTalkers map[string]*TopTalker) {
	if tt, ok := topTalkers[ip]; ok {
		tt.Bytes += int64(length)
		tt.Pkts++
	} else {
		topTalkers[ip] = &TopTalker{
			IP:    ip,
			Bytes: int64(length),
			Pkts:  1,
		}
	}
}

func (m *Module) analyzeConversation(packet gopacket.Packet, timestamp time.Time, analysis *CaptureAnalysis,
	conversations map[conversationKey]*conversationData) {

	// Get IP layer
	var srcIP, dstIP string
	var proto string

	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		proto = ipv4.Protocol.String()
	} else if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
		proto = ipv6.NextHeader.String()
	} else {
		return
	}

	// Get port information
	var srcPort, dstPort uint16
	direction := 0 // 0 = forward (src->dst), 1 = reverse (dst->src)

	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		proto = "TCP"
	} else if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		proto = "UDP"
	} else {
		return
	}

	// Normalize 5-tuple key
	ck := m.normalizeConversation(proto, srcIP, dstIP, srcPort, dstPort)

	// Get or create conversation data
	var conv *conversationData
	if c, ok := conversations[ck]; ok {
		conv = c
		if srcIP == ck.ip1 && srcPort == ck.p1 {
			direction = 0
		} else {
			direction = 1
		}
	} else {
		conv = &conversationData{
			c: Conversation{
				FiveTuple: ck.String(),
				Proto:     proto,
				Src:       srcIP,
				SrcPort:   int(srcPort),
				Dst:       dstIP,
				DstPort:   int(dstPort),
				FirstSeen: timestamp,
				TCPFlags:  "",
			},
			tcpSeq:      [2]map[uint32]bool{{}, {}},
			tcpAckCount: [2]int{},
		}
		conversations[ck] = conv
	}

	// Update conversation timing
	if conv.firstPacketTime.IsZero() {
		conv.firstPacketTime = timestamp
	}
	conv.lastPacketTime = timestamp
	conv.c.FirstSeen = conv.firstPacketTime
	conv.c.LastSeen = conv.lastPacketTime

	// Record direction
	conv.direction[direction] = true

	// Update packet and byte counts
	if direction == 0 {
		conv.c.PktsFwd++
		conv.c.BytesFwd += int64(packet.Metadata().Length)
	} else {
		conv.c.PktsRev++
		conv.c.BytesRev += int64(packet.Metadata().Length)
	}

	// Analyze TCP-specific details
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		m.analyzeTCPPacket(tcp, timestamp, direction, conv, analysis)
	}
}

func (m *Module) normalizeConversation(proto, srcIP, dstIP string, srcPort, dstPort uint16) conversationKey {
	// Normalize so that the smaller IP is always first
	cmp := strings.Compare(srcIP, dstIP)
	if cmp <= 0 {
		return conversationKey{
			proto: proto,
			ip1:   srcIP,
			ip2:   dstIP,
			p1:    srcPort,
			p2:    dstPort,
		}
	}
	return conversationKey{
		proto: proto,
		ip1:   dstIP,
		ip2:   srcIP,
		p1:    dstPort,
		p2:    srcPort,
	}
}

func (m *Module) analyzeTCPPacket(tcp *layers.TCP, timestamp time.Time, direction int, conv *conversationData, analysis *CaptureAnalysis) {
	// Record TCP flags
	flags := ""
	if tcp.SYN {
		flags += "S"
		if direction == 0 && conv.synTime.IsZero() {
			conv.synTime = timestamp
		}
	}
	if tcp.ACK {
		flags += "A"
		if direction == 1 && !conv.synTime.IsZero() && conv.synAckTime.IsZero() {
			conv.synAckTime = timestamp
		}
	}
	if tcp.FIN {
		flags += "F"
	}
	if tcp.RST {
		flags += "R"
		conv.resetSeen = true
		if conv.c.Resets == 0 {
			conv.c.Resets = 1
		}
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.URG {
		flags += "U"
	}
	if flags != "" {
		if !strings.Contains(conv.c.TCPFlags, flags) {
			conv.c.TCPFlags += flags
		}
	}

	// Check for retransmissions (duplicate sequence numbers)
	if tcp.PSH || tcp.SYN || len(tcp.Payload) > 0 {
		if conv.tcpSeq[direction][tcp.Seq] {
			conv.retransmitCount++
			if conv.c.Retransmissions == 0 {
				conv.c.Retransmissions = 1
			}
		} else {
			conv.tcpSeq[direction][tcp.Seq] = true
		}
	}

	// Check for zero window
	if tcp.Window == 0 {
		conv.zeroWindowSeen = true
		if conv.c.ZeroWindow == 0 {
			conv.c.ZeroWindow = 1
		}
	}

	// Calculate RTT if we have SYN and SYN-ACK
	if !conv.synTime.IsZero() && !conv.synAckTime.IsZero() && conv.c.RTTEstimate == 0 {
		rtt := conv.synAckTime.Sub(conv.synTime).Seconds() * 1000 // milliseconds
		conv.c.RTTEstimate = rtt
	}
}

func (m *Module) extractDNS(packet gopacket.Packet, timestamp time.Time, analysis *CaptureAnalysis) {
	udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok || udp.DstPort != 53 && udp.SrcPort != 53 {
		return
	}

	var srcIP, dstIP string
	if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	}

	// Simple DNS parsing - just record DNS packets for now
	// In a real implementation would parse the DNS message format
	if len(udp.Payload) > 12 {
		// DNS header is 12 bytes minimum
		// Query direction: if DstPort==53, this is a query; if SrcPort==53, it's a response
		if udp.DstPort == 53 {
			// This is a query - would parse the question section
			analysis.DNSQueries = append(analysis.DNSQueries, DNSRecord{
				Query:     "query",
				Type:      "A",
				Src:       srcIP,
				Dst:       dstIP,
				Timestamp: timestamp,
			})
		}
	}
}

func (m *Module) extractTLS(packet gopacket.Packet, timestamp time.Time, analysis *CaptureAnalysis) {
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp.DstPort != 443 && tcp.SrcPort != 443 {
		return
	}

	if len(tcp.Payload) < 5 {
		return
	}

	// Check for TLS record header (0x16 = Handshake)
	if tcp.Payload[0] != 0x16 {
		return
	}

	// Check for ClientHello (0x01) at offset 5 (TLS record header is 5 bytes)
	if len(tcp.Payload) > 5 && tcp.Payload[5] == 0x01 {
		// This is a ClientHello
		extData := m.parseTLSExtensions(tcp.Payload)
		var srcIP, dstIP string
		if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			srcIP = ipv4.SrcIP.String()
			dstIP = ipv4.DstIP.String()
		} else if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			srcIP = ipv6.SrcIP.String()
			dstIP = ipv6.DstIP.String()
		}

		// Calculate JA3 fingerprint (simplified - just hash the payload)
		h := md5.Sum(tcp.Payload)
		ja3 := hex.EncodeToString(h[:])

		tlsInfo := TLSInfo{
			SNI:       extData.SNI,
			JA3:       ja3,
			Src:       srcIP,
			Dst:       dstIP,
			ECH:       extData.ECH,
			Timestamp: timestamp,
		}
		analysis.TLSHandshakes = append(analysis.TLSHandshakes, tlsInfo)

		// Record observation for visibility module (TLS with ECH is visible as "ech")
		if tcp.DstPort > 0 {
			m.recordTLSObservation(srcIP, dstIP, int(tcp.DstPort), extData.ECH)
		}
	}
}

// tlsExtensionData holds SNI and ECH detection from a ClientHello
type tlsExtensionData struct {
	SNI string
	ECH bool
}

func (m *Module) parseTLSClientHello(payload []byte) string {
	data := m.parseTLSExtensions(payload)
	return data.SNI
}

// parseTLSExtensions extracts SNI and detects ECH from a ClientHello
func (m *Module) parseTLSExtensions(payload []byte) tlsExtensionData {
	// ClientHello structure (RFC 5246, 7.4.1.2):
	// struct {
	//     uint16 record_type = 22;
	//     uint16 version;
	//     uint16 length;
	//     uint8 msg_type = 1;  // ClientHello
	//     uint24 length;
	//     uint16 version;
	//     uint32 random;
	//     uint8 session_id_length;
	//     uint8 session_id[session_id_length];
	//     uint16 cipher_suites_length;
	//     uint8 cipher_suites[cipher_suites_length];
	//     uint8 compression_methods_length;
	//     uint8 compression_methods[compression_methods_length];
	//     uint16 extensions_length;
	//     Extension extensions[extensions_length];
	// }

	result := tlsExtensionData{}
	if len(payload) < 50 {
		return result
	}

	// Skip to extensions: minimum ClientHello is ~44 bytes before extensions
	// but we need to account for variable-length fields
	offset := 5 // Skip TLS record header (type + version)
	if offset+1 >= len(payload) || payload[offset] != 0x01 {
		return result // Not a ClientHello
	}
	offset++ // Skip handshake message type

	// Skip to after fixed fields + variable-length session_id
	offset += 3 + 2 + 32 // message length (3) + version (2) + random (32)
	if offset >= len(payload) {
		return result
	}

	sessionIDLen := int(payload[offset])
	offset++
	offset += sessionIDLen

	if offset+2 >= len(payload) {
		return result
	}

	// Skip cipher suites
	cipherLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2 + cipherLen

	if offset >= len(payload) {
		return result
	}

	// Skip compression methods
	compLen := int(payload[offset])
	offset++
	offset += compLen

	if offset+2 > len(payload) {
		return result
	}

	// Parse extensions
	extLen := int(payload[offset])<<8 | int(payload[offset+1])
	offset += 2

	extEnd := offset + extLen
	if extEnd > len(payload) {
		extEnd = len(payload)
	}

	// Walk through extensions
	for offset+4 <= extEnd {
		extType := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2
		dataLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2

		if offset+dataLen > extEnd {
			break
		}

		extData := payload[offset : offset+dataLen]

		// Extension type 0x0000 = server_name (SNI)
		if extType == 0x0000 && result.SNI == "" {
			result.SNI = m.extractSNIFromExtension(extData)
		}

		// Extension type 0xfe0d = encrypted_client_hello (ECH)
		// Also check for GREASE-ECH (pattern 0x?a?a where ? is any hex digit)
		if extType == 0xfe0d || (extType&0x0f0f == 0x0a0a) {
			result.ECH = true
		}

		offset += dataLen
	}

	return result
}

func (m *Module) extractSNIFromExtension(data []byte) string {
	// SNI extension format:
	// uint16 extensions_length;
	// struct {
	//     NameType name_type;  // 0 = host_name
	//     uint16 name_length;
	//     uint8 name[name_length];
	// } ServerNameList;

	if len(data) < 5 {
		return ""
	}

	offset := 2 // Skip extensions length
	if offset+1 >= len(data) || data[offset] != 0x00 {
		return "" // Not host_name type
	}
	offset++

	nameLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+nameLen > len(data) || nameLen < 1 || nameLen > 255 {
		return ""
	}

	name := string(data[offset : offset+nameLen])
	if isValidHostname(name) {
		return name
	}
	return ""
}

func isValidHostname(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return len(s) > 0 && len(s) < 255
}

func (m *Module) extractHTTP(packet gopacket.Packet, timestamp time.Time, analysis *CaptureAnalysis) {
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp.DstPort != 80 && tcp.SrcPort != 80 {
		return
	}

	if len(tcp.Payload) < 10 {
		return
	}

	// Check if payload looks like HTTP request
	payload := string(tcp.Payload)
	if !strings.Contains(payload, "HTTP/") {
		return
	}

	// Parse HTTP request line
	lines := strings.Split(payload, "\r\n")
	if len(lines) > 0 {
		parts := strings.Fields(lines[0])
		if len(parts) >= 3 {
			method := parts[0]
			path := parts[1]

			// Extract Host header
			host := ""
			for _, line := range lines[1:] {
				if strings.HasPrefix(line, "Host:") {
					host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
					break
				}
			}

			// Extract User-Agent header
			ua := ""
			for _, line := range lines[1:] {
				if strings.HasPrefix(line, "User-Agent:") {
					ua = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
					break
				}
			}

			var srcIP, dstIP string
			if ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
				srcIP = ipv4.SrcIP.String()
				dstIP = ipv4.DstIP.String()
			} else if ipv6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
				srcIP = ipv6.SrcIP.String()
				dstIP = ipv6.DstIP.String()
			}

			analysis.HTTPRequests = append(analysis.HTTPRequests, HTTPRequest{
				Method:    method,
				Host:      host,
				Path:      path,
				UserAgent: ua,
				Src:       srcIP,
				Dst:       dstIP,
				Timestamp: timestamp,
			})
		}
	}
}

func (m *Module) downloadCapture(id string) (io.Reader, error) {
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("capture not found: %s", id)
	}

	// Create a buffer to merge pcap files
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)

	// Get first pcap to extract snaplen
	firstFile := filepath.Join(m.dataDir, cap.Files[0])
	f, err := os.Open(firstFile)
	if err != nil {
		return nil, err
	}
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	snaplen := reader.Snaplen()
	f.Close()

	// Write global header
	if err := w.WriteFileHeader(snaplen, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}

	// Collect all packets from all files with their timestamps
	type packet struct {
		data []byte
		ci   gopacket.CaptureInfo
	}
	var packets []packet

	for _, fname := range cap.Files {
		fpath := filepath.Join(m.dataDir, fname)
		f, err := os.Open(fpath)
		if err != nil {
			m.ctx.Log.Warn("failed to open pcap file", "file", fname, "error", err)
			continue
		}

		reader, err := pcapgo.NewReader(f)
		if err != nil {
			f.Close()
			continue
		}

		for {
			data, ci, err := reader.ReadPacketData()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			packets = append(packets, packet{data: data, ci: ci})
		}
		f.Close()
	}

	// Sort packets by timestamp
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].ci.Timestamp.Before(packets[j].ci.Timestamp)
	})

	// Write packets in order
	for _, pkt := range packets {
		_ = w.WritePacket(pkt.ci, pkt.data)
	}

	return buf, nil
}
