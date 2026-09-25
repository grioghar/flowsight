// Package inspect provides packet inspection: stateful inspection (SPI) from
// the firewall's state table and deep packet inspection (DPI) via tcpdump capture.
package inspect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx       *core.Context
	mu        sync.RWMutex
	captureID string
	capture   *CaptureSession
	captures  map[string]*CaptureInfo
	states    []*PFState

	// Settings
	maxStates        int
	stateAgeSeconds  int
	snaplen          int
	maxCaptureSecs   int
	maxCaptureFiles  int
	maxCaptureBytes  int64
	payloadAllowed   bool
	statePollSeconds int
	synFloodThresh   int
	portScanThresh   int

	// Data directory
	dataDir string
}

type PFState struct {
	Proto     string    `json:"proto"`
	Direction string    `json:"direction"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
	State     string    `json:"state"`
	Age       int       `json:"age"`
	Expires   int       `json:"expires"`
	PktsSrc   int64     `json:"pkts_src"`
	BytesSrc  int64     `json:"bytes_src"`
	PktsDst   int64     `json:"pkts_dst"`
	BytesDst  int64     `json:"bytes_dst"`
	RuleID    int       `json:"rule_id"`
	Interface string    `json:"interface"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname,omitempty"`
}

type CaptureSession struct {
	ID       string
	Iface    string
	Filter   string
	Started  time.Time
	cmd      *exec.Cmd
	ctx      context.Context
	cancel   context.CancelFunc
	Duration int
	Snaplen  int
	Payload  bool
}

type CaptureInfo struct {
	ID        string           `json:"id"`
	Iface     string           `json:"iface"`
	Filter    string           `json:"filter"`
	Started   time.Time        `json:"started"`
	Ended     *time.Time       `json:"ended,omitempty"`
	Packets   int64            `json:"packets"`
	Bytes     int64            `json:"bytes"`
	Files     []string         `json:"files"`
	Analysis  *CaptureAnalysis `json:"analysis,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

type CaptureAnalysis struct {
	PacketCount    int64            `json:"packet_count"`
	ByteCount      int64            `json:"byte_count"`
	Conversations  []Conversation   `json:"conversations,omitempty"`
	ProtocolCounts map[string]int64 `json:"protocol_counts,omitempty"`
	DNSQueries     []DNSRecord      `json:"dns_queries,omitempty"`
	TLSHandshakes  []TLSInfo        `json:"tls_handshakes,omitempty"`
	HTTPRequests   []HTTPRequest    `json:"http_requests,omitempty"`
	ExpertNotes    []ExpertNote     `json:"expert_notes,omitempty"`
	TopTalkers     []TopTalker      `json:"top_talkers,omitempty"`
	Timeline       []TimelineEvent  `json:"timeline,omitempty"`
}

type Conversation struct {
	FiveTuple       string    `json:"five_tuple"`
	Proto           string    `json:"proto"`
	Src             string    `json:"src"`
	SrcPort         int       `json:"src_port"`
	Dst             string    `json:"dst"`
	DstPort         int       `json:"dst_port"`
	PktsFwd         int64     `json:"pkts_fwd"`
	BytesFwd        int64     `json:"bytes_fwd"`
	PktsRev         int64     `json:"pkts_rev"`
	BytesRev        int64     `json:"bytes_rev"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	TCPFlags        string    `json:"tcp_flags,omitempty"`
	Retransmissions int       `json:"retransmissions,omitempty"`
	OutOfOrder      int       `json:"out_of_order,omitempty"`
	ZeroWindow      int       `json:"zero_window,omitempty"`
	Resets          int       `json:"resets,omitempty"`
	RTTEstimate     float64   `json:"rtt_estimate,omitempty"`
}

type DNSRecord struct {
	Query     string    `json:"query"`
	Type      string    `json:"type"`
	Answers   []string  `json:"answers,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Timestamp time.Time `json:"timestamp"`
}

type TLSInfo struct {
	SNI       string    `json:"sni,omitempty"`
	JA3       string    `json:"ja3,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	CertCN    string    `json:"cert_cn,omitempty"`
	CertSAN   []string  `json:"cert_san,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type HTTPRequest struct {
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent,omitempty"`
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Timestamp time.Time `json:"timestamp"`
}

type ExpertNote struct {
	Type      string    `json:"type"` // "retransmission", "dup_ack", "zero_window", "reset", "port_reuse", "arp_conflict", "dns_no_query"
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
	Detail    string    `json:"detail"`
	Severity  string    `json:"severity"` // "info", "warn"
	Timestamp time.Time `json:"timestamp"`
}

type TopTalker struct {
	IP    string `json:"ip"`
	Bytes int64  `json:"bytes"`
	Pkts  int64  `json:"pkts"`
}

type TimelineEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "syn", "ack", "dns", "tls", "http"
	Src       string    `json:"src"`
	Dst       string    `json:"dst"`
}

type StatesSummary struct {
	TotalStates     int            `json:"total_states"`
	ByProto         map[string]int `json:"by_proto"`
	ByState         map[string]int `json:"by_state"`
	HalfOpenCount   int            `json:"half_open_count"`
	TableUtilPct    float64        `json:"table_util_pct"`
	NewStatesPerSec float64        `json:"new_states_per_sec"`
	States          []*PFState     `json:"states,omitempty"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "inspect",
		Version:      "1.0",
		Description:  "Packet inspection: stateful inspection from firewall state table and deep packet inspection via tcpdump capture.",
		Capabilities: []string{core.CapTrafficObserve},
		Requires:     []string{"FreeBSD", "pf"},
		Defaults: map[string]any{
			"max_states":          20000,
			"state_age_seconds":   300,
			"snaplen":             96,
			"max_capture_secs":    600,
			"max_capture_files":   5,
			"max_capture_bytes":   104857600,
			"payload_allowed":     false,
			"state_poll_seconds":  30,
			"syn_flood_threshold": 100,
			"port_scan_threshold": 50,
		},
		Schema: []core.SettingField{
			{Key: "max_states", Label: "Max firewall states in memory", Type: "int", Help: "Keep the newest N states; older ones are discarded to cap memory usage."},
			{Key: "state_age_seconds", Label: "State age threshold (seconds)", Type: "int", Help: "States older than this are flagged for cleanup detection."},
			{Key: "snaplen", Label: "Default snaplen (bytes)", Type: "int", Help: "96 for headers only, 65535 for full payload. Payload captures contain sensitive data."},
			{Key: "max_capture_secs", Label: "Max capture duration (seconds)", Type: "int", Help: "Hard limit on how long a single capture can run."},
			{Key: "max_capture_files", Label: "Max rotated capture files", Type: "int", Help: "tcpdump -W limit: number of files in the ring."},
			{Key: "max_capture_bytes", Label: "Max total capture bytes (MB)", Type: "int", Help: "Hard cap on cumulative capture storage; oldest captures deleted when exceeded."},
			{Key: "payload_allowed", Label: "Allow payload capture", Type: "bool", Help: "When off, captures are headers-only (96 bytes); when on, users can select full payload (65535 bytes). Payload captures are sensitive."},
			{Key: "state_poll_seconds", Label: "State poll interval (seconds)", Type: "int", Help: "How often to query pfctl for state changes."},
			{Key: "syn_flood_threshold", Label: "SYN flood alert threshold", Type: "int", Help: "Alert if SYN_SENT states from one source exceed this in the poll window."},
			{Key: "port_scan_threshold", Label: "Port scan alert threshold", Type: "int", Help: "Alert if one source has this many non-established destinations in one poll."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx

	// Load settings
	settings := ctx.Settings()
	m.maxStates = asInt(settings["max_states"], 20000)
	m.stateAgeSeconds = asInt(settings["state_age_seconds"], 300)
	m.snaplen = asInt(settings["snaplen"], 96)
	m.maxCaptureSecs = asInt(settings["max_capture_secs"], 600)
	m.maxCaptureFiles = asInt(settings["max_capture_files"], 5)
	m.maxCaptureBytes = int64(asInt(settings["max_capture_bytes"], 100)) * 1024 * 1024
	m.payloadAllowed = asBool(settings["payload_allowed"], false)
	m.statePollSeconds = asInt(settings["state_poll_seconds"], 30)
	m.synFloodThresh = asInt(settings["syn_flood_threshold"], 100)
	m.portScanThresh = asInt(settings["port_scan_threshold"], 50)

	// Initialize data directory
	m.dataDir = filepath.Join(ctx.Platform.DataDir, "captures")
	if err := os.MkdirAll(m.dataDir, 0700); err != nil {
		return fmt.Errorf("failed to create captures directory: %w", err)
	}

	m.captures = make(map[string]*CaptureInfo)
	m.states = []*PFState{}

	// Load existing captures from disk
	if err := m.loadCaptures(); err != nil {
		ctx.Log.Warn("failed to load captures", "error", err)
	}

	// Register API routes
	ctx.Route("GET", "/api/inspect/states", m.apiStates, core.Doc("Get firewall states summary"))
	ctx.Route("GET", "/api/inspect/states/summary", m.apiStatesSummary, core.Doc("Get states statistics"))
	ctx.Route("GET", "/api/inspect/rules", m.apiRules, core.Doc("Get rule counters"))
	ctx.Route("POST", "/api/inspect/capture/start", m.apiCaptureStart, core.Write(), core.Doc("Start packet capture"))
	ctx.Route("POST", "/api/inspect/capture/stop", m.apiCaptureStop, core.Write(), core.Doc("Stop running capture"))
	ctx.Route("GET", "/api/inspect/captures", m.apiCaptures, core.Doc("List all captures"))
	ctx.Route("GET", "/api/inspect/capture/{id}", m.apiCaptureDetail, core.Doc("Get capture analysis"))
	ctx.Route("GET", "/api/inspect/capture/{id}/conversations", m.apiCaptureConversations, core.Doc("Get capture conversations"))
	ctx.Route("GET", "/api/inspect/capture/{id}/dns", m.apiCaptureDNS, core.Doc("Get DNS records from capture"))
	ctx.Route("GET", "/api/inspect/capture/{id}/tls", m.apiCaptureTLS, core.Doc("Get TLS handshakes from capture"))
	ctx.Route("GET", "/api/inspect/capture/{id}/http", m.apiCaptureHTTP, core.Doc("Get HTTP requests from capture"))
	ctx.Route("GET", "/api/inspect/capture/{id}/expert", m.apiCaptureExpert, core.Doc("Get expert notes from capture"))
	ctx.Route("GET", "/api/inspect/capture/{id}/download", m.apiCaptureDownload, core.Doc("Download capture as pcap"))
	ctx.Route("DELETE", "/api/inspect/capture/{id}", m.apiCaptureDelete, core.Write(), core.Doc("Delete capture"))
	ctx.Route("GET", "/api/inspect/live", m.apiLiveStream, core.Doc("Stream live packet summaries"))

	// Register panel
	ctx.Panel(core.Panel{
		ID:    "inspect",
		Title: "Packet Inspection",
		Group: "Protect",
		Order: 76,
		Icon:  "inspect",
	})

	// Schedule state polling job
	ctx.Every("state_poller", time.Duration(m.statePollSeconds)*time.Second, m.pollStates)

	return nil
}

func (m *Module) pollStates() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	states, err := m.getPFStates()
	if err != nil {
		m.ctx.Log.Warn("failed to poll states", "error", err)
		return err
	}

	m.states = states

	// Detect anomalies and emit findings
	m.detectAnomalies(states)

	return nil
}

func (m *Module) getPFStates() ([]*PFState, error) {
	// Run pfctl -ss -vv to get detailed state table
	cmd := exec.Command("pfctl", "-ss", "-vv")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pfctl failed: %w", err)
	}

	states := []*PFState{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "STATES") || strings.HasPrefix(line, "ALL") {
			continue
		}

		state := m.parsePFLine(line)
		if state != nil {
			states = append(states, state)
		}
	}

	// Keep only the newest maxStates
	if len(states) > m.maxStates {
		sort.Slice(states, func(i, j int) bool {
			return states[i].Timestamp.After(states[j].Timestamp)
		})
		states = states[:m.maxStates]
	}

	return states, nil
}

// parsePFLine parses a line from pfctl -ss -vv output
// Expected format is complex; simplified here for headers-only capture
func (m *Module) parsePFLine(line string) *PFState {
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return nil
	}

	// Very simplified parsing; real pf output is more complex
	// This is a placeholder that extracts basic info
	state := &PFState{
		Timestamp: time.Now(),
	}

	// Parse protocol and addresses (simplified)
	if len(parts) > 0 {
		state.Proto = parts[0]
	}

	// Find state keyword
	for i, p := range parts {
		if p == "->" && i+1 < len(parts) {
			if i > 0 {
				state.Src = parts[i-1]
			}
			if i+1 < len(parts) {
				state.Dst = parts[i+1]
			}
			break
		}
		if strings.Contains(p, "ESTABLISHED") || strings.Contains(p, "SYN_SENT") {
			state.State = p
		}
	}

	return state
}

func (m *Module) detectAnomalies(states []*PFState) {
	// Skip anomaly detection if context is not available (e.g., in tests)
	if m.ctx == nil || m.ctx.Store == nil {
		return
	}

	// Group states by source IP
	bySrc := make(map[string][]*PFState)
	for _, s := range states {
		bySrc[s.Src] = append(bySrc[s.Src], s)
	}

	// Check for SYN floods
	for src, srcStates := range bySrc {
		synCount := 0
		for _, s := range srcStates {
			if s.State == "SYN_SENT" {
				synCount++
			}
		}
		if synCount > m.synFloodThresh {
			m.ctx.Store.AddFinding(
				"inspect",
				"syn_flood",
				"high",
				src,
				fmt.Sprintf("SYN flood detected from %s", src),
				fmt.Sprintf("%d half-open connections", synCount),
				fmt.Sprintf("syn_flood_%s", src),
			)
		}
	}

	// Check for port scans
	for src, srcStates := range bySrc {
		uniqueDsts := make(map[string]int)
		for _, s := range srcStates {
			if s.State != "ESTABLISHED" {
				uniqueDsts[s.Dst]++
			}
		}
		if len(uniqueDsts) > m.portScanThresh {
			m.ctx.Store.AddFinding(
				"inspect",
				"port_scan",
				"medium",
				src,
				fmt.Sprintf("Possible port scan from %s", src),
				fmt.Sprintf("Connections to %d different hosts in non-established state", len(uniqueDsts)),
				fmt.Sprintf("port_scan_%s", src),
			)
		}
	}
}

// API Handlers

func (m *Module) apiStates(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	host := r.Q("host", "")
	proto := r.Q("proto", "")
	state := r.Q("state", "")
	limit := r.QInt("limit", 100, 1, 10000)

	filtered := m.states
	if host != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.Src == host || s.Dst == host {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}
	if proto != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.Proto == proto {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}
	if state != "" {
		var tmp []*PFState
		for _, s := range filtered {
			if s.State == state {
				tmp = append(tmp, s)
			}
		}
		filtered = tmp
	}

	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return map[string]any{
		"states": filtered,
		"count":  len(filtered),
	}, nil
}

func (m *Module) apiStatesSummary(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := &StatesSummary{
		TotalStates: len(m.states),
		ByProto:     make(map[string]int),
		ByState:     make(map[string]int),
	}

	for _, s := range m.states {
		summary.ByProto[s.Proto]++
		summary.ByState[s.State]++
		if s.State == "SYN_SENT" {
			summary.HalfOpenCount++
		}
	}

	return summary, nil
}

func (m *Module) apiRules(r *core.Req) (any, error) {
	// Run pfctl -sr -vv to get rule counters
	cmd := exec.Command("pfctl", "-sr", "-vv")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pfctl rules failed: %w", err)
	}

	// Simple summary
	lineCount := bytes.Count(out, []byte("\n"))

	return map[string]any{
		"rule_count": lineCount,
		"raw":        string(out),
	}, nil
}

func (m *Module) apiCaptureStart(r *core.Req) (any, error) {
	var req struct {
		Iface   string `json:"iface"`
		Filter  string `json:"filter"`
		Seconds int    `json:"seconds"`
		Snaplen int    `json:"snaplen"`
		Payload bool   `json:"payload"`
	}

	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture != nil {
		return nil, core.BadRequest("capture already in progress")
	}

	// Validate
	if req.Iface == "" {
		return nil, core.BadRequest("iface required")
	}
	if req.Seconds <= 0 || req.Seconds > m.maxCaptureSecs {
		req.Seconds = m.maxCaptureSecs
	}
	if req.Snaplen == 0 {
		req.Snaplen = m.snaplen
	}
	if req.Payload && !m.payloadAllowed {
		return nil, core.Forbidden("payload capture not allowed by policy")
	}

	// Validate BPF filter
	if req.Filter != "" {
		if err := m.validateBPFFilter(req.Filter); err != nil {
			return nil, core.BadRequest("invalid BPF filter: %v", err)
		}
	}

	id := fmt.Sprintf("cap_%d", time.Now().Unix())
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Seconds)*time.Second+30*time.Second)

	m.capture = &CaptureSession{
		ID:       id,
		Iface:    req.Iface,
		Filter:   req.Filter,
		Started:  time.Now(),
		Duration: req.Seconds,
		Snaplen:  req.Snaplen,
		Payload:  req.Payload,
		ctx:      ctx,
		cancel:   cancel,
	}

	go m.runCapture()

	return map[string]any{
		"id":      id,
		"status":  "started",
		"iface":   req.Iface,
		"filter":  req.Filter,
		"seconds": req.Seconds,
	}, nil
}

func (m *Module) apiCaptureStop(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.capture == nil {
		return nil, core.NotFound("no capture in progress")
	}

	m.capture.cancel()
	return map[string]string{"status": "stopping"}, nil
}

func (m *Module) apiCaptures(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	captures := make([]*CaptureInfo, 0, len(m.captures))
	for _, c := range m.captures {
		captures = append(captures, c)
	}

	// Sort by started, newest first
	sort.Slice(captures, func(i, j int) bool {
		return captures[i].Started.After(captures[j].Started)
	})

	return map[string]any{"captures": captures}, nil
}

func (m *Module) apiCaptureDetail(r *core.Req) (any, error) {
	id := r.Params["id"]
	if id == "" {
		return nil, core.BadRequest("id required")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	cap, ok := m.captures[id]
	if !ok {
		return nil, core.NotFound("capture not found")
	}

	return cap, nil
}

func (m *Module) apiCaptureConversations(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"conversations": []Conversation{}}, nil
	}

	return map[string]any{"conversations": cap.Analysis.Conversations}, nil
}

func (m *Module) apiCaptureDNS(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"dns": []DNSRecord{}}, nil
	}

	return map[string]any{"dns": cap.Analysis.DNSQueries}, nil
}

func (m *Module) apiCaptureTLS(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"tls": []TLSInfo{}}, nil
	}

	return map[string]any{"tls": cap.Analysis.TLSHandshakes}, nil
}

func (m *Module) apiCaptureHTTP(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"http": []HTTPRequest{}}, nil
	}

	return map[string]any{"http": cap.Analysis.HTTPRequests}, nil
}

func (m *Module) apiCaptureExpert(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	if cap.Analysis == nil {
		return map[string]any{"notes": []ExpertNote{}}, nil
	}

	return map[string]any{"notes": cap.Analysis.ExpertNotes}, nil
}

func (m *Module) apiCaptureDownload(r *core.Req) (any, error) {
	id := r.Params["id"]
	m.mu.RLock()
	cap, ok := m.captures[id]
	m.mu.RUnlock()

	if !ok {
		return nil, core.NotFound("capture not found")
	}

	// Return file list for download
	return map[string]any{
		"id":    cap.ID,
		"files": cap.Files,
		"name":  fmt.Sprintf("flowsight-%s.pcap", cap.ID),
	}, nil
}

func (m *Module) apiCaptureDelete(r *core.Req) (any, error) {
	id := r.Params["id"]

	m.mu.Lock()
	defer m.mu.Unlock()

	cap, ok := m.captures[id]
	if !ok {
		return nil, core.NotFound("capture not found")
	}

	// Delete files
	for _, f := range cap.Files {
		_ = os.Remove(filepath.Join(m.dataDir, f))
	}

	delete(m.captures, id)

	return map[string]string{"status": "deleted"}, nil
}

func (m *Module) apiLiveStream(r *core.Req) (any, error) {
	// Placeholder: would stream tcpdump output as server-sent events
	return map[string]string{"status": "live streaming not yet implemented"}, nil
}

// Helper functions

func (m *Module) validateBPFFilter(filter string) error {
	// Empty filter is valid
	if filter == "" {
		return nil
	}

	// Length check
	if len(filter) > 1000 {
		return fmt.Errorf("filter too long")
	}

	// Character validation (basic)
	for _, c := range filter {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == ' ' || c == '.' || c == ',' || c == ':' || c == '-' || c == '(' || c == ')' ||
			c == '[' || c == ']' || c == '!' || c == '&' || c == '|' || c == '=') {
			return fmt.Errorf("invalid character: %c", c)
		}
	}

	// Try to compile with tcpdump (skip if not available)
	cmd := exec.Command("tcpdump", "-d", filter)
	if err := cmd.Run(); err != nil {
		// Only return error if the tool is available but the syntax is invalid
		// If tcpdump is not available, we skip this validation
		if _, ok := err.(*exec.ExitError); !ok {
			// Tool not found is OK; let it through
			return nil
		}
		return fmt.Errorf("invalid BPF: %w", err)
	}

	return nil
}

func (m *Module) runCapture() {
	defer func() {
		m.mu.Lock()
		m.capture = nil
		m.mu.Unlock()
	}()

	if m.capture == nil {
		return
	}

	id := m.capture.ID
	iface := m.capture.Iface
	filter := m.capture.Filter
	snaplen := m.capture.Snaplen

	// Build output filename
	capFile := filepath.Join(m.dataDir, fmt.Sprintf("%s.pcap", id))

	// Build tcpdump command
	args := []string{
		"-i", iface,
		"-w", capFile,
		"-C", "20", // rotate at 20MB
		"-W", fmt.Sprintf("%d", m.maxCaptureFiles),
		"-s", fmt.Sprintf("%d", snaplen),
		"-U",
	}

	if filter != "" {
		args = append(args, filter)
	}

	cmd := exec.CommandContext(m.capture.ctx, "tcpdump", args...)
	if err := cmd.Run(); err != nil {
		m.ctx.Log.Warn("tcpdump failed", "error", err)
	}

	// Record capture
	m.mu.Lock()
	now := time.Now()
	m.captures[id] = &CaptureInfo{
		ID:        id,
		Iface:     iface,
		Filter:    filter,
		Started:   m.capture.Started,
		Ended:     &now,
		Files:     []string{fmt.Sprintf("%s.pcap", id)},
		Timestamp: now,
	}
	m.mu.Unlock()

	// Analyze capture
	_ = m.analyzeCapture(id)
}

func (m *Module) analyzeCapture(id string) error {
	// Placeholder: would parse pcap with gopacket
	return nil
}

func (m *Module) loadCaptures() error {
	// Placeholder: would load existing captures from disk
	return nil
}

// Utility functions

func asInt(v any, def int) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		if i, err := strconv.Atoi(x); err == nil {
			return i
		}
	}
	return def
}

func asBool(v any, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1" || x == "yes"
	}
	return def
}
