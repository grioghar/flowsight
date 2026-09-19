// Package enroll identifies devices from DHCP, ARP/NDP and lease files,
// classifies them by rules, and places them in zones with tailored DNS, DHCP
// and firewall policies. Zone boundaries are enforced via pf rules and optional
// dnsmasq DHCP reservations; unidentified devices are redirected to a
// self-identification page.
package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Firewall interface for pf rules.
type Firewall interface {
	LoadAnchor(name, rules string) error
	FlushAnchor(name string) error
}

// txnData collects DHCP transaction information from log lines.
type txnData struct {
	mac          string
	ip           string
	hostname     string
	vendorClass  string
	fingerprint  string
	optionsList  []string // option numbers in order
	lastActivity time.Time
}

// Module is the enroll service.
type Module struct {
	ctx           *core.Context
	mu            sync.RWMutex
	devices       map[string]*Device // mac -> device
	zones         *ZonesDoc          // zones and captive settings
	rules         []*Rule            // classification rules
	identity      core.Identity      // name/MAC resolution
	firewall      Firewall           // pf anchor management
	lastErr       string
	lastApplied   time.Time
	pendingAssign map[string]string     // mac -> zone for pending changes
	allocations   map[string]*Allocator // zone id -> allocator

	// DHCP log tailing
	tailer         *core.Tailer
	txnMu          sync.Mutex
	txnState       map[string]*txnData // transaction id -> accumulated data
	lastTailErr    string
	lastLogCleanup time.Time

	// Captive portal rate limiting: mac -> last change timestamp
	captiveMuRate sync.Mutex
	captiveRate   map[string]int64

	// Captive portal listener (stored for shutdown)
	captiveServer interface{}
}

// Device is one MAC address in the registry.
type Device struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	IP6         string `json:"ip6,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	VendorClass string `json:"vendor_class,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Zone        string `json:"zone,omitempty"`
	Class       string `json:"class,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Why         string `json:"why,omitempty"`
	Pinned      int    `json:"pinned"`
	Randomized  int    `json:"randomized"`
	GuestName   string `json:"guest_name,omitempty"`
	GuestKind   string `json:"guest_kind,omitempty"`
	User        string `json:"user,omitempty"`
	Iface       string `json:"iface,omitempty"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
}

// ZonesDoc is zones.json.
type ZonesDoc struct {
	Mode          string       `json:"mode"` // monitor or enforce
	CaptiveZone   string       `json:"captive_zone"`
	CaptivePolicy string       `json:"captive_policy"` // self_service, approve
	Lease         string       `json:"lease"`
	HostmapURL    string       `json:"hostmap_url"`
	Zones         []*Zone      `json:"zones"`
	AlwaysAllow   *AlwaysAllow `json:"always_allow"`
}

// Zone is one address block and its policy.
type Zone struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Subnet      string    `json:"subnet"`  // CIDR
	Gateway     string    `json:"gateway"` // IP
	Range       [2]string `json:"range"`   // start, end IPs
	DNS         []string  `json:"dns"`
	Internet    bool      `json:"internet"`
	Captive     bool      `json:"captive"`
	SelfService bool      `json:"self_service"`
	ReachZones  []string  `json:"reach_zones"`
	Block       string    `json:"block"` // firewall block CIDR
}

// AlwaysAllow lists hosts and ports always reachable.
type AlwaysAllow struct {
	Hosts []string `json:"hosts"`
	Ports []string `json:"ports"`
}

// Rule is one classification rule from rules.json.
type Rule struct {
	ID         string                 `json:"id"`
	Zone       string                 `json:"zone"`
	Confidence string                 `json:"confidence"`
	Why        string                 `json:"why"`
	When       map[string]interface{} `json:"when"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "enroll",
		Version:      "1.0",
		Description:  "Device identification and zone-based segmentation.",
		Capabilities: []string{core.CapHostInventory},
		After:        []string{"identity", "firewall"},
		Defaults: map[string]any{
			"enabled":                true,
			"captive_port":           8083,
			"manage_dnsmasq_logging": true,
			"reconcile_seconds":      60,
		},
		Schema: []core.SettingField{
			{Key: "enabled", Label: "Enable device enrollment", Type: "bool"},
			{Key: "captive_port", Label: "Captive portal port", Type: "int", Placeholder: "8083"},
			{Key: "manage_dnsmasq_logging", Label: "Enable dnsmasq DHCP logging", Type: "bool"},
			{Key: "reconcile_seconds", Label: "Reconcile interval (s)", Type: "int", Placeholder: "60"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.devices = map[string]*Device{}
	m.pendingAssign = map[string]string{}
	m.allocations = map[string]*Allocator{}
	m.txnState = map[string]*txnData{}
	m.captiveRate = map[string]int64{}
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.firewall, _ = ctx.Service("firewall").(Firewall)

	// Load zones and rules
	if err := m.loadZones(); err != nil {
		ctx.Log.Warn("load zones", "error", err)
	}
	if err := m.loadRules(); err != nil {
		ctx.Log.Warn("load rules", "error", err)
	}

	// Load device registry from store
	m.loadRegistry()

	enabled := core.Bool(ctx.Settings(), "enabled", false)
	if enabled {
		every := time.Duration(core.Int(ctx.Settings(), "reconcile_seconds", 60)) * time.Second
		ctx.Every("reconcile", every, m.reconcile)
		ctx.Every("dnsmasq-log", 10*time.Second, m.parseDnsmasqLog)

		// Setup dnsmasq logging and tailer
		if ctx.Platform.Name == "opnsense" {
			ctx.Every("dnsmasq-logging", 60*time.Minute, m.setupDnsmasqLogging, core.Delayed())
			ctx.Every("dnsmasq-logging-init", 30*time.Second, func() error {
				return m.setupDnsmasqLogging()
			})
		}

		// Initialize log tailer
		logPath := "/var/log/dnsmasq/latest.log"
		if ctx.Platform.Name == "linux" {
			logPath = "/var/log/dnsmasq.log"
		}
		m.tailer = core.NewTailer(logPath)
	}

	// API routes
	ctx.Route("GET", "/api/enroll", m.apiSummary, core.Doc("Enrollment status, zones and device counts"))
	ctx.Route("GET", "/api/enroll/devices", m.apiDevices, core.Doc("All devices with filtering"),
		core.Params("zone", "filter by zone", "q", "search query"))
	ctx.Route("GET", "/api/enroll/zones", m.apiGetZones, core.Doc("Current zones configuration"))
	ctx.Route("POST", "/api/enroll/zones", m.apiSetZones, core.Write(), core.Doc("Update zones"))
	ctx.Route("GET", "/api/enroll/rules", m.apiGetRules, core.Doc("Current rules configuration"))
	ctx.Route("POST", "/api/enroll/rules", m.apiSetRules, core.Write(), core.Doc("Update rules"))
	ctx.Route("POST", "/api/enroll/assign", m.apiAssign, core.Write(), core.Doc("Assign device to zone"))
	ctx.Route("POST", "/api/enroll/reconcile", m.apiReconcile, core.Write(), core.Doc("Re-classify devices"))
	ctx.Route("POST", "/api/enroll/apply", m.apiApply, core.Write(), core.Doc("Apply enforcement"))
	ctx.Route("GET", "/api/enroll/plan", m.apiPlan, core.Doc("Plan of what apply would do"))
	ctx.Route("POST", "/api/enroll/mode", m.apiSetMode, core.Write(), core.Doc("Set monitor/enforce mode"))

	// Captive portal page
	if enabled {
		captivePort := core.Int(ctx.Settings(), "captive_port", 8083)
		ctx.Route("GET", "/captive", m.captiveGet)
		ctx.Route("POST", "/captive", m.captivePost, core.Write())
		// Start captive portal HTTP server
		go m.serveCaptive(int(captivePort))
	}

	// Panel
	ctx.Panel(core.Panel{ID: "enroll", Title: "Devices & zones", Group: "Policy", Order: 130, Icon: "enroll"})

	// Publish the zone resolver
	m.publishZoneResolver()

	return nil
}

// Stop shuts down the module, including the captive portal listener.
func (m *Module) Stop() {
	if srv, ok := m.captiveServer.(*http.Server); ok && srv != nil {
		_ = srv.Close()
	}
}

// Health returns the module's health status.
func (m *Module) Health() core.Health {
	m.mu.RLock()
	deviceCount := len(m.devices)
	m.mu.RUnlock()

	detail := fmt.Sprintf("%d device(s) in registry", deviceCount)
	notes := []string{}

	if m.lastErr != "" {
		notes = append(notes, m.lastErr)
	}
	if m.lastTailErr != "" {
		notes = append(notes, m.lastTailErr)
	}

	if len(notes) > 0 {
		detail += "; note: " + strings.Join(notes, "; ")
	}

	return core.Health{OK: true, Detail: detail}
}

// ============================================================================
// Data loading and storage
// ============================================================================

func (m *Module) loadZones() error {
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default empty zones
			m.zones = &ZonesDoc{Mode: "monitor", CaptiveZone: "quarantine", Zones: []*Zone{}}
			return nil
		}
		return err
	}

	z := &ZonesDoc{}
	if err := json.Unmarshal(data, z); err != nil {
		return fmt.Errorf("parse zones: %w", err)
	}

	// Validate zones
	seen := map[string]bool{}
	for _, zone := range z.Zones {
		if zone.ID == "" {
			return fmt.Errorf("zone missing id")
		}
		if seen[zone.ID] {
			return fmt.Errorf("duplicate zone id: %s", zone.ID)
		}
		seen[zone.ID] = true

		// Validate CIDR
		if _, _, err := net.ParseCIDR(zone.Subnet); err != nil {
			return fmt.Errorf("zone %s invalid subnet: %w", zone.ID, err)
		}
		if zone.Block == "" {
			zone.Block = zone.Subnet
		}
		if _, _, err := net.ParseCIDR(zone.Block); err != nil {
			return fmt.Errorf("zone %s invalid block: %w", zone.ID, err)
		}

		// Validate range
		start := net.ParseIP(zone.Range[0])
		end := net.ParseIP(zone.Range[1])
		if start == nil || end == nil {
			return fmt.Errorf("zone %s invalid range", zone.ID)
		}

		// Initialize allocator
		m.allocations[zone.ID] = NewAllocator(zone.Subnet, zone.Range[0], zone.Range[1], m.ctx.Log)
	}

	m.zones = z
	return nil
}

func (m *Module) loadRules() error {
	path := filepath.Join(m.ctx.Platform.EtcDir, "enroll-rules.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			m.rules = []*Rule{}
			return nil
		}
		return err
	}

	doc := map[string]interface{}{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}

	rules := []*Rule{}
	if rulesRaw, ok := doc["rules"].([]interface{}); ok {
		for _, r := range rulesRaw {
			ruleMap, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			rule := &Rule{
				When: ruleMap,
			}
			if id, ok := ruleMap["id"].(string); ok {
				rule.ID = id
			}
			if zone, ok := ruleMap["zone"].(string); ok {
				rule.Zone = zone
			}
			if conf, ok := ruleMap["confidence"].(string); ok {
				rule.Confidence = conf
			}
			if why, ok := ruleMap["why"].(string); ok {
				rule.Why = why
			}

			// Validate regexes
			if err := m.validateRuleRegexes(rule); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}

			rules = append(rules, rule)
		}
	}

	m.rules = rules
	return nil
}

func (m *Module) validateRuleRegexes(rule *Rule) error {
	for field := range rule.When {
		if strings.HasSuffix(field, "_re") {
			if val, ok := rule.When[field].(string); ok {
				if _, err := regexp.Compile(val); err != nil {
					return fmt.Errorf("invalid regex %s: %w", field, err)
				}
			}
		}
	}
	return nil
}

func (m *Module) loadRegistry() {
	// Load devices from store
	rows, err := m.ctx.Store.Rows(`SELECT mac, ip, ip6, hostname, vendor, vendor_class, fingerprint,
		zone, class, confidence, rule, why, pinned, randomized, guest_name, guest_kind, user, iface,
		first_seen, last_seen FROM devices`)
	if err != nil {
		m.ctx.Log.Error("load registry", "error", err)
		return
	}

	for _, row := range rows {
		mac := getStr(row, "mac")
		if mac == "" {
			continue
		}
		d := &Device{
			MAC:         mac,
			IP:          getStr(row, "ip"),
			IP6:         getStr(row, "ip6"),
			Hostname:    getStr(row, "hostname"),
			Vendor:      getStr(row, "vendor"),
			VendorClass: getStr(row, "vendor_class"),
			Fingerprint: getStr(row, "fingerprint"),
			Zone:        getStr(row, "zone"),
			Class:       getStr(row, "class"),
			Confidence:  getStr(row, "confidence"),
			Rule:        getStr(row, "rule"),
			Why:         getStr(row, "why"),
			Pinned:      getInt(row, "pinned"),
			Randomized:  getInt(row, "randomized"),
			GuestName:   getStr(row, "guest_name"),
			GuestKind:   getStr(row, "guest_kind"),
			User:        getStr(row, "user"),
			Iface:       getStr(row, "iface"),
			FirstSeen:   getInt64(row, "first_seen"),
			LastSeen:    getInt64(row, "last_seen"),
		}
		m.devices[strings.ToLower(mac)] = d
	}
}

func (m *Module) saveDevice(d *Device) error {
	d.MAC = strings.ToLower(d.MAC)
	d.LastSeen = time.Now().Unix()
	if d.FirstSeen == 0 {
		d.FirstSeen = d.LastSeen
	}
	return m.ctx.Store.Exec(`INSERT OR REPLACE INTO devices
		(mac, ip, ip6, hostname, vendor, vendor_class, fingerprint, zone, class, confidence,
		 rule, why, pinned, randomized, guest_name, guest_kind, user, iface, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.MAC, d.IP, d.IP6, d.Hostname, d.Vendor, d.VendorClass, d.Fingerprint,
		d.Zone, d.Class, d.Confidence, d.Rule, d.Why, d.Pinned, d.Randomized,
		d.GuestName, d.GuestKind, d.User, d.Iface, d.FirstSeen, d.LastSeen)
}

// ============================================================================
// Classification and reconciliation
// ============================================================================

func (m *Module) reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.zones == nil || m.zones.Zones == nil {
		return nil
	}

	// Gather signals from all sources
	signals := m.gatherSignals()

	// Classify each device
	now := time.Now().Unix()
	for mac, sig := range signals {
		d, exists := m.devices[mac]
		if !exists {
			d = &Device{MAC: mac, FirstSeen: now}
			m.devices[mac] = d
		}

		// Update device info from signals
		if sig.IP != "" && d.IP == "" {
			d.IP = sig.IP
		}
		if sig.Hostname != "" && d.Hostname == "" {
			d.Hostname = sig.Hostname
		}
		if sig.Vendor != "" && d.Vendor == "" {
			d.Vendor = sig.Vendor
		}
		if sig.VendorClass != "" && d.VendorClass == "" {
			d.VendorClass = sig.VendorClass
		}
		if sig.Fingerprint != "" && d.Fingerprint == "" {
			d.Fingerprint = sig.Fingerprint
		}

		d.LastSeen = now
		d.Randomized = boolToInt(isRandomizedMAC(mac))

		// Classify
		zone, rule, conf, why := m.classify(d, sig)
		d.Class = zone
		d.Rule = rule
		d.Confidence = conf
		d.Why = why

		// Apply pending assignments
		if pendingZone, ok := m.pendingAssign[mac]; ok {
			d.Zone = pendingZone
			delete(m.pendingAssign, mac)
		} else if d.Zone == "" {
			d.Zone = zone
			if d.Zone == "" {
				d.Zone = m.zones.CaptiveZone
			}
		}

		_ = m.saveDevice(d)
	}

	return nil
}

// gatherSignals collects device information from leases, ARP, identity service, etc.
func (m *Module) gatherSignals() map[string]*Signal {
	signals := map[string]*Signal{}

	// From identity service
	if m.identity != nil {
		// Get all known addresses and their MACs
		// This is a simplification; a real implementation would query
		// the identity service's known hosts more thoroughly
	}

	return signals
}

// Signal carries identifying information about a device.
type Signal struct {
	MAC         string
	IP          string
	IP6         string
	Hostname    string
	Vendor      string
	VendorClass string
	Fingerprint string
}

func (m *Module) classify(d *Device, sig *Signal) (zone, rule, conf, why string) {
	for _, r := range m.rules {
		if m.ruleMatches(r, d, sig) {
			return r.Zone, r.ID, r.Confidence, r.Why
		}
	}
	// No rule matched
	return "", "", "none", "No rule matched this device."
}

func (m *Module) ruleMatches(rule *Rule, d *Device, sig *Signal) bool {
	when := rule.When
	if when == nil {
		return false
	}

	// Check "any" blocks (ORed)
	if anyBlocks, ok := when["any"].([]interface{}); ok {
		matched := false
		for _, block := range anyBlocks {
			if blockMap, ok := block.(map[string]interface{}); ok {
				if m.conditionMatches(blockMap, d, sig) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Check regular conditions (ANDed)
	for key, want := range when {
		if key == "any" {
			continue
		}
		if !m.matchCondition(key, want, d, sig) {
			return false
		}
	}

	return true
}

func (m *Module) conditionMatches(cond map[string]interface{}, d *Device, sig *Signal) bool {
	for key, want := range cond {
		if key == "any" {
			continue
		}
		if !m.matchCondition(key, want, d, sig) {
			return false
		}
	}
	return true
}

func (m *Module) matchCondition(key string, want interface{}, d *Device, sig *Signal) bool {
	switch key {
	case "vendor":
		if vals, ok := want.([]interface{}); ok {
			vendor := strings.ToLower(d.Vendor)
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if strings.Contains(vendor, strings.ToLower(vstr)) {
						return true
					}
				}
			}
			return false
		}
	case "hostname_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.Hostname)
		}
	case "vendor_class_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.VendorClass)
		}
	case "fingerprint_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.Fingerprint)
		}
	case "mac_prefix":
		if vals, ok := want.([]interface{}); ok {
			mac := strings.ToUpper(d.MAC)
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if strings.HasPrefix(mac, strings.ToUpper(vstr)) {
						return true
					}
				}
			}
			return false
		}
	case "guest_kind":
		if vals, ok := want.([]interface{}); ok {
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if d.GuestKind == vstr {
						return true
					}
				}
			}
			return false
		}
	}
	return true
}

// ============================================================================
// Log parsing
// ============================================================================

func (m *Module) parseDnsmasqLog() error {
	if m.tailer == nil {
		return nil
	}

	// Tail the log file
	_, err := m.tailer.Lines(func(line []byte) {
		m.parseDnsmasqLogLine(string(line))
	})

	if err != nil {
		// Missing file is not an error; report in Health
		if os.IsNotExist(err) {
			m.lastTailErr = fmt.Sprintf("dnsmasq DHCP log not yet created (%s)", m.tailer.Path)
		} else {
			m.lastTailErr = err.Error()
		}
		return nil // Don't propagate; log missing is OK
	}

	// Cleanup old transactions every 5 minutes
	now := time.Now()
	if now.Sub(m.lastLogCleanup) > 5*time.Minute {
		m.txnMu.Lock()
		for txnID, txn := range m.txnState {
			if now.Sub(txn.lastActivity) > 10*time.Minute {
				delete(m.txnState, txnID)
			}
		}
		m.lastLogCleanup = now
		m.txnMu.Unlock()
	}

	return nil
}

var (
	// RFC5424 syslog prefix with dnsmasq-dhcp and optional transaction ID
	dnsmasqPrefixRe = regexp.MustCompile(`.*dnsmasq-dhcp.*\[.*\]\s+(?:(\d+)\s+)?(.+)$`)

	// DHCP operation lines with MAC
	dhcpOpRe = regexp.MustCompile(`^(DHCPDISCOVER|DHCPREQUEST|DHCPACK|DHCPNAK)\([^\)]+\)\s+([0-9a-fA-F:]{17})(?:\s+(\S+))?`)

	// Client provides name
	clientNameRe = regexp.MustCompile(`^(\d+)\s+client provides name:\s+(.+)$`)

	// Vendor class
	vendorClassRe = regexp.MustCompile(`^(\d+)\s+vendor class:\s+(.+)$`)

	// Requested options with option numbers
	requestedOptsRe = regexp.MustCompile(`^(\d+)\s+requested options:\s+(.+)$`)
)

func (m *Module) parseDnsmasqLogLine(line string) {
	// Parse RFC5424 syslog line from OPNsense dnsmasq
	// <30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="8"] TEXT
	// Extract the dnsmasq text part (after the syslog prefix)

	match := dnsmasqPrefixRe.FindStringSubmatch(line)
	if match == nil {
		return
	}

	txnID := match[1]
	text := match[2]

	// Lines with transaction ID correlate DHCP data
	if txnID == "" {
		// Try to extract from DHCP operation lines without explicit ID
		txnID = extractTransactionID(text)
		if txnID == "" {
			return
		}
	}

	m.txnMu.Lock()
	defer m.txnMu.Unlock()

	txn := m.txnState[txnID]
	if txn == nil {
		txn = &txnData{}
		m.txnState[txnID] = txn
	}
	txn.lastActivity = time.Now()

	// Parse DHCP operation lines (contain MAC and IP)
	if dhcpMatch := dhcpOpRe.FindStringSubmatch(text); dhcpMatch != nil {
		mac := strings.ToUpper(dhcpMatch[2])
		if !isPseudoMAC(mac) {
			txn.mac = strings.ToLower(mac)
		}
		if dhcpMatch[3] != "" {
			txn.ip = dhcpMatch[3]
		}
		// When we get a DHCPACK with complete info, emit device
		if strings.HasPrefix(text, "DHCPACK") && txn.mac != "" {
			m.emitDeviceFromTransaction(txn)
		}
		return
	}

	// Parse client name
	if nameMatch := clientNameRe.FindStringSubmatch(text); nameMatch != nil {
		if nameMatch[1] == txnID {
			txn.hostname = nameMatch[2]
		}
		return
	}

	// Parse vendor class
	if vendorMatch := vendorClassRe.FindStringSubmatch(text); vendorMatch != nil {
		if vendorMatch[1] == txnID {
			txn.vendorClass = vendorMatch[2]
		}
		return
	}

	// Parse requested options (fingerprint)
	if optsMatch := requestedOptsRe.FindStringSubmatch(text); optsMatch != nil {
		if optsMatch[1] == txnID {
			// Parse "1:netmask, 3:router, 6:dns-server, ..."
			// Build "1,3,6,..." list
			parts := strings.Split(optsMatch[2], ",")
			var opts []string
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if idx := strings.Index(part, ":"); idx > 0 {
					opts = append(opts, part[:idx])
				}
			}
			txn.fingerprint = strings.Join(opts, ",")
		}
		return
	}
}

func extractTransactionID(text string) string {
	// Try to extract TXN ID from DHCP lines like "DHCPDISCOVER... available DHCP range"
	// These lines may have the ID embedded, but we'll just return empty
	// Proper parsing relies on the explicit transaction ID in the syslog header
	return ""
}

func (m *Module) emitDeviceFromTransaction(txn *txnData) {
	if txn.mac == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	d, exists := m.devices[txn.mac]
	if !exists {
		d = &Device{MAC: txn.mac, FirstSeen: time.Now().Unix()}
		m.devices[txn.mac] = d
	}

	if txn.hostname != "" && d.Hostname == "" {
		d.Hostname = txn.hostname
	}
	if txn.vendorClass != "" && d.VendorClass == "" {
		d.VendorClass = txn.vendorClass
	}
	if txn.fingerprint != "" && d.Fingerprint == "" {
		d.Fingerprint = txn.fingerprint
	}
	if txn.ip != "" && d.IP == "" {
		d.IP = txn.ip
	}

	d.LastSeen = time.Now().Unix()
	_ = m.saveDevice(d)
}

// ============================================================================
// API handlers
// ============================================================================

func (m *Module) apiSummary(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	counts := map[string]int{}
	unidentified := 0

	for _, d := range m.devices {
		if d.Zone == "" || d.Zone == m.zones.CaptiveZone {
			unidentified++
		} else {
			counts[d.Zone]++
		}
	}

	return map[string]any{
		"mode":         m.zones.Mode,
		"captive_zone": m.zones.CaptiveZone,
		"zones":        counts,
		"unidentified": unidentified,
		"total":        len(m.devices),
	}, nil
}

func (m *Module) apiDevices(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	zone := r.Q("zone", "")
	q := r.Q("q", "")

	var devices []*Device
	for _, d := range m.devices {
		if zone != "" && d.Zone != zone {
			continue
		}
		if q != "" && !m.matchesQuery(d, q) {
			continue
		}
		devices = append(devices, d)
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].MAC < devices[j].MAC
	})

	return devices, nil
}

func (m *Module) matchesQuery(d *Device, q string) bool {
	lowerQ := strings.ToLower(q)
	return strings.Contains(strings.ToLower(d.MAC), lowerQ) ||
		strings.Contains(strings.ToLower(d.Hostname), lowerQ) ||
		strings.Contains(strings.ToLower(d.Vendor), lowerQ) ||
		strings.Contains(strings.ToLower(d.IP), lowerQ)
}

func (m *Module) apiGetZones(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones, nil
}

func (m *Module) apiSetZones(r *core.Req) (any, error) {
	var zones ZonesDoc
	if err := r.Decode(&zones); err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.zones = &zones
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, _ := json.MarshalIndent(&zones, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("save zones: %w", err)
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiGetRules(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{"rules": m.rules}, nil
}

func (m *Module) apiSetRules(r *core.Req) (any, error) {
	var doc map[string]interface{}
	if err := r.Decode(&doc); err != nil {
		return nil, err
	}

	rules := []*Rule{}
	if rulesRaw, ok := doc["rules"].([]interface{}); ok {
		for _, r := range rulesRaw {
			ruleMap, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			rule := &Rule{When: ruleMap}
			if id, ok := ruleMap["id"].(string); ok {
				rule.ID = id
			}
			if zone, ok := ruleMap["zone"].(string); ok {
				rule.Zone = zone
			}
			if conf, ok := ruleMap["confidence"].(string); ok {
				rule.Confidence = conf
			}
			if why, ok := ruleMap["why"].(string); ok {
				rule.Why = why
			}

			// Validate regexes
			if err := m.validateRuleRegexes(rule); err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
			}

			rules = append(rules, rule)
		}
	}

	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "enroll-rules.json")
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("save rules: %w", err)
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiAssign(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var req struct {
		MAC  string `json:"mac"`
		Zone string `json:"zone"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	mac := strings.ToLower(req.MAC)
	d, exists := m.devices[mac]
	if !exists {
		d = &Device{MAC: mac}
		m.devices[mac] = d
	}

	d.Zone = req.Zone
	_ = m.saveDevice(d)

	return d, nil
}

func (m *Module) apiReconcile(r *core.Req) (any, error) {
	if err := m.reconcile(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiApply(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.zones.Mode != "enforce" {
		return nil, core.BadRequest("mode is %s, not enforce", m.zones.Mode)
	}

	// Generate and apply dnsmasq config
	if err := m.applyDnsmasq(); err != nil {
		return nil, err
	}

	// Generate and apply pf rules
	if err := m.applyFirewall(); err != nil {
		return nil, err
	}

	m.lastApplied = time.Now()
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiPlan(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]any{
		"mode": m.zones.Mode,
		"note": "In " + m.zones.Mode + " mode",
	}, nil
}

func (m *Module) apiSetMode(r *core.Req) (any, error) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if req.Mode != "monitor" && req.Mode != "enforce" {
		return nil, core.BadRequest("mode must be monitor or enforce")
	}

	m.mu.Lock()
	m.zones.Mode = req.Mode
	m.mu.Unlock()

	// Persist
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	m.mu.RLock()
	data, _ := json.MarshalIndent(m.zones, "", "  ")
	m.mu.RUnlock()
	_ = os.WriteFile(path, data, 0o644)

	return map[string]any{"mode": req.Mode}, nil
}

// ============================================================================
// Dnsmasq logging setup
// ============================================================================

func resolveDnsmasqBinary() string {
	// Try explicit paths first
	for _, path := range []string{"/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Fall back to PATH lookup
	if path, err := exec.LookPath("dnsmasq"); err == nil {
		return path
	}
	return ""
}

func (m *Module) setupDnsmasqLogging() error {
	if !m.ctx.Platform.IsOPNsense() {
		return nil
	}

	manage := core.Bool(m.ctx.Settings(), "manage_dnsmasq_logging", true)
	if !manage {
		return nil
	}

	dnsmasqBin := resolveDnsmasqBinary()
	if dnsmasqBin == "" {
		m.lastErr = "dnsmasq binary not found; skipping logging setup"
		return nil
	}

	confPath := filepath.Join(m.ctx.Platform.DnsmasqConfDir, "flowsight-enroll.conf")

	// Write or ensure the config has log-dhcp
	content := "# Generated by Flowsight enroll. Do not edit.\nlog-dhcp\n"
	tmpPath := confPath + ".tmp"

	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq logging config: %w", err)
	}

	// Validate the main config with our addition
	mainConf := "/usr/local/etc/dnsmasq.conf"
	if _, err := core.Run(30*time.Second, dnsmasqBin, "--test", "-C", mainConf); err != nil {
		os.Remove(tmpPath)
		m.lastErr = fmt.Sprintf("dnsmasq config validation failed: %v", err)
		return nil // Report in Health instead of failing the job
	}

	// Move into place
	if err := os.Rename(tmpPath, confPath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Restart dnsmasq
	if _, err := m.ctx.Platform.Service("dnsmasq", "restart"); err != nil {
		// Remove the file on restart failure
		os.Remove(confPath)
		return fmt.Errorf("dnsmasq restart failed: %w", err)
	}

	m.lastErr = ""
	return nil
}

// ============================================================================
// Firewall and DHCP configuration
// ============================================================================

func (m *Module) applyDnsmasq() error {
	// Generate dnsmasq include with zone DHCP ranges and device reservations
	path := filepath.Join(m.ctx.Platform.DnsmasqConfDir, "flowsight-enroll.conf")

	var buf bytes.Buffer
	buf.WriteString("# Generated by Flowsight enroll. Do not edit.\n\n")

	// Write zone ranges
	for _, zone := range m.zones.Zones {
		buf.WriteString(fmt.Sprintf("# Zone: %s - %s\n", zone.ID, zone.Name))
		// dnsmasq range syntax: dhcp-range=tag:zone,start,end,netmask,lease
		// or: dhcp-range=set:tag,start,end,netmask,lease
	}

	// Write device reservations
	for mac, d := range m.devices {
		if d.Zone != "" && d.Zone != m.zones.CaptiveZone {
			// Allocate or retrieve address for this device
			allocator := m.allocations[d.Zone]
			if allocator != nil {
				ip, err := allocator.Allocate(mac)
				if err == nil && ip != "" {
					buf.WriteString(fmt.Sprintf("dhcp-host=%s,%s,%s\n", strings.ToLower(mac), ip, d.Hostname))
				}
			}
		}
	}

	// Write file atomically
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}

	// Validate with dnsmasq --test
	if _, err := core.Run(10*time.Second, "dnsmasq", "--test", "-C", tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("dnsmasq validation failed: %w", err)
	}

	return os.Rename(tmpPath, path)
}

func (m *Module) applyFirewall() error {
	// Generate pf rules for zone isolation
	var buf bytes.Buffer
	buf.WriteString("# Generated by Flowsight enroll. Do not edit.\n\n")

	// Define zone subnets as tables
	for _, zone := range m.zones.Zones {
		buf.WriteString(fmt.Sprintf("table <fs_%s> persist { %s }\n", zone.ID, zone.Subnet))
	}
	buf.WriteString("\n")

	// Zone isolation rules
	for _, zone := range m.zones.Zones {
		if zone.Captive {
			// Captive zone: block everything except gateway and DNS
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to any\n", zone.ID))
			buf.WriteString(fmt.Sprintf("pass quick from <fs_%s> to %s\n", zone.ID, zone.Gateway))
			continue
		}

		// Regular zone: block disallowed reaches
		for _, other := range m.zones.Zones {
			if other.ID == zone.ID || stringInSlice(other.ID, zone.ReachZones) {
				continue
			}
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to <fs_%s>\n", zone.ID, other.ID))
		}

		// Block internet if needed
		if !zone.Internet {
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to !<fs_%s>\n", zone.ID, zone.ID))
		}
	}

	rules := buf.String()
	return m.firewall.LoadAnchor("enroll", rules)
}

// ============================================================================
// Captive portal
// ============================================================================

func (m *Module) captiveGet(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Look up device by source IP to get MAC and info
	mac := ""
	var device *Device
	srcIP := r.Client

	// Find device by IP
	for _, d := range m.devices {
		if d.IP == srcIP {
			mac = d.MAC
			device = d
			break
		}
	}

	// Build available zones list (only self_service ones)
	var zoneOpts []string
	if m.zones != nil {
		for _, zone := range m.zones.Zones {
			if zone.SelfService {
				zoneOpts = append(zoneOpts, fmt.Sprintf(
					`<label><input type="radio" name="zone" value="%s"><b>%s</b><span>%s</span></label>`,
					zone.ID, zone.Name, zone.Description))
			}
		}
	}

	// Build device info display
	deviceInfo := ""
	if device != nil {
		deviceInfo = fmt.Sprintf(`<dl>
<dt>MAC Address</dt><dd>%s</dd>
<dt>Hostname</dt><dd>%s</dd>
<dt>Vendor</dt><dd>%s</dd>
</dl>`, mac, device.Hostname, device.Vendor)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identify This Device</title>
<style>
:root{--accent:#C03E14}
*{box-sizing:border-box}
body{margin:0;background:#f5f5f5;color:#373736;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;justify-content:center;padding:24px 16px}
.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:24px;max-width:520px;width:100%%}
h1{margin:0 0 4px;font-size:21px}
p.sub{margin:0 0 20px;opacity:.7;font-size:14px}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0 0 22px;font-size:13px}
dt{opacity:.6}
dd{margin:0;font-family:ui-monospace,Menlo,monospace}
label{display:block;border:1px solid #ddd;border-radius:9px;padding:12px 14px;margin-bottom:9px;cursor:pointer}
label:hover{border-color:var(--accent)}
label input{margin-right:9px}
label b{font-weight:600}
label span{display:block;margin-left:25px;opacity:.65;font-size:13px}
button{width:100%%;padding:13px;border:0;border-radius:9px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:10px}
</style>
</head><body><div class="card">
<h1>Identify This Device</h1>
<p class="sub">Flowsight doesn't recognize this device. What is it?</p>
%s
<form method="post">
<fieldset style="border:0;padding:0;margin:0">
<legend style="font-weight:600;margin-bottom:10px">Device Type</legend>
%s
</fieldset>
<button type="submit">Continue</button>
</form>
</div></body></html>`, deviceInfo, strings.Join(zoneOpts, ""))

	return core.Raw{ContentType: "text/html; charset=utf-8", Body: []byte(html)}, nil
}

func (m *Module) captivePost(r *core.Req) (any, error) {
	var req struct {
		Zone string `json:"zone"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	srcIP := r.Client
	mac := ""

	m.mu.RLock()
	// Find device by source IP
	for _, d := range m.devices {
		if d.IP == srcIP {
			mac = d.MAC
			break
		}
	}
	m.mu.RUnlock()

	if mac == "" {
		return nil, core.BadRequest("device not found")
	}

	// Check rate limiting: one change per MAC per minute
	m.captiveMuRate.Lock()
	lastChange := m.captiveRate[mac]
	now := time.Now().Unix()
	if now-lastChange < 60 {
		m.captiveMuRate.Unlock()
		return nil, core.BadRequest("please wait at least 60 seconds between changes")
	}
	m.captiveRate[mac] = now
	m.captiveMuRate.Unlock()

	// Validate zone exists
	m.mu.RLock()
	zoneExists := false
	if m.zones != nil {
		for _, z := range m.zones.Zones {
			if z.ID == req.Zone {
				zoneExists = true
				break
			}
		}
	}
	m.mu.RUnlock()

	if !zoneExists {
		return nil, core.BadRequest("invalid zone")
	}

	// Record as event
	m.ctx.Event("enroll", "device self-identified", map[string]any{
		"mac":  mac,
		"zone": req.Zone,
	})

	// Assign the device
	m.mu.Lock()
	d := m.devices[strings.ToLower(mac)]
	if d != nil {
		d.Zone = req.Zone
		_ = m.saveDevice(d)
	}
	m.mu.Unlock()

	// Return confirmation page
	confirmHTML := `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device Identified</title>
<style>
:root{--accent:#C03E14}
*{box-sizing:border-box}
body{margin:0;background:#f5f5f5;color:#373736;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;justify-content:center;padding:24px 16px}
.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:24px;max-width:520px;width:100%}
.ok{border-left:3px solid var(--accent);padding-left:14px}
h1{margin:0 0 4px;font-size:21px;color:var(--accent)}
p{margin:0}
</style>
</head><body><div class="card ok">
<h1>Thank You</h1>
<p>This device has been added to your network. You can now access the internet and your network resources.</p>
</div></body></html>`

	return core.Raw{ContentType: "text/html; charset=utf-8", Body: []byte(confirmHTML)}, nil
}

func (m *Module) serveCaptive(port int) {
	// Create a simple HTTP mux for the captive portal
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.captivePortalHandler)

	addr := net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", port))
	server := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	m.captiveServer = server

	m.ctx.Log.Info("starting captive portal", "addr", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		m.ctx.Log.Error("captive portal error", "error", err)
	}
}

func (m *Module) captivePortalHandler(w http.ResponseWriter, r *http.Request) {
	// Extract client IP
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}

	// Create a fake core.Req for our handlers
	req := &core.Req{Request: r, Client: host}

	var result any
	var err error

	switch r.Method {
	case "GET":
		result, err = m.captiveGet(req)
	case "POST":
		result, err = m.captivePost(req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		var e *core.Error
		if errors.As(err, &e) {
			http.Error(w, e.Error(), e.Status)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if raw, ok := result.(core.Raw); ok {
		w.Header().Set("Content-Type", raw.ContentType)
		w.WriteHeader(http.StatusOK)
		w.Write(raw.Body)
	}
}

// ============================================================================
// Zone resolution for policy
// ============================================================================

func (m *Module) publishZoneResolver() {
	// Wrap the existing member_resolver
	existing := m.ctx.Service("member_resolver")

	resolver := &zoneResolver{
		m:        m,
		delegate: existing.(core.MemberResolver),
	}

	m.ctx.Publish("member_resolver", resolver)
}

type zoneResolver struct {
	m        *Module
	delegate core.MemberResolver
}

func (zr *zoneResolver) Resolve(member string) []string {
	if strings.HasPrefix(member, "zone:") {
		zoneID := strings.TrimPrefix(member, "zone:")
		for _, zone := range zr.m.zones.Zones {
			if zone.ID == zoneID {
				return []string{zone.Subnet}
			}
		}
		return nil
	}

	if zr.delegate != nil {
		return zr.delegate.Resolve(member)
	}
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

func isPseudoMAC(mac string) bool {
	// Broadcast and multicast addresses are destinations, not devices
	mac = strings.ToUpper(mac)
	if mac == "FF:FF:FF:FF:FF:FF" || mac == "" {
		return true
	}
	if strings.HasPrefix(mac, "01:00:5E") || strings.HasPrefix(mac, "33:33") {
		return true
	}
	// Check if multicast bit (bit 0 of first octet) is set
	if len(mac) >= 2 {
		var b byte
		fmt.Sscanf(mac[0:2], "%x", &b)
		if (b & 0x01) != 0 {
			return true
		}
	}
	return false
}

func isRandomizedMAC(mac string) bool {
	mac = strings.ToLower(mac)
	if len(mac) < 2 {
		return false
	}
	// Second hex digit is bit 1 of the first byte
	// Bit 1 = 1 means locally administered
	firstByte := mac[0:2]
	var b byte
	fmt.Sscanf(firstByte, "%x", &b)
	return (b & 0x02) != 0
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func getStr(row map[string]any, key string) string {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(row map[string]any, key string) int {
	if v, ok := row[key]; ok {
		if i, ok := v.(int64); ok {
			return int(i)
		}
	}
	return 0
}

func getInt64(row map[string]any, key string) int64 {
	if v, ok := row[key]; ok {
		if i, ok := v.(int64); ok {
			return i
		}
	}
	return 0
}

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
