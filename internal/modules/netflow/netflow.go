// Package netflow implements a collector module for NetFlow v5/v9, IPFIX, and sFlow v5.
// It listens on configurable UDP ports, parses flow records from network devices,
// and converts them to core.Flow for storage and enrichment alongside ntopng flows.
package netflow

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Module implements the netflow collector.
type Module struct {
	ctx        *core.Context
	mu         sync.RWMutex
	collectors map[string]*collector
	exporters  map[string]*exporterState
	identity   core.Identity
	lastErr    string
	lastOK     time.Time
	stopOnce   sync.Once
	stopSignal chan struct{}
	wg         sync.WaitGroup
}

// collector holds a single UDP socket and its listeners.
type collector struct {
	protocol string // "netflow5", "netflow9", "ipfix", "sflow5"
	conn     *net.UDPConn
	stop     chan struct{}
	wg       sync.WaitGroup
	m        *Module
}

// exporterState tracks per-exporter metrics and templates.
type exporterState struct {
	addr         string
	protocol     string
	recordsTotal uint64
	flowsTotal   uint64
	dropsTotal   uint64
	lastSeen     time.Time

	// Template caches: LRU with max 64 templates per exporter
	tmplCache9 *templateCache
	tmplCacheI *templateCache
}

type template9 struct {
	domainID   uint16
	templateID uint16
	fields     []field9
}

type field9 struct {
	fieldType uint16
	length    uint16
}

type templateIP struct {
	domainID   uint16
	templateID uint16
	fields     []fieldIP
}

type fieldIP struct {
	id      uint16
	length  uint16
	length_ bool // true if length was variable (65535)
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "netflow", Version: "1.0",
		Description:  "UDP flow collectors for NetFlow v5/v9, IPFIX, and sFlow v5.",
		Capabilities: []string{core.CapTrafficObserve},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"enabled":           false,
			"bind_address":      "",
			"netflow5_port":     2055,
			"netflow9_port":     2055,
			"ipfix_port":        2055,
			"sflow5_port":       6343,
			"allowed_cidrs":     "",
			"sampling_override": 0,
			"max_exporters":     100,
		},
		Schema: []core.SettingField{
			{Key: "enabled", Label: "Enable netflow collectors", Type: "bool",
				Section: "Network Flow Collection", Help: "UDP listeners must be turned on before exporters can connect."},
			{Key: "bind_address", Label: "Bind address", Type: "string", Placeholder: "LAN address or 0.0.0.0",
				Section: "Network Flow Collection", Help: "Leave empty to use the platform default LAN bind address."},
			{Key: "netflow5_port", Label: "NetFlow v5 port", Type: "int",
				Section: "Network Flow Collection"},
			{Key: "netflow9_port", Label: "NetFlow v9 port", Type: "int",
				Section: "Network Flow Collection"},
			{Key: "ipfix_port", Label: "IPFIX port", Type: "int",
				Section: "Network Flow Collection"},
			{Key: "sflow5_port", Label: "sFlow v5 port", Type: "int",
				Section: "Network Flow Collection"},
			{Key: "allowed_cidrs", Label: "Allowed exporter CIDRs", Type: "text",
				Section: "Security", Help: "Newline-separated. Leave empty for local networks only (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local)."},
			{Key: "sampling_override", Label: "Sampling multiplier", Type: "int",
				Section: "Data", Help: "Multiply bytes/packets by this value (0 = use flow-provided rate)."},
			{Key: "max_exporters", Label: "Maximum concurrent exporters", Type: "int",
				Section: "Data", Help: "Drop records from exporters beyond this limit."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.collectors = make(map[string]*collector)
	m.exporters = make(map[string]*exporterState)
	m.stopSignal = make(chan struct{})
	identity, _ := ctx.Service("identity").(core.Identity)
	m.identity = identity

	ctx.Route("GET", "/api/netflow/status", m.apiStatus,
		core.Doc("Per-exporter status: protocol, records, flows, drops, templates, last seen, bytes"))

	ctx.Panel(core.Panel{ID: "flowsources", Title: "Flow sources", Group: "Monitor", Order: 35, Icon: "flows"})

	ctx.Every("reap_exporters", 10*time.Minute, m.reapExporters, core.Delayed())

	return m.reconfigure(ctx.Settings())
}

func (m *Module) reconfigure(s map[string]any) error {
	if !core.Bool(s, "enabled", false) {
		m.Stop()
		return nil
	}

	bind := core.Str(s, "bind_address", "")
	if bind == "" {
		bind = "0.0.0.0"
	}

	ports := map[string]int{
		"netflow5": core.Int(s, "netflow5_port", 2055),
		"netflow9": core.Int(s, "netflow9_port", 2055),
		"ipfix":    core.Int(s, "ipfix_port", 2055),
		"sflow5":   core.Int(s, "sflow5_port", 6343),
	}

	_ = m.parseAllowedCIDRs(core.Str(s, "allowed_cidrs", ""))

	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop existing collectors not in this config or with different bind
	for name, c := range m.collectors {
		// Protocol names: "netflow5", "netflow9", "ipfix", "sflow5"
		var proto string
		switch name {
		case "netflow5", "netflow9", "ipfix", "sflow5":
			proto = name
		default:
			continue
		}
		if ports[proto] <= 0 || bind != c.conn.LocalAddr().(*net.UDPAddr).IP.String() {
			c.stop <- struct{}{}
			delete(m.collectors, name)
		}
	}

	// Start new collectors
	for proto, port := range ports {
		if port <= 0 {
			continue
		}
		if _, ok := m.collectors[proto]; ok {
			continue // already running
		}

		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", bind, port))
		if err != nil {
			m.lastErr = err.Error()
			return err
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			m.lastErr = err.Error()
			return err
		}
		if err := conn.SetReadBuffer(1 << 20); err != nil { // 1MB read buffer
			conn.Close()
			return err
		}

		c := &collector{
			protocol: proto,
			conn:     conn,
			stop:     make(chan struct{}),
			m:        m,
		}
		m.collectors[proto] = c

		// Start listener goroutine
		c.wg.Add(1)
		go c.listen()
	}

	m.lastErr = ""
	m.lastOK = time.Now()

	return nil
}

func (m *Module) OnConfigChange(s map[string]any) error {
	return m.reconfigure(s)
}

func (m *Module) Health() core.Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if m.lastOK.IsZero() {
		return core.Health{OK: true, Detail: "waiting for first packet"}
	}
	numExporters := len(m.exporters)
	numFlows := uint64(0)
	for _, ex := range m.exporters {
		numFlows += atomic.LoadUint64(&ex.flowsTotal)
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("%d exporters, %d flows", numExporters, numFlows)}
}

func (m *Module) Stop() {
	m.stopOnce.Do(func() {
		m.mu.Lock()
		for _, c := range m.collectors {
			select {
			case c.stop <- struct{}{}:
			default:
			}
		}
		m.collectors = make(map[string]*collector)
		m.mu.Unlock()
		close(m.stopSignal)
	})
}

// parseAllowedCIDRs parses newline-separated CIDR strings.
// If empty, defaults to RFC1918 and link-local.
func (m *Module) parseAllowedCIDRs(cidrs string) []*net.IPNet {
	defaults := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local
		"fe80::/10",      // IPv6 link-local
	}

	if cidrs == "" {
		cidrs = ""
		for _, d := range defaults {
			cidrs += d + "\n"
		}
	}

	var allowed []*net.IPNet
	for _, line := range splitLines(cidrs) {
		_, net_, err := net.ParseCIDR(line)
		if err == nil && net_ != nil {
			allowed = append(allowed, net_)
		}
	}
	return allowed
}

func splitLines(s string) []string {
	var out []string
	var buf string
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if buf != "" {
				out = append(out, buf)
				buf = ""
			}
		} else {
			buf += string(c)
		}
	}
	if buf != "" {
		out = append(out, buf)
	}
	return out
}

// listener goroutine for one collector
func (c *collector) listen() {
	defer c.wg.Done()
	buf := make([]byte, 64*1024) // 64KB max UDP packet
	for {
		select {
		case <-c.stop:
			c.conn.Close()
			return
		default:
		}

		// Set a read deadline so we can check stop signal periodically
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, remoteAddr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return
		}

		if n == 0 {
			continue
		}

		// Check allowed CIDR
		allowed := c.m.ctx.Settings()["allowed_cidrs"]
		var allowedNets []*net.IPNet
		if allowedStr, ok := allowed.(string); ok && allowedStr != "" {
			allowedNets = c.m.parseAllowedCIDRs(allowedStr)
		} else {
			allowedNets = c.m.parseAllowedCIDRs("")
		}
		if !isIPAllowed(remoteAddr.IP, allowedNets) {
			continue
		}

		// Dispatch to handler based on protocol
		packet := buf[:n]
		go func() {
			defer func() { recover() }()
			switch c.protocol {
			case "netflow5":
				c.handleNetFlow5(packet, remoteAddr)
			case "netflow9":
				c.handleNetFlow9(packet, remoteAddr)
			case "ipfix":
				c.handleIPFIX(packet, remoteAddr)
			case "sflow5":
				c.handleSFlow5(packet, remoteAddr)
			}
		}()
	}
}

func isIPAllowed(ip net.IP, allowed []*net.IPNet) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, net_ := range allowed {
		if net_.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *collector) getExporter(addr string) *exporterState {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()

	if ex, ok := c.m.exporters[addr]; ok {
		ex.lastSeen = time.Now()
		return ex
	}

	if len(c.m.exporters) >= core.Int(c.m.ctx.Settings(), "max_exporters", 100) {
		// Drop this exporter
		return nil
	}

	ex := &exporterState{
		addr:       addr,
		protocol:   c.protocol,
		lastSeen:   time.Now(),
		tmplCache9: newTemplateCache(64),
		tmplCacheI: newTemplateCache(64),
	}
	c.m.exporters[addr] = ex
	return ex
}

func (m *Module) reapExporters() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-30 * time.Minute)
	for addr, ex := range m.exporters {
		if ex.lastSeen.Before(cutoff) {
			delete(m.exporters, addr)
		}
	}
	return nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var exporters []map[string]any
	for addr, ex := range m.exporters {
		templates := 0
		if ex.tmplCache9 != nil {
			templates += ex.tmplCache9.Count()
		}
		if ex.tmplCacheI != nil {
			templates += ex.tmplCacheI.Count()
		}
		exporters = append(exporters, map[string]any{
			"address":       addr,
			"protocol":      ex.protocol,
			"records_total": atomic.LoadUint64(&ex.recordsTotal),
			"flows_total":   atomic.LoadUint64(&ex.flowsTotal),
			"drops_total":   atomic.LoadUint64(&ex.dropsTotal),
			"templates":     templates,
			"last_seen":     ex.lastSeen.Unix(),
		})
	}

	return map[string]any{
		"enabled":   core.Bool(m.ctx.Settings(), "enabled", false),
		"exporters": exporters,
		"ok":        m.lastErr == "",
		"error":     m.lastErr,
	}, nil
}
