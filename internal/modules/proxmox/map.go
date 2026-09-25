package proxmox

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Edge represents a dependency between guests
type Edge struct {
	From   int    `json:"from"` // source VMID
	To     int    `json:"to"`   // dest VMID
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Flows  int64  `json:"flows"`
	Bytes  int64  `json:"bytes"`
	Source string `json:"source"` // "observed", "declared", "sockets"
}

// ExternalDep represents an external dependency
type ExternalDep struct {
	Guest       int    `json:"guest"` // VMID
	Destination string `json:"destination"`
	Name        string `json:"name"`
	Bytes       int64  `json:"bytes"`
}

// Requirements holds parsed guest requirements
type Requirements struct {
	VMID         int                  `json:"vmid"`
	Node         string               `json:"node"`
	StartupOrder int                  `json:"startup_order,omitempty"`
	StartupUp    int                  `json:"startup_up,omitempty"`
	StartupDown  int                  `json:"startup_down,omitempty"`
	Cores        int                  `json:"cores,omitempty"`
	Memory       int64                `json:"memory,omitempty"`
	Storage      map[string]string    `json:"storage,omitempty"` // disk -> storage
	Bridges      []string             `json:"bridges,omitempty"`
	VLANs        []int                `json:"vlans,omitempty"`
	HA           string               `json:"ha,omitempty"`
	Tags         []string             `json:"tags,omitempty"`
	CloneOf      int                  `json:"clone_of,omitempty"`
	TemplateOf   []int                `json:"template_of,omitempty"`
	Features     []string             `json:"features,omitempty"`
	AgentFacts   map[string]string    `json:"agent_facts,omitempty"`
	DependsOn    []DependencyRelation `json:"depends_on,omitempty"`
	DependentOn  []DependencyRelation `json:"dependent_on,omitempty"`
	ExternalDeps []ExternalDep        `json:"external_deps,omitempty"`
}

type DependencyRelation struct {
	VMID   int    `json:"vmid"`
	Name   string `json:"name"`
	Port   int    `json:"port,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Source string `json:"source"`
}

// MapResponse is the response for the map API
type MapResponse struct {
	Guests       []Guest                 `json:"guests"`
	Edges        []Edge                  `json:"edges"`
	External     []ExternalDep           `json:"external"`
	Requirements map[string]Requirements `json:"requirements"`
}

// apiMap returns the dependency map
func (m *Module) apiMap(r *core.Req) (any, error) {
	hours := intFromQ(r.Q("hours", "24"), 24)
	if hours < 1 {
		hours = 1
	}
	if hours > 168 {
		hours = 168
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inventory == nil || len(m.inventory.Guests) == 0 {
		return &MapResponse{
			Guests:       []Guest{},
			Edges:        []Edge{},
			External:     []ExternalDep{},
			Requirements: make(map[string]Requirements),
		}, nil
	}

	resp := &MapResponse{
		Guests:       m.inventory.Guests,
		Edges:        []Edge{},
		External:     []ExternalDep{},
		Requirements: make(map[string]Requirements),
	}

	// Build guest VMID -> Guest map for lookups
	guestByVMID := make(map[int]*Guest)
	ipToGuest := make(map[string]int)  // IP -> VMID
	macToGuest := make(map[string]int) // MAC -> VMID
	for i := range m.inventory.Guests {
		g := &m.inventory.Guests[i]
		guestByVMID[g.VMID] = g
		for _, ip := range g.IPs {
			ipToGuest[ip] = g.VMID
		}
		for _, mac := range g.MACs {
			macToGuest[strings.ToLower(mac)] = g.VMID
		}
	}

	// Get observed traffic edges from rollups
	resp.Edges = append(resp.Edges, m.getObservedEdges(hours, ipToGuest, guestByVMID)...)

	// Get declared edges and requirements from config
	declaredEdges := m.getDeclaredEdges(guestByVMID)
	resp.Edges = append(resp.Edges, declaredEdges...)
	// What VMs report from the inside, when the socket probe is on.
	resp.Edges = append(resp.Edges, m.socketEdges(ipToGuest)...)

	// Get external dependencies
	resp.External = m.getExternalDeps(hours, ipToGuest, guestByVMID)

	// Build requirements for each guest
	for _, guest := range m.inventory.Guests {
		req := m.buildRequirements(&guest, guestByVMID, resp.Edges, resp.External)
		key := fmt.Sprintf("%d:%s", guest.VMID, guest.Node)
		resp.Requirements[key] = req
	}

	return resp, nil
}

// apiRequirements returns requirements for a specific guest
func (m *Module) apiRequirements(r *core.Req) (any, error) {
	vmidStr := r.Q("vmid", "")
	node := r.Q("node", "")

	m.mu.Lock()
	defer m.mu.Unlock()

	guest, found := m.findGuest(vmidStr, node)
	if !found {
		return nil, fmt.Errorf("guest not found")
	}

	// Build guest maps
	guestByVMID := make(map[int]*Guest)
	for i := range m.inventory.Guests {
		g := &m.inventory.Guests[i]
		guestByVMID[g.VMID] = g
	}

	// Get edges for this guest
	hours := intFromQ(r.Q("hours", "24"), 24)
	if hours < 1 {
		hours = 1
	}
	ipToGuest := make(map[string]int)
	for _, g := range m.inventory.Guests {
		for _, ip := range g.IPs {
			ipToGuest[ip] = g.VMID
		}
	}

	// Get all edges
	var edges []Edge
	edges = append(edges, m.getObservedEdges(hours, ipToGuest, guestByVMID)...)
	edges = append(edges, m.getDeclaredEdges(guestByVMID)...)
	edges = append(edges, m.socketEdges(ipToGuest)...)

	guestIPMap := map[string]int{}
	for _, ip := range guest.IPs {
		guestIPMap[ip] = guest.VMID
	}
	external := m.getExternalDeps(hours, guestIPMap, guestByVMID)
	req := m.buildRequirements(&guest, guestByVMID, edges, external)
	return req, nil
}

func (m *Module) getObservedEdges(hours int, ipToGuest map[string]int, guestByVMID map[int]*Guest) []Edge {
	var edges []Edge
	windowSeconds := int64(hours * 3600)
	cutoff := time.Now().Unix() - windowSeconds

	// Only rows that touch a guest address on the destination side matter
	// (both ends must be guests for an edge), and rollup_dst is indexed on
	// dst_ip; a whole-table aggregation over a day took minutes on the
	// gateway and timed the page out.
	ips := make([]string, 0, len(ipToGuest))
	for ip := range ipToGuest {
		ips = append(ips, ip)
	}
	var rows []map[string]any
	for i := 0; i < len(ips); i += 200 {
		j := i + 200
		if j > len(ips) {
			j = len(ips)
		}
		ph := make([]string, 0, j-i)
		args := []any{cutoff}
		for _, ip := range ips[i:j] {
			ph = append(ph, "?")
			args = append(args, ip)
		}
		part, err := m.ctx.Store.Rows(
			`SELECT src_ip, dst_ip, dst_port, proto, SUM(flows) as flows, SUM(bytes_in+bytes_out) as bytes
			 FROM rollup_dst WHERE bucket >= ? AND dst_ip IN (`+strings.Join(ph, ",")+`) GROUP BY src_ip, dst_ip, dst_port, proto`,
			args...)
		if err != nil {
			return edges
		}
		rows = append(rows, part...)
	}

	edgeMap := make(map[string]*Edge)

	for _, row := range rows {
		srcIP, _ := row["src_ip"].(string)
		dstIP, _ := row["dst_ip"].(string)
		proto, _ := row["proto"].(string)
		dstPort, _ := row["dst_port"].(int64)
		flows, _ := row["flows"].(int64)
		bytes, _ := row["bytes"].(int64)

		fromVMID, fromOK := ipToGuest[srcIP]
		toVMID, toOK := ipToGuest[dstIP]

		if !fromOK || !toOK {
			continue // Not guest-to-guest
		}

		key := fmt.Sprintf("%d:%d:%d:%s", fromVMID, toVMID, dstPort, proto)
		if existing, ok := edgeMap[key]; ok {
			existing.Flows += flows
			existing.Bytes += bytes
		} else {
			edgeMap[key] = &Edge{
				From:   fromVMID,
				To:     toVMID,
				Port:   int(dstPort),
				Proto:  proto,
				Flows:  flows,
				Bytes:  bytes,
				Source: "observed",
			}
		}
	}

	for _, edge := range edgeMap {
		edges = append(edges, *edge)
	}

	return edges
}

func (m *Module) getDeclaredEdges(guestByVMID map[int]*Guest) []Edge {
	var edges []Edge

	// Parse startup order and dependencies
	for _, guest := range guestByVMID {
		// Startup order creates an implicit dependency
		if strings.Contains(guest.Description, "startup:") {
			// If this guest has startup=order=N, all guests with order < N should run first
			// This is a weak dependency, marked as declared
		}

		// Parse bridges and see if other guests share them
		for _, mac := range guest.MACs {
			for otherVMID, other := range guestByVMID {
				if otherVMID == guest.VMID {
					continue
				}
				for _, otherMAC := range other.MACs {
					if mac == otherMAC {
						// Same bridge/network
						edges = append(edges, Edge{
							From:   guest.VMID,
							To:     otherVMID,
							Source: "declared",
						})
					}
				}
			}
		}
	}

	return edges
}

func (m *Module) getExternalDeps(hours int, ipToGuest map[string]int, guestByVMID map[int]*Guest) []ExternalDep {
	var deps []ExternalDep

	if len(ipToGuest) == 0 {
		return deps
	}

	windowSeconds := int64(hours * 3600)
	cutoff := time.Now().Unix() - windowSeconds

	// Get identity module for local network checking
	identity, _ := m.ctx.Service("identity").(core.Identity)

	// Build placeholders and args for guest IPs
	var placeholders []string
	var args []interface{}
	args = append(args, cutoff)
	for ip := range ipToGuest {
		placeholders = append(placeholders, "?")
		args = append(args, ip)
	}

	// Query rollup_dst for external destinations from guest IPs
	rows, err := m.ctx.Store.Rows(
		`SELECT dst_ip, SUM(flows) as flows, SUM(bytes_in+bytes_out) as bytes
		 FROM rollup_dst WHERE bucket >= ? AND src_ip IN (
		 	`+strings.Join(placeholders, ",")+`
		 ) GROUP BY dst_ip ORDER BY bytes DESC LIMIT 20`,
		args...)
	if err != nil {
		return deps
	}

	// Build external dependency list, filtering out local IPs
	extDepMap := make(map[string]*ExternalDep)
	for _, row := range rows {
		dstIP, _ := row["dst_ip"].(string)
		bytes, _ := row["bytes"].(int64)

		// Skip if destination is local or belongs to a guest
		if dstIP == "" || ipToGuest[dstIP] > 0 {
			continue
		}
		if identity != nil && identity.IsLocal(dstIP) {
			continue
		}

		// Check if we already have this IP
		if existing, ok := extDepMap[dstIP]; ok {
			existing.Bytes += bytes
		} else {
			extDepMap[dstIP] = &ExternalDep{
				Destination: dstIP,
				Bytes:       bytes,
			}
		}
	}

	// Try to resolve domain names from identity
	if identity != nil {
		for dstIP := range extDepMap {
			if name := identity.Name(dstIP); name != "" {
				extDepMap[dstIP].Name = name
			}
		}
	}

	// Convert to slice and keep only top 8
	for _, dep := range extDepMap {
		deps = append(deps, *dep)
	}
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Bytes > deps[j].Bytes
	})
	if len(deps) > 8 {
		deps = deps[:8]
	}

	return deps
}

func (m *Module) buildRequirements(guest *Guest, guestByVMID map[int]*Guest, edges []Edge, external []ExternalDep) Requirements {
	req := Requirements{
		VMID:       guest.VMID,
		Node:       guest.Node,
		Cores:      guest.Cores,
		Memory:     guest.Memory,
		Tags:       guest.Tags,
		Storage:    make(map[string]string),
		AgentFacts: make(map[string]string),
	}

	// Parse startup order, storage, bridges from description/config
	// This is complex and would need more parsing logic

	// Collect edges involving this guest
	for _, edge := range edges {
		if edge.From == guest.VMID && edge.To != guest.VMID {
			req.DependsOn = append(req.DependsOn, DependencyRelation{
				VMID:   edge.To,
				Port:   edge.Port,
				Proto:  edge.Proto,
				Source: edge.Source,
			})
		}
		if edge.To == guest.VMID && edge.From != guest.VMID {
			req.DependentOn = append(req.DependentOn, DependencyRelation{
				VMID:   edge.From,
				Port:   edge.Port,
				Proto:  edge.Proto,
				Source: edge.Source,
			})
		}
	}

	// Deduplicate relations
	req.DependsOn = dedupeRelations(req.DependsOn, guestByVMID)
	req.DependentOn = dedupeRelations(req.DependentOn, guestByVMID)

	// External dependencies come from the one query the caller already ran
	// for every guest; a query per guest scanned the day's rollup 57 times.
	for _, d := range external {
		if d.Guest == guest.VMID {
			req.ExternalDeps = append(req.ExternalDeps, d)
		}
	}

	return req
}

func dedupeRelations(rels []DependencyRelation, guestByVMID map[int]*Guest) []DependencyRelation {
	seen := make(map[string]DependencyRelation)
	for _, rel := range rels {
		if guest, ok := guestByVMID[rel.VMID]; ok {
			rel.Name = guest.Name
		}
		key := fmt.Sprintf("%d:%d:%s:%s", rel.VMID, rel.Port, rel.Proto, rel.Source)
		if existing, ok := seen[key]; ok {
			// Keep the entry with more information
			if rel.Port != 0 && existing.Port == 0 {
				seen[key] = rel
			}
		} else {
			seen[key] = rel
		}
	}

	var result []DependencyRelation
	for _, rel := range seen {
		result = append(result, rel)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].VMID != result[j].VMID {
			return result[i].VMID < result[j].VMID
		}
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		return result[i].Proto < result[j].Proto
	})
	return result
}

// intFromQ converts string to int with default
func intFromQ(s string, def int) int {
	var i int
	if _, err := fmt.Sscanf(s, "%d", &i); err != nil {
		return def
	}
	return i
}

// parseStartupOrder extracts order, up, down from startup config string
func parseStartupOrder(startup string) (order int, up int, down int) {
	// Format: order=N,up=S,down=S
	parts := strings.Split(startup, ",")
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			continue
		}
		key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch key {
		case "order":
			fmt.Sscanf(val, "%d", &order)
		case "up":
			fmt.Sscanf(val, "%d", &up)
		case "down":
			fmt.Sscanf(val, "%d", &down)
		}
	}
	return
}

// extractStorageFromConfig finds all storage mounts and their storage backend
func extractStorageFromConfig(config map[string]interface{}) map[string]string {
	storage := make(map[string]string)
	storageRe := regexp.MustCompile(`^(scsi|virtio|sata|ide|rootfs|mp)(\d*)$`)

	for key, val := range config {
		if matches := storageRe.FindStringSubmatch(key); matches != nil {
			if s, ok := val.(string); ok {
				// Extract storage backend from value: storage:volume,... or local-lvm:volume,...
				parts := strings.Split(s, ",")
				if len(parts) > 0 {
					// First part is the storage identifier
					storage[key] = parts[0]
				}
			}
		}
	}
	return storage
}

// extractBridgesFromConfig finds all bridges and VLAN tags
func extractBridgesFromConfig(config map[string]interface{}) ([]string, []int) {
	var bridges []string
	var vlans []int
	netRe := regexp.MustCompile(`^net\d+$`)

	for key, val := range config {
		if netRe.MatchString(key) {
			if s, ok := val.(string); ok {
				parts := strings.Split(s, ",")
				for _, part := range parts {
					if strings.HasPrefix(part, "bridge=") {
						bridge := strings.TrimPrefix(part, "bridge=")
						bridges = append(bridges, bridge)
					}
					if strings.HasPrefix(part, "tag=") {
						var vlan int
						fmt.Sscanf(strings.TrimPrefix(part, "tag="), "%d", &vlan)
						if vlan > 0 {
							vlans = append(vlans, vlan)
						}
					}
				}
			}
		}
	}
	return dedupeStrings(bridges), dedupeInts(vlans)
}

func dedupeStrings(s []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range s {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	return result
}

func dedupeInts(s []int) []int {
	seen := make(map[int]bool)
	var result []int
	for _, v := range s {
		if !seen[v] {
			result = append(result, v)
			seen[v] = true
		}
	}
	sort.Ints(result)
	return result
}
