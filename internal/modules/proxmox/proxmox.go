// Package proxmox maps Proxmox VE host and guest information into FlowSight
// for inventory, enrichment, and optional notes write-back.
package proxmox

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx           *core.Context
	client        *http.Client
	insecureHTTP  *http.Client
	mu            sync.Mutex
	inventory     *Inventory
	lastPollTime  int64
	lastPollError string
	polling       sync.Mutex
}

type Inventory struct {
	Nodes  []Node   `json:"nodes"`
	Guests []Guest  `json:"guests"`
	LastAt int64    `json:"last_at"`
	Errors []string `json:"errors"`
}

type Node struct {
	Name       string `json:"name"`
	PVEVersion string `json:"pve_version"`
	CPU        int    `json:"cpu"`         // percentage * 100
	MemPercent int    `json:"mem_percent"` // percentage * 100
	Uptime     int64  `json:"uptime"`
	Load       string `json:"load"`
	RootFSPct  int    `json:"rootfs_pct"`
	Kernel     string `json:"kernel"`
}

type Guest struct {
	VMID           int      `json:"vmid"`
	Type           string   `json:"type"` // "qemu" or "lxc"
	Node           string   `json:"node"`
	Name           string   `json:"name"`
	Status         string   `json:"status"` // "running", "stopped"
	Tags           []string `json:"tags"`
	MACs           []string `json:"macs"`
	IPs            []string `json:"ips"`
	OS             string   `json:"os"`
	OSType         string   `json:"ostype,omitempty"`
	Hostname       string   `json:"hostname"`
	Cores          int      `json:"cores"`
	Memory         int64    `json:"memory"`
	Uptime         int64    `json:"uptime,omitempty"`
	AgentState     string   `json:"agent_state"`
	Description    string   `json:"description"`
	NotesSyncedAt  int64    `json:"notes_synced_at"`
	DescriptionSet bool     `json:"description_set"`
}

type GuestInventoryService interface {
	GuestFor(macOrIP string) (Guest, bool)
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "proxmox",
		Version:      "1.0",
		Description:  "Proxmox VE inventory: host, node, and guest information with optional notes write-back and enrichment",
		Capabilities: []string{core.CapHostInventory},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"enabled":       true,
			"hosts":         []string{},
			"token_id":      "",
			"token_secret":  "",
			"fingerprint":   "",
			"verify_tls":    false,
			"poll_minutes":  5,
			"write_notes":   false,
			"notes_targets": "guests",
			"exclude_vmids": []string{},
			"name_guests":   true,
		},
		Schema: []core.SettingField{
			{Key: "hosts", Label: "Proxmox nodes", Type: "list",
				Help: "One URL per line, e.g. https://pve.local:8006. Empty: module idles."},
			{Key: "token_id", Label: "API token ID", Type: "string",
				Help: "Format: user@realm!tokenname, e.g. flowsight@pve!flowsight"},
			{Key: "token_secret", Label: "API token secret", Type: "secret"},
			{Key: "fingerprint", Label: "TLS fingerprint (SHA-256)", Type: "string",
				Help: "Colon-separated hex, e.g. 4C:9E:F6:... Pinned cert verification."},
			{Key: "verify_tls", Label: "Verify TLS with system roots", Type: "bool",
				Help: "Off: use fingerprint pinning. On: system CA roots + pinned cert if set."},
			{Key: "poll_minutes", Label: "Poll interval (minutes)", Type: "int"},
			{Key: "write_notes", Label: "Write notes to guest descriptions", Type: "bool"},
			{Key: "notes_targets", Label: "Write notes to", Type: "string",
				Help: "guests or guests+nodes"},
			{Key: "exclude_vmids", Label: "Exclude VMs (comma-separated vmids)", Type: "list"},
			{Key: "name_guests", Label: "Use guest names when no lease hostname", Type: "bool"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.inventory = &Inventory{Guests: []Guest{}, Nodes: []Node{}}

	// Set up HTTP clients
	tlsConfig := &tls.Config{}
	if !core.Bool(ctx.Settings(), "verify_tls", false) {
		tlsConfig.InsecureSkipVerify = true
	}
	m.insecureHTTP = &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	m.client = m.insecureHTTP

	if fingerprint := core.Str(ctx.Settings(), "fingerprint", ""); fingerprint != "" {
		m.client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					VerifyPeerCertificate: m.makePinVerifier(fingerprint),
					InsecureSkipVerify:    true,
				},
			},
		}
	}

	// Load inventory from KV
	_ = m.ctx.Store.KVGet("proxmox.inventory", m.inventory)

	// Register routes
	ctx.Route("GET", "/api/proxmox/inventory", m.apiInventory, core.Doc("Nodes and guests"))
	ctx.Route("GET", "/api/proxmox/status", m.apiStatus, core.Doc("Connection status and last poll"))
	ctx.Route("POST", "/api/proxmox/poll", m.apiPoll, core.Write(), core.Doc("Poll now"))
	ctx.Route("GET", "/api/proxmox/guest", m.apiGuest, core.Doc("Guest by VMID and node"))
	ctx.Route("GET", "/api/proxmox/notes/preview", m.apiNotesPreview, core.Doc("Preview notes block"))
	ctx.Route("POST", "/api/proxmox/notes/write", m.apiNotesWrite, core.Write(), core.Doc("Write notes"))
	ctx.Route("GET", "/api/proxmox/map", m.apiMap, core.Doc("Dependency map"))
	ctx.Route("GET", "/api/proxmox/requirements", m.apiRequirements, core.Doc("Guest requirements"))

	// Register panel
	ctx.Panel(core.Panel{
		ID:    "proxmox",
		Title: "Proxmox",
		Group: "Inventory",
		Order: 160,
		Icon:  "proxmox",
	})

	// Periodic poll
	pollMin := core.Int(ctx.Settings(), "poll_minutes", 5)
	if pollMin > 0 && len(core.Strs(ctx.Settings(), "hosts")) > 0 {
		ctx.Every("proxmox_poll", time.Duration(pollMin)*time.Minute, m.doPoll)
	}

	// Publish the inventory service
	ctx.Publish("proxmox_inventory", m)

	return nil
}

// GuestFor implements GuestInventoryService
func (m *Module) GuestFor(macOrIP string) (Guest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inventory == nil {
		return Guest{}, false
	}
	macOrIP = strings.ToLower(macOrIP)
	for _, g := range m.inventory.Guests {
		for _, mac := range g.MACs {
			if strings.ToLower(mac) == macOrIP {
				return g, true
			}
		}
		for _, ip := range g.IPs {
			if ip == macOrIP {
				return g, true
			}
		}
	}
	return Guest{}, false
}

// Parsers

type pveNodes struct {
	Data []struct {
		Node           string  `json:"node"`
		CPU            float64 `json:"cpu"`
		MaxCPU         int     `json:"maxcpu"`
		Memory         int64   `json:"mem"`
		MaxMemory      int64   `json:"maxmem"`
		Disk           int64   `json:"disk"`
		MaxDisk        int64   `json:"maxdisk"`
		Uptime         int64   `json:"uptime"`
		SSLFingerprint string  `json:"ssl_fingerprint"`
		Status         string  `json:"status"`
	} `json:"data"`
}

type pveNodeStatus struct {
	Data struct {
		PVEVersion    string                      `json:"pveversion"`
		CPUInfo       struct{ Cores int }         `json:"cpuinfo"`
		Memory        struct{ Used, Total int64 } `json:"memory"`
		Rootfs        struct{ Used, Total int64 } `json:"rootfs"`
		Uptime        int64                       `json:"uptime"`
		LoadAvg       []string                    `json:"loadavg"`
		CurrentKernel struct {
			Release string `json:"release"`
		} `json:"current-kernel"`
	} `json:"data"`
}

type pveVersion struct {
	Data struct {
		Release string `json:"release"`
		Version string `json:"version"`
	} `json:"data"`
}

type pveQEMUList struct {
	Data []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Node   string `json:"node"`
		Tags   string `json:"tags"`
		Config struct {
			Cores       int    `json:"cores"`
			Memory      int    `json:"memory"`
			OSType      string `json:"ostype"`
			Description string `json:"description"`
		} `json:"config"`
	} `json:"data"`
}

type pveQEMUConfig struct {
	Data struct {
		Cores       int    `json:"cores"`
		Memory      int    `json:"memory"`
		OSType      string `json:"ostype"`
		Description string `json:"description"`
		Digest      string `json:"digest"`
		Agent       string `json:"agent"`
	} `json:"data"`
}

type pveLXCList struct {
	Data []struct {
		VMID   int    `json:"vmid"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Node   string `json:"node"`
		Tags   string `json:"tags"`
	} `json:"data"`
}

type pveLXCConfig struct {
	Data struct {
		Cores       int    `json:"cores"`
		Memory      int    `json:"memory"`
		OSType      string `json:"ostype"`
		Description string `json:"description"`
		Digest      string `json:"digest"`
	} `json:"data"`
}

type pveQEMUStatus struct {
	Data struct {
		Status string `json:"status"`
		Uptime int64  `json:"uptime"`
	} `json:"data"`
}

type pveLXCStatus struct {
	Data struct {
		Status string `json:"status"`
		Uptime int64  `json:"uptime"`
	} `json:"data"`
}

type pveAgentNetworkResp struct {
	Result []struct {
		HardwareAddress string `json:"hardware-address"`
		IPAddresses     []struct {
			IPAddress string `json:"ip-address"`
			Type      string `json:"ip-address-type"`
		} `json:"ip-addresses"`
		Name string `json:"name"`
	} `json:"result"`
}

type pveAgentHostname struct {
	Result struct {
		HostName string `json:"host-name"`
	} `json:"result"`
}

type pveAgentOSInfo struct {
	Result struct {
		KernelRelease string `json:"kernel-release"`
		KernelVersion string `json:"kernel-version"`
		Machine       string `json:"machine"`
	} `json:"result"`
}

type pveLXCInterfaces struct {
	Data []struct {
		Name    string `json:"name"`
		HwAddr  string `json:"hwaddr"`
		Address []struct {
			Address string `json:"address"`
			Family  string `json:"family"`
		} `json:"address"`
	} `json:"data"`
}

// HTTP and polling

func (m *Module) makePinVerifier(fingerprint string) func([][]byte, [][]*x509.Certificate) error {
	parts := strings.Split(strings.ToLower(fingerprint), ":")
	if len(parts) != 32 {
		return nil
	}
	var pinned [32]byte
	for i, p := range parts {
		var b byte
		fmt.Sscanf(p, "%2x", &b)
		pinned[i] = b
	}

	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		h := sha256.Sum256(rawCerts[0])
		if h != pinned {
			return fmt.Errorf("cert fingerprint mismatch: got %s, expected %s", hex.EncodeToString(h[:]), fingerprint)
		}
		return nil
	}
}

func (m *Module) get(hostURL, path string) ([]byte, error) {
	u, err := url.Parse(hostURL)
	if err != nil {
		return nil, err
	}
	u.Path = path
	req, _ := http.NewRequest("GET", u.String(), nil)
	tokenID := core.Str(m.ctx.Settings(), "token_id", "")
	tokenSecret := core.Str(m.ctx.Settings(), "token_secret", "")
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	client := m.client
	if !core.Bool(m.ctx.Settings(), "verify_tls", false) && core.Str(m.ctx.Settings(), "fingerprint", "") == "" {
		client = m.insecureHTTP
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (m *Module) put(hostURL, path string, form map[string]string) ([]byte, error) {
	u, err := url.Parse(hostURL)
	if err != nil {
		return nil, err
	}
	u.Path = path

	vals := url.Values{}
	for k, v := range form {
		vals.Set(k, v)
	}

	req, _ := http.NewRequest("PUT", u.String(), strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenID := core.Str(m.ctx.Settings(), "token_id", "")
	tokenSecret := core.Str(m.ctx.Settings(), "token_secret", "")
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (m *Module) extractMACs(config map[string]interface{}) []string {
	var macs []string
	netRe := regexp.MustCompile(`^net\d+$`)
	macRe := regexp.MustCompile(`(?i)[a-f0-9]{2}(?::[a-f0-9]{2}){5}`)

	for k, v := range config {
		if netRe.MatchString(k) {
			if s, ok := v.(string); ok {
				if matches := macRe.FindAllString(s, -1); len(matches) > 0 {
					macs = append(macs, strings.ToLower(matches[0]))
				}
			}
		}
	}
	return macs
}

func (m *Module) doPoll() error {
	m.polling.Lock()
	defer m.polling.Unlock()

	hosts := core.Strs(m.ctx.Settings(), "hosts")
	if len(hosts) == 0 {
		return nil
	}

	inventory := &Inventory{
		Guests: []Guest{},
		Nodes:  []Node{},
		LastAt: time.Now().Unix(),
		Errors: []string{},
	}

	excludeVMIDs := make(map[string]bool)
	for _, vmid := range core.Strs(m.ctx.Settings(), "exclude_vmids") {
		excludeVMIDs[vmid] = true
	}

	identity, _ := m.ctx.Service("identity").(core.Identity)

	for _, hostURL := range hosts {
		if err := m.pollHost(hostURL, inventory, excludeVMIDs, identity); err != nil {
			inventory.Errors = append(inventory.Errors, fmt.Sprintf("%s: %v", hostURL, err))
		}
	}

	// Enrichment: UpsertHosts and notes write
	m.enrichment(inventory, excludeVMIDs, identity)

	// Save inventory
	m.mu.Lock()
	m.inventory = inventory
	m.lastPollTime = time.Now().Unix()
	m.lastPollError = strings.Join(inventory.Errors, "; ")
	m.mu.Unlock()

	m.ctx.Store.KVSet("proxmox.inventory", inventory)

	return nil
}

func (m *Module) pollHost(hostURL string, inv *Inventory, excludeVMIDs map[string]bool, identity core.Identity) error {
	// GET /nodes
	body, err := m.get(hostURL, "/api2/json/nodes")
	if err != nil {
		return fmt.Errorf("nodes: %w", err)
	}
	var nodesList pveNodes
	if err := json.Unmarshal(body, &nodesList); err != nil {
		return fmt.Errorf("parse nodes: %w", err)
	}

	for _, nodeData := range nodesList.Data {
		node := Node{Name: nodeData.Node}

		// GET /nodes/{n}/status
		statusBody, err := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/status", nodeData.Node))
		if err == nil {
			var status pveNodeStatus
			if err := json.Unmarshal(statusBody, &status); err == nil {
				node.PVEVersion = status.Data.PVEVersion
				node.CPU = int(float64(status.Data.CPUInfo.Cores) * 100)
				if status.Data.Memory.Total > 0 {
					node.MemPercent = int(status.Data.Memory.Used * 100 / status.Data.Memory.Total)
				}
				node.Uptime = status.Data.Uptime
				if len(status.Data.LoadAvg) > 0 {
					node.Load = status.Data.LoadAvg[0]
				}
				if status.Data.Rootfs.Total > 0 {
					node.RootFSPct = int(status.Data.Rootfs.Used * 100 / status.Data.Rootfs.Total)
				}
				node.Kernel = status.Data.CurrentKernel.Release
			}
		}

		inv.Nodes = append(inv.Nodes, node)

		// Poll QEMU guests
		qemuBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu", nodeData.Node))
		var qemuList pveQEMUList
		if err := json.Unmarshal(qemuBody, &qemuList); err == nil {
			for _, qData := range qemuList.Data {
				if excludeVMIDs[fmt.Sprintf("%d", qData.VMID)] {
					continue
				}

				g := Guest{
					VMID:        qData.VMID,
					Type:        "qemu",
					Node:        nodeData.Node,
					Name:        qData.Name,
					Status:      qData.Status,
					Description: qData.Config.Description,
					Cores:       qData.Config.Cores,
					Memory:      int64(qData.Config.Memory),
					Tags:        strings.Fields(qData.Tags),
					OSType:      qData.Config.OSType,
				}

				// Get config for MACs and digest
				configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/config", nodeData.Node, qData.VMID))
				var qConfig pveQEMUConfig
				if err := json.Unmarshal(configBody, &qConfig); err == nil {
					configMap := make(map[string]interface{})
					json.Unmarshal(configBody, &configMap)
					if cfg, ok := configMap["data"].(map[string]interface{}); ok {
						g.MACs = m.extractMACs(cfg)
					}

					// Get status and agent info if running
					if g.Status == "running" {
						statusBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/status/current", nodeData.Node, qData.VMID))
						var qStatus pveQEMUStatus
						if err := json.Unmarshal(statusBody, &qStatus); err == nil {
							g.Uptime = qStatus.Data.Uptime
						}

						// Agent network if available
						if qConfig.Data.Agent == "1" {
							netBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/network-get-interfaces", nodeData.Node, qData.VMID))
							var agentNet pveAgentNetworkResp
							if err := json.Unmarshal(netBody, &agentNet); err == nil && agentNet.Result != nil {
								for _, iface := range agentNet.Result {
									if iface.HardwareAddress != "" && iface.HardwareAddress != "00:00:00:00:00:00" {
										g.MACs = append(g.MACs, strings.ToLower(iface.HardwareAddress))
									}
									for _, addr := range iface.IPAddresses {
										if addr.IPAddress != "" && addr.Type == "ipv4" || addr.Type == "ipv6" {
											ip := net.ParseIP(addr.IPAddress)
											if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
												g.IPs = append(g.IPs, addr.IPAddress)
											}
										}
									}
								}
								g.AgentState = "responding"
							} else {
								g.AgentState = "not responding"
							}

							// Agent hostname
							hostnameBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/get-host-name", nodeData.Node, qData.VMID))
							var agentHostname pveAgentHostname
							if err := json.Unmarshal(hostnameBody, &agentHostname); err == nil && agentHostname.Result.HostName != "" {
								g.Hostname = agentHostname.Result.HostName
							}

							// Agent osinfo
							osinfoBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/get-osinfo", nodeData.Node, qData.VMID))
							var agentOS pveAgentOSInfo
							if err := json.Unmarshal(osinfoBody, &agentOS); err == nil && agentOS.Result.KernelRelease != "" {
								g.OS = agentOS.Result.KernelRelease
								if agentOS.Result.KernelVersion != "" {
									g.OS += " (" + agentOS.Result.KernelVersion + ")"
								}
							}
						}
					}
				}

				inv.Guests = append(inv.Guests, g)
			}
		}

		// Poll LXC containers
		lxcBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc", nodeData.Node))
		var lxcList pveLXCList
		if err := json.Unmarshal(lxcBody, &lxcList); err == nil {
			for _, lxcData := range lxcList.Data {
				if excludeVMIDs[fmt.Sprintf("%d", lxcData.VMID)] {
					continue
				}

				g := Guest{
					VMID:   lxcData.VMID,
					Type:   "lxc",
					Node:   lxcData.Node,
					Name:   lxcData.Name,
					Status: lxcData.Status,
					Tags:   strings.Fields(lxcData.Tags),
				}

				// Get config for memory
				configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/config", nodeData.Node, lxcData.VMID))
				var lxcConfig pveLXCConfig
				if err := json.Unmarshal(configBody, &lxcConfig); err == nil {
					g.Memory = int64(lxcConfig.Data.Memory)
					g.Cores = lxcConfig.Data.Cores
					g.OSType = lxcConfig.Data.OSType
					g.Description = lxcConfig.Data.Description
				}

				// Get status
				if g.Status == "running" {
					statusBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/status/current", nodeData.Node, lxcData.VMID))
					var lxcStatus pveLXCStatus
					if err := json.Unmarshal(statusBody, &lxcStatus); err == nil {
						g.Uptime = lxcStatus.Data.Uptime
					}

					// Get interfaces
					ifBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/lxc/%d/interfaces", nodeData.Node, lxcData.VMID))
					var ifaces pveLXCInterfaces
					if err := json.Unmarshal(ifBody, &ifaces); err == nil && ifaces.Data != nil {
						for _, iface := range ifaces.Data {
							if iface.HwAddr != "" && iface.HwAddr != "00:00:00:00:00:00" {
								g.MACs = append(g.MACs, strings.ToLower(iface.HwAddr))
							}
							for _, addr := range iface.Address {
								ip := net.ParseIP(addr.Address)
								if ip != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
									g.IPs = append(g.IPs, addr.Address)
								}
							}
						}
					}
				}

				inv.Guests = append(inv.Guests, g)
			}
		}
	}

	return nil
}

func (m *Module) enrichment(inv *Inventory, excludeVMIDs map[string]bool, identity core.Identity) {
	// UpsertHosts for each guest
	var updates []core.HostUpdate

	for _, guest := range inv.Guests {
		if excludeVMIDs[fmt.Sprintf("%d", guest.VMID)] {
			continue
		}

		vendor := fmt.Sprintf("Proxmox VE %s on %s", guest.Type, guest.Node)

		// For each IP, create a host update
		for _, ip := range guest.IPs {
			name := ""
			if core.Bool(m.ctx.Settings(), "name_guests", true) {
				// Only use guest name if no identity (lease hostname) for this IP
				identityName := ""
				if identity != nil {
					identityName = identity.Name(ip)
				}
				// If identity has no name for this IP, use guest name
				if identityName == "" {
					name = guest.Name
				}
			}

			update := core.HostUpdate{
				IP:         ip,
				Name:       name,
				Vendor:     vendor,
				OS:         guest.OS,
				DeviceType: "vm",
				Source:     "proxmox",
				IsLocal:    boolPtr(true),
				LastSeen:   time.Now().Unix(),
			}

			// Add MACs for the first update (we don't have a good way to map IPs to MACs right now)
			for _, mac := range guest.MACs {
				updates = append(updates, core.HostUpdate{
					MAC:        mac,
					Vendor:     vendor,
					OS:         guest.OS,
					DeviceType: "vm",
					Source:     "proxmox",
					IsLocal:    boolPtr(true),
					LastSeen:   time.Now().Unix(),
				})
				break
			}

			updates = append(updates, update)
		}
	}

	if len(updates) > 0 {
		m.ctx.Store.UpsertHosts(updates)
	}
}

func boolPtr(b bool) *bool {
	return &b
}

// API routes

func (m *Module) apiInventory(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inventory == nil {
		return map[string]interface{}{"nodes": []Node{}, "guests": []Guest{}}, nil
	}
	return map[string]interface{}{"nodes": m.inventory.Nodes, "guests": m.inventory.Guests}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := map[string]interface{}{
		"last_poll":   m.lastPollTime,
		"error":       m.lastPollError,
		"node_count":  0,
		"guest_count": 0,
	}

	if m.inventory != nil {
		status["node_count"] = len(m.inventory.Nodes)
		status["guest_count"] = len(m.inventory.Guests)
	}

	return status, nil
}

func (m *Module) apiPoll(r *core.Req) (any, error) {
	go m.doPoll()
	return map[string]bool{"polling": true}, nil
}

func (m *Module) apiGuest(r *core.Req) (any, error) {
	vmid := r.Q("vmid", "")
	node := r.Q("node", "")

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inventory == nil {
		return nil, errors.New("no inventory")
	}

	for _, g := range m.inventory.Guests {
		if fmt.Sprintf("%d", g.VMID) == vmid && g.Node == node {
			return g, nil
		}
	}

	return nil, errors.New("guest not found")
}

func (m *Module) apiNotesPreview(r *core.Req) (any, error) {
	vmid := r.Q("vmid", "")
	node := r.Q("node", "")

	m.mu.Lock()
	guest, found := m.findGuest(vmid, node)
	m.mu.Unlock()

	if !found {
		return nil, errors.New("guest not found")
	}

	block := m.buildNotesBlock(guest)
	return map[string]string{"block": block}, nil
}

func (m *Module) apiNotesWrite(r *core.Req) (any, error) {
	if !core.Bool(m.ctx.Settings(), "write_notes", false) {
		return nil, errors.New("notes writing is disabled")
	}

	var req struct {
		VMID *int   `json:"vmid"`
		Node string `json:"node"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.inventory == nil {
		return nil, errors.New("no inventory")
	}

	var guestToWrite *Guest
	if req.VMID != nil {
		for i := range m.inventory.Guests {
			if m.inventory.Guests[i].VMID == *req.VMID && m.inventory.Guests[i].Node == req.Node {
				guestToWrite = &m.inventory.Guests[i]
				break
			}
		}
	}

	if guestToWrite == nil {
		return nil, errors.New("guest not found")
	}

	// Actually write the notes
	if err := m.writeGuestNotes(guestToWrite); err != nil {
		return nil, err
	}

	return map[string]bool{"written": true}, nil
}

func (m *Module) findGuest(vmidStr, node string) (Guest, bool) {
	if m.inventory == nil {
		return Guest{}, false
	}
	for _, g := range m.inventory.Guests {
		if fmt.Sprintf("%d", g.VMID) == vmidStr && g.Node == node {
			return g, true
		}
	}
	return Guest{}, false
}

func (m *Module) buildNotesBlock(guest Guest) string {
	var buf bytes.Buffer
	buf.WriteString("<!-- flowsight:begin -->\n")
	buf.WriteString(fmt.Sprintf("**FlowSight:** %s\n\n", guest.Name))

	if guest.Type != "" {
		buf.WriteString(fmt.Sprintf("- **Type:** %s\n", guest.Type))
	}
	if len(guest.IPs) > 0 {
		buf.WriteString(fmt.Sprintf("- **IPs:** %s\n", strings.Join(guest.IPs, ", ")))
	}
	if guest.Hostname != "" {
		buf.WriteString(fmt.Sprintf("- **Hostname:** %s\n", guest.Hostname))
	}
	if guest.OS != "" {
		buf.WriteString(fmt.Sprintf("- **OS:** %s\n", guest.OS))
	}
	if guest.AgentState != "" {
		buf.WriteString(fmt.Sprintf("- **Agent:** %s\n", guest.AgentState))
	}

	buf.WriteString("\n<!-- flowsight:end -->\n")
	return buf.String()
}

func (m *Module) writeGuestNotes(guest *Guest) error {
	hosts := core.Strs(m.ctx.Settings(), "hosts")
	if len(hosts) == 0 {
		return errors.New("no hosts configured")
	}

	hostURL := hosts[0] // Use first host for now
	newBlock := m.buildNotesBlock(*guest)

	// Get current config with digest
	configBody, err := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID))
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	var configResp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(configBody, &configResp); err != nil {
		return err
	}

	digest, _ := configResp.Data["digest"].(string)
	currentDesc, _ := configResp.Data["description"].(string)

	// Merge notes block
	newDesc := m.mergeNotesBlock(currentDesc, newBlock)

	// Write back
	form := map[string]string{
		"description": newDesc,
	}
	if digest != "" {
		form["digest"] = digest
	}

	_, err = m.put(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID), form)
	if err != nil {
		// Retry once on digest mismatch
		if strings.Contains(err.Error(), "digest") {
			configBody, _ := m.get(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID))
			json.Unmarshal(configBody, &configResp)
			digest, _ = configResp.Data["digest"].(string)
			currentDesc, _ = configResp.Data["description"].(string)
			newDesc = m.mergeNotesBlock(currentDesc, newBlock)
			form["description"] = newDesc
			form["digest"] = digest
			_, err = m.put(hostURL, fmt.Sprintf("/api2/json/nodes/%s/%s/%d/config", guest.Node, guest.Type, guest.VMID), form)
		}
		if err != nil {
			return err
		}
	}

	guest.NotesSyncedAt = time.Now().Unix()
	return nil
}

func (m *Module) mergeNotesBlock(currentDesc, newBlock string) string {
	const begin = "<!-- flowsight:begin -->"
	const end = "<!-- flowsight:end -->"

	startIdx := strings.Index(currentDesc, begin)
	endIdx := strings.Index(currentDesc, end)

	if startIdx == -1 || endIdx == -1 {
		// No existing block, append
		if currentDesc != "" && !strings.HasSuffix(currentDesc, "\n") {
			currentDesc += "\n"
		}
		return currentDesc + "\n" + newBlock
	}

	// Replace the block
	before := currentDesc[:startIdx]
	after := currentDesc[endIdx+len(end):]
	return before + newBlock + after
}
