// Package identity answers "who is this address": DHCP leases, the ARP and
// NDP tables, the resolver's answers, enrolment and the OUI registry are all
// folded into one name and one MAC per host. Every other module names hosts
// through the service this publishes, so the answer is the same everywhere.
package identity

import (
	"bufio"
	"encoding/csv"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx *core.Context

	mu      sync.RWMutex
	names   map[string]string // ip -> best name
	macs    map[string]string // ip -> mac
	ips     map[string][]string
	seenAt  map[string]map[string]int64 // mac -> address -> last seen
	vendors map[string]string           // oui -> vendor
	leases  map[string]Lease            // mac -> lease
	nets    []*net.IPNet
	netStrs []string
	updated time.Time
	static  map[string]string // ip -> name from reservations / hosts files
	overr   map[string]string // ip -> operator-assigned name
}

type Lease struct {
	MAC, IP, Hostname string
	Expires           int64
	Source            string
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "identity", Version: "1.0",
		Description:  "Names and MAC addresses for every host, from DHCP, ARP/NDP, DNS answers and the OUI registry.",
		Capabilities: []string{core.CapHostInventory, core.CapIdentity},
		Defaults: map[string]any{
			"refresh_seconds":      30,
			"extra_lease_files":    []string{},
			"local_networks":       []string{},
			"address_memory_hours": 24,
		},
		Schema: []core.SettingField{
			{Key: "refresh_seconds", Label: "Refresh interval (s)", Type: "int"},
			{Key: "local_networks", Label: "Local networks", Type: "list",
				Help: "CIDRs considered local. Empty: derived from the firewall's own interfaces."},
			{Key: "extra_lease_files", Label: "Extra lease files", Type: "list"},
			{Key: "address_memory_hours", Label: "Remember a device's addresses for (hours)", Type: "int",
				Help: "How long an address stays associated with its device after the neighbour entry goes. Operating systems rotate temporary IPv6 addresses; remembering them keeps policy, names and history attached to the device."},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.names = map[string]string{}
	m.macs = map[string]string{}
	m.ips = map[string][]string{}
	m.leases = map[string]Lease{}
	m.vendors = map[string]string{}
	m.static = map[string]string{}
	m.overr = map[string]string{}
	m.loadOUI()
	m.loadOverrides()
	ctx.Publish("identity", m)
	ctx.Publish("member_resolver", m)
	every := time.Duration(core.Int(ctx.Settings(), "refresh_seconds", 30)) * time.Second
	ctx.Every("refresh", every, m.refresh)
	ctx.Route("GET", "/api/identity/hosts", m.apiHosts, core.Doc("Known hosts with names, MACs, vendors and last activity"),
		core.Params("hours", "activity window", "all", "include inactive"))
	ctx.Route("GET", "/api/identity/lookup", m.apiLookup, core.Doc("Name, MAC and vendor for one address"),
		core.Params("ip", "address"))
	ctx.Route("GET", "/api/identity/leases", m.apiLeases, core.Doc("Current DHCP leases"))
	ctx.Route("POST", "/api/identity/name", m.apiSetName, core.Write(), core.Doc("Assign a display name to an address"))
	ctx.Panel(core.Panel{ID: "hosts", Title: "Hosts", Group: "Visibility", Order: 20, Icon: "hosts"})
	ctx.Panel(core.Panel{ID: "host", Title: "Host", Group: "Visibility", Order: 21, Detail: true})
	return nil
}

// ---------------------------------------------------------------- service

func (m *Module) Name(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n := m.overr[ip]; n != "" {
		return n
	}
	if n := m.names[ip]; n != "" {
		return n
	}
	return ""
}

func (m *Module) MAC(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.macs[ip]
}

func (m *Module) Vendor(mac string) string {
	mac = strings.ToLower(mac)
	if len(mac) < 8 {
		return ""
	}
	if isRandomized(mac) {
		return ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v := m.vendors[mac[:13]]; v != "" { // /36 blocks stored as aa:bb:cc:d
		return v
	}
	return m.vendors[mac[:8]]
}

func (m *Module) IsLocal(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsLinkLocalUnicast() {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, n := range m.nets {
		if n.Contains(p) {
			return true
		}
	}
	// Before the interface scan has run there is nothing to compare against;
	// RFC1918 is the best guess then. Once local networks are known, an
	// RFC1918 address outside them (a double-NAT WAN, an upstream router) is
	// not local.
	return len(m.nets) == 0 && p.IsPrivate()
}

func (m *Module) LocalNetworks() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.netStrs...)
}

// EffectiveSettings reports what empty settings resolve to on this platform.
func (m *Module) EffectiveSettings() map[string]any {
	var files []string
	for _, f := range m.ctx.Platform.DHCPLeases {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		files = append([]string(nil), m.ctx.Platform.DHCPLeases...)
	}
	nets := m.LocalNetworks()
	if len(nets) == 0 {
		nets = []string{"(none detected yet)"}
	}
	return map[string]any{"local_networks": nets, "extra_lease_files": files}
}

// remember records that a device was seen at an address, so the association
// outlives the neighbour entry (operating systems rotate temporary IPv6
// addresses; a device must not lose its policy or its name when they do).
func (m *Module) remember(mac, ip string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	ip = strings.TrimSpace(ip)
	if mac == "" || ip == "" || net.ParseIP(ip) == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seenAt == nil {
		m.seenAt = map[string]map[string]int64{}
	}
	if m.seenAt[mac] == nil {
		m.seenAt[mac] = map[string]int64{}
	}
	m.seenAt[mac][ip] = time.Now().Unix()
}

// rememberedIPs returns every device's addresses, dropping those not seen
// within the memory window.
func (m *Module) rememberedIPs() map[string][]string {
	hours := core.Int(m.ctx.Settings(), "address_memory_hours", 24)
	if hours < 1 {
		hours = 1
	}
	cut := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	out := map[string][]string{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for mac, ips := range m.seenAt {
		for ip, at := range ips {
			if at < cut {
				delete(ips, ip)
				continue
			}
			out[mac] = append(out[mac], ip)
		}
		if len(ips) == 0 {
			delete(m.seenAt, mac)
			continue
		}
		sort.Slice(out[mac], func(i, j int) bool { return ips[out[mac][i]] < ips[out[mac][j]] })
	}
	return out
}

// Addresses implements core.AddressBook: every address of the device that
// holds ip. IPv4 and IPv6 are the same thing here.
func (m *Module) Addresses(ip string) []string {
	mac := m.MAC(ip)
	if mac == "" {
		return []string{ip}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := append([]string(nil), m.ips[mac]...)
	if !contains(list, ip) {
		list = append(list, ip)
	}
	return list
}

// Resolve implements core.MemberResolver for mac:, device: and all.
func (m *Module) Resolve(ref string) []string {
	switch {
	case ref == "all":
		return m.LocalNetworks()
	case strings.HasPrefix(ref, "mac:"):
		mac := strings.ToLower(ref[4:])
		m.mu.RLock()
		defer m.mu.RUnlock()
		var out []string
		for _, ip := range m.ips[mac] {
			out = append(out, cidr(ip))
		}
		return out
	case strings.HasPrefix(ref, "device:"):
		want := strings.ToLower(ref[7:])
		m.mu.RLock()
		var hit []string
		for ip, n := range m.names {
			if strings.ToLower(n) == want {
				hit = append(hit, ip)
			}
		}
		for ip, n := range m.overr {
			if strings.ToLower(n) == want {
				hit = append(hit, ip)
			}
		}
		m.mu.RUnlock()
		// One name means one device: take every address it holds, v4 and v6.
		seen := map[string]bool{}
		var out []string
		for _, ip := range hit {
			for _, a := range m.Addresses(ip) {
				if c := cidr(a); !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

func cidr(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	return ip + "/32"
}

func isRandomized(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	for _, c := range mac[:2] {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c-'a') + 10
		}
	}
	return b&2 != 0
}

// ---------------------------------------------------------------- refresh

func (m *Module) refresh() error {
	leases := m.readLeases()
	arp := m.readNeighbours()
	static := m.readReservations()
	nets := m.localNets()

	names := map[string]string{}
	macs := map[string]string{}
	// Everything seen now is remembered against its device; see seen().
	for ip, mac := range arp {
		m.remember(mac, ip)
	}
	for _, l := range leases {
		if l.IP != "" && l.MAC != "" {
			m.remember(l.MAC, l.IP)
		}
	}
	ips := m.rememberedIPs()
	for mac, list := range ips {
		for _, ip := range list {
			macs[ip] = mac
		}
	}
	for _, l := range leases {
		if l.IP != "" {
			macs[l.IP] = l.MAC
			if l.Hostname != "" && l.Hostname != "*" {
				names[l.IP] = l.Hostname
			}
		}
	}
	for ip, n := range static {
		names[ip] = n
	}
	// Resolver answers name the far end; only used when nothing else did.
	rows, _ := m.ctx.Store.Rows(`SELECT ip, name FROM dns_names WHERE ts > ? LIMIT 50000`,
		time.Now().Add(-24*time.Hour).Unix())
	for _, r := range rows {
		ip, _ := r["ip"].(string)
		n, _ := r["name"].(string)
		if _, ok := names[ip]; !ok && ip != "" && n != "" {
			names[ip] = n
		}
	}
	// Enrolment / device table contributions.
	drows, _ := m.ctx.Store.Rows(`SELECT mac, ip, hostname, guest_name FROM devices WHERE ip IS NOT NULL`)
	for _, r := range drows {
		ip, _ := r["ip"].(string)
		mac, _ := r["mac"].(string)
		h, _ := r["hostname"].(string)
		g, _ := r["guest_name"].(string)
		if ip == "" {
			continue
		}
		if _, ok := names[ip]; !ok {
			if h != "" {
				names[ip] = h
			} else if g != "" {
				names[ip] = g
			}
		}
		if mac != "" {
			if _, ok := macs[ip]; !ok {
				macs[ip] = strings.ToLower(mac)
			}
		}
	}

	m.mu.Lock()
	// A device has one name, whatever address it is using: carry the name
	// learned on any of its addresses (DHCP, reservation) to all of them,
	// which is what makes IPv6 rows read like IPv4 ones.
	for _, list := range ips {
		name := ""
		for _, ip := range list {
			if n := static[ip]; n != "" {
				name = n
				break
			}
			if n := names[ip]; n != "" && name == "" {
				name = n
			}
		}
		if name == "" {
			continue
		}
		for _, ip := range list {
			if names[ip] == "" {
				names[ip] = name
			}
		}
	}
	m.names, m.macs, m.ips, m.leases, m.static = names, macs, ips, leases, static
	m.nets = nets
	m.netStrs = m.netStrs[:0]
	for _, n := range nets {
		m.netStrs = append(m.netStrs, n.String())
	}
	m.updated = time.Now()
	m.mu.Unlock()

	// Fold identities into the hosts table so reports carry names.
	var ups []core.HostUpdate
	for ip, mac := range macs {
		if !m.IsLocal(ip) {
			continue
		}
		ups = append(ups, core.HostUpdate{IP: ip, MAC: mac, Name: names[ip], Vendor: m.Vendor(mac),
			Source: "identity", IsLocal: ptr(true)})
	}
	for ip, n := range names {
		if _, done := macs[ip]; done || !m.IsLocal(ip) {
			continue
		}
		ups = append(ups, core.HostUpdate{IP: ip, Name: n, Source: "identity", IsLocal: ptr(true)})
	}
	return m.ctx.Store.UpsertHosts(ups)
}

func ptr(b bool) *bool { return &b }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var macRe = regexp.MustCompile(`(?i)^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$`)

func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !macRe.MatchString(s) {
		return ""
	}
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// readLeases parses dnsmasq, ISC dhcpd and Kea lease files, whichever exist.
func (m *Module) readLeases() map[string]Lease {
	out := map[string]Lease{}
	files := append([]string(nil), m.ctx.Platform.DHCPLeases...)
	files = append(files, core.Strs(m.ctx.Settings(), "extra_lease_files")...)
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(f, "dnsmasq"):
			parseDnsmasq(fh, out)
		case strings.HasSuffix(f, ".csv"):
			parseKea(fh, out)
		default:
			parseISC(fh, out)
		}
		fh.Close()
	}
	return out
}

func parseDnsmasq(fh *os.File, out map[string]Lease) {
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 4 {
			continue
		}
		// IPv6 lines carry a DUID, not a MAC; keep IPv4 identity only.
		mac := normMAC(p[1])
		if mac == "" || strings.Contains(p[2], ":") {
			continue
		}
		var exp int64
		if v, err := parseInt(p[0]); err == nil {
			exp = v
		}
		name := p[3]
		if name == "*" {
			name = ""
		}
		out[mac] = Lease{MAC: mac, IP: p[2], Hostname: name, Expires: exp, Source: "dnsmasq"}
	}
}

func parseISC(fh *os.File, out map[string]Lease) {
	sc := bufio.NewScanner(fh)
	var cur Lease
	var active bool
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "lease "):
			cur = Lease{IP: strings.Fields(line)[1], Source: "isc"}
			active = true
		case strings.HasPrefix(line, "hardware ethernet "):
			cur.MAC = normMAC(strings.TrimSuffix(strings.Fields(line)[2], ";"))
		case strings.HasPrefix(line, "client-hostname "):
			cur.Hostname = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, "client-hostname "), ";"), `"`)
		case strings.HasPrefix(line, "binding state "):
			active = strings.Contains(line, "active")
		case line == "}":
			if cur.MAC != "" && active {
				out[cur.MAC] = cur
			}
		}
	}
}

func parseKea(fh *os.File, out map[string]Lease) {
	r := csv.NewReader(fh)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil || len(recs) < 2 {
		return
	}
	idx := map[string]int{}
	for i, h := range recs[0] {
		idx[h] = i
	}
	for _, rec := range recs[1:] {
		get := func(k string) string {
			if i, ok := idx[k]; ok && i < len(rec) {
				return rec[i]
			}
			return ""
		}
		mac := normMAC(get("hwaddr"))
		if mac == "" || get("state") == "1" {
			continue
		}
		out[mac] = Lease{MAC: mac, IP: get("address"), Hostname: strings.TrimSuffix(get("hostname"), "."),
			Source: "kea"}
	}
}

func parseInt(s string) (int64, error) {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		v = v*10 + int64(c-'0')
	}
	return v, nil
}

// readReservations picks names out of dnsmasq dhcp-host lines and /etc/hosts.
func (m *Module) readReservations() map[string]string {
	out := map[string]string{}
	dir := m.ctx.Platform.DnsmasqConfDir
	var files []string
	if m.ctx.Platform.Family == "freebsd" {
		files = append(files, "/usr/local/etc/dnsmasq.conf")
	} else {
		files = append(files, "/etc/dnsmasq.conf")
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, dir+"/"+e.Name())
			}
		}
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "dhcp-host=") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(line, "dhcp-host="), ",")
			var ip, name string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				switch {
				case net.ParseIP(p) != nil:
					ip = p
				case strings.HasPrefix(p, "set:"), strings.HasPrefix(p, "id:"), normMAC(p) != "",
					strings.HasSuffix(p, "h"), strings.HasSuffix(p, "m"), p == "infinite", p == "ignore":
				default:
					if name == "" && !strings.Contains(p, ":") {
						name = p
					}
				}
			}
			if ip != "" && name != "" {
				out[ip] = name
			}
		}
		fh.Close()
	}
	if fh, err := os.Open("/etc/hosts"); err == nil {
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			p := strings.Fields(line)
			if len(p) >= 2 && net.ParseIP(p[0]) != nil && !net.ParseIP(p[0]).IsLoopback() {
				if _, ok := out[p[0]]; !ok {
					out[p[0]] = p[1]
				}
			}
		}
		fh.Close()
	}
	return out
}

// localNets returns the configured local networks, or the firewall's own
// interface networks.
func (m *Module) localNets() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range core.Strs(m.ctx.Settings(), "local_networks") {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	if len(out) > 0 {
		return dedupeNets(out)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	wan := defaultRouteInterface()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 || ifc.Name == wan {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := n.Mask.Size()
			// A /32 or a public /64 on WAN is not a LAN. Keep RFC1918/ULA and
			// anything with a real prefix on IPv4.
			if n.IP.To4() != nil {
				if ones >= 31 || !n.IP.IsPrivate() {
					continue
				}
			} else if !n.IP.IsPrivate() && ones == bits {
				continue
			}
			nn := &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}
			out = append(out, nn)
		}
	}
	return dedupeNets(out)
}

// dedupeNets drops repeats (an alias address, a second interface on the
// same subnet) while keeping the first occurrence's order.
func dedupeNets(in []*net.IPNet) []*net.IPNet {
	seen := map[string]bool{}
	out := in[:0]
	for _, n := range in {
		k := n.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, n)
	}
	return out
}

// defaultRouteInterface names the interface carrying the default route: the
// WAN, whose network is never "local" even when it happens to be RFC1918.
func defaultRouteInterface() string {
	if out, err := core.Run(5*time.Second, "/sbin/route", "-n", "get", "default"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "interface:" {
				return f[1]
			}
		}
	}
	if out, err := core.Run(5*time.Second, "ip", "-4", "route", "show", "default"); err == nil {
		f := strings.Fields(out)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" {
				return f[i+1]
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------- OUI

// loadOUI reads the vendor registry shipped with the package (share dir) or
// the operating system's copy. Format: "aa:bb:cc<TAB>Vendor" or manuf style.
func (m *Module) loadOUI() {
	cands := []string{
		m.ctx.Platform.ShareDir + "/oui.txt",
		"/usr/local/share/flowsight/oui.txt",
		"/usr/share/flowsight/oui.txt",
		"/usr/local/share/ntopng/httpdocs/other/EtherOUI.txt",
		"/usr/share/ieee-data/oui.txt",
		"/usr/share/misc/oui.txt",
		"/usr/local/share/wireshark/manuf",
		"/usr/share/wireshark/manuf",
	}
	vend := map[string]string{}
	for _, f := range cands {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<16), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			// ieee oui.txt: "00-00-0C   (hex)\t\tCisco Systems, Inc"
			if strings.Contains(line, "(hex)") {
				p := strings.SplitN(line, "(hex)", 2)
				pre := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p[0]), "-", ":"))
				vend[pre] = strings.TrimSpace(p[1])
				continue
			}
			fields := strings.Split(line, "\t")
			if len(fields) < 2 {
				fields = strings.Fields(line)
			}
			if len(fields) < 2 {
				continue
			}
			pre := strings.ToLower(strings.TrimSpace(fields[0]))
			name := strings.TrimSpace(fields[len(fields)-1])
			if len(fields) >= 3 && strings.TrimSpace(fields[2]) != "" {
				name = strings.TrimSpace(fields[2]) // manuf long name
			}
			if i := strings.Index(pre, "/"); i > 0 {
				pre = pre[:i]
			}
			pre = strings.ReplaceAll(pre, "-", ":")
			if len(pre) >= 8 {
				if len(pre) > 13 {
					pre = pre[:13]
				} else if len(pre) > 8 {
					pre = pre[:8]
				}
				vend[pre] = name
			}
		}
		fh.Close()
		if len(vend) > 1000 {
			break
		}
	}
	m.mu.Lock()
	m.vendors = vend
	m.mu.Unlock()
	if len(vend) == 0 {
		m.ctx.Log.Warn("no OUI registry found; vendor names will be empty")
	}
}

func (m *Module) loadOverrides() {
	var o map[string]string
	if m.ctx.Store.KVGet("identity.names", &o) && o != nil {
		m.mu.Lock()
		m.overr = o
		m.mu.Unlock()
	}
}

// readNeighbours reads the ARP and NDP tables through the OS tools. On
// FreeBSD that is arp(8)/ndp(8); on Linux ip(8).
func (m *Module) readNeighbours() map[string]string {
	out := map[string]string{}
	if m.ctx.Platform.Family == "freebsd" {
		if s, err := core.Run(10*time.Second, "/usr/sbin/arp", "-an"); err == nil {
			for _, line := range strings.Split(s, "\n") {
				// ? (192.168.1.5) at 00:11:22:33:44:55 on vtnet0 expires in 1180 seconds [ethernet]
				f := strings.Fields(line)
				if len(f) >= 4 && f[2] == "at" {
					ip := strings.Trim(f[1], "()")
					if mac := normMAC(f[3]); mac != "" {
						out[ip] = mac
					}
				}
			}
		}
		if s, err := core.Run(10*time.Second, "/usr/sbin/ndp", "-an"); err == nil {
			for _, line := range strings.Split(s, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && strings.Contains(f[0], ":") {
					if mac := normMAC(f[1]); mac != "" {
						ip := f[0]
						if i := strings.Index(ip, "%"); i > 0 {
							ip = ip[:i]
						}
						if !strings.HasPrefix(ip, "fe80") {
							out[ip] = mac
						}
					}
				}
			}
		}
		return out
	}
	if s, err := core.Run(10*time.Second, "ip", "-4", "neigh"); err == nil {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "lladdr" {
					if mac := normMAC(f[i+1]); mac != "" {
						out[f[0]] = mac
					}
				}
			}
		}
	}
	if s, err := core.Run(10*time.Second, "ip", "-6", "neigh"); err == nil {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) > 0 && strings.HasPrefix(f[0], "fe80") {
				continue
			}
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "lladdr" {
					if mac := normMAC(f[i+1]); mac != "" {
						out[f[0]] = mac
					}
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- API

func (m *Module) apiHosts(r *core.Req) (any, error) {
	since := r.Since(24)
	q := `SELECT h.*, COALESCE(d.zone, h.zone) AS zone FROM hosts h LEFT JOIN devices d ON d.mac = h.mac
		WHERE h.is_local=1`
	args := []any{}
	if r.Q("all", "") == "" {
		q += ` AND h.last_seen >= ?`
		args = append(args, since)
	}
	q += ` ORDER BY h.bytes_in + h.bytes_out DESC LIMIT 2000`
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	m.mu.RLock()
	for _, row := range rows {
		ip, _ := row["ip"].(string)
		if n := m.overr[ip]; n != "" {
			row["name"] = n
		} else if n := m.names[ip]; n != "" && row["name"] == nil {
			row["name"] = n
		}
		if mac, _ := row["mac"].(string); mac != "" {
			row["vendor"] = m.Vendor(mac)
			row["randomized"] = isRandomized(mac)
		}
	}
	m.mu.RUnlock()
	return map[string]any{"hosts": rows, "updated": m.updated.Unix()}, nil
}

func (m *Module) apiLookup(r *core.Req) (any, error) {
	ip := r.Q("ip", "")
	if net.ParseIP(ip) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	mac := m.MAC(ip)
	return map[string]any{"ip": ip, "name": m.Name(ip), "mac": mac, "vendor": m.Vendor(mac),
		"local": m.IsLocal(ip), "randomized": isRandomized(mac)}, nil
}

func (m *Module) apiLeases(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []map[string]any
	for _, l := range m.leases {
		out = append(out, map[string]any{"mac": l.MAC, "ip": l.IP, "hostname": l.Hostname,
			"expires": l.Expires, "source": l.Source, "vendor": m.Vendor(l.MAC)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["ip"].(string) < out[j]["ip"].(string) })
	return map[string]any{"leases": out}, nil
}

var nameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._'-]{0,63}$`)

func (m *Module) apiSetName(r *core.Req) (any, error) {
	var in struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	if net.ParseIP(in.IP) == nil {
		return nil, core.BadRequest("ip must be an address")
	}
	if in.Name != "" && !nameOK.MatchString(in.Name) {
		return nil, core.BadRequest("name may contain letters, digits, space, dot, dash and underscore")
	}
	m.mu.Lock()
	if in.Name == "" {
		delete(m.overr, in.IP)
	} else {
		m.overr[in.IP] = in.Name
	}
	snapshot := map[string]string{}
	for k, v := range m.overr {
		snapshot[k] = v
	}
	m.mu.Unlock()
	if err := m.ctx.Store.KVSet("identity.names", snapshot); err != nil {
		return nil, err
	}
	_ = m.ctx.Store.UpsertHosts([]core.HostUpdate{{IP: in.IP, Name: in.Name, Source: "operator"}})
	return map[string]any{"ok": true}, nil
}
