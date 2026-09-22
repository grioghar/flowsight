package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// provider renders the proxy configuration and the interception rules from
// the policy document. web.block terminates denied names at the ClientHello
// and serves the block page for plain HTTP; tls.inspect bumps selected
// clients with the FlowSight CA when the tls module has one.
type provider struct {
	m *Module
}

func (p *provider) Name() string { return "squid" }

func (p *provider) Capabilities() []string {
	caps := []string{core.CapWebBlock}
	if ca, ok := p.m.ctx.Service("ca").(CAProvider); ok && ca.SquidCertPath() != "" {
		caps = append(caps, core.CapTLSInspect)
	}
	return caps
}

var idRe = regexp.MustCompile(`[^a-z0-9_]+`)

func (p *provider) Compile(doc *core.PolicyDoc) (core.Artifact, error) {
	m := p.m
	s := m.ctx.Settings()
	res, _ := m.ctx.Service("member_resolver").(core.MemberResolver)
	now := time.Now()
	excluded := doc.ExcludedCIDRs(res)
	exclSet := map[string]bool{}
	for _, e := range excluded {
		exclSet[e] = true
	}
	var pols []squidPolicy
	for i := range doc.Policies {
		pol := &doc.Policies[i]
		if !pol.Enabled || !doc.Active(pol.Schedule, now) {
			continue
		}
		wantsWeb, wantsTLS := false, false
		for _, r := range pol.Requirements() {
			if r == core.CapWebBlock {
				wantsWeb = true
			}
			if r == core.CapTLSInspect {
				wantsTLS = true
			}
		}
		if !wantsWeb && !wantsTLS {
			continue
		}
		var members []string
		for _, mm := range doc.Members(pol, res) {
			if !exclSet[mm] {
				members = append(members, mm)
			}
		}
		if len(members) == 0 {
			continue
		}
		sp := squidPolicy{ID: idRe.ReplaceAllString(strings.ToLower(pol.Name), "_"), Members: members,
			Monitor: pol.Action == "monitor", Inspect: pol.TLS.Inspect, Bypass: pol.TLS.Bypass}
		if sp.Inspect {
			// Names whose clients pin their certificate cannot be decrypted by
			// anyone; relaying them keeps those sites working.
			sp.Bypass = append(append([]string(nil), sp.Bypass...), m.pinnedNames()...)
		}
		if wantsWeb {
			set := map[string]bool{}
			for _, d := range pol.Deny.Domains {
				set[d] = true
			}
			for _, c := range pol.Deny.Categories {
				if m.cats == nil {
					return core.Artifact{}, fmt.Errorf("policy %q uses category %q but the categories module is not loaded", pol.Name, c)
				}
				list, err := m.cats.Domains(c)
				if err != nil {
					return core.Artifact{}, fmt.Errorf("policy %q: %v", pol.Name, err)
				}
				for _, d := range list {
					set[d] = true
				}
			}
			for _, d := range pol.Allow.Domains {
				delete(set, d)
			}
			for _, d := range doc.Exclusions.Domains {
				delete(set, d)
			}
			for _, t := range pol.Deny.TLDs {
				set[t] = true // ".zip" in a dstdomain file matches every name under the TLD
			}
			for d := range set {
				sp.Domains = append(sp.Domains, d)
			}
			sort.Strings(sp.Domains)
			sp.Allow = append([]string(nil), pol.Allow.Domains...)
		}
		pols = append(pols, sp)
	}
	sort.Slice(pols, func(i, j int) bool { return pols[i].ID < pols[j].ID })

	nets := core.Strs(s, "networks")
	if len(nets) == 0 && m.identity != nil {
		nets = m.identity.LocalNetworks()
	}
	var v4nets []string
	for _, n := range nets {
		if !strings.Contains(n, ":") {
			v4nets = append(v4nets, n)
		}
	}
	caPath := ""
	if ca, ok := m.ctx.Service("ca").(CAProvider); ok {
		caPath = ca.SquidCertPath()
	}
	var dns []string
	if m.ctx.Platform.IsOPNsense() || m.ctx.Platform.Family == "freebsd" {
		dns = []string{"127.0.0.1"}
	}
	params := squidParams{
		HTTPPort: core.Int(s, "http_port", 3128), HTTPSPort: core.Int(s, "https_port", 3129),
		Dir: m.dir, LogDir: m.logDir, RunDir: m.runDir, User: core.Str(s, "squid_user", "squid"),
		Group:     pfGroup(m.ctx.Platform),
		LocalNets: nets, CAPath: caPath, CertDB: filepath.Join(m.ctx.Platform.DataDir, "ssl_db"),
		CertgenBin: m.certgenBin(), BlockPageURL: firstNonEmpty(doc.Options.BlockPageURL, m.blockPageURL()),
		PeekServerCert: core.Bool(s, "peek_server_cert", false), Policies: pols, Exclusions: excluded,
		ExclDomains: doc.Exclusions.Domains, DNSServers: dns, Workers: core.Int(s, "workers", 1),
		V6Listener: v6Listener(s),
	}
	_, files := params.render()
	out := map[string]string{}
	for name, text := range files {
		out[filepath.Join(m.dir, name)] = text
	}
	localTable := "flowsight_local"
	if m.fw != nil {
		localTable = m.fw.LocalTable()
	}
	rdr := ""
	if m.wanted() {
		rdr = pfRules(core.Strs(s, "interfaces"), v4nets, excluded, params.HTTPPort, params.HTTPSPort, localTable, params.V6Listener)
	}
	out[filepath.Join(m.dir, "pf-web.conf")] = rdr
	note := fmt.Sprintf("%d web polic(ies)", len(pols))
	if !m.wanted() {
		note += ", interception off"
	}
	return core.Artifact{Files: out, Note: note}, nil
}

// v6Listener returns the configured IPv6 listener address when it is a valid,
// non-loopback IPv6 address the firewall actually holds; anything else is
// ignored so a typo cannot blackhole IPv6 web traffic.
func v6Listener(s map[string]any) string {
	v := strings.TrimSpace(core.Str(s, "ipv6_listener", ""))
	if v == "" {
		return ""
	}
	ip := net.ParseIP(v)
	if ip == nil || ip.To4() != nil || ip.IsLoopback() {
		return ""
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
			return ip.String()
		}
	}
	return ""
}

// pfGroup returns the group that may open /dev/pf, when one is set up.
func pfGroup(p *core.Platform) string {
	if p.Family != "freebsd" {
		return ""
	}
	if st, err := os.Stat("/dev/pf"); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if g, err := user.LookupGroupId(fmt.Sprint(sys.Gid)); err == nil && g.Name != "wheel" && g.Name != "root" {
				return g.Name
			}
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (p *provider) Current() (core.Artifact, error) {
	files := map[string]string{}
	entries, _ := os.ReadDir(p.m.dir)
	for _, e := range entries {
		n := e.Name()
		if n == "placeholder.pem" || strings.HasSuffix(n, ".tmp") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(p.m.dir, n))
		if err == nil {
			files[filepath.Join(p.m.dir, n)] = string(b)
		}
	}
	if _, ok := files[filepath.Join(p.m.dir, "pf-web.conf")]; !ok {
		files[filepath.Join(p.m.dir, "pf-web.conf")] = ""
	}
	return core.Artifact{Files: files}, nil
}

// Apply writes the files, asks squid to parse them, reloads (or starts) it,
// then loads the interception rules last: traffic is never redirected to a
// proxy that has not accepted its configuration. On failure the previous
// files are restored.
func (p *provider) Apply(a core.Artifact) (string, error) {
	m := p.m
	cur, _ := p.Current()
	restore := func() {
		for path, text := range cur.Files {
			if text == "" {
				_ = os.Remove(path)
				continue
			}
			_ = os.WriteFile(path, []byte(text), 0o644)
		}
	}
	for path, text := range a.Files {
		if strings.TrimSpace(text) == "" && filepath.Base(path) != "squid.conf" {
			_ = os.Remove(path)
			continue
		}
		if err := os.WriteFile(path+".tmp", []byte(text), 0o644); err != nil {
			restore()
			return "", err
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			restore()
			return "", err
		}
	}
	// Drop ACL files that are no longer referenced.
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".acl") {
			if _, keep := a.Files[filepath.Join(m.dir, n)]; !keep {
				_ = os.Remove(filepath.Join(m.dir, n))
			}
		}
	}
	rdr := a.Files[filepath.Join(m.dir, "pf-web.conf")]
	if !m.wanted() {
		if m.running() {
			m.stopSquid()
		}
		return "interception off; proxy stopped", nil
	}
	if err := m.reloadSquid(); err != nil {
		// Keep the rejected configuration beside the live one for inspection.
		_ = os.WriteFile(filepath.Join(m.dir, "squid.conf.rejected"), []byte(a.Files[filepath.Join(m.dir, "squid.conf")]), 0o644)
		restore()
		if m.fw != nil {
			_ = m.fw.FlushAnchor("web")
		}
		m.setErr(err.Error())
		return "", err
	}
	if !m.waitListening(15 * time.Second) {
		if m.fw != nil {
			_ = m.fw.FlushAnchor("web")
		}
		m.setErr("proxy accepted the configuration but is not listening; interception withheld")
		return "", fmt.Errorf("proxy is not accepting connections on its ports; interception withheld (see %s/cache.log)", m.logDir)
	}
	m.setErr("")
	if m.fw != nil {
		if err := m.fw.LoadAnchor("web", rdr); err != nil {
			return "", fmt.Errorf("proxy reloaded but interception rules failed: %v", err)
		}
	}
	sum := sha256.Sum256([]byte(a.Files[filepath.Join(m.dir, "squid.conf")]))
	return "proxy reconfigured, interception loaded (" + hex.EncodeToString(sum[:5]) + ")", nil
}
