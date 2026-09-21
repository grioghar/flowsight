// Package web owns a transparent squid instance: it renders the
// configuration, keeps the process running, tails its log for per-request
// visibility with server names, and provides web.block (terminate at the
// ClientHello, block page for plain HTTP) and tls.inspect (bump with the
// FlowSight CA for selected clients).
//
// Owning the instance rather than riding on a distribution's proxy plugin is
// deliberate: ssl_bump rules are first-match and global, so per-client
// decisions need to come first, and only the owner of squid.conf can put
// them there.
package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
	"github.com/grioghar/flowsight/internal/modules/firewall"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx      *core.Context
	dir      string
	logDir   string
	runDir   string
	tail     *core.Tailer
	mu       sync.Mutex
	lastErr  string
	requests int64
	identity core.Identity
	fw       firewall.Firewall
	cats     core.Categories
	blockSrv *http.Server
	blocks   map[string]int64 // policy -> count since start
}

// CAProvider is published by the tls module: the combined PEM squid needs.
type CAProvider interface {
	// SquidCertPath returns the path of a cert+key PEM, or "" when no CA exists.
	SquidCertPath() string
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "web", Version: "1.0",
		Description:  "Transparent proxy: server names on every web session, inline blocking at the TLS handshake, optional inspection.",
		Capabilities: []string{core.CapWebObserve, core.CapTLSObserve},
		Requires:     []string{"squid", "pf"},
		After:        []string{"identity", "firewall", "categories", "tls"},
		Defaults: map[string]any{
			"enabled":          true,
			"intercept":        false,
			"http_port":        3128,
			"https_port":       3129,
			"interfaces":       []string{},
			"networks":         []string{},
			"peek_server_cert": false,
			"ipv6_listener":    "",
			"block_page_port":  8082,
			"workers":          1,
			"squid_user":       "squid",
		},
		Schema: []core.SettingField{
			{Key: "intercept", Label: "Intercept web traffic", Type: "bool",
				Help: "Redirect port 80 and 443 from the local networks through the proxy. Off: the proxy runs but sees nothing."},
			{Key: "networks", Label: "Networks to intercept", Type: "list", Help: "CIDRs. Empty: every local network."},
			{Key: "interfaces", Label: "Interfaces", Type: "list", Help: "pf interface names (vtnet0, igb1). Empty: any."},
			{Key: "http_port", Label: "HTTP listener port", Type: "int"},
			{Key: "https_port", Label: "HTTPS listener port", Type: "int"},
			{Key: "peek_server_cert", Label: "Record server certificates without inspecting", Type: "bool",
				Help: "Peeks one step further into the handshake to log the server certificate, then splices. A few servers dislike it."},
			{Key: "ipv6_listener", Label: "IPv6 listener address", Type: "string",
				Help: "An IPv6 address the firewall holds on the LAN (a unique local address as a virtual IP works well). Empty: IPv6 web traffic is not intercepted."},
			{Key: "block_page_port", Label: "Block page port", Type: "int"},
			{Key: "workers", Label: "Squid workers", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.fw, _ = ctx.Service("firewall").(firewall.Firewall)
	m.cats, _ = ctx.Service("categories").(core.Categories)
	m.blocks = map[string]int64{}
	m.dir = filepath.Join(ctx.Platform.EtcDir, "squid")
	m.logDir = filepath.Join(ctx.Platform.LogDir, "squid")
	m.runDir = filepath.Join(ctx.Platform.RunDir, "squid")
	for _, d := range []string{m.dir, m.logDir, m.runDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := m.ensurePlaceholderCert(); err != nil {
		return err
	}
	m.tail = core.NewTailer(filepath.Join(m.logDir, "access.log"))
	ctx.Provider(&provider{m: m})
	ctx.Every("tail", 3*time.Second, m.pollLog)
	ctx.Every("supervise", 20*time.Second, m.supervise)
	ctx.Route("GET", "/api/web/summary", m.apiSummary, core.Doc("Web activity: top sites, categories, blocked requests"),
		core.Params("hours", "window"))
	ctx.Route("GET", "/api/web/log", m.apiLog, core.Doc("Recent web requests"),
		core.Params("ip", "client", "domain", "substring", "blocked", "only blocked", "limit", "rows"))
	ctx.Route("GET", "/api/web/status", m.apiStatus, core.Doc("Proxy process state and configuration"))
	ctx.Panel(core.Panel{ID: "web", Title: "Web", Group: "Visibility", Order: 45, Icon: "web"})
	m.startBlockPage()
	return nil
}

func (m *Module) Stop() {
	if m.blockSrv != nil {
		_ = m.blockSrv.Close()
	}
}

func (m *Module) OnConfigChange(s map[string]any) error {
	// The provider re-renders on the next reconcile; interception rules are
	// re-evaluated there too.
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != "" {
		return core.Health{OK: false, Detail: m.lastErr}
	}
	if !m.running() {
		return core.Health{OK: true, Detail: "proxy not running (policy not applied yet)"}
	}
	return core.Health{OK: true, Detail: fmt.Sprintf("proxy running, %d requests read", m.requests)}
}

// ---------------------------------------------------------------- process

func (m *Module) confPath() string { return filepath.Join(m.dir, "squid.conf") }
func (m *Module) pidPath() string  { return filepath.Join(m.runDir, "squid.pid") }

func (m *Module) squidBin() string {
	if b := m.ctx.Platform.SquidBin; b != "" {
		if _, err := os.Stat(b); err == nil {
			return b
		}
	}
	for _, c := range []string{"/usr/local/sbin/squid", "/usr/sbin/squid"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (m *Module) certgenBin() string {
	for _, c := range []string{"/usr/local/libexec/squid/security_file_certgen", "/usr/lib/squid/security_file_certgen",
		"/usr/libexec/squid/security_file_certgen"} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func (m *Module) running() bool {
	b, err := os.ReadFile(m.pidPath())
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscallSignal0()) == nil
}

// listening reports whether the proxy accepts connections on its ports. Only
// a proxy that answers may have traffic redirected to it; anything else would
// take the network's web access down with it.
func (m *Module) listening() bool {
	s := m.ctx.Settings()
	for _, port := range []int{core.Int(s, "http_port", 3128), core.Int(s, "https_port", 3129)} {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			return false
		}
		c.Close()
	}
	return true
}

// waitListening polls for the listeners after a start or reconfigure.
func (m *Module) waitListening(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if m.listening() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// supervise keeps the proxy in the state the configuration asks for.
func (m *Module) supervise() error {
	wantRunning := m.wanted()
	if !wantRunning {
		if m.running() {
			m.stopSquid()
		}
		m.setErr("")
		return nil
	}
	if _, err := os.Stat(m.confPath()); err != nil {
		return nil // nothing rendered yet; the provider will
	}
	if !m.running() {
		if err := m.startSquid(); err != nil {
			m.setErr(err.Error())
			if m.fw != nil {
				_ = m.fw.FlushAnchor("web")
			}
			return err
		}
	}
	if !m.waitListening(10 * time.Second) {
		// Running but deaf: pull the redirects rather than blackhole the LAN.
		if m.fw != nil {
			_ = m.fw.FlushAnchor("web")
		}
		m.setErr("proxy process is up but not accepting connections; interception withdrawn (see squid cache.log)")
		return fmt.Errorf("proxy not listening")
	}
	if m.fw != nil {
		if rdr, err := os.ReadFile(filepath.Join(m.dir, "pf-web.conf")); err == nil {
			_ = m.fw.LoadAnchor("web", string(rdr))
		}
	}
	m.setErr("")
	return nil
}

func (m *Module) wanted() bool {
	return core.Bool(m.ctx.Settings(), "intercept", false)
}

func (m *Module) setErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

func (m *Module) startSquid() error {
	bin := m.squidBin()
	if bin == "" {
		return fmt.Errorf("squid is not installed")
	}
	// Initialise the certificate database once, owned by the squid user.
	if cg := m.certgenBin(); cg != "" {
		db := filepath.Join(m.ctx.Platform.DataDir, "ssl_db")
		if _, err := os.Stat(db); err != nil {
			_, _ = core.Run(60*time.Second, cg, "-c", "-s", db, "-M", "16MB")
			_, _ = core.Run(10*time.Second, "chown", "-R", core.Str(m.ctx.Settings(), "squid_user", "squid"), db)
		}
	}
	_, _ = core.Run(10*time.Second, "chown", "-R", core.Str(m.ctx.Settings(), "squid_user", "squid"), m.logDir, m.runDir)
	if out, err := core.Run(60*time.Second, bin, "-k", "parse", "-f", m.confPath(), "-n", "flowsight"); err != nil {
		return fmt.Errorf("squid rejected the configuration: %s", tailLines(out, 4))
	}
	if out, err := core.Run(60*time.Second, bin, "-f", m.confPath(), "-n", "flowsight"); err != nil {
		return fmt.Errorf("squid failed to start: %s", tailLines(out, 4))
	}
	m.ctx.Event("system", "proxy started", nil)
	return nil
}

func (m *Module) reloadSquid() error {
	bin := m.squidBin()
	if bin == "" {
		return fmt.Errorf("squid is not installed")
	}
	if out, err := core.Run(60*time.Second, bin, "-k", "parse", "-f", m.confPath(), "-n", "flowsight"); err != nil {
		return fmt.Errorf("squid rejected the configuration: %s", tailLines(out, 4))
	}
	if !m.running() {
		return m.startSquid()
	}
	out, err := core.Run(60*time.Second, bin, "-k", "reconfigure", "-f", m.confPath(), "-n", "flowsight")
	if err != nil {
		return fmt.Errorf("squid reconfigure: %s", tailLines(out, 4))
	}
	return nil
}

func (m *Module) stopSquid() {
	if bin := m.squidBin(); bin != "" {
		_, _ = core.Run(60*time.Second, bin, "-k", "shutdown", "-f", m.confPath(), "-n", "flowsight")
	}
	if m.fw != nil {
		_ = m.fw.FlushAnchor("web")
	}
	m.ctx.Event("system", "proxy stopped", nil)
}

// tailLines picks the lines that explain a squid failure: the FATAL and
// ERROR lines, or the last few when there are none.
func tailLines(s string, n int) string {
	var picked []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.Contains(l, "FATAL") || strings.Contains(l, "ERROR") || strings.Contains(l, "Bungled") {
			if i := strings.Index(l, "| "); i > 0 {
				l = l[i+2:]
			}
			picked = append(picked, l)
		}
	}
	if len(picked) == 0 {
		picked = strings.Split(strings.TrimSpace(s), "\n")
	}
	if len(picked) > n {
		picked = picked[len(picked)-n:]
	}
	return strings.Join(picked, " | ")
}

// ensurePlaceholderCert creates the self-signed certificate squid needs to
// open an https_port for peeking when no inspection CA exists. It is never
// presented to a client: peek-and-splice hands the origin's own certificate
// through untouched.
func (m *Module) ensurePlaceholderCert() error {
	path := filepath.Join(m.dir, "placeholder.pem")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: "flowsight-proxy-placeholder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, _ = core.Run(5*time.Second, "chown", core.Str(m.ctx.Settings(), "squid_user", "squid"), path)
	return nil
}

// ---------------------------------------------------------------- log

// Log line (see logformat flowsight):
// ts dur client cport server sport status/code bytes_out bytes_in method "url" sni bump_mode tlsver "subject" "issuer" ua
var logRe = regexp.MustCompile(`^(\d+)\.(\d+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+?)/(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s?(.*)$`)

func (m *Module) pollLog() error {
	var flows []core.Flow
	var sessions []tlsRec
	blockedHosts := map[string]int64{}
	n, err := m.tail.Lines(func(line []byte) {
		mm := logRe.FindStringSubmatch(string(line))
		if mm == nil {
			return
		}
		ts, _ := strconv.ParseInt(mm[1], 10, 64)
		dur, _ := strconv.ParseFloat(mm[3], 64)
		client, server := mm[4], mm[6]
		sport, _ := strconv.Atoi(mm[7])
		code, status := mm[8], mm[9]
		bytesOut, _ := strconv.ParseInt(mm[10], 10, 64) // squid -> client
		bytesIn, _ := strconv.ParseInt(mm[11], 10, 64)  // client -> squid
		method, url := mm[12], mm[13]
		sni, mode, tlsver := dash(mm[14]), dash(mm[15]), dash(mm[16])
		subject, issuer := dash(mm[17]), dash(mm[18])
		if strings.HasPrefix(code, "NONE") && method == "CONNECT" && sni == "" {
			return // the tunnel setup half of a CONNECT; the close carries the numbers
		}
		domain := sni
		if domain == "" {
			domain = hostOf(url)
		}
		if domain == "" && server != "" && server != "-" {
			domain = server
		}
		if net.ParseIP(domain) != nil {
			domain = ""
		}
		verdict := "observed"
		if strings.Contains(code, "DENIED") || status == "403" && strings.Contains(code, "TCP_DENIED") {
			verdict = "blocked"
		}
		if mode == "terminate" {
			verdict = "blocked"
		}
		proto := "http"
		if method == "CONNECT" || mode != "" && mode != "none" || sport == 443 {
			proto = "tls"
		}
		fl := core.Flow{TS: ts, EndTS: ts, Key: fmt.Sprintf("squid/%s/%s/%s/%d", client, server, domain, ts),
			SrcIP: client, DstIP: nzs(server), DstPort: sport, Proto: proto, Domain: domain,
			BytesIn: bytesOut, BytesOut: bytesIn, Duration: dur / 1000, Verdict: verdict,
			Source: "squid", TLSVersion: tlsver, TLSSNI: sni, App: "", Category: ""}
		if m.cats != nil && domain != "" {
			if cs := m.cats.Classify(domain); len(cs) > 0 {
				fl.Category = cs[0]
				fl.Attrs = map[string]any{"web_categories": strings.Join(cs, ",")}
			}
		}
		if verdict == "blocked" {
			fl.Policy = "web"
			blockedHosts[client]++
		}
		flows = append(flows, fl)
		if proto == "tls" && (sni != "" || subject != "") {
			sessions = append(sessions, tlsRec{ts: ts, src: client, dst: server, port: sport, sni: sni,
				version: tlsver, mode: mode, subject: subject, issuer: issuer})
		}
	})
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	m.mu.Lock()
	m.requests += int64(n)
	m.mu.Unlock()
	if len(flows) == 0 {
		return nil
	}
	var ups []core.HostUpdate
	for ip, c := range blockedHosts {
		ups = append(ups, core.HostUpdate{IP: ip, Blocked: c, Source: "web"})
	}
	_ = m.ctx.Store.UpsertHosts(ups)
	if err := m.ctx.Store.AddFlows(flows); err != nil {
		return err
	}
	return m.writeTLS(sessions)
}

type tlsRec struct {
	ts                                  int64
	src, dst                            string
	port                                int
	sni, version, mode, subject, issuer string
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func nzs(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func hostOf(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		u = h
	}
	return strings.ToLower(u)
}

// ---------------------------------------------------------------- block page

func (m *Module) blockPageURL() string {
	port := core.Int(m.ctx.Settings(), "block_page_port", 8082)
	ip := "127.0.0.1"
	if m.identity != nil {
		// The page must be reachable by clients: use the first local network's
		// gateway address if we can find one on our own interfaces.
		if a := firstLocalAddr(); a != "" {
			ip = a
		}
	}
	return fmt.Sprintf("http://%s:%d/blocked", ip, port)
}

func firstLocalAddr() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
				return n.IP.String()
			}
		}
	}
	return ""
}

func (m *Module) startBlockPage() {
	port := core.Int(m.ctx.Settings(), "block_page_port", 8082)
	mux := http.NewServeMux()
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		policy := r.URL.Query().Get("policy")
		u := r.URL.Query().Get("url")
		m.mu.Lock()
		m.blocks[policy]++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, blockHTML, htmlEscape(hostOf(u)), htmlEscape(policy))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/blocked", http.StatusFound)
	})
	srv, err := core.ServeOn(fmt.Sprintf(":%d", port), mux)
	if err != nil {
		m.ctx.Log.Warn("block page listener failed", "error", err.Error())
		return
	}
	m.blockSrv = srv
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

const blockHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Blocked</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;background:#f6f7f9;color:#1c2430;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:40px;max-width:520px}
h1{font-size:22px;margin:0 0 12px}p{line-height:1.5;margin:8px 0}code{background:#eef1f5;padding:2px 6px;border-radius:4px}
.tag{display:inline-block;background:#fde8e8;color:#9b1c1c;border-radius:999px;padding:2px 10px;font-size:12px;margin-bottom:14px}</style></head>
<body><div class="card"><div class="tag">Blocked by network policy</div><h1>%s is not available on this network</h1>
<p>A policy named <code>%s</code> applies to this device and does not allow this site.</p>
<p>If you believe this is a mistake, ask the person who manages this network.</p></div></body></html>`

// ---------------------------------------------------------------- API

func (m *Module) name(ip string) string {
	if m.identity == nil {
		return ""
	}
	return m.identity.Name(ip)
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	since := r.Since(24)
	st := m.ctx.Store
	limit := r.QInt("limit", 15, 1, 100)
	sites, _ := st.Rows(`SELECT domain, MAX(category) AS category, SUM(flows) AS requests, SUM(bytes_in) AS bytes_in,
		SUM(bytes_out) AS bytes_out, COUNT(DISTINCT src_ip) AS hosts FROM rollup_domain WHERE bucket>=?
		GROUP BY domain ORDER BY requests DESC LIMIT ?`, since, limit)
	cats, _ := st.Rows(`SELECT COALESCE(NULLIF(category,''),'uncategorised') AS category, SUM(flows) AS requests,
		SUM(bytes_in) AS bytes_in FROM rollup_domain WHERE bucket>=? GROUP BY 1 ORDER BY requests DESC LIMIT ?`, since, limit)
	blocked, _ := st.Rows(`SELECT domain, SUM(flows) AS requests, COUNT(DISTINCT src_ip) AS hosts FROM rollup_domain
		WHERE bucket>=? AND verdict='blocked' GROUP BY domain ORDER BY requests DESC LIMIT ?`, since, limit)
	clients, _ := st.Rows(`SELECT src_ip AS ip, SUM(flows) AS requests, SUM(bytes_in) AS bytes_in,
		SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked FROM rollup_domain WHERE bucket>=?
		GROUP BY src_ip ORDER BY requests DESC LIMIT ?`, since, limit)
	for _, c := range clients {
		ip, _ := c["ip"].(string)
		if nme := m.name(ip); nme != "" {
			c["name"] = nme
		}
	}
	totals, _ := st.Row(`SELECT SUM(flows) AS requests, SUM(CASE WHEN verdict='blocked' THEN flows ELSE 0 END) AS blocked,
		COUNT(DISTINCT domain) AS domains, COUNT(DISTINCT src_ip) AS clients FROM rollup_domain WHERE bucket>=?`, since)
	tlsModes, _ := st.Rows(`SELECT mode, COUNT(*) AS sessions FROM tls_sessions WHERE ts>=? AND source='squid' GROUP BY mode`, since)
	return map[string]any{"sites": sites, "categories": cats, "blocked": blocked, "clients": clients,
		"totals": totals, "tls_modes": tlsModes, "hours": r.Hours(24), "running": m.running(),
		"intercepting": m.wanted()}, nil
}

func (m *Module) apiLog(r *core.Req) (any, error) {
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	domain, err := r.QSafe("domain", "", 128)
	if err != nil {
		return nil, err
	}
	q := `SELECT ts, src_ip, dst_ip, dst_port, proto, domain, category, bytes_in, bytes_out, duration, verdict, policy,
		tls_version FROM flows WHERE source='squid'`
	args := []any{}
	if ip != "" {
		q += ` AND src_ip=?`
		args = append(args, ip)
	}
	if domain != "" {
		q += ` AND domain LIKE ?`
		args = append(args, "%"+strings.ToLower(domain)+"%")
	}
	if r.Q("blocked", "") != "" {
		q += ` AND verdict='blocked'`
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := m.ctx.Store.Rows(q, args...)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		sip, _ := row["src_ip"].(string)
		if nme := m.name(sip); nme != "" {
			row["src_name"] = nme
		}
	}
	return map[string]any{"requests": rows}, nil
}

func (m *Module) apiStatus(r *core.Req) (any, error) {
	conf, _ := os.ReadFile(m.confPath())
	m.mu.Lock()
	blocks := map[string]int64{}
	for k, v := range m.blocks {
		blocks[k] = v
	}
	lastErr := m.lastErr
	m.mu.Unlock()
	var files []string
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		files = append(files, e.Name())
	}
	sort.Strings(files)
	return map[string]any{"running": m.running(), "intercepting": m.wanted(), "config": string(conf),
		"files": files, "block_page": m.blockPageURL(), "block_page_hits": blocks, "error": lastErr,
		"squid": m.squidBin(), "certgen": m.certgenBin()}, nil
}

// writeTLS records sessions and, when the server certificate was peeked or
// the connection bumped, the certificate identity for the inventory.
func (m *Module) writeTLS(sessions []tlsRec) error {
	if len(sessions) == 0 {
		return nil
	}
	return m.ctx.Store.Tx(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO tls_sessions(ts,src_ip,dst_ip,dst_port,sni,version,mode,fingerprint,source)
			VALUES(?,?,?,?,?,?,?,?,'squid')`)
		if err != nil {
			return err
		}
		defer ins.Close()
		up, err := tx.Prepare(`INSERT INTO tls_certs(fingerprint,subject,issuer,self_signed,first_seen,last_seen,seen,hosts,snis,source)
			VALUES(?,?,?,?,?,?,1,?,?,'squid')
			ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen, seen=seen+1`)
		if err != nil {
			return err
		}
		defer up.Close()
		now := time.Now().Unix()
		for _, s := range sessions {
			fp := ""
			if s.subject != "" {
				// Squid's log does not carry the fingerprint; key the inventory
				// on subject+issuer, which is stable for one certificate.
				sum := sha256.Sum256([]byte(s.subject + "|" + s.issuer))
				fp = "sq-" + hex.EncodeToString(sum[:12])
			}
			mode := s.mode
			if mode == "" || mode == "none" {
				mode = "splice"
			}
			if _, err := ins.Exec(s.ts, s.src, nzs(s.dst), s.port, dash(s.sni), dash(s.version), mode, nz(fp)); err != nil {
				return err
			}
			if fp != "" {
				self := 0
				if s.subject == s.issuer {
					self = 1
				}
				hosts, _ := json.Marshal([]string{s.dst})
				snis, _ := json.Marshal([]string{s.sni})
				if _, err := up.Exec(fp, s.subject, nz(s.issuer), self, now, now, string(hosts), string(snis)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}
