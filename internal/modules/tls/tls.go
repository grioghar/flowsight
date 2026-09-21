// Package tls is SSL transparency: a FlowSight-managed certificate authority
// for inspection, the certificate inventory built from everything the
// firewall sees (peeked handshakes, bumped sessions, Suricata TLS records),
// and the findings that come out of it: expired, self-signed, short-lived or
// never-before-seen issuers on the network.
//
// The CA is generated here in Go, never with an external tool, and its key
// never leaves the firewall. Inspection itself is decided per policy and
// carried out by the web module's proxy; this module only supplies the CA
// and reports on what was seen.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

type Module struct {
	ctx  *core.Context
	dir  string
	mu   sync.Mutex
	cert *x509.Certificate
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name: "tls", Version: "1.0",
		Description:  "SSL transparency: the inspection CA, the certificate inventory and certificate findings.",
		Capabilities: []string{core.CapTLSObserve},
		After:        []string{"identity"},
		Defaults: map[string]any{
			"ca_name":          "FlowSight Inspection CA",
			"ca_years":         10,
			"expiry_warn_days": 14,
		},
		Schema: []core.SettingField{
			{Key: "ca_name", Label: "CA common name", Type: "string", Restart: true},
			{Key: "ca_years", Label: "CA validity (years)", Type: "int"},
			{Key: "expiry_warn_days", Label: "Warn on certificates expiring within (days)", Type: "int"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.dir = filepath.Join(ctx.Platform.EtcDir, "tls")
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	m.loadCA()
	ctx.Publish("ca", m)
	ctx.Every("findings", 15*time.Minute, m.findings, core.Delayed())
	ctx.Route("GET", "/api/tls/ca", m.apiCA, core.Doc("The inspection CA: subject, fingerprint, validity, whether it exists"))
	ctx.Route("POST", "/api/tls/ca/create", m.apiCreate, core.Write(), core.Needs("tls.inspect"), core.Doc("Create (or replace) the inspection CA"))
	ctx.Route("POST", "/api/tls/ca/delete", m.apiDelete, core.Write(), core.Doc("Delete the inspection CA; inspection stops"))
	ctx.Route("GET", "/api/tls/ca/download", m.apiDownload, core.Doc("The CA certificate in PEM (or DER with ?format=der) for installing on devices"))
	ctx.Route("GET", "/api/tls/certs", m.apiCerts, core.Doc("Certificates seen on the network"),
		core.Params("hours", "window", "q", "search subject/issuer/sni", "limit", "rows", "problem", "only problematic"))
	ctx.Route("GET", "/api/tls/summary", m.apiSummary, core.Doc("TLS versions, bump modes, issuers, problems"),
		core.Params("hours", "window"))
	ctx.Route("GET", "/api/tls/sessions", m.apiSessions, core.Doc("Recent TLS sessions"),
		core.Params("ip", "client", "sni", "substring", "limit", "rows"))
	ctx.Panel(core.Panel{ID: "tls", Title: "TLS", Group: "Security", Order: 70, Icon: "tls"})
	return nil
}

func (m *Module) Health() core.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return core.Health{OK: true, Detail: "no inspection CA (create one to enable TLS inspection)"}
	}
	return core.Health{OK: true, Detail: "CA " + m.cert.Subject.CommonName + " valid until " +
		m.cert.NotAfter.Format("2006-01-02")}
}

// ---------------------------------------------------------------- CA

func (m *Module) certPath() string  { return filepath.Join(m.dir, "ca.crt") }
func (m *Module) keyPath() string   { return filepath.Join(m.dir, "ca.key") }
func (m *Module) squidPath() string { return filepath.Join(m.dir, "ca-squid.pem") }

// SquidCertPath implements the CA service the web module consumes.
func (m *Module) SquidCertPath() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cert == nil {
		return ""
	}
	if _, err := os.Stat(m.squidPath()); err != nil {
		return ""
	}
	return m.squidPath()
}

func (m *Module) loadCA() {
	b, err := os.ReadFile(m.certPath())
	if err != nil {
		return
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.cert = c
	m.mu.Unlock()
}

// createCA generates an EC P-256 root. Squid's certificate generator signs
// leaf certificates with it; browsers accept EC roots universally now, and
// signing is far cheaper than RSA for a busy proxy.
func (m *Module) createCA(name string, years int) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	if years <= 0 || years > 30 {
		years = 10
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"FlowSight"}, OrganizationalUnit: []string{host}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(m.certPath(), certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(m.keyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	// squid wants cert and key in one file, readable by its own user.
	combined := append(append([]byte{}, certPEM...), keyPEM...)
	if err := os.WriteFile(m.squidPath(), combined, 0o640); err != nil {
		return err
	}
	_, _ = core.Run(5*time.Second, "chown", "root:squid", m.squidPath())
	_, _ = core.Run(5*time.Second, "chmod", "750", m.dir)
	_, _ = core.Run(5*time.Second, "chown", "root:squid", m.dir)
	c, _ := x509.ParseCertificate(der)
	m.mu.Lock()
	m.cert = c
	m.mu.Unlock()
	m.ctx.Event("config", "inspection CA created: "+name, map[string]any{"severity": "medium"})
	return nil
}

func fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// ---------------------------------------------------------------- findings

// findings turns the inventory into things worth looking at.
func (m *Module) findings() error {
	st := m.ctx.Store
	now := time.Now().Unix()
	warn := int64(core.Int(m.ctx.Settings(), "expiry_warn_days", 14)) * 86400
	keep := map[string]bool{}
	rows, _ := st.Rows(`SELECT fingerprint, subject, issuer, not_after, self_signed, snis, hosts, seen FROM tls_certs
		WHERE last_seen >= ?`, now-7*86400)
	for _, r := range rows {
		fp, _ := r["fingerprint"].(string)
		subj, _ := r["subject"].(string)
		na, _ := r["not_after"].(int64)
		self, _ := r["self_signed"].(int64)
		snis, _ := r["snis"].(string)
		subject := subj
		if len(subject) > 80 {
			subject = subject[:80]
		}
		switch {
		case na > 0 && na < now:
			f := "tls:expired:" + fp
			keep[f] = true
			_, _ = st.AddFinding("tls", "expired-certificate", "medium", subject,
				"Expired certificate in use: "+subject,
				fmt.Sprintf("Expired %s; served for %s.", time.Unix(na, 0).Format("2006-01-02"), snis), f)
		case na > 0 && na-now < warn:
			f := "tls:expiring:" + fp
			keep[f] = true
			_, _ = st.AddFinding("tls", "expiring-certificate", "low", subject,
				"Certificate expires soon: "+subject,
				fmt.Sprintf("Expires %s; served for %s.", time.Unix(na, 0).Format("2006-01-02"), snis), f)
		}
		if self == 1 {
			f := "tls:selfsigned:" + fp
			keep[f] = true
			_, _ = st.AddFinding("tls", "self-signed-certificate", "low", subject,
				"Self-signed certificate seen: "+subject, "Served for "+snis+". Expected for local devices, not for internet services.", f)
		}
	}
	_, _ = st.ResolveFindings("tls", keep)
	return nil
}

// ---------------------------------------------------------------- API

func (m *Module) apiCA(r *core.Req) (any, error) {
	m.mu.Lock()
	c := m.cert
	m.mu.Unlock()
	if c == nil {
		return map[string]any{"exists": false}, nil
	}
	return map[string]any{"exists": true, "subject": c.Subject.String(), "not_before": c.NotBefore.Unix(),
		"not_after": c.NotAfter.Unix(), "fingerprint_sha256": fingerprint(c), "serial": c.SerialNumber.String(),
		"squid_ready": m.SquidCertPath() != "", "download": "/api/tls/ca/download"}, nil
}

func (m *Module) apiCreate(r *core.Req) (any, error) {
	b := r.Body()
	name, _ := b["name"].(string)
	if name == "" {
		name = core.Str(m.ctx.Settings(), "ca_name", "FlowSight Inspection CA")
	}
	if len(name) > 64 || strings.ContainsAny(name, "\n\r") {
		return nil, core.BadRequest("name must be at most 64 characters")
	}
	years := core.Int(m.ctx.Settings(), "ca_years", 10)
	if y, ok := b["years"].(float64); ok && y > 0 {
		years = int(y)
	}
	m.mu.Lock()
	exists := m.cert != nil
	m.mu.Unlock()
	if exists && b["replace"] != true {
		return nil, core.BadRequest("a CA already exists; pass replace=true to generate a new one (every device must then trust the new certificate)")
	}
	if err := m.createCA(name, years); err != nil {
		return nil, err
	}
	return m.apiCA(r)
}

func (m *Module) apiDelete(r *core.Req) (any, error) {
	for _, p := range []string{m.certPath(), m.keyPath(), m.squidPath()} {
		_ = os.Remove(p)
	}
	m.mu.Lock()
	m.cert = nil
	m.mu.Unlock()
	m.ctx.Event("config", "inspection CA deleted", map[string]any{"severity": "medium"})
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiDownload(r *core.Req) (any, error) {
	b, err := os.ReadFile(m.certPath())
	if err != nil {
		return nil, core.NotFound("no CA exists")
	}
	if r.Q("format", "") == "der" {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, fmt.Errorf("bad PEM on disk")
		}
		return core.Raw{ContentType: "application/x-x509-ca-cert", Filename: "flowsight-ca.der", Body: blk.Bytes}, nil
	}
	return core.Raw{ContentType: "application/x-pem-file", Filename: "flowsight-ca.crt", Body: b}, nil
}

func (m *Module) apiCerts(r *core.Req) (any, error) {
	since := r.Since(24 * 7)
	q, err := r.QSafe("q", "", 100)
	if err != nil {
		return nil, err
	}
	sql := `SELECT * FROM tls_certs WHERE last_seen>=?`
	args := []any{since}
	if q != "" {
		sql += ` AND (subject LIKE ? OR issuer LIKE ? OR snis LIKE ?)`
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if r.Q("problem", "") != "" {
		sql += ` AND (self_signed=1 OR (not_after>0 AND not_after<?))`
		args = append(args, time.Now().Unix())
	}
	sql += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 2000))
	rows, err := m.ctx.Store.Rows(sql, args...)
	return map[string]any{"certificates": rows}, err
}

func (m *Module) apiSummary(r *core.Req) (any, error) {
	since := r.Since(24)
	st := m.ctx.Store
	versions, _ := st.Rows(`SELECT COALESCE(NULLIF(version,''),'unknown') AS version, COUNT(*) AS sessions FROM tls_sessions
		WHERE ts>=? GROUP BY 1 ORDER BY sessions DESC`, since)
	modes, _ := st.Rows(`SELECT COALESCE(NULLIF(mode,''),'unknown') AS mode, COUNT(*) AS sessions FROM tls_sessions
		WHERE ts>=? GROUP BY 1 ORDER BY sessions DESC`, since)
	issuers, _ := st.Rows(`SELECT issuer, COUNT(*) AS certificates, SUM(seen) AS seen FROM tls_certs WHERE last_seen>=?
		GROUP BY issuer ORDER BY seen DESC LIMIT 15`, since)
	snis, _ := st.Rows(`SELECT sni, COUNT(*) AS sessions, COUNT(DISTINCT src_ip) AS clients FROM tls_sessions
		WHERE ts>=? AND sni<>'' GROUP BY sni ORDER BY sessions DESC LIMIT 15`, since)
	totals, _ := st.Row(`SELECT COUNT(*) AS sessions, COUNT(DISTINCT sni) AS names, COUNT(DISTINCT src_ip) AS clients,
		SUM(CASE WHEN mode='bump' THEN 1 ELSE 0 END) AS inspected FROM tls_sessions WHERE ts>=?`, since)
	problems := st.Int(`SELECT COUNT(*) FROM tls_certs WHERE last_seen>=? AND (self_signed=1 OR (not_after>0 AND not_after<?))`,
		since, time.Now().Unix())
	ca, _ := m.apiCA(r)
	return map[string]any{"versions": versions, "modes": modes, "issuers": issuers, "names": snis, "totals": totals,
		"problem_certificates": problems, "ca": ca, "hours": r.Hours(24)}, nil
}

func (m *Module) apiSessions(r *core.Req) (any, error) {
	ip, err := r.QSafe("ip", "", 64)
	if err != nil {
		return nil, err
	}
	sni, err := r.QSafe("sni", "", 128)
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM tls_sessions WHERE 1=1`
	args := []any{}
	if ip != "" {
		q += ` AND src_ip=?`
		args = append(args, ip)
	}
	if sni != "" {
		q += ` AND sni LIKE ?`
		args = append(args, "%"+sni+"%")
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, r.QInt("limit", 200, 1, 5000))
	rows, err := m.ctx.Store.Rows(q, args...)
	return map[string]any{"sessions": rows}, err
}
