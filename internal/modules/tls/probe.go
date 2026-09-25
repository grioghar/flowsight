package tls

// Filling in the certificate inventory.
//
// The proxy's log names a certificate by its subject and issuer and nothing
// more: no validity dates, no key, no fingerprint. Suricata's log carries
// dates when the IDS is running, and stateful packet inspection carries everything for
// the sessions it opens, but most networks have neither, and a spliced
// session never shows its certificate at all.
//
// So FlowSight asks. For the server names it has seen recently and knows
// too little about, it opens a TLS connection from the firewall, reads the
// certificate the server presents, and writes the whole record: validity,
// key, signature, alternative names, fingerprint, and whether the chain
// verifies against the system roots. That is one handshake per name, a few
// at a time, and it is what makes the TLS page's expiry, key and trust
// columns real rather than empty.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	ctls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// probeCerts completes the inventory for names whose record is thin.
func (m *Module) probeCerts() error {
	if !core.Bool(m.ctx.Settings(), "probe_certificates", true) {
		return nil
	}
	limit := core.Int(m.ctx.Settings(), "probe_per_run", 25)
	if limit < 1 || limit > 200 {
		limit = 25
	}
	since := time.Now().Add(-24 * time.Hour).Unix()
	// Names seen recently whose certificate has no validity recorded, most
	// used first; a name probed lately is left alone.
	rows, err := m.ctx.Store.Rows(`
		SELECT s.sni AS sni, COUNT(*) AS n FROM tls_sessions s
		WHERE s.ts >= ? AND s.sni IS NOT NULL AND s.sni <> ''
		  AND NOT EXISTS (SELECT 1 FROM tls_certs c WHERE c.not_after > 0 AND c.snis LIKE '%"' || s.sni || '"%')
		GROUP BY s.sni ORDER BY n DESC LIMIT ?`, since, limit*3)
	if err != nil {
		return err
	}
	var probed, failed int
	deadline := time.Now().Add(2 * time.Minute)
	for _, r := range rows {
		if probed >= limit || time.Now().After(deadline) {
			break
		}
		name, _ := r["sni"].(string)
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" || net.ParseIP(name) != nil || !strings.Contains(name, ".") {
			continue
		}
		m.mu.Lock()
		last := m.probedAt[name]
		m.mu.Unlock()
		if time.Since(last) < 12*time.Hour {
			continue
		}
		m.mu.Lock()
		if m.probedAt == nil {
			m.probedAt = map[string]time.Time{}
		}
		m.probedAt[name] = time.Now()
		m.mu.Unlock()
		if err := m.probeOne(name); err != nil {
			failed++
			continue
		}
		probed++
	}
	m.mu.Lock()
	m.lastProbe = time.Now()
	m.probedCount += probed
	m.mu.Unlock()
	return nil
}

// probeOne opens one TLS connection and records what the server presents.
func (m *Module) probeOne(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	d := &net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(name, "443"))
	if err != nil {
		return err
	}
	defer raw.Close()
	// The handshake is not verified here: the point is to see what is served,
	// including an expired or self-signed certificate. Trust is judged after.
	conn := ctls.Client(raw, &ctls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: ctls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return fmt.Errorf("no certificate")
	}
	leaf := st.PeerCertificates[0]
	trusted := verifyChain(name, st.PeerCertificates)
	return m.recordCert(name, leaf, trusted, versionName(st.Version))
}

func verifyChain(name string, chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: inter})
	return err == nil
}

// recordCert writes the full identity of one certificate into the inventory.
func (m *Module) recordCert(sni string, c *x509.Certificate, trusted bool, version string) error {
	sum := sha256.Sum256(c.Raw)
	fp := hex.EncodeToString(sum[:])
	keyType, bits := keyOf(c)
	self := 0
	if c.Subject.String() == c.Issuer.String() {
		self = 1
	}
	sans := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sort.Strings(sans)
	sansJSON, _ := json.Marshal(sans)
	snis, _ := json.Marshal([]string{sni})
	hosts, _ := json.Marshal([]string{})
	now := time.Now().Unix()
	err := m.ctx.Store.Exec(`INSERT INTO tls_certs(fingerprint,subject,issuer,sans,serial,not_before,not_after,
		key_type,key_bits,sig_alg,self_signed,trusted,first_seen,last_seen,seen,hosts,snis,source,attrs)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,'probe',?)
		ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen, seen=seen+1,
		  sans=excluded.sans, serial=excluded.serial, not_before=excluded.not_before, not_after=excluded.not_after,
		  key_type=excluded.key_type, key_bits=excluded.key_bits, sig_alg=excluded.sig_alg,
		  trusted=excluded.trusted, snis=excluded.snis`,
		fp, c.Subject.String(), c.Issuer.String(), string(sansJSON), c.SerialNumber.String(),
		c.NotBefore.Unix(), c.NotAfter.Unix(), keyType, bits, c.SignatureAlgorithm.String(), self, boolInt(trusted),
		now, now, string(hosts), string(snis), `{"tls_version":"`+version+`"}`)
	return err
}

func keyOf(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "EC", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return "", 0
}

func versionName(v uint16) string {
	switch v {
	case ctls.VersionTLS10:
		return "TLS/1.0"
	case ctls.VersionTLS11:
		return "TLS/1.1"
	case ctls.VersionTLS12:
		return "TLS/1.2"
	case ctls.VersionTLS13:
		return "TLS/1.3"
	}
	return ""
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
