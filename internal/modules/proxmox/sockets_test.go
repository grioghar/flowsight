package proxmox

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func TestParseSocketsSSAndNetstat(t *testing.T) {
	ss := "0      0      192.168.1.105:32400   192.168.1.119:51234\n0      0      [fd00::5]:22          [fd00::9]:40000\n0 0 192.168.1.105:44123 192.168.1.53:53\n"
	p := parseSockets(ss)
	if len(p) != 3 || p[0].LocalPort != 32400 || p[0].RemoteIP != "192.168.1.119" || p[1].RemoteIP != "fd00::9" || p[2].RemotePort != 53 {
		t.Fatalf("ss parse: %+v", p)
	}
	ns := "Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 192.168.1.105:32400     192.168.1.119:51234     ESTABLISHED\ntcp6       0      0 ::ffff:192.168.1.105:22 ::ffff:192.168.1.9:5000 TIME_WAIT\n"
	p = parseSockets(ns)
	if len(p) != 1 || p[0].RemotePort != 51234 {
		t.Fatalf("netstat parse: %+v", p)
	}
}

func TestPeerEdgesPointAtTheServiceSide(t *testing.T) {
	ipToGuest := map[string]int{"192.168.1.119": 7, "192.168.1.53": 3108}
	peers := []socketPeer{{LocalPort: 32400, RemoteIP: "192.168.1.119", RemotePort: 51234}, {LocalPort: 32400, RemoteIP: "192.168.1.119", RemotePort: 51235}, {LocalPort: 44123, RemoteIP: "192.168.1.53", RemotePort: 53}, {LocalPort: 1, RemoteIP: "8.8.8.8", RemotePort: 53}}
	e := peerEdges(3111, peers, ipToGuest)
	if len(e) != 2 {
		t.Fatalf("edges: %+v", e)
	}
	if e[0].From != 7 || e[0].To != 3111 || e[0].Port != 32400 || e[0].Flows != 2 {
		t.Fatalf("client-opened connection should point at the server port: %+v", e[0])
	}
	if e[1].From != 3111 || e[1].To != 3108 || e[1].Port != 53 || e[1].Source != "sockets" {
		t.Fatalf("outbound: %+v", e[1])
	}
}

func TestPinnedFingerprintDecidesTrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"data":[]}`)) }))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	raw := strings.ToUpper(hex.EncodeToString(sum[:]))
	var parts []string
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	good := strings.Join(parts, ":")
	mk := func(fp string, verify bool) *Module {
		dir := t.TempDir()
		path := filepath.Join(dir, "flowsight.json")
		if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, err := core.LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		cfg.DeclareModule("proxmox", map[string]any{"fingerprint": fp, "verify_tls": verify, "token_id": "t", "token_secret": "s"})
		return &Module{ctx: &core.Context{Name: "proxmox", Config: cfg}}
	}
	if _, err := mk(good, false).get(srv.URL, "/api2/json/nodes"); err != nil {
		t.Fatalf("right pin refused: %v", err)
	}
	if _, err := mk(strings.Repeat("00:", 31)+"00", false).get(srv.URL, "/api2/json/nodes"); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if _, err := mk(raw, false).get(srv.URL, "/api2/json/nodes"); err != nil {
		t.Fatalf("pin without colons should be accepted: %v", err)
	}
	if _, err := mk("not-a-fingerprint", false).get(srv.URL, "/api2/json/nodes"); err == nil {
		t.Fatal("a malformed pin must refuse, never fall through to unverified")
	}
	if _, err := mk("", true).get(srv.URL, "/api2/json/nodes"); err == nil {
		t.Fatal("self-signed certificate accepted under system roots")
	}
	if _, err := mk("", false).get(srv.URL, "/api2/json/nodes"); err == nil || !strings.Contains(err.Error(), "never made unverified") {
		t.Fatalf("no pin and no verify should refuse: %v", err)
	}
}
