package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/grioghar/flowsight/internal/licensing"
)

func newTestServer(t *testing.T) (*server, ed25519.PublicKey, *httptest.Server) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := openStore(filepath.Join(t.TempDir(), "l.db"))
	if err != nil {
		t.Fatal(err)
	}
	sv := &server{s: s, priv: priv, admin: "adm", issuer: "test", lease: 24 * time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/activate", sv.activate)
	mux.HandleFunc("POST /v1/refresh", sv.activate)
	mux.HandleFunc("POST /v1/deactivate", sv.deactivate)
	mux.HandleFunc("/admin/", sv.adminHandler)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return sv, pub, ts
}

func post(t *testing.T, url, token string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestActivateSeatsRevoke(t *testing.T) {
	sv, pub, ts := newTestServer(t)

	// Admin creates a Pro key with one seat.
	code, created := post(t, ts.URL+"/admin/licenses", "adm", map[string]any{"tier": "pro", "licensee": "Ada", "expires": "+30d"})
	if code != 200 {
		t.Fatalf("create: %d %v", code, created)
	}
	key := created["key"].(string)
	if code, _ := post(t, ts.URL+"/admin/licenses", "wrong", map[string]any{}); code != 401 {
		t.Fatalf("admin auth not enforced: %d", code)
	}

	// First installation activates and gets a verifiable, bound token.
	code, rep := post(t, ts.URL+"/v1/activate", "", map[string]any{"key": key, "installation": "inst_a", "hostname": "fw-a"})
	if code != 200 {
		t.Fatalf("activate: %d %v", code, rep)
	}
	l, err := licensing.Parse(rep["token"].(string), pub)
	if err != nil {
		t.Fatal(err)
	}
	if l.Tier != "pro" || l.Installation != "inst_a" || l.Refresh == "" || l.Licensee != "Ada" {
		t.Fatalf("token wrong: %+v", l)
	}

	// Same installation again is a refresh, not a new seat.
	if code, _ = post(t, ts.URL+"/v1/refresh", "", map[string]any{"key": key, "installation": "inst_a"}); code != 200 {
		t.Fatalf("refresh: %d", code)
	}
	// A second installation is refused: one seat.
	code, rep = post(t, ts.URL+"/v1/activate", "", map[string]any{"key": key, "installation": "inst_b", "hostname": "fw-b"})
	if code != 409 || rep["code"] != "seats" {
		t.Fatalf("second seat: %d %v", code, rep)
	}
	// Releasing the first frees the seat for the second.
	post(t, ts.URL+"/v1/deactivate", "", map[string]any{"key": key, "installation": "inst_a"})
	if code, _ = post(t, ts.URL+"/v1/activate", "", map[string]any{"key": key, "installation": "inst_b"}); code != 200 {
		t.Fatalf("after release: %d", code)
	}

	// Unknown and revoked keys are told apart from transient errors.
	if code, rep = post(t, ts.URL+"/v1/activate", "", map[string]any{"key": "FSP-NOPE-NOPE-NOPE-NOPE", "installation": "x"}); code != 403 || rep["code"] != "unknown" {
		t.Fatalf("unknown: %d %v", code, rep)
	}
	if code, _ = post(t, ts.URL+"/admin/licenses/"+key+"/revoke", "adm", map[string]any{"reason": "chargeback"}); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	if code, rep = post(t, ts.URL+"/v1/refresh", "", map[string]any{"key": key, "installation": "inst_b"}); code != 403 || rep["code"] != "revoked" {
		t.Fatalf("revoked refresh: %d %v", code, rep)
	}
	_ = sv
}

func TestOfflineToken(t *testing.T) {
	sv, pub, ts := newTestServer(t)
	_, created := post(t, ts.URL+"/admin/licenses", "adm", map[string]any{"tier": "business", "licensee": "Corp", "seats": 3, "expires": "never", "limits": map[string]int{"retention_days": 730}})
	key := created["key"].(string)
	code, rep := post(t, ts.URL+"/admin/licenses/"+key+"/offline", "adm", map[string]any{"installation": "inst_air"})
	if code != 200 {
		t.Fatalf("offline: %d %v", code, rep)
	}
	l, err := licensing.Parse(rep["token"].(string), pub)
	if err != nil {
		t.Fatal(err)
	}
	if l.Refresh != "" || l.Installation != "inst_air" || l.Expires != "" || l.Limit("retention_days") != 730 || l.Tier != "business" {
		t.Fatalf("offline token wrong: %+v", l)
	}
	// The CLI path mints the same kind of document.
	row, _ := sv.s.get(key)
	tok, err := token(row, sv.priv, "", 0, "cli")
	if err != nil {
		t.Fatal(err)
	}
	if l2, err := licensing.Parse(tok, pub); err != nil || l2.Installation != "" || l2.Issuer != "cli" {
		t.Fatalf("cli token: %v %+v", err, l2)
	}
}
