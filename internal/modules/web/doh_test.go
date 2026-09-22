package web

import "testing"

func TestParseDoHURL(t *testing.T) {
	// dig +noedns example.com A, base64url of the wire message
	p, q, ok := parseDoHURL("https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE")
	if !ok || p != "cloudflare-dns.com" || q == nil || q.Name != "example.com" || q.Type != "A" {
		t.Fatalf("got %q %+v %v", p, q, ok)
	}
	if _, q2, ok := parseDoHURL("https://dns.google/resolve?name=news.ycombinator.com&type=A"); !ok || q2 == nil || q2.Name != "news.ycombinator.com" {
		t.Fatalf("json form: %+v %v", q2, ok)
	}
	if p3, q3, ok := parseDoHURL("https://dns.quad9.net/dns-query"); !ok || p3 != "dns.quad9.net" || q3 != nil {
		t.Fatalf("post form: %q %+v %v", p3, q3, ok)
	}
	if _, _, ok := parseDoHURL("https://example.com/index.html"); ok {
		t.Fatal("not a DoH url")
	}
}
