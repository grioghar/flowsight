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

// The distinguished names in a squid line contain spaces, so they are logged
// in quotes; a proxy still running the previous configuration writes them
// bare. Both must parse, and neither may swallow the other's field.
func TestLogLineCertNames(t *testing.T) {
	quoted := `1790060505.972 5470 10.99.0.162 40554 93.184.216.34 443 TCP_TUNNEL/200 900833 1933 CONNECT "example.com:443" example.com bump TLSv1.3 "/CN=example.com" "/C=US/O=Let's Encrypt/CN=R11" curl/8.14.1`
	mm := logRe.FindStringSubmatch(quoted)
	if mm == nil {
		t.Fatal("quoted line did not parse")
	}
	if got := either(mm[17], mm[18]); got != "/CN=example.com" {
		t.Fatalf("subject %q", got)
	}
	if got := either(mm[19], mm[20]); got != "/C=US/O=Let's Encrypt/CN=R11" {
		t.Fatalf("issuer %q", got)
	}
	bare := `1790060505.972 5470 10.99.0.162 40554 93.184.216.34 443 TCP_TUNNEL/200 900833 1933 CONNECT "example.com:443" example.com bump TLSv1.3 - - curl/8.14.1`
	mm = logRe.FindStringSubmatch(bare)
	if mm == nil {
		t.Fatal("bare line did not parse")
	}
	if got := dash(either(mm[17], mm[18])); got != "" {
		t.Fatalf("subject %q", got)
	}
	if got := dash(either(mm[19], mm[20])); got != "" {
		t.Fatalf("issuer %q", got)
	}
}
