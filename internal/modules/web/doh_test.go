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

// squid logs a bumped CONNECT as NONE_NONE/000 with no bytes whether the
// client accepted the minted certificate or refused it. The difference is
// whether a request follows on the same client connection. Counting the
// CONNECT alone as a refusal marked working sites as pinned and spliced them,
// losing inspection on exactly the sites that could be inspected.
func TestBumpedConnectIsNotARefusalByItself(t *testing.T) {
	// Accepted: the CONNECT, then a request on the same client port.
	accepted := []string{
		`1790065644.519 253 2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6 59163 2607:6bc0::10 443 NONE_NONE/000 0 0 CONNECT "[2607:6bc0::10]:443" bridge.claudeusercontent.com bump TLS/1.3 "-" "-" -`,
		`1790065644.660 140 2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6 59163 2607:6bc0::10 443 TCP_MISS/426 293 677 GET "https://bridge.claudeusercontent.com/devices/x" bridge.claudeusercontent.com bump TLS/1.3 "-" "-" -`,
	}
	// Refused: three CONNECTs on three ports and nothing inside any of them.
	refused := []string{
		`1790065160.674 495 2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6 55652 2620:100:601c:20::a27d:614 443 NONE_NONE/000 0 0 CONNECT "[2620:100:601c:20::a27d:614]:443" d6.dropbox.com bump TLS/1.3 "-" "-" -`,
		`1790065160.676 491 2600:1700:3ab0:f43f:4825:7e4e:55d:b2b6 55653 2620:100:601c:20::a27d:614 443 NONE_NONE/000 0 0 CONNECT "[2620:100:601c:20::a27d:614]:443" d6.dropbox.com bump TLS/1.3 "-" "-" -`,
	}
	for _, line := range append(accepted, refused...) {
		mm := logRe.FindStringSubmatch(line)
		if mm == nil {
			t.Fatalf("line did not parse: %s", line[:60])
		}
		if got := dash(mm[15]); got != "bump" {
			t.Fatalf("bump mode not read, got %q", got)
		}
		if got := mm[5]; got == "" {
			t.Fatal("client port not captured; the outcome cannot be correlated without it")
		}
	}
	// The two accepted lines share a client port; the refused ones do not
	// share theirs with any request line.
	a0 := logRe.FindStringSubmatch(accepted[0])
	a1 := logRe.FindStringSubmatch(accepted[1])
	if a0[5] != a1[5] {
		t.Fatalf("the request inside the tunnel must carry the same client port: %s vs %s", a0[5], a1[5])
	}
	if a1[12] == "CONNECT" {
		t.Fatal("the inner request must not look like another CONNECT")
	}
	r0 := logRe.FindStringSubmatch(refused[0])
	if r0[5] == a1[5] {
		t.Fatal("test data is wrong: the refused connection shares a port with the accepted one")
	}
}
