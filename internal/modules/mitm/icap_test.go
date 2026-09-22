package mitm

import (
	"bufio"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// A REQMOD message as squid sends it: the request headers, then the body
// preview in chunked form.
func TestReadICAPReqmod(t *testing.T) {
	hdr := "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\n" +
		"Content-Type: application/dns-message\r\nCookie: secret=value\r\n\r\n"
	// A DNS query for example.com A.
	msg, _ := base64.StdEncoding.DecodeString("AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE=")
	body := "b\r\n" + string(msg[:11]) + "\r\n" +
		strconv.FormatInt(int64(len(msg)-11), 16) + "\r\n" + string(msg[11:]) + "\r\n0\r\n\r\n"
	raw := "REQMOD icap://127.0.0.1:1344/reqmod ICAP/1.0\r\n" +
		"Host: 127.0.0.1:1344\r\nX-Client-IP: 10.99.0.162\r\nAllow: 204\r\n" +
		"Encapsulated: req-hdr=0, req-body=" + itoa(len(hdr)) + "\r\n\r\n" + hdr + body
	req, err := readICAP(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readICAP: %v", err)
	}
	if req.Method != "REQMOD" {
		t.Fatalf("method %q", req.Method)
	}
	if got := req.ClientIP(); got != "10.99.0.162" {
		t.Fatalf("client %q", got)
	}
	if req.HTTPRequest == nil || req.HTTPRequest.Host != "cloudflare-dns.com" {
		t.Fatalf("request %+v", req.HTTPRequest)
	}
	if len(req.Body) != len(msg) {
		t.Fatalf("body %d want %d", len(req.Body), len(msg))
	}
	h := safeHeaders(req.HTTPRequest.Header)
	if !strings.Contains(h["Cookie"], "not recorded") {
		t.Fatalf("cookie recorded: %q", h["Cookie"])
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
