package web

// DNS over HTTPS, seen from inside an inspected session.
//
// A DoH client sends its query to a provider over HTTPS, so the network's
// own resolver never sees it and FlowSight's DNS page is blind to it. Once
// the session is inspected the request itself is visible, and how much of
// the query FlowSight can recover depends on which form the client used:
//
//	GET  /dns-query?dns=<base64url of the DNS message>   the name is in the
//	     URL, so it is recovered here and filed like any other lookup.
//	POST /dns-query  (body: application/dns-message)     the name is in the
//	     body, which a proxy log does not carry; the query is recorded as
//	     "a DoH request to this provider" and nothing more.
//
// Firefox and Chrome use POST, so for them the honest control is to deny
// the built-in "encrypted-dns" category: the canary name makes Firefox turn
// DoH off by itself, and blocking the providers sends any client back to the
// resolver, where every lookup is visible again.

import (
	"encoding/base64"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

// dohQuery is the name and type recovered from one DoH request.
type dohQuery struct {
	Name, Type string
}

// parseDoHURL recognises a DoH request and, for the GET form, decodes the
// question inside it. ok is false when the URL is not a DoH request.
func parseDoHURL(rawURL string) (provider string, q *dohQuery, ok bool) {
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	host, rest, _ := strings.Cut(u, "/")
	if host == "" {
		return "", nil, false
	}
	path, query, _ := strings.Cut(rest, "?")
	path = "/" + strings.TrimPrefix(path, "/")
	// The registered path is /dns-query; providers also use /dns-query/{id}
	// and a few use /resolve or /query.
	p := strings.ToLower(path)
	if !(strings.HasPrefix(p, "/dns-query") || p == "/resolve" || p == "/query" || strings.HasSuffix(p, "/dns-query")) {
		return "", nil, false
	}
	provider = strings.ToLower(host)
	if i := strings.IndexByte(provider, ':'); i > 0 {
		provider = provider[:i]
	}
	for _, kv := range strings.Split(query, "&") {
		k, v, _ := strings.Cut(kv, "=")
		switch strings.ToLower(k) {
		case "dns": // RFC 8484 wire format, base64url without padding
			if msg, err := base64.RawURLEncoding.DecodeString(v); err == nil {
				if name, qtype, ok := dnsQuestion(msg); ok {
					return provider, &dohQuery{Name: name, Type: qtype}, true
				}
			}
		case "name": // the JSON API Google and Cloudflare also offer
			if v != "" {
				return provider, &dohQuery{Name: strings.ToLower(strings.TrimSuffix(v, ".")), Type: "A"}, true
			}
		}
	}
	return provider, nil, true
}

// DNSQuestion reads the first question of a DNS message in wire format. It
// is exported because deep inspection decodes the same thing out of a
// request body.
func DNSQuestion(msg []byte) (name, qtype string, ok bool) { return dnsQuestion(msg) }

// dnsQuestion reads the first question of a DNS message in wire format.
func dnsQuestion(msg []byte) (name, qtype string, ok bool) {
	if len(msg) < 13 || msg[4] == 0 && msg[5] == 0 { // header + at least one question
		return "", "", false
	}
	var sb strings.Builder
	i := 12
	for i < len(msg) {
		n := int(msg[i])
		if n == 0 {
			i++
			break
		}
		if n&0xc0 != 0 { // a pointer has no place in a question
			return "", "", false
		}
		if i+1+n > len(msg) || sb.Len()+n > 253 {
			return "", "", false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[i+1 : i+1+n])
		i += 1 + n
	}
	if sb.Len() == 0 || i+2 > len(msg) {
		return "", "", false
	}
	t := int(msg[i])<<8 | int(msg[i+1])
	return strings.ToLower(sb.String()), dnsTypeName(t), true
}

func dnsTypeName(t int) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 43:
		return "DS"
	case 48:
		return "DNSKEY"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	}
	return "TYPE"
}

// noteDoH files what an inspected DoH request revealed. A GET carries the
// question and becomes a DNS record like any other; a POST is recorded as a
// request to that provider so the operator can see DoH is in use and by whom.
func (m *Module) noteDoH(ts int64, client, url, method string, ms float64) *core.DNSRecord {
	provider, q, ok := parseDoHURL(url)
	if !ok {
		return nil
	}
	rec := &core.DNSRecord{TS: ts, Client: client, Action: "pass", RCode: "NOERROR",
		AnswerSource: "doh " + provider, MS: ms, Source: "doh:" + provider}
	if q != nil {
		rec.Domain, rec.QType = q.Name, q.Type
		return rec
	}
	if strings.EqualFold(method, "POST") {
		// The question is in the body, which the proxy log does not carry.
		rec.Domain = provider
		rec.QType = "DoH"
		rec.AnswerSource = "doh (query in body)"
		return rec
	}
	return nil
}
