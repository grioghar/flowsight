package paths

// Fetching things the operator told us to fetch, without being turned into a
// way to reach things the operator did not.
//
// Two settings take URLs: the cable map and the land-route sources. A daemon
// that fetches an arbitrary URL from inside the network is a proxy to
// everything the network can see -- the router's own admin interface, a
// printer, the hypervisor's management port -- and the person typing the URL
// need not be the person who owns the network. So the client used for those
// fetches refuses to dial anything that is not a public address, and it
// refuses at dial time, after the name has been resolved, because a name is
// allowed to say one thing to a resolver and another to a socket.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var errNotPublic = errors.New("refusing to fetch from a non-public address")

// publicOnly rejects addresses that are not on the public internet.
func publicOnly(ip net.IP) error {
	switch {
	case ip == nil:
		return errNotPublic
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return errNotPublic
	}
	// Carrier-grade NAT and the documentation ranges are not "private" to Go
	// but are not the internet either.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 { // 100.64.0.0/10
			return errNotPublic
		}
		if v4[0] == 192 && v4[1] == 0 && v4[2] == 0 { // 192.0.0.0/24
			return errNotPublic
		}
	}
	return nil
}

// safeClient fetches only from public hosts over http or https, and re-checks
// every address it is about to dial -- so a redirect, or a name that resolves
// differently the second time, cannot walk it somewhere private.
func safeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, // deliberately not from the environment: the operator's URL is the whole of the request
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ipa := range ips {
				if err := publicOnly(ipa.IP); err != nil {
					last = fmt.Errorf("%s: %w", host, err)
					continue
				}
				c, err := dialer.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
				if err == nil {
					return c, nil
				}
				last = err
			}
			if last == nil {
				last = fmt.Errorf("%s: no address", host)
			}
			return nil, last
		},
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          4,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return checkFetchURL(req.URL.String())
		},
	}
}

// checkFetchURL is the shape a user-supplied fetch URL must have.
func checkFetchURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q: only http and https are fetched", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%q: no host", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q: credentials in a fetch URL are not used", raw)
	}
	// A literal address gets checked here as well as at dial time, so the
	// refusal names the reason rather than a socket error.
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		if err := publicOnly(ip); err != nil {
			return fmt.Errorf("%q: %w", raw, err)
		}
	}
	return nil
}

// validIP is the gate between a string that came off the wire and anything
// that uses it as a key, a name to resolve, or part of a URL.
func validIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}
