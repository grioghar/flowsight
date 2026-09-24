package paths

// Servers that say where they are.
//
// An anycast address is announced from dozens of sites, and no database,
// measurement or range list can say which one a packet from here reached.
// The server can. Every root server and most large resolvers answer a CHAOS
// TXT query for id.server (or the older hostname.bind) with the name of the
// instance: DFW.cf.f.root-servers.org, c01.MCI.eroot, groot-con2-1. The root
// operators also publish, per letter, the list of their sites with those
// identifiers and the town each is in, so an answer can be looked up rather
// than decoded; where it cannot, the identifier is read like a router name.
// Either way the clock still rules: an instance the round trip could not
// reach is not believed, whatever it called itself.

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const nsidKV = "paths.nsid:"
const nsidTTL = 7 * 24 * time.Hour

// Identity is what a server said about itself, and what was made of it.
type Identity struct {
	ID      string  `json:"id"`
	Site    string  `json:"site,omitempty"` // town, country
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
	By      string  `json:"by,omitempty"` // "root-servers.org" or "name code"
	Letter  string  `json:"letter,omitempty"`
	At      int64   `json:"at"`
	Located bool    `json:"located"`
}

type cachedIdentity struct {
	At time.Time
	I  *Identity
}

// chaosTXT asks a name server, over UDP, for a CHAOS-class TXT record and
// returns the first string. Hand-built, because the standard library has
// no DNS client for anything but the resolver's own questions.
func chaosTXT(ip, qname string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "53"), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	id := uint16(time.Now().UnixNano())
	msg := make([]byte, 0, 64)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = append(msg, 0x00, 0x00)               // flags: query, no recursion
	msg = binary.BigEndian.AppendUint16(msg, 1) // one question
	msg = append(msg, 0, 0, 0, 0, 0, 0)         // no answers, authority, additional
	for _, label := range strings.Split(strings.TrimSuffix(qname, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 16) // TXT
	msg = binary.BigEndian.AppendUint16(msg, 3)  // CHAOS
	if _, err := conn.Write(msg); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return parseTXTAnswer(buf[:n], id)
}

// parseTXTAnswer walks a reply and returns the first TXT string in the
// answer section.
func parseTXTAnswer(b []byte, id uint16) (string, error) {
	if len(b) < 12 || binary.BigEndian.Uint16(b[0:2]) != id {
		return "", errors.New("not our answer")
	}
	if rcode := b[3] & 0x0f; rcode != 0 {
		return "", fmt.Errorf("rcode %d", rcode)
	}
	qd, an := int(binary.BigEndian.Uint16(b[4:6])), int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	skipName := func() error {
		for {
			if off >= len(b) {
				return errors.New("truncated")
			}
			l := int(b[off])
			if l == 0 {
				off++
				return nil
			}
			if l&0xc0 == 0xc0 {
				off += 2
				return nil
			}
			off += 1 + l
		}
	}
	for i := 0; i < qd; i++ {
		if err := skipName(); err != nil {
			return "", err
		}
		off += 4
	}
	for i := 0; i < an; i++ {
		if err := skipName(); err != nil {
			return "", err
		}
		if off+10 > len(b) {
			return "", errors.New("truncated")
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			return "", errors.New("truncated")
		}
		if typ == 16 && rdlen > 0 {
			l := int(b[off])
			if l > rdlen-1 {
				l = rdlen - 1
			}
			return string(b[off+1 : off+1+l]), nil
		}
		off += rdlen
	}
	return "", errors.New("no TXT in answer")
}

// identifyServer asks id.server, then hostname.bind, and returns the first
// non-empty identifier.
func identifyServer(ip string) (string, error) {
	var lastErr error
	for _, q := range []string{"id.server", "hostname.bind"} {
		s, err := chaosTXT(ip, q, 2*time.Second)
		if err == nil && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s), nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no identifier")
	}
	return "", lastErr
}

// ---------------------------------------------------------------- root sites

// rootSite is one published site of one root letter.
type rootSite struct {
	Letter, Town, Country string
	Lat, Lon              float64
	Identifiers           []string
}

const rootSitesFile = "root-sites.json"

// refreshRootSites pulls each letter's site list once a week.
func (m *Module) refreshRootSites() error {
	dir := m.providersDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, rootSitesFile)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < 7*24*time.Hour {
		return m.loadRootSites()
	}
	var all []rootSite
	client := safeClient(time.Minute)
	for _, L := range "ABCDEFGHIJKLM" {
		u := fmt.Sprintf("https://root-servers.org/root/%c/json/", L)
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "FlowSight/"+m.version()+" (+https://github.com/grioghar/flowsight)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var in struct {
			Sites []struct {
				Town, Country string
				Latitude      float64
				Longitude     float64
				Identifiers   []string
			}
		}
		if json.Unmarshal(body, &in) != nil {
			continue
		}
		for _, s := range in.Sites {
			all = append(all, rootSite{Letter: strings.ToLower(string(L)), Town: s.Town, Country: s.Country, Lat: s.Latitude, Lon: s.Longitude, Identifiers: s.Identifiers})
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(all) == 0 {
		return errors.New("root-servers.org: nothing fetched")
	}
	b, _ := json.Marshal(all)
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	return m.loadRootSites()
}

func (m *Module) loadRootSites() error {
	b, err := os.ReadFile(filepath.Join(m.providersDir(), rootSitesFile))
	if err != nil {
		return nil
	}
	var all []rootSite
	if json.Unmarshal(b, &all) != nil {
		return nil
	}
	byID := map[string]rootSite{}
	for _, s := range all {
		for _, id := range s.Identifiers {
			byID[strings.ToLower(id)] = s
		}
	}
	m.mu.Lock()
	m.rootSites, m.rootByID = all, byID
	m.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- decoding

var idToken = regexp.MustCompile(`^([a-z]{2})?([a-z]{3,})(\d+[a-z]?)?$`)

// identityHost turns an instance identifier into something the router-name
// decoder reads: tokens as given, plus each token with its instance suffix
// removed and, where a two-letter country leads it, without that too.
// "u-ci-nominet2.usdal1" becomes "u.ci.nominet2.usdal1.usdal.dal.x.y".
func identityHost(id string) string {
	var labels, bare []string
	for _, tok := range strings.FieldsFunc(strings.ToLower(id), func(r rune) bool { return r == '-' || r == '.' || r == '_' }) {
		if tok == "" {
			continue
		}
		labels = append(labels, tok)
		if m := idToken.FindStringSubmatch(tok); m != nil && (m[1] != "" || m[3] != "") {
			if m[3] != "" {
				bare = append(bare, m[1]+m[2])
			}
			if m[1] != "" && countryHeads[m[1]] {
				bare = append(bare, m[2])
			}
		}
	}
	// The bare forms go last, beside the pseudo-domain: the decoder trusts
	// a code more the nearer the domain it sits, and an instance name puts
	// its site anywhere.
	return strings.Join(append(labels, bare...), ".") + ".x.y"
}

// decodeIdentity turns an identifier into a place: the published site with
// that identifier, else the airport code in it read like a router name.
func (m *Module) decodeIdentity(id string, rtt float64, h Home) *Identity {
	out := &Identity{ID: id, At: time.Now().Unix()}
	low := strings.ToLower(id)
	m.mu.Lock()
	byID := m.rootByID
	m.mu.Unlock()
	if s, ok := byID[low]; ok {
		out.Site, out.Lat, out.Lon, out.By, out.Letter, out.Located = s.Town+", "+s.Country, s.Lat, s.Lon, "root-servers.org", s.Letter, true
	} else {
		// A published identifier may carry an instance suffix the list omits.
		for k, s := range byID {
			if strings.HasPrefix(low, k) || strings.HasPrefix(k, low) {
				out.Site, out.Lat, out.Lon, out.By, out.Letter, out.Located = s.Town+", "+s.Country, s.Lat, s.Lon, "root-servers.org", s.Letter, true
				break
			}
		}
	}
	if !out.Located {
		// Read the codes in it the way a router name is read, and take the
		// best one the clock allows. Instance names dress their codes up
		// -- qro1a, usdal1, usmes2, dfw07 -- so each token is also offered
		// bare: instance suffix stripped, country prefix stripped.
		host := identityHost(low)
		if match, score, _ := m.placeFromName(host, rtt, h); score >= 0.55 && match.Pop.City != "" {
			out.Site, out.Lat, out.Lon, out.By, out.Located = match.Pop.City, match.Pop.Lat, match.Pop.Lon, "name code "+match.Code, true
		}
	}
	if out.Located && rtt > 0 && !reachable(h, out.Lat, out.Lon, rtt) {
		out.Located = false // it said so, but the clock says it cannot be there from here
		out.By += " (unreachable at this round trip; not used)"
	}
	return out
}

// identityFor is the cached identity, or nothing.
func (m *Module) identityFor(ip string) *Identity {
	if m.ctx == nil || m.ctx.Store == nil {
		return nil
	}
	var c cachedIdentity
	if m.ctx.Store.KVGet(nsidKV+ip, &c) && time.Since(c.At) < nsidTTL {
		return c.I
	}
	return nil
}

// wantIdentity queues an anycast hop for the next probe run.
func (m *Module) wantIdentity(ip string, rtt float64) {
	if !validIP(ip) || m.ctx == nil || m.ctx.Store == nil {
		return
	}
	var c cachedIdentity
	if m.ctx.Store.KVGet(nsidKV+ip, &c) && time.Since(c.At) < nsidTTL {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, q := range m.nsidQueue {
		if q.IP == ip {
			return
		}
	}
	if len(m.nsidQueue) < 200 {
		m.nsidQueue = append(m.nsidQueue, assistCandidate{IP: ip, RTT: rtt})
	}
}

// identifyJob asks a handful of queued servers each run. A CHAOS query is
// a single small packet; twenty a run is nothing to anyone.
func (m *Module) identifyJob() error {
	if !core.Bool(m.ctx.Settings(), "identify", true) {
		return nil
	}
	m.mu.Lock()
	q := append([]assistCandidate(nil), m.nsidQueue...)
	m.nsidQueue = nil
	m.mu.Unlock()
	h := m.home()
	for i, c := range q {
		if i >= 20 {
			break
		}
		id, err := identifyServer(c.IP)
		var ident *Identity
		if err != nil {
			ident = &Identity{ID: "", By: "no answer: " + err.Error(), At: time.Now().Unix()}
		} else {
			ident = m.decodeIdentity(id, c.RTT, h)
		}
		_ = m.ctx.Store.KVSet(nsidKV+c.IP, cachedIdentity{At: time.Now(), I: ident})
		m.mu.Lock()
		m.nsidAsked++
		if ident.Located {
			m.nsidPlaced++
		}
		m.mu.Unlock()
	}
	return nil
}

func (m *Module) identifyStatus() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]any{"on": core.Bool(m.ctx.Settings(), "identify", true), "asked_this_session": m.nsidAsked, "placed_this_session": m.nsidPlaced,
		"known": m.ctx.Store.KVCount(nsidKV), "queued": len(m.nsidQueue), "root_sites": len(m.rootSites)}
}
