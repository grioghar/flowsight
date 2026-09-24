package paths

// Who runs a hop, and where it actually is.
//
// A traceroute gives an address and a time. Everything else a reader wants to
// know -- whose router this is, which network announces it, what building it
// might be in -- has to come from somewhere else, and the sources disagree in
// ways that matter:
//
//   the router's own name   a site code the operator wrote down. Best evidence
//                           of the city, when it is there at all.
//   the routing table       which network announces the address today. This is
//                           who runs it, and it is current.
//   the registry            who the block is allocated to, and the postal
//                           address on that allocation. That address is a head
//                           office, not a data centre, and saying otherwise
//                           would put every Lumen router in Monroe, Louisiana.
//   PeeringDB               buildings an operator has said it occupies, with
//                           street addresses. Real addresses, but presence in
//                           a city is not proof that this router is in it, so
//                           these are only offered once the name has already
//                           given us the city, and are always a short list.
//
// Each is labelled where it came from. None of them is allowed to speak for
// another.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Detail is everything known about a hop beyond the measurement itself.
type Detail struct {
	// Name is the reverse-DNS name, resolved here rather than inherited.
	Name string `json:"name,omitempty"`

	// From the router's name.
	PoPCode string  `json:"pop_code,omitempty"`
	PoPCity string  `json:"pop_city,omitempty"`
	PoPLat  float64 `json:"pop_lat,omitempty"`
	PoPLon  float64 `json:"pop_lon,omitempty"`

	// From the routing table.
	ASN    string `json:"asn,omitempty"`
	ASName string `json:"as_name,omitempty"`
	Prefix string `json:"prefix,omitempty"`

	// From the registry.
	RIR       string `json:"rir,omitempty"`
	Allocated string `json:"allocated,omitempty"`
	NetName   string `json:"net_name,omitempty"`
	Org       string `json:"org,omitempty"`
	// OrgAddr is the address on the allocation. It is a head office. The
	// field name says address and the label in the interface has to say so
	// too, or a reader will take it for the router's address.
	OrgAddr string `json:"org_addr,omitempty"`

	// From PeeringDB.
	Facilities []Facility `json:"facilities,omitempty"`
	// Scoped says the list was narrowed to the city the router's name gave.
	// False means these are simply everywhere the operator is, which is not
	// evidence about this hop, and the interface must not present it as such.
	Scoped bool `json:"facilities_scoped"`
}

// Facility is a building an operator has published a presence in.
type Facility struct {
	Name    string  `json:"name"`
	Address string  `json:"address,omitempty"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
}

var labelSplit = regexp.MustCompile(`[-_]`)
var codeThenDigits = regexp.MustCompile(`^([a-z]{2,4})[0-9]{0,3}$`)
var sixLetters = regexp.MustCompile(`^[a-z]{6,8}$`)

// decodePoP reads a site out of a router's hostname.
//
// The site code sits nearer the domain than the interface does -- the name is
// built interface-first, ae10.edge1.dal2.sp.lumen.tech -- so the labels are
// read back to front and the first place name wins. The registered domain is
// dropped first, because plenty of operators have a country or a city in it.
func decodePoP(host string) (code string, p pop, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return "", pop{}, false
	}
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		labels = labels[:len(labels)-2]
	}
	var parts []string
	for _, l := range labels {
		for _, x := range labelSplit.Split(l, -1) {
			if x != "" {
				parts = append(parts, x)
			}
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		x := parts[i]
		if skip[x] {
			continue
		}
		if m := codeThenDigits.FindStringSubmatch(x); m != nil {
			if q, hit := pops[m[1]]; hit {
				return m[1], q, true
			}
		}
		// Telephone-company style: "tpkaks" is Topeka plus a state, "sndgca"
		// is San Diego plus one. The first three letters carry the city.
		if sixLetters.MatchString(x) {
			if q, hit := pops[x[:3]]; hit {
				return x[:3], q, true
			}
		}
	}
	return "", pop{}, false
}

// reverseName asks what a router calls itself. Most do not answer: a hop with
// no name is the common case, not a fault, and the caller must carry on.
func reverseName(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ---- routing table, via DNS ----

// originASN asks Team Cymru which network announces an address. It is a DNS
// query rather than an HTTP one, which means it is cheap, cached by the
// resolver, and works on a box with no outbound HTTP.
func originASN(ip string) (asn, prefix, rir, allocated string) {
	rev, ok := reverseV4(ip)
	if !ok {
		return "", "", "", ""
	}
	txt, err := net.LookupTXT(rev + ".origin.asn.cymru.com")
	if err != nil || len(txt) == 0 {
		return "", "", "", ""
	}
	f := splitPipe(txt[0])
	if len(f) < 5 {
		return "", "", "", ""
	}
	// The first field can list several origins for a prefix announced by more
	// than one network. One of them is the answer and nothing here can say
	// which, so the first is taken and the ambiguity is not hidden behind an
	// invented certainty.
	asn = strings.Fields(f[0])[0]
	return asn, f[1], f[3], f[4]
}

func asName(asn string) string {
	if asn == "" {
		return ""
	}
	txt, err := net.LookupTXT("AS" + asn + ".asn.cymru.com")
	if err != nil || len(txt) == 0 {
		return ""
	}
	f := splitPipe(txt[0])
	return f[len(f)-1]
}

func reverseV4(ip string) (string, bool) {
	a := net.ParseIP(ip)
	if a == nil || a.To4() == nil {
		return "", false // Cymru serves v6 under a different zone; not wired up
	}
	p := strings.Split(a.To4().String(), ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0], true
}

func splitPipe(s string) []string {
	f := strings.Split(strings.Trim(s, `"`), "|")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

// ---- registry, via RDAP ----

type rdapReply struct {
	Name     string `json:"name"`
	Entities []struct {
		Roles      []string        `json:"roles"`
		VCardArray json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

// rdapNet reads the allocation and the registrant off the registry.
//
// rdap.org is a redirector to whichever registry holds the block, so one URL
// covers all five. The address arrives in a vCard, and not where a reader of
// the spec would expect: the structured value is empty and the whole thing is
// in the "label" parameter, which is why this decodes the raw array instead of
// unmarshalling into a struct.
func rdapNet(c *http.Client, ip string) (netName, org, addr string) {
	resp, err := c.Get("https://rdap.org/ip/" + ip)
	if err != nil {
		return "", "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", ""
	}
	var r rdapReply
	if json.Unmarshal(body, &r) != nil {
		return "", "", ""
	}
	netName = r.Name
	for _, e := range r.Entities {
		if !hasRole(e.Roles, "registrant") {
			continue
		}
		o, a := vcard(e.VCardArray)
		if o != "" {
			org = o
		}
		if a != "" {
			addr = a
		}
	}
	return netName, org, addr
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// vcard pulls the display name and the postal label out of a jCard.
func vcard(raw json.RawMessage) (name, addr string) {
	if len(raw) == 0 {
		return "", ""
	}
	var outer []json.RawMessage
	if json.Unmarshal(raw, &outer) != nil || len(outer) < 2 {
		return "", ""
	}
	var entries [][]json.RawMessage
	if json.Unmarshal(outer[1], &entries) != nil {
		return "", ""
	}
	for _, e := range entries {
		if len(e) < 4 {
			continue
		}
		var kind string
		if json.Unmarshal(e[0], &kind) != nil {
			continue
		}
		switch kind {
		case "fn":
			var v string
			if json.Unmarshal(e[3], &v) == nil {
				name = v
			}
		case "adr":
			var params struct {
				Label string `json:"label"`
			}
			if json.Unmarshal(e[1], &params) == nil && params.Label != "" {
				addr = strings.Join(nonEmptyLines(params.Label), ", ")
			}
		}
	}
	return name, addr
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// ---- buildings, via PeeringDB ----

type pdbNet struct {
	Data []struct {
		ID       int `json:"id"`
		FacCount int `json:"fac_count"`
	} `json:"data"`
}

type pdbNetFac struct {
	Data []struct {
		Name  string `json:"name"`
		FacID int    `json:"fac_id"`
		City  string `json:"city"`
	} `json:"data"`
}

type pdbFac struct {
	Data []struct {
		Name     string  `json:"name"`
		Address1 string  `json:"address1"`
		City     string  `json:"city"`
		State    string  `json:"state"`
		Zipcode  string  `json:"zipcode"`
		Country  string  `json:"country"`
		Lat      float64 `json:"latitude"`
		Lon      float64 `json:"longitude"`
	} `json:"data"`
}

// facilitiesFor lists buildings an operator has published, narrowed to a city
// when one is known.
//
// The narrowing is the whole point. An operator the size of Cloudflare
// publishes presence in three hundred buildings, and handing a reader all of
// them under the heading of one hop would be worse than saying nothing. When
// the city is known the list is short and genuinely about this router; when it
// is not, the caller is told so through Scoped and has to present it as the
// unrelated list that it is.
func facilitiesFor(c *http.Client, asn, city string) (out []Facility, scoped bool) {
	if asn == "" {
		return nil, false
	}
	var n pdbNet
	if !getJSON(c, "https://www.peeringdb.com/api/net?asn="+asn, &n) || len(n.Data) == 0 {
		return nil, false
	}
	if n.Data[0].FacCount == 0 {
		return nil, false // plenty of large carriers publish nothing
	}
	var nf pdbNetFac
	if !getJSON(c, fmt.Sprintf("https://www.peeringdb.com/api/netfac?net_id=%d", n.Data[0].ID), &nf) {
		return nil, false
	}
	city = strings.ToLower(strings.TrimSpace(strings.SplitN(city, ",", 2)[0]))
	var want []int
	for _, r := range nf.Data {
		if city != "" && strings.ToLower(r.City) == city {
			want = append(want, r.FacID)
		}
	}
	scoped = len(want) > 0
	if !scoped {
		for i, r := range nf.Data {
			if i >= 3 {
				break
			}
			want = append(want, r.FacID)
		}
	}
	if len(want) > 4 {
		want = want[:4]
	}
	for _, id := range want {
		var f pdbFac
		if !getJSON(c, fmt.Sprintf("https://www.peeringdb.com/api/fac/%d", id), &f) || len(f.Data) == 0 {
			continue
		}
		d := f.Data[0]
		parts := []string{}
		for _, x := range []string{d.Address1, d.City, d.State, d.Zipcode, d.Country} {
			if x != "" {
				parts = append(parts, x)
			}
		}
		out = append(out, Facility{Name: d.Name, Address: strings.Join(parts, ", "),
			City: d.City, Lat: d.Lat, Lon: d.Lon})
	}
	return out, scoped
}

func getJSON(c *http.Client, url string, into any) bool {
	resp, err := c.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return false
	}
	return json.Unmarshal(body, into) == nil
}

// ---- assembling and caching ----

func (m *Module) registryOK() bool {
	return core.Bool(m.ctx.Settings(), "registry", true)
}

func (m *Module) facilitiesOK() bool {
	return core.Bool(m.ctx.Settings(), "facilities", true)
}

const detailKV = "paths.detail."

// detailTTL is long because none of this changes quickly. An allocation
// outlives most networks; a building does not move. Re-asking hourly would
// spend someone else's rate limit to learn nothing.
const detailTTL = 30 * 24 * time.Hour

// detailSchema is bumped whenever what gets gathered changes. Without it a
// month-long cache quietly serves answers collected by an older, thinner
// version of this code, and the new fields read as "nothing known" rather
// than "not asked yet".
const detailSchema = 2

type cachedDetail struct {
	At time.Time `json:"at"`
	V  int       `json:"v"`
	D  Detail    `json:"d"`
}

// cached returns what is already known about an address, if anything.
func (m *Module) cached(ip string) (Detail, bool) {
	var c cachedDetail
	if m.ctx.Store.KVGet(detailKV+ip, &c) && c.V == detailSchema && time.Since(c.At) < detailTTL {
		return c.D, true
	}
	return Detail{}, false
}

// detailFor gathers everything known about one address.
//
// This is the slow path and it is not for a waiting reader: a registry and
// PeeringDB are two round trips across the internet each, and a graph with
// four hundred hops in it once took long enough that the page gave up before
// the answer arrived. It runs on a timer instead, filling the cache a few
// addresses at a time, and the page shows what has been gathered so far.
func (m *Module) detailFor(ip, host string) Detail {
	if d, ok := m.cached(ip); ok {
		return d
	}
	var d Detail
	// Resolve the name here rather than take whatever the enrichment module
	// happened to have. Everything below hangs off this one string, and
	// depending on another module's optional setting for it means the whole
	// inference goes quiet without anything looking broken -- which is
	// precisely what it did: seven hundred hops, not one name, no sites read.
	if host == "" {
		host = reverseName(ip)
	}
	d.Name = host
	if code, p, ok := decodePoP(host); ok {
		d.PoPCode, d.PoPCity, d.PoPLat, d.PoPLon = code, p.City, p.Lat, p.Lon
	}
	d.ASN, d.Prefix, d.RIR, d.Allocated = originASN(ip)
	d.ASName = asName(d.ASN)

	if m.registryOK() {
		client := &http.Client{Timeout: 15 * time.Second}
		d.NetName, d.Org, d.OrgAddr = rdapNet(client, ip)
		if m.facilitiesOK() {
			d.Facilities, d.Scoped = facilitiesFor(client, d.ASN, d.PoPCity)
		}
	}
	_ = m.ctx.Store.KVSet(detailKV+ip, cachedDetail{At: time.Now(), V: detailSchema, D: d})
	return d
}

// describeFast is what a waiting reader gets: whatever is already cached, plus
// a reverse lookup for anything that is not, under a deadline. A name alone is
// enough to place a router, which is the part that changes the map; the rest
// arrives on the next load once the warmer has fetched it.
func (m *Module) describeFast(pairs map[string]string, budget time.Duration) (map[string]Detail, []string) {
	out := make(map[string]Detail, len(pairs))
	var cold []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	deadline := time.Now().Add(budget)

	for ip, host := range pairs {
		if d, ok := m.cached(ip); ok {
			out[ip] = d
			continue
		}
		mu.Lock()
		cold = append(cold, ip)
		mu.Unlock()
		wg.Add(1)
		go func(ip, host string) {
			defer wg.Done()
			if time.Now().After(deadline) {
				return
			}
			sem <- struct{}{}
			defer func() { <-sem }()
			if time.Now().After(deadline) {
				return
			}
			if host == "" {
				host = reverseName(ip)
			}
			if host == "" {
				return
			}
			var d Detail
			d.Name = host
			if code, p, ok := decodePoP(host); ok {
				d.PoPCode, d.PoPCity, d.PoPLat, d.PoPLon = code, p.City, p.Lat, p.Lon
			}
			// Deliberately not cached: this is a partial answer, and writing
			// it under the same key the warmer uses would make "not asked
			// yet" indistinguishable from "asked, and there is nothing".
			mu.Lock()
			out[ip] = d
			mu.Unlock()
		}(ip, host)
	}
	wg.Wait()
	return out, cold
}

// note remembers addresses that still need the slow lookup.
func (m *Module) note(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		m.pending = map[string]bool{}
	}
	for _, ip := range ips {
		if len(m.pending) >= 2000 {
			return
		}
		m.pending[ip] = true
	}
}

// warm fills the cache for a few addresses at a time.
//
// Small, and on a timer. Two of these sources are free services run by other
// people, and a gateway that empties its whole backlog at them in one burst is
// how a source stops answering for everybody.
func (m *Module) warm() error {
	if !m.registryOK() {
		return nil
	}
	m.mu.Lock()
	var batch []string
	for ip := range m.pending {
		batch = append(batch, ip)
		delete(m.pending, ip)
		if len(batch) >= 12 {
			break
		}
	}
	m.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, ip := range batch {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			m.detailFor(ip, "")
		}(ip)
	}
	wg.Wait()
	return nil
}
