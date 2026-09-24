package paths

// Where the clouds say their addresses are.
//
// The big providers publish which prefixes they use in which region, and
// for an address in one of those ranges that is the best answer there is:
// the operator's own statement, updated weekly, about where the prefix is
// announced. It outranks a registration database and a latency estimate
// alike. Two kinds of range are published. Regional ranges carry a region
// -- us-east-1, westus2, europe-west4 -- which a table below turns into the
// city the region is built in. Anycast ranges (Cloudflare, Fastly, the
// clouds' own "global" services) are announced everywhere at once, and the
// only honest thing to say about such an address is that no single place
// holds it; a database position for one is set aside and the hop is left
// for the timing.
//
// Each feed is fetched through the public-only client, read as a stream --
// Microsoft's file is a hundred megabytes -- and kept as a small text file
// of prefix, region and coordinates; nothing large is held. Refreshed
// weekly, which is how often the sources change.

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// providerFeed is one published source.
type providerFeed struct {
	Name  string // shown on the card
	Key   string // file name
	URL   string
	Parse func(r io.Reader, emit func(prefix, region string, anycast bool)) error
}

var providerFeeds = []providerFeed{
	{"AWS", "aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", parseAWS},
	{"Google Cloud", "gcp", "https://www.gstatic.com/ipranges/cloud.json", parseGCP},
	{"Microsoft Azure", "azure", "", parseAzure}, // URL discovered per fetch
	{"Oracle Cloud", "oci", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", parseOCI},
	{"DigitalOcean", "do", "https://digitalocean.com/geo/google.csv", parseGeofeed},
	{"Linode / Akamai", "linode", "https://geoip.linode.com/", parseGeofeed},
	{"Cloudflare", "cloudflare", "https://www.cloudflare.com/ips-v4", parseAnycastList},
	{"Cloudflare IPv6", "cloudflare6", "https://www.cloudflare.com/ips-v6", parseAnycastList},
	{"Fastly", "fastly", "https://api.fastly.com/public-ip-list", parseFastly},
}

const azureDetailsPage = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"

var azureLinkRe = regexp.MustCompile(`https://download\.microsoft\.com/download/[^"' <>]*ServiceTags_Public_[0-9]+\.json`)

// providerRange is one row as kept and looked up.
type providerRange struct {
	Net      *net.IPNet
	Provider string
	Region   string
	Lat, Lon float64
	City     string
	Anycast  bool
}

// providerIndex answers "whose range, and where" for an address. Buckets by
// the first octet (or first sixteen bits) keep a lookup to a few dozen
// prefixes instead of fifty thousand; the longest matching prefix wins.
type providerIndex struct {
	mu   sync.RWMutex
	v4   map[byte][]providerRange
	v6   map[uint16][]providerRange
	memo map[string]*providerRange
	n    int
}

func (x *providerIndex) add(r providerRange) {
	if v4 := r.Net.IP.To4(); v4 != nil {
		ones, _ := r.Net.Mask.Size()
		first, last := v4[0], v4[0]
		if ones < 8 {
			last = first | byte(0xff>>uint(ones))
		}
		for b := int(first); b <= int(last); b++ {
			x.v4[byte(b)] = append(x.v4[byte(b)], r)
		}
	} else {
		ones, _ := r.Net.Mask.Size()
		first := uint16(r.Net.IP[0])<<8 | uint16(r.Net.IP[1])
		last := first
		if ones < 16 {
			last = first | uint16(0xffff>>uint(ones))
		}
		for b := int(first); b <= int(last); b++ {
			x.v6[uint16(b)] = append(x.v6[uint16(b)], r)
		}
	}
	x.n++
}

func (x *providerIndex) lookup(ip string) *providerRange {
	a := net.ParseIP(ip)
	if a == nil {
		return nil
	}
	x.mu.RLock()
	if r, ok := x.memo[ip]; ok {
		x.mu.RUnlock()
		return r
	}
	var cands []providerRange
	if v4 := a.To4(); v4 != nil {
		cands = x.v4[v4[0]]
		a = v4
	} else {
		cands = x.v6[uint16(a[0])<<8|uint16(a[1])]
	}
	var best *providerRange
	bestBits := -1
	for i := range cands {
		if !cands[i].Net.Contains(a) {
			continue
		}
		if bits, _ := cands[i].Net.Mask.Size(); bits > bestBits {
			best, bestBits = &cands[i], bits
		}
	}
	x.mu.RUnlock()
	x.mu.Lock()
	if x.memo == nil || len(x.memo) > 50000 {
		x.memo = map[string]*providerRange{}
	}
	x.memo[ip] = best
	x.mu.Unlock()
	return best
}

// ---------------------------------------------------------------- parsers

func parseAWS(r io.Reader, emit func(string, string, bool)) error {
	var in struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
		} `json:"prefixes"`
		IPv6 []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return err
	}
	for _, p := range in.Prefixes {
		emit(p.IPPrefix, p.Region, p.Region == "GLOBAL")
	}
	for _, p := range in.IPv6 {
		emit(p.IPv6Prefix, p.Region, p.Region == "GLOBAL")
	}
	return nil
}

func parseGCP(r io.Reader, emit func(string, string, bool)) error {
	var in struct {
		Prefixes []struct {
			IPv4  string `json:"ipv4Prefix"`
			IPv6  string `json:"ipv6Prefix"`
			Scope string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return err
	}
	for _, p := range in.Prefixes {
		pfx := p.IPv4
		if pfx == "" {
			pfx = p.IPv6
		}
		emit(pfx, p.Scope, p.Scope == "global")
	}
	return nil
}

func parseOCI(r io.Reader, emit func(string, string, bool)) error {
	var in struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return err
	}
	for _, rg := range in.Regions {
		for _, c := range rg.CIDRs {
			emit(c.CIDR, rg.Region, false)
		}
	}
	return nil
}

// parseAzure streams the service-tag file, keeping only the regional
// AzureCloud aggregates. The file is around a hundred megabytes; reading it
// whole would be a hundred megabytes of heap on a firewall for a table
// that compacts to a few hundred kilobytes.
func parseAzure(r io.Reader, emit func(string, string, bool)) error {
	dec := json.NewDecoder(r)
	// Walk to "values".
	for {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if s, ok := t.(string); ok && s == "values" {
			break
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return fmt.Errorf("azure: values is not an array")
	}
	for dec.More() {
		var v struct {
			Name       string `json:"name"`
			Properties struct {
				Region          string   `json:"region"`
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		}
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if !strings.HasPrefix(v.Name, "AzureCloud.") || v.Properties.Region == "" {
			continue
		}
		for _, p := range v.Properties.AddressPrefixes {
			emit(p, v.Properties.Region, false)
		}
	}
	return nil
}

// parseGeofeed reads an RFC 8805 file: prefix, country, region, city,
// postal. The region carried on is "city, country" for the place table.
func parseGeofeed(r io.Reader, emit func(string, string, bool)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rec, err := csv.NewReader(strings.NewReader(line)).Read()
		if err != nil || len(rec) < 4 {
			continue
		}
		emit(strings.TrimSpace(rec[0]), strings.TrimSpace(rec[3])+", "+strings.TrimSpace(rec[1]), false)
	}
	return sc.Err()
}

func parseAnycastList(r io.Reader, emit func(string, string, bool)) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if p := strings.TrimSpace(sc.Text()); p != "" && !strings.HasPrefix(p, "#") {
			emit(p, "anycast", true)
		}
	}
	return sc.Err()
}

func parseFastly(r io.Reader, emit func(string, string, bool)) error {
	var in struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return err
	}
	for _, p := range append(in.Addresses, in.IPv6Addresses...) {
		emit(p, "anycast", true)
	}
	return nil
}

// ---------------------------------------------------------------- fetch

type providerState struct {
	On    bool                     `json:"on"`
	Feeds map[string]providerStats `json:"feeds"`
	Total int                      `json:"prefixes"`
}

type providerStats struct {
	Name      string `json:"name"`
	Prefixes  int    `json:"prefixes"`
	Unplaced  int    `json:"unplaced_regions,omitempty"` // rows whose region no table knows
	FetchedAt int64  `json:"fetched_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (m *Module) providersDir() string { return filepath.Join(m.ctx.Platform.DataDir, "providers") }

// refreshProviders fetches any feed missing or a week old, compacts it to
// disk, and reloads the index from every file present.
func (m *Module) refreshProviders() error {
	if !core.Bool(m.ctx.Settings(), "provider_feeds", true) {
		m.mu.Lock()
		m.providers, m.provider = &providerIndex{v4: map[byte][]providerRange{}, v6: map[uint16][]providerRange{}}, providerState{}
		m.mu.Unlock()
		return nil
	}
	dir := m.providersDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// One feed per run, and the run is gentle: a hundred-megabyte file
	// pulled flat out, on a gateway that is also routing, inspecting and
	// counting every flow, is a hundred megabytes taken from everything else.
	// The job comes round every half hour, does the stalest feed, and idles
	// once all are fresh; a week's staleness is the trigger.
	m.mu.Lock()
	stats := m.provider.Feeds
	m.mu.Unlock()
	if stats == nil {
		stats = map[string]providerStats{}
	}
	var pick *providerFeed
	var pickAge time.Duration
	for i := range providerFeeds {
		f := &providerFeeds[i]
		path := filepath.Join(dir, f.Key+".csv")
		st := stats[f.Key]
		st.Name = f.Name
		if fi, err := os.Stat(path); err == nil {
			st.FetchedAt = fi.ModTime().Unix()
		}
		stats[f.Key] = st
		age := 365 * 24 * time.Hour
		if st.FetchedAt > 0 {
			age = time.Since(time.Unix(st.FetchedAt, 0))
		}
		if age > 7*24*time.Hour && age > pickAge {
			pick, pickAge = f, age
		}
	}
	if pick != nil {
		path := filepath.Join(dir, pick.Key+".csv")
		st := stats[pick.Key]
		if n, unplaced, err := m.fetchProvider(*pick, path); err != nil {
			st.Error = err.Error()
			// Not again for a day: a failing feed must not be hammered.
			_ = os.Chtimes(path, time.Now().Add(-6*24*time.Hour), time.Now().Add(-6*24*time.Hour))
		} else {
			st.Prefixes, st.Unplaced, st.FetchedAt, st.Error = n, unplaced, time.Now().Unix(), ""
		}
		stats[pick.Key] = st
	}
	return m.loadProviders(stats)
}

// throttled reads at most rate bytes per second, so a big file arrives at a
// walking pace and leaves the link and the CPU to the traffic the gateway
// exists for.
type throttled struct {
	r     io.Reader
	rate  int
	start time.Time
	n     int64
}

func (t *throttled) Read(p []byte) (int, error) {
	if len(p) > 64<<10 {
		p = p[:64<<10]
	}
	n, err := t.r.Read(p)
	t.n += int64(n)
	if t.start.IsZero() {
		t.start = time.Now()
	}
	// Sleep until the bytes so far fit the rate.
	want := time.Duration(float64(t.n) / float64(t.rate) * float64(time.Second))
	if ahead := want - time.Since(t.start); ahead > 0 {
		time.Sleep(ahead)
	}
	return n, err
}

func (m *Module) fetchProvider(f providerFeed, path string) (int, int, error) {
	u := f.URL
	if f.Key == "azure" {
		if v := strings.TrimSpace(core.Str(m.ctx.Settings(), "azure_service_tags_url", "")); v != "" {
			u = v
		} else {
			var err error
			if u, err = m.discoverAzure(); err != nil {
				return 0, 0, err
			}
		}
	}
	if err := checkFetchURL(u); err != nil {
		return 0, 0, err
	}
	client := safeClient(6 * time.Minute)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "FlowSight/"+m.version()+" (+https://github.com/grioghar/flowsight)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("%s", resp.Status)
	}
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	w := bufio.NewWriter(out)
	n, unplaced := 0, 0
	emit := func(prefix, region string, anycast bool) {
		prefix = strings.TrimSpace(prefix)
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			return
		}
		pl, ok := regionPlace(f.Key, region)
		if !ok && !anycast {
			unplaced++
			return
		}
		fmt.Fprintf(w, "%s,%s,%s,%.4f,%.4f,%s,%t\n", prefix, f.Name, csvSafe(region), pl.Lat, pl.Lon, csvSafe(pl.City), anycast)
		n++
	}
	err = f.Parse(&throttled{r: io.LimitReader(resp.Body, 512<<20), rate: 2 << 20}, emit)
	w.Flush()
	out.Close()
	if err != nil {
		os.Remove(tmp)
		return 0, 0, err
	}
	if n == 0 {
		os.Remove(tmp)
		return 0, unplaced, fmt.Errorf("no usable ranges in the file")
	}
	return n, unplaced, os.Rename(tmp, path)
}

func csvSafe(s string) string { return strings.NewReplacer(",", " ", "\n", " ").Replace(s) }

// discoverAzure finds this week's file: Microsoft moves the link every
// Monday and the download page carries it.
func (m *Module) discoverAzure() (string, error) {
	client := safeClient(time.Minute)
	req, err := http.NewRequest("GET", azureDetailsPage, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; FlowSight/"+m.version()+")")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if u := azureLinkRe.Find(b); u != nil {
		return string(u), nil
	}
	return "", fmt.Errorf("azure: no ServiceTags_Public link on the download page; set azure_service_tags_url")
}

// loadProviders reads every compact file into a fresh index.
func (m *Module) loadProviders(stats map[string]providerStats) error {
	idx := &providerIndex{v4: map[byte][]providerRange{}, v6: map[uint16][]providerRange{}}
	dir := m.providersDir()
	for _, f := range providerFeeds {
		path := filepath.Join(dir, f.Key+".csv")
		fh, err := os.Open(path)
		if err != nil {
			continue
		}
		st := stats[f.Key]
		if st.Name == "" {
			st.Name = f.Name
		}
		count := 0
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			p := strings.Split(sc.Text(), ",")
			if len(p) < 7 {
				continue
			}
			_, n, err := net.ParseCIDR(p[0])
			if err != nil {
				continue
			}
			lat, _ := strconv.ParseFloat(p[3], 64)
			lon, _ := strconv.ParseFloat(p[4], 64)
			idx.add(providerRange{Net: n, Provider: p[1], Region: p[2], Lat: lat, Lon: lon, City: p[5], Anycast: p[6] == "true"})
			count++
		}
		fh.Close()
		st.Prefixes = count
		stats[f.Key] = st
	}
	m.mu.Lock()
	m.providers = idx
	m.provider = providerState{On: true, Feeds: stats, Total: idx.n}
	m.mu.Unlock()
	m.routes.reset()
	return nil
}

// providerPlace is what the clouds say about an address, if anything.
func (m *Module) providerPlace(ip string) *providerRange {
	m.mu.Lock()
	idx := m.providers
	m.mu.Unlock()
	if idx == nil {
		return nil
	}
	return idx.lookup(ip)
}

// providerNames lists the feeds, for the card.
func providerNames() []string {
	var out []string
	for _, f := range providerFeeds {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}
