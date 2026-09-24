package paths

// The anycast census: a lookup that says "this address is anycast, and here
// are the sites it is served from".
//
// LACeS, the University of Twente and CAIDA's longitudinal anycast census,
// publishes every day the /24s and /48s it has detected as anycast, with the
// AS and the list of sites it located instances at. Forty-odd thousand IPv4
// prefixes and eighteen thousand IPv6. For a hop in one of them the honest
// statement is: this address is announced from many datacentres at once, and
// from here you are reaching a local or regional one -- the site nearest the
// hop before it, as far as the round trip allows. No database position and no
// measurement made from somewhere else says anything about which.

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

var censusURLs = []string{
	"https://manycast.net/api/v1/export/IPv4-latest.csv.gz",
	"https://manycast.net/api/v1/export/IPv6-latest.csv.gz",
}

const censusFile = "census.csv"

// anySite is one place an anycast prefix has been seen served from.
type anySite struct {
	City string  `json:"city,omitempty"`
	CC   string  `json:"cc,omitempty"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
}

// parseCensus reads the published CSV and emits prefix, AS and sites.
func parseCensus(r io.Reader, emit func(prefix string, asn int, sites []anySite)) (int, error) {
	cr := csv.NewReader(r)
	cr.LazyQuotes = true
	cr.FieldsPerRecord = -1
	head, err := cr.Read()
	if err != nil {
		return 0, err
	}
	col := map[string]int{}
	for i, h := range head {
		col[strings.TrimSpace(h)] = i
	}
	pi, ai, li, ok1 := col["prefix"], col["ASN"], col["locations"], true
	if _, ok := col["prefix"]; !ok {
		ok1 = false
	}
	if _, ok := col["locations"]; !ok {
		ok1 = false
	}
	if !ok1 {
		return 0, fmt.Errorf("census: unexpected columns %v", head)
	}
	n := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if len(rec) <= li || len(rec) <= pi {
			continue
		}
		asn := 0
		if ai < len(rec) {
			asn, _ = strconv.Atoi(strings.TrimSpace(rec[ai]))
		}
		var raw []struct {
			City string  `json:"city"`
			CC   string  `json:"country_code"`
			Lat  float64 `json:"lat"`
			Lon  float64 `json:"lon"`
		}
		_ = json.Unmarshal([]byte(rec[li]), &raw)
		sites := make([]anySite, 0, len(raw))
		for _, s := range raw {
			if s.City == "" && s.CC == "" {
				continue // an unconstrained placeholder
			}
			sites = append(sites, anySite{City: s.City, CC: s.CC, Lat: s.Lat, Lon: s.Lon})
		}
		emit(strings.TrimSpace(rec[pi]), asn, sites)
		n++
	}
	return n, nil
}

// refreshCensus fetches both lists once a week and compacts them.
func (m *Module) refreshCensus() error {
	if !core.Bool(m.ctx.Settings(), "anycast_census", true) {
		return nil
	}
	dir := m.providersDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, censusFile)
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) < 7*24*time.Hour {
		return nil
	}
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	total := 0
	var problems []string
	for _, u := range censusURLs {
		n, err := m.fetchCensusOne(u, out)
		if err != nil {
			problems = append(problems, shortHost(u)+": "+err.Error())
		}
		total += n
		time.Sleep(2 * time.Second)
	}
	out.Close()
	m.mu.Lock()
	m.censusErr = strings.Join(problems, "; ")
	m.mu.Unlock()
	if total == 0 {
		os.Remove(tmp)
		return fmt.Errorf("anycast census: nothing fetched (%s)", strings.Join(problems, "; "))
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	m.mu.Lock()
	stats := m.provider.Feeds
	m.mu.Unlock()
	if stats == nil {
		stats = map[string]providerStats{}
	}
	return m.loadProviders(stats)
}

// fetchCensusOne pulls one list and appends its rows. The server may hand
// the file back already inflated -- Go's client asks for gzip transfer
// encoding and undoes it -- so the stream is sniffed rather than assumed.
func (m *Module) fetchCensusOne(u string, out io.Writer) (int, error) {
	if err := checkFetchURL(u); err != nil {
		return 0, err
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "FlowSight/"+m.version()+" (+https://github.com/grioghar/flowsight)")
	resp, err := safeClient(5 * time.Minute).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s", resp.Status)
	}
	br := bufio.NewReader(&throttled{r: io.LimitReader(resp.Body, 512<<20), rate: 2 << 20})
	var r io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return 0, err
		}
		defer gz.Close()
		r = gz
	}
	return parseCensus(r, func(prefix string, asn int, sites []anySite) {
		if _, _, err := net.ParseCIDR(prefix); err != nil {
			return
		}
		b, _ := json.Marshal(sites)
		fmt.Fprintf(out, "%s\t%d\t%s\n", prefix, asn, b)
	})
}

// nearSites keeps the few sites that could be the instance reached from
// here: the closest to the origin, within a hemisphere's worth of distance.
// Sixty thousand prefixes each with thirty sites were two hundred megabytes
// of heap on a daemon with a quarter of that to spend; six sites within
// five thousand kilometres answer the same question for a fiftieth of it.
func nearSites(sites []anySite, home Home) []anySite {
	if len(sites) <= 6 || !home.OK {
		if len(sites) > 6 {
			return sites[:6]
		}
		return sites
	}
	type d struct {
		km float64
		s  anySite
	}
	ds := make([]d, 0, len(sites))
	for _, s := range sites {
		km := greatCircleKM(home.Lat, home.Lon, s.Lat, s.Lon)
		if km <= 5000 {
			ds = append(ds, d{km, s})
		}
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i].km < ds[j].km })
	if len(ds) > 6 {
		ds = ds[:6]
	}
	out := make([]anySite, 0, len(ds))
	for _, x := range ds {
		out = append(out, x.s)
	}
	return out
}

// loadCensusInto adds the census rows to a provider index, all anycast.
func loadCensusInto(idx *providerIndex, path string, home Home) int {
	fh, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer fh.Close()
	n := 0
	rd := csv.NewReader(fh)
	rd.Comma = '\t'
	rd.LazyQuotes = true
	rd.FieldsPerRecord = -1
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		_, ipn, err := net.ParseCIDR(rec[0])
		if err != nil {
			continue
		}
		asn, _ := strconv.Atoi(rec[1])
		var sites []anySite
		_ = json.Unmarshal([]byte(rec[2]), &sites)
		total := len(sites)
		sites = nearSites(sites, home)
		prov := "anycast census"
		if asn > 0 {
			prov = fmt.Sprintf("anycast census, AS%d", asn)
		}
		idx.add(providerRange{Net: ipn, Provider: prov, Region: "anycast", Anycast: true, Sites: sites, SiteTotal: total})
		n++
	}
	return n
}

// anycastOperators are networks whose addresses are served anycast or by
// global load balancing as a matter of course. A hop of theirs whose
// registered or measured position the round trip rules out is not a mystery,
// it is an anycast instance nearer than the record says.
var anycastOperators = map[int]string{
	15169: "Google", 36040: "Google", 396982: "Google", 13335: "Cloudflare", 54113: "Fastly",
	20940: "Akamai", 16625: "Akamai", 32787: "Akamai", 16509: "Amazon", 14618: "Amazon",
	714: "Apple", 6185: "Apple", 32934: "Meta", 8075: "Microsoft", 62597: "NS1", 12008: "Vercara",
	19905: "Vercara", 36236: "NetActuate", 19281: "Quad9", 36692: "OpenDNS", 7342: "Verisign",
	26415: "Verisign", 42: "PCH", 3856: "PCH", 397213: "ICANN", 2635: "Automattic", 209242: "Cloudflare",
}

func anycastOperator(asn string) (string, bool) {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(asn)), "AS"))
	if err != nil {
		return "", false
	}
	name, ok := anycastOperators[n]
	return name, ok
}
