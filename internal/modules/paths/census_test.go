package paths

import (
	"strings"
	"testing"
)

func TestCensusRowsCarryTheirSites(t *testing.T) {
	csvText := "prefix,AB_ICMPv4,AB_TCPv4,AB_DNSv4,GCD_ICMPv4,GCD_TCPv4,partial,backing_prefix,ASN,locations\n" +
		`104.16.124.0/24,31,31,0,74,29,False,104.16.112.0/20,13335,"[{""candidate_diameter"": 22.0, ""city"": ""Honolulu"", ""country_code"": ""US"", ""id"": ""HNL"", ""lat"": 21.3187, ""lon"": -157.922, ""num_constraints"": 1}, {""candidate_diameter"": 0.0, ""city"": null, ""country_code"": null, ""id"": ""NoCity"", ""lat"": 39.51, ""lon"": -76.16, ""num_constraints"": 0}, {""candidate_diameter"": 10.0, ""city"": ""Dallas"", ""country_code"": ""US"", ""id"": ""DFW"", ""lat"": 32.8968, ""lon"": -97.038, ""num_constraints"": 2}]"` + "\n" +
		`17.253.207.0/24,15,0,16,21,0,False,17.253.207.0/24,714,"[{""candidate_diameter"": 0.0, ""city"": ""Miami"", ""country_code"": ""US"", ""id"": ""MIA"", ""lat"": 25.79, ""lon"": -80.29, ""num_constraints"": 1}]"` + "\n"
	got := map[string][]anySite{}
	asns := map[string]int{}
	n, err := parseCensus(strings.NewReader(csvText), func(p string, asn int, s []anySite) { got[p] = s; asns[p] = asn })
	if err != nil || n != 2 {
		t.Fatalf("%d rows, %v", n, err)
	}
	if len(got["104.16.124.0/24"]) != 2 || asns["104.16.124.0/24"] != 13335 || got["104.16.124.0/24"][1].City != "Dallas" {
		t.Fatalf("cloudflare row: %+v", got["104.16.124.0/24"])
	}
	if who, ok := anycastOperator("13335"); !ok || who != "Cloudflare" {
		t.Fatal("cloudflare is an anycast operator")
	}
	if _, ok := anycastOperator("8075"); !ok {
		t.Fatal("microsoft is an anycast operator")
	}
	if _, ok := anycastOperator("7018"); ok {
		t.Fatal("AT&T is not")
	}
}

// An anycast hop with census sites lands on the site nearest its anchor.
func TestAnycastHopLandsOnTheNearestCensusSite(t *testing.T) {
	g := Graph{
		Nodes: []Node{
			{ID: "d", Index: 6, IPs: []string{"12.1.1.1"}, RTT: 18.3, Located: true, Lat: 32.78, Lon: -96.8, City: "Dallas", Source: "name"},
			{ID: "cf", Index: 7, IPs: []string{"104.16.124.96"}, RTT: 19.4, Anycast: true, AnycastSites: 3,
				anycastSites: []anySite{{City: "Honolulu", CC: "US", Lat: 21.3, Lon: -157.9}, {City: "Dallas", CC: "US", Lat: 32.9, Lon: -97.0}, {City: "Toronto", CC: "CA", Lat: 43.7, Lon: -79.4}}},
		},
		Legs: []Leg{{From: "d", To: "cf", Destinations: []string{"104.16.124.96"}}},
	}
	interpolateGaps(&g)
	n := g.Nodes[1]
	if n.Source != "anycast" || n.City != "Dallas" || !strings.Contains(n.BetweenHow, "3 sites") || !strings.Contains(n.BetweenHow, "local or regional") {
		t.Fatalf("%+v", n)
	}
}

func TestOnlyOperatorEndpointsAreTreatedAsAnycast(t *testing.T) {
	g := Graph{Nodes: []Node{
		{ID: "bb", Index: 8, IPs: []string{"17.0.14.53"}, RTT: 61, Located: true, Lat: 37.3, Lon: -122.0, City: "Cupertino", Source: "database", Detail: &Detail{ASN: "714"}},
		{ID: "edge", Index: 9, IPs: []string{"17.253.207.1"}, RTT: 28, Located: true, Lat: 37.3, Lon: -122.0, City: "Cupertino", Source: "database", Detail: &Detail{ASN: "714"}},
		{ID: "named", Index: 9, IPs: []string{"8.8.4.4"}, RTT: 20, Located: true, Lat: 32.8, Lon: -96.8, City: "Dallas", Source: "name", Detail: &Detail{ASN: "15169"}},
	}, Legs: []Leg{{From: "bb", To: "edge", Destinations: []string{"17.253.207.1"}}, {From: "bb", To: "named", Destinations: []string{"8.8.4.4"}}}}
	markEndpoints(&g)
	markOperatorAnycast(&g)
	if g.Nodes[0].Anycast || !g.Nodes[0].Located {
		t.Fatal("a backbone router of an anycast operator is not anycast")
	}
	if !g.Nodes[1].Anycast || g.Nodes[1].Located || g.Nodes[1].SetAside == "" {
		t.Fatalf("an endpoint of an anycast operator placed by the database is anycast and set aside: %+v", g.Nodes[1])
	}
	if g.Nodes[2].Anycast {
		t.Fatal("a name-placed endpoint is left alone")
	}
}

func TestCensusReaderSniffsGzip(t *testing.T) {
	// Covered by fetchCensusOne's peek; the parser itself must accept plain text.
	n, err := parseCensus(strings.NewReader("prefix,ASN,locations\n1.1.1.0/24,13335,\"[]\"\n"), func(string, int, []anySite) {})
	if err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestOnlyNearbySitesAreKept(t *testing.T) {
	home := Home{Lat: 39.18, Lon: -96.57, OK: true}
	var sites []anySite
	for i := 0; i < 40; i++ {
		sites = append(sites, anySite{City: "far", Lat: -30, Lon: 100 + float64(i)})
	}
	sites = append(sites, anySite{City: "Dallas", Lat: 32.8, Lon: -96.8}, anySite{City: "Chicago", Lat: 41.9, Lon: -87.6}, anySite{City: "Honolulu", Lat: 21.3, Lon: -157.9})
	kept := nearSites(sites, home)
	// Honolulu is 6,100 km away and falls outside the regional radius.
	if len(kept) != 2 || kept[0].City != "Dallas" || kept[1].City != "Chicago" {
		t.Fatalf("%+v", kept)
	}
	if got := nearSites(sites, Home{}); len(got) != 6 {
		t.Fatalf("without an origin the first six are kept, got %d", len(got))
	}
}
