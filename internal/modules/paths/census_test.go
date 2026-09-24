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
