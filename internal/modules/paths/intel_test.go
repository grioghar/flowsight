package paths

import "testing"

func TestDecodePoPReadsRealRouterNames(t *testing.T) {
	cases := []struct {
		host string
		code string
		city string
	}{
		{"ae10.edge1.dal2.sp.lumen.tech", "dal", "Dallas, TX, US"},
		{"po1.owr03.lax31.ntwk.msn.net", "lax", "Los Angeles, CA, US"},
		{"be21.owr01.dfw34.ntwk.msn.net", "dfw", "Dallas, TX, US"},
		{"be1013.rwa02.dm4.ntwk.msn.net", "dm", "Des Moines, IA, US"},
		{"172-11-154-1.lightspeed.tpkaks.sbcglobal.net", "tpk", "Topeka, KS, US"},
	}
	for _, c := range cases {
		code, p, ok := decodePoP(c.host)
		if !ok {
			t.Errorf("%s: no site read", c.host)
			continue
		}
		if code != c.code || p.City != c.city {
			t.Errorf("%s: got %s/%s, want %s/%s", c.host, code, p.City, c.code, c.city)
		}
	}
}

// A wrong city is worse than no city: it is drawn on the map with the same
// confidence as a right one. These are the shapes most likely to produce one.
func TestDecodePoPDeclinesWhenItDoesNotKnow(t *testing.T) {
	for _, host := range []string{
		"",
		"one.one.one.one",       // no site anywhere in it
		"dns.google",            // two labels, both the registered domain
		"ae10.ae11.example.com", // interface names only
		"host.example.org",
		"xe-0-0-0.example.net",
	} {
		if code, _, ok := decodePoP(host); ok {
			t.Errorf("%q: invented site %q", host, code)
		}
	}
}

// The site code sits nearer the domain than the interface does. A name with a
// place-like fragment early on must not beat the real one later.
func TestDecodePoPPrefersTheSiteOverTheInterface(t *testing.T) {
	code, p, ok := decodePoP("man1.agg2.fra3.example.net")
	if !ok {
		t.Fatal("read nothing")
	}
	if code != "fra" || p.City != "Frankfurt, DE" {
		t.Fatalf("got %s/%s, want fra/Frankfurt, DE", code, p.City)
	}
}

func TestSplitPlace(t *testing.T) {
	cases := []struct{ in, city, region, country string }{
		{"Los Angeles, CA, US", "Los Angeles", "CA", "US"},
		{"London, GB", "London", "", "GB"},
		{"Singapore", "Singapore", "", ""},
	}
	for _, c := range cases {
		city, region, country := splitPlace(c.in)
		if city != c.city || region != c.region || country != c.country {
			t.Errorf("%q: got %q/%q/%q", c.in, city, region, country)
		}
	}
}

func TestSplitPipeTrimsCymruFields(t *testing.T) {
	f := splitPipe(`"3356 | 4.0.0.0/9 | US | arin | 1992-12-01"`)
	if len(f) != 5 || f[0] != "3356" || f[1] != "4.0.0.0/9" || f[4] != "1992-12-01" {
		t.Fatalf("got %#v", f)
	}
}

func TestReverseV4(t *testing.T) {
	if r, ok := reverseV4("4.68.39.1"); !ok || r != "1.39.68.4" {
		t.Fatalf("got %q ok=%v", r, ok)
	}
	// v6 lives in a different zone and is not wired up; it must decline
	// rather than hand back a v4-shaped string.
	if _, ok := reverseV4("2606:4700::1111"); ok {
		t.Fatal("accepted a v6 address")
	}
}

// The jCard carries the postal address in a parameter, not in the value.
// Reading the value gives seven empty strings and a confident blank.
func TestVCardReadsAddressFromTheLabelParameter(t *testing.T) {
	raw := []byte(`["vcard",[
		["version",{},"text","4.0"],
		["fn",{},"text","Level 3 Parent, LLC"],
		["adr",{"label":"100 CenturyLink Drive\nMonroe\nLA\n71203\nUnited States"},"text",["","","","","","",""]]
	]]`)
	name, addr := vcard(raw)
	if name != "Level 3 Parent, LLC" {
		t.Errorf("name = %q", name)
	}
	want := "100 CenturyLink Drive, Monroe, LA, 71203, United States"
	if addr != want {
		t.Errorf("addr = %q, want %q", addr, want)
	}
}

// The carriers each spell a place differently, and every one of these appears
// in real router names on a working network. A miss is not harmless: the hop
// keeps the address database's answer, which is what these are here to
// overrule, and a wrong placement can then be ruled out for a distance it
// never had.
func TestDecodePoPHandlesEachCarriersSpelling(t *testing.T) {
	cases := []struct{ host, city string }{
		{"be2764.ccr32.dfw01.atlas.cogentco.com", "Dallas, TX, US"},        // code plus unit number
		{"dls-b23-link.ip.twelve99.net", "Dallas, TX, US"},                 // Arelion's own abbreviation
		{"ash-b2-link.ip.twelve99.net", "Ashburn, VA, US"},                 // ditto
		{"adm-bb2-link.ip.twelve99.net", "Amsterdam, NL"},                  // ditto
		{"ae-13.a01.dllstx14.us.bb.gin.ntt.net", "Dallas, TX, US"},         // NTT: city plus state, four and two
		{"ae-6.a03.londen12.uk.bb.gin.ntt.net", "London, GB"},              // NTT abroad
		{"CENTURYLINK.edge6.Dallas3.Level3.net", "Dallas, TX, US"},         // Level 3 spells it out
		{"JAPAN-REGIS.ear2.SanJose1.Level3.net", "San Jose, CA, US"},       // and runs two words together
		{"ae3.6.bar1.Portland1.net.lumen.tech", "Portland, OR, US"},        // Lumen, likewise
		{"172-11-154-1.lightspeed.tpkaks.sbcglobal.net", "Topeka, KS, US"}, // AT&T: three and three
		{"ae14.cr3-mtl1.ip4.gtt.net", "Montreal, QC, CA"},                  // GTT
	}
	for _, c := range cases {
		_, p, ok := decodePoP(c.host)
		if !ok {
			t.Errorf("%s: read no site", c.host)
			continue
		}
		if p.City != c.city {
			t.Errorf("%s: got %q, want %q", c.host, p.City, c.city)
		}
	}
}

// The spelled-out names are derived from the code table, so a place can never
// be in one and not the other.
func TestCityNamesAgreeWithTheCodes(t *testing.T) {
	if len(cityNames) < 60 {
		t.Fatalf("only %d spelled-out names derived; the table should be most of pops", len(cityNames))
	}
	if p, ok := cityNames["losangeles"]; !ok || p.City != "Los Angeles, CA, US" {
		t.Errorf("a two-word city should run together: %v %v", p, ok)
	}
	for _, p := range cityNames {
		if p.Lat == 0 && p.Lon == 0 {
			t.Errorf("%s has no coordinates", p.City)
		}
	}
}
