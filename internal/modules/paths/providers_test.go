package paths

import (
	"net"
	"strings"
	"testing"
)

func collect(t *testing.T, f providerFeed, body string) map[string][3]any {
	t.Helper()
	got := map[string][3]any{}
	if err := f.Parse(strings.NewReader(body), func(p, r string, a bool) { got[p] = [3]any{r, a, true} }); err != nil {
		t.Fatalf("%s: %v", f.Name, err)
	}
	return got
}

func feed(key string) providerFeed {
	for _, f := range providerFeeds {
		if f.Key == key {
			return f
		}
	}
	panic(key)
}

func TestProviderFeedsParseTheirPublishedShapes(t *testing.T) {
	aws := collect(t, feed("aws"), `{"prefixes":[{"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"AMAZON"},{"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f14::/35","region":"us-west-2"}]}`)
	if aws["3.5.140.0/22"][0] != "ap-northeast-2" || aws["13.32.0.0/15"][1] != true || aws["2600:1f14::/35"][0] != "us-west-2" {
		t.Fatalf("aws: %v", aws)
	}
	gcp := collect(t, feed("gcp"), `{"prefixes":[{"ipv4Prefix":"34.1.208.0/20","service":"Google Cloud","scope":"africa-south1"},{"ipv6Prefix":"2600:1900:4000::/44","scope":"us-central1"},{"ipv4Prefix":"8.34.208.0/20","scope":"global"}]}`)
	if gcp["34.1.208.0/20"][0] != "africa-south1" || gcp["2600:1900:4000::/44"][0] != "us-central1" || gcp["8.34.208.0/20"][1] != true {
		t.Fatalf("gcp: %v", gcp)
	}
	oci := collect(t, feed("oci"), `{"regions":[{"region":"mx-monterrey-1","cidrs":[{"cidr":"40.233.0.0/19","tags":["OCI"]}]},{"region":"us-ashburn-1","cidrs":[{"cidr":"129.213.0.0/16","tags":[]}]}]}`)
	if oci["129.213.0.0/16"][0] != "us-ashburn-1" {
		t.Fatalf("oci: %v", oci)
	}
	az := collect(t, feed("azure"), `{"changeNumber":1,"cloud":"Public","values":[{"name":"ActionGroup","id":"x","properties":{"region":"","addressPrefixes":["1.2.3.0/24"]}},{"name":"AzureCloud.westus2","id":"y","properties":{"region":"westus2","addressPrefixes":["13.66.128.0/17","2603:1030:c00::/47"]}},{"name":"AzureCloud","properties":{"region":"","addressPrefixes":["4.0.0.0/8"]}}]}`)
	if len(az) != 2 || az["13.66.128.0/17"][0] != "westus2" || az["2603:1030:c00::/47"][0] != "westus2" {
		t.Fatalf("azure: %v", az)
	}
	geo := collect(t, feed("linode"), "# geofeed\n2600:3c00::/32,US,US-TX,Richardson,\n5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XH\n")
	if geo["2600:3c00::/32"][0] != "Richardson, US" || geo["5.101.96.0/21"][0] != "Amsterdam, NL" {
		t.Fatalf("geofeed: %v", geo)
	}
	cf := collect(t, feed("cloudflare"), "173.245.48.0/20\n103.21.244.0/22\n")
	if len(cf) != 2 || cf["173.245.48.0/20"][1] != true {
		t.Fatalf("cloudflare: %v", cf)
	}
	fs := collect(t, feed("fastly"), `{"addresses":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}`)
	if len(fs) != 2 || fs["2a04:4e40::/32"][1] != true {
		t.Fatalf("fastly: %v", fs)
	}
}

func TestRegionTablesAndLookup(t *testing.T) {
	for _, c := range []struct{ feed, region, city string }{
		{"aws", "us-east-1", "Ashburn"}, {"gcp", "europe-west4", "Eemshaven"}, {"azure", "westus2", "Quincy"},
		{"oci", "us-ashburn-1", "Ashburn"}, {"linode", "Richardson, US", "Richardson"}, {"do", "Bangalore, IN", "Bangalore"},
		{"do", "Prague, CZ", "Prague"},
	} {
		p, ok := regionPlace(c.feed, c.region)
		if !ok || !strings.HasPrefix(p.City, c.city) {
			t.Fatalf("%s %s -> %+v %v", c.feed, c.region, p, ok)
		}
	}
	if _, ok := regionPlace("aws", "xx-nowhere-9"); ok {
		t.Fatal("an unknown region must not be placed")
	}
	idx := &providerIndex{v4: map[byte][]providerRange{}, v6: map[uint16][]providerRange{}}
	mk := func(cidr, prov, region string, any bool) providerRange {
		_, n, _ := net.ParseCIDR(cidr)
		return providerRange{Net: n, Provider: prov, Region: region, Anycast: any}
	}
	idx.add(mk("13.64.0.0/11", "Azure", "broad", false))
	idx.add(mk("13.66.128.0/17", "Azure", "westus2", false))
	idx.add(mk("2600:1f14::/35", "AWS", "us-west-2", false))
	idx.add(mk("173.245.48.0/20", "Cloudflare", "anycast", true))
	if r := idx.lookup("13.66.200.1"); r == nil || r.Region != "westus2" {
		t.Fatalf("longest prefix should win: %+v", r)
	}
	if r := idx.lookup("13.70.0.1"); r == nil || r.Region != "broad" {
		t.Fatalf("the broad range should still answer: %+v", r)
	}
	if r := idx.lookup("2600:1f14:1::5"); r == nil || r.Provider != "AWS" {
		t.Fatalf("v6 lookup: %+v", r)
	}
	if r := idx.lookup("173.245.50.9"); r == nil || !r.Anycast {
		t.Fatalf("anycast: %+v", r)
	}
	if idx.lookup("8.8.8.8") != nil || idx.lookup("nonsense") != nil {
		t.Fatal("addresses outside every range must not match")
	}
}
