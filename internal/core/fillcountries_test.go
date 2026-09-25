package core

import "testing"

type fakeLook map[string]string

func (f fakeLook) CountryOf(ip string) string { return f[ip] }

type fakeAny map[string]string

func (f fakeAny) Anycast(ip string) (bool, string) { op, ok := f[ip]; return ok, op }

func TestFillCountriesLooksUpTheFarEnd(t *testing.T) {
	look := fakeLook{"8.8.8.8": "US", "2001:db8::1": "DE", "104.16.1.1": "CA"}
	anyc := fakeAny{"104.16.1.1": "Cloudflare", "8.8.8.8": "Google"}
	local := func(ip string) bool { return ip == "192.168.1.5" }
	flows := []Flow{
		{SrcIP: "192.168.1.5", DstIP: "8.8.8.8"},
		{SrcIP: "2001:db8::1", DstIP: "192.168.1.5"},
		{SrcIP: "192.168.1.5", DstIP: "192.168.1.9"},
		{SrcIP: "192.168.1.5", DstIP: "1.1.1.1", Country: "AU"},
		{SrcIP: "192.168.1.5", DstIP: "104.16.1.1"},
	}
	FillCountries(flows, look, anyc, local)
	if flows[0].Country != "US" || !flows[0].Anycast {
		t.Fatalf("google resolver: %+v", flows[0])
	}
	if flows[1].Country != "DE" || flows[1].Anycast {
		t.Fatalf("inbound: %+v", flows[1])
	}
	if flows[2].Country != "" || flows[3].Country != "AU" {
		t.Fatalf("local / preset: %+v %+v", flows[2], flows[3])
	}
	if flows[4].Country != "CA" || !flows[4].Anycast {
		t.Fatalf("anycast keeps its registered country and is flagged: %+v", flows[4])
	}
	// Nil lookups are fine.
	FillCountries(flows, nil, nil, nil)
}
