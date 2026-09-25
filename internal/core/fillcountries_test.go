package core

import "testing"

type fakeLook map[string]string

func (f fakeLook) CountryOf(ip string) string { return f[ip] }

func TestFillCountriesLooksUpTheFarEnd(t *testing.T) {
	look := fakeLook{"8.8.8.8": "US", "2001:db8::1": "DE"}
	local := func(ip string) bool { return ip == "192.168.1.5" }
	flows := []Flow{{SrcIP: "192.168.1.5", DstIP: "8.8.8.8"}, {SrcIP: "2001:db8::1", DstIP: "192.168.1.5"}, {SrcIP: "192.168.1.5", DstIP: "192.168.1.9"}, {SrcIP: "192.168.1.5", DstIP: "1.1.1.1", Country: "AU"}}
	FillCountries(flows, look, local)
	if flows[0].Country != "US" || flows[1].Country != "DE" || flows[2].Country != "" || flows[3].Country != "AU" {
		t.Fatalf("%+v", flows)
	}
}
