package paths

import (
	"encoding/json"
	"testing"
)

func TestGeofeedURLIsFoundInRDAP(t *testing.T) {
	var r rdapReply
	if err := json.Unmarshal([]byte(`{"name":"EXAMPLE-NET","remarks":[{"title":"description","description":["Example Corp backbone"]},{"title":"Geofeed","description":["https://geo.example.net/feed.csv"]}],"entities":[]}`), &r); err != nil {
		t.Fatal(err)
	}
	if u := geofeedFromRDAP(&r); u != "https://geo.example.net/feed.csv" {
		t.Fatalf("remark: %q", u)
	}
	var r2 rdapReply
	_ = json.Unmarshal([]byte(`{"links":[{"rel":"self","href":"https://rdap.arin.net/registry/ip/1.2.3.0"},{"rel":"geofeed","href":"https://example.org/geofeed.csv"}],"remarks":[{"description":["geofeed: https://example.org/other.csv"]}]}`), &r2)
	if u := geofeedFromRDAP(&r2); u != "https://example.org/geofeed.csv" {
		t.Fatalf("link should win: %q", u)
	}
	var r3 rdapReply
	_ = json.Unmarshal([]byte(`{"remarks":[{"description":["Geofeed https://example.org/g.csv."]}]}`), &r3)
	if u := geofeedFromRDAP(&r3); u != "https://example.org/g.csv" {
		t.Fatalf("inline form: %q", u)
	}
	if geofeedFromRDAP(&rdapReply{}) != "" {
		t.Fatal("nothing named, nothing found")
	}
	if geofeedFile("https://a") == geofeedFile("https://b") || len(geofeedFile("x")) < 20 {
		t.Fatal("file names should be distinct and hashed")
	}
}
