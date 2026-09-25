package firewall

import (
	"reflect"
	"testing"
)

func TestGeoSpecsRoundTrip(t *testing.T) {
	in := []geoSpec{
		{Table: "fs_geo_cn", Countries: []string{"CN"}},
		{Table: "fs_geox_iot-abroad", Countries: []string{"US", "CA"}, Invert: true},
	}
	rules := "block return quick from 10.0.0.5 to <fs_geo_cn> label \"x\"\n"
	for _, g := range in {
		rules += "table <" + g.Table + "> persist\n" + g.comment() + "\n"
	}
	got := geoSpecs(rules)
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("got %+v want %+v", got, in)
	}
	if geoSpecs("block all\n# not a geo line\n") != nil {
		t.Fatal("stray comments must not become tables")
	}
}
